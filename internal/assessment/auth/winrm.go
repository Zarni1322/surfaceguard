package auth

import (
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
	"github.com/masterzen/winrm"
)

// Ensure compile-time check.
var _ Connector = (*WinRMConnector)(nil)

// WinRMConnector implements the Connector interface for WinRM.
type WinRMConnector struct {
	timeout time.Duration
}

// NewWinRMConnector creates a new WinRM connector.
func NewWinRMConnector(timeout time.Duration) *WinRMConnector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &WinRMConnector{timeout: timeout}
}

// Protocol returns WinRM.
func (c *WinRMConnector) Protocol() models.Protocol {
	return models.ProtocolWinRM
}

// Connect opens a WinRM session.
func (c *WinRMConnector) Connect(ctx context.Context, profile *Profile) (Session, error) {
	useHTTPS := true
	if profile.Port == 5985 {
		useHTTPS = false
	}

	endpoint := &winrm.Endpoint{
		Host:     profile.Host,
		Port:     profile.Port,
		HTTPS:    useHTTPS,
		Insecure: true,
		Timeout:  c.timeout,
	}

	client, err := winrm.NewClient(endpoint, profile.Username, profile.Password)
	if err != nil {
		return nil, fmt.Errorf("winrm client: %w", err)
	}

	shell, err := client.CreateShell()
	if err != nil {
		return nil, fmt.Errorf("winrm shell: %w", err)
	}

	return &winrmSession{
		client: client,
		shell:  shell,
	}, nil
}

// winrmSession wraps a WinRM shell for command execution.
type winrmSession struct {
	client *winrm.Client
	shell  *winrm.Shell
}

func (s *winrmSession) RunCommand(ctx context.Context, command string) (string, error) {
	cmd, err := s.shell.Execute("cmd", "/c", command)
	if err != nil {
		return "", fmt.Errorf("execute: %w", err)
	}

	var stdout, stderr strings.Builder

	// Read stdout in a goroutine.
	stdoutDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(&stdout, cmd.Stdout)
		stdoutDone <- err
	}()

	// Read stderr.
	stderrDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(&stderr, cmd.Stderr)
		stderrDone <- err
	}()

	// Wait for both or context cancel.
	select {
	case <-stdoutDone:
	case <-stderrDone:
	case <-ctx.Done():
		return "", ctx.Err()
	}

	cmd.Wait()
	if cmd.ExitCode() != 0 && stderr.Len() > 0 {
		return stdout.String(), fmt.Errorf("exit %d: %s", cmd.ExitCode(), strings.TrimSpace(stderr.String()))
	}

	return stdout.String(), nil
}

func (s *winrmSession) Close() error {
	if s.shell != nil {
		s.shell.Close()
	}
	return nil
}
