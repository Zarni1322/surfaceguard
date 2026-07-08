package auth

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/evilhunter/surfaceguard/pkg/models"
	"golang.org/x/crypto/ssh"
)

// Ensure compile-time check.
var _ Connector = (*SSHConnector)(nil)

// SSHConnector implements the Connector interface for SSH.
type SSHConnector struct{}

// NewSSHConnector creates a new SSH connector.
func NewSSHConnector() *SSHConnector {
	return &SSHConnector{}
}

// Protocol returns SSH.
func (c *SSHConnector) Protocol() models.Protocol {
	return models.ProtocolSSH
}

// Connect opens an SSH session using the given profile.
func (c *SSHConnector) Connect(ctx context.Context, profile *Profile) (Session, error) {
	addr := fmt.Sprintf("%s:%d", profile.Host, profile.Port)
	var auth ssh.AuthMethod

	switch profile.AuthMethod {
	case "password":
		auth = ssh.Password(profile.Password)
	case "key":
		signer, err := ssh.ParsePrivateKey([]byte(profile.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("parse key: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	case "key+passphrase":
		signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(profile.PrivateKey), []byte(profile.Password))
		if err != nil {
			return nil, fmt.Errorf("parse key with passphrase: %w", err)
		}
		auth = ssh.PublicKeys(signer)
	default:
		return nil, fmt.Errorf("unsupported SSH auth method: %s", profile.AuthMethod)
	}

	config := &ssh.ClientConfig{
		User:            profile.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Config: ssh.Config{
			KeyExchanges: []string{
				// Modern KEX (preferred)
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group14-sha256",
				// Legacy fallbacks
				"diffie-hellman-group-exchange-sha1",
				"diffie-hellman-group14-sha1",
				"diffie-hellman-group1-sha1",
			},
		},
		HostKeyAlgorithms: []string{
			ssh.KeyAlgoED25519,
			ssh.KeyAlgoECDSA256,
			ssh.KeyAlgoECDSA384,
			ssh.KeyAlgoECDSA521,
			ssh.KeyAlgoRSA,
			ssh.InsecureKeyAlgoDSA,
		},
	}

	// Dial with context via net.Dialer.
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh handshake: %w", err)
	}

	client := ssh.NewClient(sshConn, chans, reqs)
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("session: %w", err)
	}

	return &sshSession{
		client:  client,
		session: session,
	}, nil
}

// sshSession wraps an SSH session for command execution.
type sshSession struct {
	client  *ssh.Client
	session *ssh.Session
}

func (s *sshSession) RunCommand(ctx context.Context, command string) (string, error) {
	// Create a new session for each command — ssh.Session can only Run() once.
	sub, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sub.Close()

	var stdout, stderr bytes.Buffer
	sub.Stdout = &stdout
	sub.Stderr = &stderr

	errCh := make(chan error, 1)
	go func() {
		errCh <- sub.Run(command)
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return "", fmt.Errorf("%s: %s", err, strings.TrimSpace(stderr.String()))
		}
		return stdout.String(), nil
	case <-ctx.Done():
		sub.Signal(ssh.SIGINT)
		return "", ctx.Err()
	}
}

func (s *sshSession) Close() error {
	if s.session != nil {
		s.session.Close()
	}
	if s.client != nil {
		s.client.Close()
	}
	return nil
}
