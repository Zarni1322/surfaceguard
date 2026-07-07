// Package auth handles credential profiles, encryption, and protocol-level
// authentication for SSH, WinRM, and SNMP.
package auth

import (
	"context"
	"fmt"
	"strings"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// Profile holds a decrypted credential profile ready for connection.
type Profile struct {
	ID         int64
	Name       string
	Protocol   models.Protocol
	Host       string
	Port       int
	Username   string
	AuthMethod string // password, key, key+passphrase, community, snmpv3
	Password   string // plaintext password or key passphrase (in memory only)
	PrivateKey string // SSH private key PEM data
	Community  string // SNMP community string
	// SNMPv3 fields
	Snmpv3Username   string
	Snmpv3AuthProto  string // MD5, SHA
	Snmpv3AuthPass   string
	Snmpv3PrivProto  string // DES, AES
	Snmpv3PrivPass   string
}

// Validate checks that the profile has the required fields for its protocol.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return fmt.Errorf("profile name is required")
	}
	if p.Host == "" {
		return fmt.Errorf("host is required")
	}

	switch p.Protocol {
	case models.ProtocolSSH:
		if p.Username == "" {
			return fmt.Errorf("username is required for SSH")
		}
		switch p.AuthMethod {
		case "password":
			if p.Password == "" {
				return fmt.Errorf("password is required for SSH password auth")
			}
		case "key":
			if p.PrivateKey == "" {
				return fmt.Errorf("private key is required for SSH key auth")
			}
		case "key+passphrase":
			if p.PrivateKey == "" {
				return fmt.Errorf("private key is required for SSH key+passphrase auth")
			}
			if p.Password == "" {
				return fmt.Errorf("passphrase is required for SSH key+passphrase auth")
			}
		default:
			return fmt.Errorf("unsupported SSH auth method: %s", p.AuthMethod)
		}
		if p.Port == 0 {
			p.Port = 22
		}

	case models.ProtocolWinRM:
		if p.Username == "" {
			return fmt.Errorf("username is required for WinRM")
		}
		if p.Password == "" {
			return fmt.Errorf("password is required for WinRM")
		}
		if p.Port == 0 {
			p.Port = 5986 // HTTPS WinRM default
		}

	case models.ProtocolSNMP:
		switch p.AuthMethod {
		case "community":
			if p.Community == "" {
				return fmt.Errorf("community string is required")
			}
		case "snmpv3":
			if p.Snmpv3Username == "" {
				return fmt.Errorf("SNMPv3 username is required")
			}
		default:
			return fmt.Errorf("unsupported SNMP auth method: %s", p.AuthMethod)
		}
		if p.Port == 0 {
			p.Port = 161
		}

	default:
		return fmt.Errorf("unsupported protocol: %s", p.Protocol)
	}
	return nil
}

// ============================================================================
// Connector interface
// ============================================================================

// Session represents a single authenticated session to a remote host.
type Session interface {
	// RunCommand executes a command on the remote host and returns combined output.
	RunCommand(ctx context.Context, command string) (string, error)
	// Close terminates the session.
	Close() error
}

// Connector establishes authenticated sessions to remote targets.
type Connector interface {
	// Connect opens a new session using the given profile.
	Connect(ctx context.Context, profile *Profile) (Session, error)
	// Protocol returns the protocol this connector handles.
	Protocol() models.Protocol
}

// ============================================================================
// Validation helpers
// ============================================================================

// ValidationCheckResult describes a single check outcome.
type ValidationCheckResult struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message,omitempty"`
}

// ValidationResult aggregates all checks for a credential validation.
type ValidationResult struct {
	Status string               `json:"status"` // SUCCESS, WARNING, FAILED
	Checks []ValidationCheckResult `json:"checks"`
}

// AddCheck appends a check and updates the overall status.
func (vr *ValidationResult) AddCheck(name, status, message string) {
	vr.Checks = append(vr.Checks, ValidationCheckResult{Name: name, Status: status, Message: message})
	if status == "fail" && vr.Status == "SUCCESS" {
		vr.Status = "FAILED"
	} else if status == "warn" && vr.Status == "SUCCESS" {
		vr.Status = "WARNING"
	}
}

// ============================================================================
// String helpers
// ============================================================================

// Redact removes secrets from a profile for logging/serialization.
func RedactPassword(s string) string {
	if s == "" {
		return ""
	}
	return strings.Repeat("*", 8)
}
