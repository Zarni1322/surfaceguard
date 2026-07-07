package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
	"github.com/gosnmp/gosnmp"
)

// Ensure compile-time check.
var _ Connector = (*SNMPConnector)(nil)

// SNMPConnector implements the Connector interface for SNMP.
type SNMPConnector struct {
	timeout time.Duration
}

// NewSNMPConnector creates a new SNMP connector.
func NewSNMPConnector(timeout time.Duration) *SNMPConnector {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &SNMPConnector{timeout: timeout}
}

// Protocol returns SNMP.
func (c *SNMPConnector) Protocol() models.Protocol {
	return models.ProtocolSNMP
}

// Connect opens an SNMP connection. Returns a session that reads from the
// device via SNMP GET/BULK.
func (c *SNMPConnector) Connect(ctx context.Context, profile *Profile) (Session, error) {
	var snmp gosnmp.GoSNMP

	snmp.Target = profile.Host
	snmp.Port = uint16(profile.Port)
	snmp.Timeout = c.timeout

	switch profile.AuthMethod {
	case "community":
		snmp.Version = gosnmp.Version2c
		snmp.Community = profile.Community
	case "snmpv3":
		snmp.Version = gosnmp.Version3
		snmp.SecurityModel = gosnmp.UserSecurityModel
		msgFlags := gosnmp.NoAuthNoPriv
		if profile.Snmpv3AuthPass != "" {
			msgFlags = gosnmp.AuthNoPriv
		}
		if profile.Snmpv3PrivPass != "" {
			msgFlags = gosnmp.AuthPriv
		}
		snmp.MsgFlags = msgFlags
		snmp.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 profile.Snmpv3Username,
			AuthenticationProtocol:   snmpAuthProtocol(profile.Snmpv3AuthProto),
			AuthenticationPassphrase: profile.Snmpv3AuthPass,
			PrivacyProtocol:          snmpPrivProtocol(profile.Snmpv3PrivProto),
			PrivacyPassphrase:        profile.Snmpv3PrivPass,
		}
	default:
		return nil, fmt.Errorf("unsupported SNMP auth method: %s", profile.AuthMethod)
	}

	if err := snmp.Connect(); err != nil {
		return nil, fmt.Errorf("snmp connect: %w", err)
	}

	// Verify connection with a GET of sysDescr.0 (.1.3.6.1.2.1.1.1.0).
	result, err := snmp.Get([]string{".1.3.6.1.2.1.1.1.0"})
	if err != nil {
		snmp.Conn.Close()
		return nil, fmt.Errorf("snmp get sysDescr: %w", err)
	}

	sysDescr := ""
	if len(result.Variables) > 0 {
		sysDescr = snmpValueToString(result.Variables[0])
	}

	return &snmpSession{
		conn:     &snmp,
		sysDescr: sysDescr,
	}, nil
}

// snmpSession wraps an SNMP connection for data retrieval.
type snmpSession struct {
	conn     *gosnmp.GoSNMP
	sysDescr string
}

func (s *snmpSession) RunCommand(ctx context.Context, command string) (string, error) {
	// SNMP doesn't run commands — we interpret OIDs here.
	// The "command" parameter is an OID like "1.3.6.1.2.1.1.1.0" for sysDescr.
	if strings.HasPrefix(command, ".") || strings.HasPrefix(command, "1.") {
		oid := command
		if !strings.HasPrefix(oid, ".") {
			oid = "." + oid
		}
		result, err := s.conn.Get([]string{oid})
		if err != nil {
			return "", fmt.Errorf("snmp get %s: %w", oid, err)
		}
		if len(result.Variables) > 0 {
			return snmpValueToString(result.Variables[0]), nil
		}
		return "", nil
	}

	// For "sysDescr" we return the cached value.
	if command == "sysDescr" {
		return s.sysDescr, nil
	}

	// "walk" prefix triggers SNMP walk on a table OID.
	if strings.HasPrefix(command, "walk ") {
		oid := strings.TrimSpace(strings.TrimPrefix(command, "walk "))
		if !strings.HasPrefix(oid, ".") {
			oid = "." + oid
		}
		return s.snmpWalk(ctx, oid)
	}

	return "", fmt.Errorf("unknown SNMP command: %s", command)
}

func (s *snmpSession) snmpWalk(ctx context.Context, oid string) (string, error) {
	var results strings.Builder
	if err := s.conn.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		results.WriteString(fmt.Sprintf("%s = %s\n", pdu.Name, snmpValueToString(pdu)))
		return nil
	}); err != nil {
		return "", err
	}
	return results.String(), nil
}

func (s *snmpSession) Close() error {
	if s.conn != nil && s.conn.Conn != nil {
		s.conn.Conn.Close()
	}
	return nil
}

func snmpValueToString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case int:
		return fmt.Sprintf("%d", v)
	case uint:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%.2f", v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func snmpAuthProtocol(proto string) gosnmp.SnmpV3AuthProtocol {
	switch strings.ToUpper(proto) {
	case "MD5":
		return gosnmp.MD5
	case "SHA":
		return gosnmp.SHA
	default:
		return gosnmp.NoAuth
	}
}

func snmpPrivProtocol(proto string) gosnmp.SnmpV3PrivProtocol {
	switch strings.ToUpper(proto) {
	case "DES":
		return gosnmp.DES
	case "AES":
		return gosnmp.AES
	default:
		return gosnmp.NoPriv
	}
}

