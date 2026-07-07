package fingerprint

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// AnalyzeTLS performs TLS certificate analysis against a target host:port.
// Returns TLSResult with version, certificate details, and security indicators.
func AnalyzeTLS(host string, port int, timeout time.Duration) *models.TLSResult {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: false,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result := &models.TLSResult{
		Host: host,
		Port: port,
	}

	// Determine TLS version.
	switch state.Version {
	case tls.VersionTLS13:
		result.Version = "TLS 1.3"
	case tls.VersionTLS12:
		result.Version = "TLS 1.2"
	case tls.VersionTLS11:
		result.Version = "TLS 1.1"
		result.DeprecatedProto = true
	case tls.VersionTLS10:
		result.Version = "TLS 1.0"
		result.DeprecatedProto = true
	default:
		result.Version = fmt.Sprintf("unknown (0x%04X)", state.Version)
		result.DeprecatedProto = true
	}

	// Certificate details.
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertificateCN = cert.Subject.CommonName
		result.CertificateIssuer = cert.Issuer.CommonName
		result.CertificateExpiry = cert.NotAfter
		result.DaysUntilExpiry = int(time.Until(cert.NotAfter).Hours() / 24)
		if result.DaysUntilExpiry < 0 {
			result.DaysUntilExpiry = 0
		}
		result.SelfSigned = cert.IsCA && cert.Subject.CommonName == cert.Issuer.CommonName

		// Extract SANs.
		if len(cert.DNSNames) > 0 {
			result.SANs = cert.DNSNames
		}
	}

	// Weak cipher detection.
	result.WeakCipher = isWeakCipher(state.CipherSuite)

	return result
}

// isWeakCipher checks if a cipher suite ID is considered weak or deprecated.
func isWeakCipher(cipherSuite uint16) bool {
	switch cipherSuite {
	case tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA,
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
		return true
	}
	return false
}
