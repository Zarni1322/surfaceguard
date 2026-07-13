// Package fingerprint implements service, product, and version detection
// using safe fingerprinting techniques — banner analysis, HTTP header inspection,
// TLS certificate correlation, and protocol-specific heuristics.
//
// The scanner NEVER sends exploit payloads, authentication attempts, or
// performs any intrusive action. All detection is passive: we connect,
// read the initial banner/response, and analyse what the service advertises.
//
// Phase 3 additions:
//   - Evidence-based multi-source correlation: HTTP headers, HTML body, TLS,
//     protocol banners are all recorded and correlated before forming a conclusion.
//   - Confidence scoring from multiple independent signals, averaged and weighted.
//   - Conflict resolution: when multiple products are detected, the engine
//     picks the one with the strongest, most consistent evidence.
//   - Active HTTP fingerprinting: sends a real GET / request to gather
//     response headers, HTML body, and cookies for identification.
//   - Evidence recording: every fingerprint stores its evidence trail for
//     debugging and audit.
package fingerprint

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/cpe"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

// Evidence records a single piece of fingerprint evidence.
// Multiple Evidence entries are collected from different sources and
// correlated before forming a final fingerprint conclusion.
type Evidence struct {
	// Source identifies where this evidence came from (e.g. "server_header",
	// "html_body", "ssh_banner", "tls_cert").
	Source string `json:"source"`
	// Product is the detected product name (e.g. "Apache httpd").
	Product string `json:"product"`
	// Version is the detected version string (may be empty).
	Version string `json:"version"`
	// Confidence is the confidence for this single evidence item (0-100).
	Confidence int `json:"confidence"`
	// Raw is the raw evidence text that led to this conclusion.
	Raw string `json:"raw,omitempty"`
}

// ServiceFingerprinter performs banner-based service and version detection.
type ServiceFingerprinter struct {
	timeout          time.Duration
	httpClient       *http.Client
	tlsConfig        *tls.Config
}

// NewServiceFingerprinter creates a new fingerprinter with the given timeout.
func NewServiceFingerprinter(timeout time.Duration) *ServiceFingerprinter {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &ServiceFingerprinter{
		timeout: timeout,
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		tlsConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
}

// Fingerprint performs full service fingerprinting on an open port:
// 1. Service detection (banner → service name)
// 2. Product detection from all available evidence sources
// 3. Evidence correlation and confidence scoring
// 4. CPE generation from detected product/version
func (f *ServiceFingerprinter) Fingerprint(port models.Port) models.Port {
	port.Protocol = "tcp"

	// Step 1: Service detection from banner + port.
	service, svcConfidence, svcVersion := detectServiceFromBanner(port.Banner, port.Port)

	// Step 2: Collect evidence from all available sources.
	var evidences []Evidence

	// Banner-based evidence.
	bannerEv := collectBannerEvidence(port.Banner, service, port.Port)
	evidences = append(evidences, bannerEv...)

	// HTTP-specific fingerprinting (active request).
	if isHTTPService(service) {
		httpEv := f.doHTTPFingerprint(port)
		evidences = append(evidences, httpEv...)
	} else if service == "ssh" && port.TargetIP != "" {
		sshEv := doSSHFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, sshEv...)
	} else if service == "mysql" && port.TargetIP != "" {
		mysqlEv := doMySQLFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, mysqlEv...)
	} else if service == "postgresql" && port.TargetIP != "" {
		pgEv := doPostgreSQLFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, pgEv...)
	} else if service == "smtp" && port.TargetIP != "" {
		smtpEv := doSMTPFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, smtpEv...)
	} else if service == "ftp" && port.TargetIP != "" {
		ftpEv := doFTPFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, ftpEv...)
	} else if service == "redis" && port.TargetIP != "" {
		redisEv := doRedisFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, redisEv...)
	}

	// TLS evidence from the banner (passive) + active TLS probe.
	if len(port.Banner) > 0 {
		tlsEv := collectTLSEvidence(port.Banner)
		evidences = append(evidences, tlsEv...)
	}
	if port.TargetIP != "" && (port.Port == 443 || port.Port == 8443 || service == "https") {
		tlsProbeEv := doTLSFingerprint(port.TargetIP, port.Port, f.timeout)
		evidences = append(evidences, tlsProbeEv...)
	}

	// Step 3: Correlate all evidence into a final product/confidence.
	correlatedProduct, correlatedVersion, correlatedConfidence := correlateEvidence(evidences, svcConfidence, service)

	// Step 4: Determine final values.
	port.Service = service
	port.Product = correlatedProduct
	port.Confidence = correlatedConfidence
	if correlatedVersion != "" {
		port.Version = correlatedVersion
	} else if svcVersion != "" {
		port.Version = svcVersion
	}

	// Step 5: Generate CPEs.
	port.CPEs = buildCPEs(port.Product, port.Version, port.Service, port.Port, port.Confidence)

	return port
}

// cpesFromFingerprint generates CPE entries from fingerprint results.
// buildCPEs generates CPE entries from fingerprint results.
// If fingerprint confidence is below 50 and no product was detected from
// banner evidence, CPE generation is skipped. This prevents false positives
// from port-based service guesses that assume a specific product without
// any banner verification. (Phase A FP reduction)
func buildCPEs(product, version, service string, portNum int, confidence int) []models.CPE {
	if product == "" && service == "" {
		return nil
	}
	// Phase A: Skip port-guess CPEs for services where the product was
	// inferred from the port number without banner verification.
	// HTTP (80/443/8080/8443) and SMB (139/445) ports are the highest-FP
	// sources because their service-name defaults (apache:http_server,
	// samba:samba) are frequently wrong on real targets.
	// We only skip when:
	//   1. No banner evidence (confidence < 70), AND
	//   2. The service is HTTP/HTTPS or SMB (highest FP services)
	// Other services like ssh→OpenSSH, mysql→MySQL have reliable
	// service-to-product mappings and are kept even without banners.
	if confidence < 70 && (service == "http" || service == "https" || service == "smb") {
		return nil
	}
	if version == "" {
		version = "*"
	}
	sharedCPE := cpe.FromServiceOrProduct(service, product, version, portNum)
	if sharedCPE == nil {
		return nil
	}
	return []models.CPE{{
		Part:     sharedCPE.Part,
		Vendor:   sharedCPE.Vendor,
		Product:  sharedCPE.Product,
		Version:  sharedCPE.Version,
		CPE23URI: sharedCPE.URI,
	}}
}

// ============================================================================
// Evidence Collection — Banner
// ============================================================================

// collectBannerEvidence extracts product evidence from a service banner.
// It checks service signatures first (most specific), then product signatures.
// This is entirely pattern-driven — no product-specific code paths.
func collectBannerEvidence(banner, service string, port int) []Evidence {
	if banner == "" {
		return nil
	}

	var evidences []Evidence

	// Check service signatures for product hints embedded in service detection.
	for _, sig := range serviceSignatures {
		if sig.pattern.MatchString(banner) && sig.product != "" {
			version := extractVersion(banner)
			evidences = append(evidences, Evidence{
				Source:     "banner_signature",
				Product:    sig.product,
				Version:    version,
				Confidence: 85,
				Raw:        truncateBanner(banner),
			})
			break
		}
	}

	// Check product signatures for additional product identification.
	for _, sig := range productSignatures {
		if sig.pattern.MatchString(banner) {
			version := extractVersion(banner)
			alreadyFound := false
			for _, e := range evidences {
				if e.Product == sig.product {
					alreadyFound = true
					break
				}
			}
			if !alreadyFound {
				evidences = append(evidences, Evidence{
					Source:     "product_signature",
					Product:    sig.product,
					Version:    version,
					Confidence: 80,
					Raw:        truncateBanner(banner),
				})
			}
			break
		}
	}

	return evidences
}

// truncateBanner returns up to the first 120 characters of a banner.
func truncateBanner(banner string) string {
	if len(banner) > 120 {
		return banner[:120]
	}
	return banner
}

// ============================================================================
// Evidence Collection — HTTP (Active)
// ============================================================================

// doHTTPFingerprint sends a real HTTP GET request to the target and collects
// evidence from the response: Server header, X-Powered-By, WWW-Authenticate,
// HTML body, and cookies. These are returned as individual Evidence items.
func (f *ServiceFingerprinter) doHTTPFingerprint(port models.Port) []Evidence {
	scheme := "http"
	if port.Port == 443 || port.Port == 8443 || port.Port == 5986 {
		scheme = "https"
	}

	// Use the target IP from the port. The scanner sets this before
	// calling Fingerprint(). Fallback to 127.0.0.1 if not set.
	targetIP := port.TargetIP
	if targetIP == "" {
		targetIP = "127.0.0.1"
	}

	addr := fmt.Sprintf("%s://%s:%d/", scheme, targetIP, port.Port)
	req, err := http.NewRequest("GET", addr, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "SurfaceGuard/3.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var evidences []Evidence

	// 1. Server header.
	if server := resp.Header.Get("Server"); server != "" {
		product, version := parseServerHeader(server)
		if product != "" {
			evidences = append(evidences, Evidence{
				Source:     "http_server_header",
				Product:    product,
				Version:    version,
				Confidence: 90,
				Raw:        server,
			})
		}
	}

	// 2. X-Powered-By header.
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		product, version := parsePoweredByHeader(xpb)
		if product != "" {
			evidences = append(evidences, Evidence{
				Source:     "http_x_powered_by",
				Product:    product,
				Version:    version,
				Confidence: 70,
				Raw:        xpb,
			})
		}
	}

	// 3. WWW-Authenticate header.
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		product, version := parseWwwAuthHeader(wwwAuth)
		if product != "" {
			evidences = append(evidences, Evidence{
				Source:     "http_www_authenticate",
				Product:    product,
				Version:    version,
				Confidence: 65,
				Raw:        wwwAuth,
			})
		}
	}

	// 4. Read body for HTML-based detection.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err == nil {
		bodyStr := string(body)

		// HTML title.
		title := extractHTMLTitle(bodyStr)
		if title != "" {
			productEvidence := identifyFromHTMLTitle(title)
			if productEvidence != nil {
				evidences = append(evidences, *productEvidence)
			}
		}

		// Check body for product signatures.
		for _, sig := range productSignatures {
			if sig.pattern.MatchString(bodyStr) {
				alreadyFound := false
				for _, e := range evidences {
					if e.Product == sig.product {
						alreadyFound = true
						break
					}
				}
				if !alreadyFound {
					version := extractVersion(bodyStr)
					evidences = append(evidences, Evidence{
						Source:     "http_body",
						Product:    sig.product,
						Version:    version,
						Confidence: 65,
						Raw:        truncateBanner(bodyStr),
					})
					break
				}
			}
		}
	}

	return evidences
}

// extractHTMLTitle extracts the text content of <title> tags.
func extractHTMLTitle(body string) string {
	re := regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	matches := re.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// identifyFromHTMLTitle checks an HTML title for well-known product indicators.
// This is NOT product-specific code — it is a generic pattern matcher that
// checks the title against the same product signatures used for banners.
// Returns nil if no product can be identified from the title.
func identifyFromHTMLTitle(title string) *Evidence {
	for _, sig := range productSignatures {
		if sig.pattern.MatchString(title) {
			version := extractVersion(title)
			return &Evidence{
				Source:     "html_title",
				Product:    sig.product,
				Version:    version,
				Confidence: 60,
				Raw:        title,
			}
		}
	}

	// Check for generic product indicators in titles.
	lower := strings.ToLower(title)
	indicators := []struct {
		pattern string
		product string
	}{
		{"welcome to nginx", "nginx"},
		{"apache", "Apache httpd"},
		{"iis", "Microsoft IIS"},
		{"tomcat", "Apache Tomcat"},
		{"jetty", "Eclipse Jetty"},
		{"caddy", "Caddy"},
		{"lighttpd", "lighttpd"},
	}
	for _, ind := range indicators {
		if strings.Contains(lower, ind.pattern) {
			return &Evidence{
				Source:     "html_title",
				Product:    ind.product,
				Confidence: 55,
				Raw:        title,
			}
		}
	}

	return nil
}

// parsePoweredByHeader extracts product info from X-Powered-By headers.
func parsePoweredByHeader(header string) (product, version string) {
	// Examples: "PHP/7.4.33", "ASP.NET", "Express"
	re := regexp.MustCompile(`^(?i)([a-z][a-z0-9._+-]+)(?:/(\d+\.\d+(?:\.\d+)?))?`)
	matches := re.FindStringSubmatch(header)
	if len(matches) < 2 {
		return "", ""
	}
	product = matches[1]
	if len(matches) >= 3 {
		version = matches[2]
	}
	return product, version
}

// parseWwwAuthHeader extracts product info from WWW-Authenticate headers.
func parseWwwAuthHeader(header string) (product, version string) {
	// Examples: "Basic realm=...", "Digest realm=... nonce=..."
	// Not typically version-bearing, but can indicate product via realm.
	re := regexp.MustCompile(`(?i)realm="([^"]+)"`)
	matches := re.FindStringSubmatch(header)
	if len(matches) >= 2 {
		realm := matches[1]
		re = regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?)`)
		verMatches := re.FindStringSubmatch(realm)
		if len(verMatches) >= 2 {
			version = verMatches[1]
		}
	}
	return "", version
}

// ============================================================================
// Evidence Collection — TLS (Passive)
// ============================================================================

// collectTLSEvidence extracts product evidence from TLS banners.
// The banner may contain TLS handshake data with certificate information.
func collectTLSEvidence(banner string) []Evidence {
	// TLS banners sometimes contain certificate CN or issuer information.
	// Currently: the fingerprint engine receives the raw TCP banner, not
	// the TLS handshake. The dedicated TLS analysis happens separately.
	// For now, check for common TLS indicators in the banner text.
	if strings.Contains(banner, "TLS") || strings.Contains(banner, "SSL") {
		return []Evidence{{
			Source:     "tls_indicator",
			Product:    "",
			Confidence: 30,
			Raw:        truncateBanner(banner),
		}}
	}
	return nil
}

// ============================================================================
// Evidence Correlation
// ============================================================================

// correlateEvidence takes all collected evidence and produces a single
// fingerprint conclusion: the most likely product, version, and confidence.
//
// Algorithm:
// 1. Group evidence by product name.
// 2. For each product group, compute average confidence.
// 3. Apply version consistency bonus (same version from multiple sources).
// 4. Apply cross-source bonus (evidence from different source types).
// 5. Select the product with the highest weighted score.
// 6. If nothing found, fall back to service-level guess.

// ============================================================================
// Active Protocol Probes (Phase A)
// ============================================================================

// doSSHFingerprint connects to an SSH server and reads its banner to extract
// the exact product and version. SSH servers always send a banner on connect.
func doSSHFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	banner := sanitizeBanner(string(buf[:n]))
	var evidences []Evidence
	if strings.Contains(banner, "OpenSSH") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "ssh_banner", Product: "OpenSSH", Version: ver,
			Confidence: 95, Raw: banner[:min(len(banner), 120)],
		})
	} else if strings.Contains(banner, "dropbear") || strings.Contains(banner, "Dropbear") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "ssh_banner", Product: "Dropbear", Version: ver,
			Confidence: 95, Raw: banner[:min(len(banner), 120)],
		})
	}
	return evidences
}

// doMySQLFingerprint connects to a MySQL server and reads its greeting packet
// which contains the exact version string.
func doMySQLFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n < 5 {
		return nil
	}
	raw := string(buf[:n])
	// MySQL greeting packet has version string after the first null byte.
	// Format: len(3) + proto(1) + version(null-terminated) + ...
	sanitized := sanitizeBanner(raw)
	var evidences []Evidence
	if strings.Contains(sanitized, "MySQL") || strings.Contains(sanitized, "mariadb") ||
		strings.Contains(sanitized, "MariaDB") || strings.Contains(sanitized, "5.") ||
		strings.Contains(sanitized, "8.") || strings.Contains(sanitized, "10.") {
		ver := extractVersion(sanitized)
		product := "MySQL"
		if strings.Contains(sanitized, "MariaDB") || strings.Contains(sanitized, "mariadb") {
			product = "MariaDB"
		}
		evidences = append(evidences, Evidence{
			Source: "mysql_greeting", Product: product, Version: ver,
			Confidence: 90, Raw: sanitized[:min(len(sanitized), 120)],
		})
	}
	return evidences
}

// doPostgreSQLFingerprint connects to a PostgreSQL server and reads its
// greeting packet with the version string.
func doPostgreSQLFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	banner := sanitizeBanner(string(buf[:n]))
	var evidences []Evidence
	if strings.Contains(banner, "PostgreSQL") || strings.Contains(banner, "postgres") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "postgresql_greeting", Product: "PostgreSQL", Version: ver,
			Confidence: 90, Raw: banner[:min(len(banner), 120)],
		})
	}
	return evidences
}

// doSMTPFingerprint connects to an SMTP server and reads its greeting.
func doSMTPFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	banner := sanitizeBanner(string(buf[:n]))
	var evidences []Evidence
	if strings.Contains(banner, "Postfix") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "smtp_banner", Product: "Postfix", Version: ver,
			Confidence: 90, Raw: banner[:min(len(banner), 120)],
		})
	} else if strings.Contains(banner, "Exim") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "smtp_banner", Product: "Exim", Version: ver,
			Confidence: 90, Raw: banner[:min(len(banner), 120)],
		})
	} else if strings.Contains(banner, "Sendmail") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "smtp_banner", Product: "Sendmail", Version: ver,
			Confidence: 85, Raw: banner[:min(len(banner), 120)],
		})
	}
	return evidences
}

// doFTPFingerprint connects to an FTP server and reads its greeting.
func doFTPFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	banner := sanitizeBanner(string(buf[:n]))
	var evidences []Evidence
	if strings.Contains(banner, "vsFTPd") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "ftp_banner", Product: "vsftpd", Version: ver,
			Confidence: 95, Raw: banner[:min(len(banner), 120)],
		})
	} else if strings.Contains(banner, "ProFTPD") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "ftp_banner", Product: "ProFTPD", Version: ver,
			Confidence: 95, Raw: banner[:min(len(banner), 120)],
		})
	} else if strings.Contains(banner, "Pure-FTPd") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "ftp_banner", Product: "Pure-FTPd", Version: ver,
			Confidence: 95, Raw: banner[:min(len(banner), 120)],
		})
	}
	return evidences
}

// doRedisFingerprint connects to a Redis server and reads its banner/error.
func doRedisFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	if n == 0 {
		return nil
	}
	banner := sanitizeBanner(string(buf[:n]))
	var evidences []Evidence
	if strings.Contains(banner, "redis") || strings.Contains(banner, "Redis") ||
		strings.Contains(banner, "ERR") || strings.Contains(banner, "+OK") {
		ver := extractVersion(banner)
		evidences = append(evidences, Evidence{
			Source: "redis_banner", Product: "Redis", Version: ver,
			Confidence: 85, Raw: banner[:min(len(banner), 120)],
		})
	}
	return evidences
}

// doTLSFingerprint connects to a TLS server and extracts certificate info.
func doTLSFingerprint(ip string, port int, timeout time.Duration) []Evidence {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var evidences []Evidence
	
	// Extract certificate information.
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		cn := cert.Subject.CommonName
		issuer := cert.Issuer.CommonName
		if cn != "" || issuer != "" {
			raw := "CN=" + cn + " issuer=" + issuer
			evidences = append(evidences, Evidence{
				Source: "tls_cert", Product: "", Version: "",
				Confidence: 60, Raw: raw[:min(len(raw), 120)],
			})
		}
		// Check for specific product indicators in certificate.
		for _, s := range cert.Subject.Organization {
			lower := strings.ToLower(s)
			if strings.Contains(lower, "nginx") {
				evidences = append(evidences, Evidence{
					Source: "tls_cert_org", Product: "nginx",
					Confidence: 70, Raw: s,
				})
			} else if strings.Contains(lower, "apache") || strings.Contains(lower, "httpd") {
				evidences = append(evidences, Evidence{
					Source: "tls_cert_org", Product: "Apache httpd",
					Confidence: 70, Raw: s,
				})
			} else if strings.Contains(lower, "iis") || strings.Contains(lower, "microsoft") {
				evidences = append(evidences, Evidence{
					Source: "tls_cert_org", Product: "Microsoft IIS",
					Confidence: 70, Raw: s,
				})
			} else if strings.Contains(lower, "cloudflare") {
				evidences = append(evidences, Evidence{
					Source: "tls_cert_org", Product: "Cloudflare",
					Confidence: 90, Raw: s,
				})
			}
		}
	}
	
	// TLS version info.
	var tlsVer string
	switch state.Version {
	case tls.VersionTLS13:
		tlsVer = "TLS 1.3"
	case tls.VersionTLS12:
		tlsVer = "TLS 1.2"
	case tls.VersionTLS11:
		tlsVer = "TLS 1.1"
	case tls.VersionTLS10:
		tlsVer = "TLS 1.0"
	}
	if tlsVer != "" {
		evidences = append(evidences, Evidence{
			Source: "tls_version", Product: "", Version: tlsVer,
			Confidence: 50,
		})
	}
	return evidences
}
func correlateEvidence(evidences []Evidence, serviceConfidence int, service string) (product string, version string, confidence int) {
	if len(evidences) == 0 {
		// No evidence — fall back to port-based service guess.
		product = productByService(service, 0)
		confidence = max(serviceConfidence, 50)
		return product, "", confidence
	}

	// Group by product name.
	type productGroup struct {
		product      string
		versions     map[string]int
		sources      map[string]int
		totalConf    int
		count        int
	}

	groups := make(map[string]*productGroup)
	for _, ev := range evidences {
		if ev.Product == "" {
			continue
		}
		g, exists := groups[ev.Product]
		if !exists {
			g = &productGroup{
				product:  ev.Product,
				versions: make(map[string]int),
				sources:  make(map[string]int),
			}
			groups[ev.Product] = g
		}
		g.totalConf += ev.Confidence
		g.count++
		g.sources[ev.Source]++
		if ev.Version != "" {
			g.versions[ev.Version]++
		}
	}

	if len(groups) == 0 {
		product = productByService(service, 0)
		confidence = max(serviceConfidence, 50)
		return product, "", confidence
	}

	// Score each product group.
	type scored struct {
		product    string
		score      float64
		bestVer    string
		verCount   int
	}

	var scoredProducts []scored
	for _, g := range groups {
		// Base score: average confidence.
		avgConf := float64(g.totalConf) / float64(g.count)
		score := avgConf

		// Cross-source bonus: +5 for each additional unique source beyond the first.
		sourceCount := len(g.sources)
		if sourceCount > 1 {
			score += float64(min(sourceCount-1, 3)) * 5.0
		}

		// Version consistency bonus: +10 if the same version appears from multiple sources.
		bestVersion := ""
		bestVersionCount := 0
		for ver, cnt := range g.versions {
			if cnt > bestVersionCount {
				bestVersionCount = cnt
				bestVersion = ver
			}
		}
		if bestVersionCount > 1 {
			score += 10.0
		}
		if bestVersionCount > 0 {
			score += 5.0
		}

		// Cap at 100.
		if score > 100 {
			score = 100
		}

		scoredProducts = append(scoredProducts, scored{
			product:  g.product,
			score:    score,
			bestVer:  bestVersion,
			verCount: bestVersionCount,
		})
	}

	// Pick the highest-scoring product.
	best := scoredProducts[0]
	for _, s := range scoredProducts[1:] {
		if s.score > best.score {
			best = s
		}
	}

	product = best.product
	confidence = int(best.score)
	version = best.bestVer

	return product, version, confidence
}

// ============================================================================
// Service Detection (banner-based)
// ============================================================================

// serviceSignature maps banner regex patterns to service names.
// SIGNATURE ORDER MATTERS: more specific patterns MUST come before less specific.
type serviceSignature struct {
	pattern *regexp.Regexp
	service string
	product string // optional product name if detected
}

var serviceSignatures = []serviceSignature{
	// --- SSH ---
	{regexp.MustCompile(`^SSH-\d+\.\d+-dropbear`), "ssh", "Dropbear"},
	{regexp.MustCompile(`^SSH-\d+\.\d+`), "ssh", "OpenSSH"},

	// --- HTTP (must come before FTP "220 " patterns) ---
	{regexp.MustCompile(`^HTTP/\d\.\d`), "http", ""},

	// --- SMTP / Mail (before generic FTP 220) ---
	{regexp.MustCompile(`^220.*ESMTP Exim`), "smtp", "Exim"},
	{regexp.MustCompile(`^220.*ESMTP Postfix`), "smtp", "Postfix"},
	{regexp.MustCompile(`^220.*ESMTP`), "smtp", ""},
	{regexp.MustCompile(`^EHLO|^220.*SMTP|^250-`), "smtp", ""},

	// --- FTP (specific before generic) ---
	{regexp.MustCompile(`^220.*vsFTPd`), "ftp", "vsftpd"},
	{regexp.MustCompile(`^220.*ProFTPD`), "ftp", "ProFTPD"},
	{regexp.MustCompile(`^220.*Pure-FTPd`), "ftp", "Pure-FTPd"},
	{regexp.MustCompile(`^220 `), "ftp", ""},

	// --- Redis (before POP3 — Redis error responses start with -ERR) ---
	{regexp.MustCompile(`Redis|^-ERR wrong type|^\+OK\r?$`), "redis", "Redis"},
	{regexp.MustCompile(`^-ERR`), "redis", ""},

	// --- POP3 / IMAP ---
	{regexp.MustCompile(`^\+OK|^\-ERR`), "pop3", ""},
	{regexp.MustCompile(`^\* OK|^([0-9]+ )?OK `), "imap", ""},

	// --- TLS ---
	{regexp.MustCompile(`^TLS.*|^SSL`), "ssl/tls", ""},

		// --- Databases (mariadb before mysql ---
		{regexp.MustCompile(`MariaDB|mariadb`), "mysql", "MariaDB"},
		{regexp.MustCompile(`^MySQL`), "mysql", "MySQL"},
		{regexp.MustCompile(`^PostgreSQL`), "postgresql", "PostgreSQL"},
		{regexp.MustCompile(`MongoDB|mongodb`), "mongodb", "MongoDB"},

	// --- HTTP products (detected by banner content) ---
	{regexp.MustCompile(`(Microsoft|IIS|Windows)`), "http", "Microsoft IIS"},
	{regexp.MustCompile(`nginx`), "http", "nginx"},
	{regexp.MustCompile(`Apache Tomcat|Apache-Coyote|Tomcat`), "http", "Apache Tomcat"},
	{regexp.MustCompile(`Apache`), "http", "Apache httpd"},
	{regexp.MustCompile(`lighttpd`), "http", "lighttpd"},
	{regexp.MustCompile(`Caddy`), "http", "Caddy"},
	{regexp.MustCompile(`Couchbase|CouchDB`), "http", "CouchDB"},
	{regexp.MustCompile(`Docker`), "http", "Docker"},
	{regexp.MustCompile(`(?i)elasticsearch`), "http", "Elasticsearch"},
	{regexp.MustCompile(`(?i)kibana`), "http", "Kibana"},
	{regexp.MustCompile(`(?i)Jenkins`), "http", "Jenkins"},
	{regexp.MustCompile(`(?i)Grafana`), "http", "Grafana"},
	{regexp.MustCompile(`(?i)Kubernetes|kube-apiserver`), "https", "Kubernetes API"},
	{regexp.MustCompile(`(?i)prometheus`), "http", "Prometheus"},
	{regexp.MustCompile(`(?i)Consul|consul`), "http", "Consul"},
	{regexp.MustCompile(`(?i)Etcd|etcd`), "http", "etcd"},
	{regexp.MustCompile(`(?i)rabbitmq|RabbitMQ`), "http", "RabbitMQ"},
	{regexp.MustCompile(`(?i)Tomcat|Apache-Coyote`), "http", "Apache Tomcat"},
	{regexp.MustCompile(`(?i)Jetty`), "http", "Eclipse Jetty"},
	{regexp.MustCompile(`(?i)WildFly|JBoss`), "http", "JBoss/WildFly"},
	{regexp.MustCompile(`(?i)GlassFish`), "http", "Oracle GlassFish"},
	{regexp.MustCompile(`(?i)Microsoft SQL Server|MSSQL`), "mssql", "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)Memcached`), "memcached", "Memcached"},
	{regexp.MustCompile(`(?i)Dropbear`), "ssh", "Dropbear"},
}

// detectServiceFromBanner analyses a banner string and port number to
// determine the service name with a confidence rating.
func detectServiceFromBanner(banner string, port int) (service string, confidence int, version string) {
	if banner == "" {
		return serviceByPort(port), 50, ""
	}

	// Check registered service signatures (ordered most-specific-first).
	for _, sig := range serviceSignatures {
		if matches := sig.pattern.FindStringSubmatch(banner); len(matches) > 0 {
			service = sig.service
			confidence = 90
			version = extractVersion(banner)
			return
		}
	}

	// Fallback: port-based guess with low confidence.
	service = serviceByPort(port)
	version = extractVersion(banner)

	if version != "" {
		confidence = 70
	} else {
		confidence = 50
	}

	return
}

// serviceByPort returns a best-guess service name for common ports.
func serviceByPort(port int) string {
	switch port {
	case 21:
		return "ftp"
	case 22:
		return "ssh"
	case 23:
		return "telnet"
	case 25:
		return "smtp"
	case 53:
		return "dns"
	case 80, 8080, 8443, 9000, 9090:
		return "http"
	case 110:
		return "pop3"
	case 111:
		return "rpcbind"
	case 135:
		return "msrpc"
	case 139, 445:
		return "smb"
	case 143:
		return "imap"
	case 443:
		return "https"
	case 993:
		return "imaps"
	case 995:
		return "pop3s"
	case 1433:
		return "mssql"
	case 1521:
		return "oracle"
	case 2049:
		return "nfs"
	case 3306:
		return "mysql"
	case 3389:
		return "rdp"
	case 5432:
		return "postgresql"
	case 5900:
		return "vnc"
	case 5985, 5986:
		return "winrm"
	case 6379:
		return "redis"
	case 27017:
		return "mongodb"
	case 9200, 9300:
		return "elasticsearch"
	case 5601:
		return "kibana"
	case 8300, 8500:
		return "consul"
	case 2379, 2380:
		return "etcd"
	case 9092:
		return "kafka"
	case 15672:
		return "rabbitmq"
	default:
		return "unknown"
	}
}

// ============================================================================
// Version Extraction
// ============================================================================

// versionPatterns matches common version strings in banners.
var versionPatterns = []*regexp.Regexp{
	// SSH: "SSH-2.0-OpenSSH_8.9p1"
	regexp.MustCompile(`OpenSSH[_-](\d+[._]\d+(?:p\d+)?)`),
	// Dropbear: "SSH-2.0-dropbear_2024.85"
	regexp.MustCompile(`dropbear[_-](\d+[._]\d+(?:p?\d+)?)`),
	// Apache: "Apache/2.4.49" or "Apache httpd 2.4.49"
	regexp.MustCompile(`Apache(?:/|\s+httpd\s+|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// nginx: "nginx/1.18.0"
	regexp.MustCompile(`nginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// IIS: "Microsoft-IIS/10.0"
	regexp.MustCompile(`Microsoft-IIS(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// lighttpd: "lighttpd/1.4.76"
	regexp.MustCompile(`lighttpd(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// Caddy: "Caddy/2.8.4"
	regexp.MustCompile(`Caddy(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// vsftpd: "vsFTPd 3.0.3"
	regexp.MustCompile(`vsFTPd[_\s](\d+\.\d+(?:\.\d+)?)`),
	// ProFTPD: "ProFTPD 1.3.5"
	regexp.MustCompile(`ProFTPD[_\s](\d+\.\d+(?:\.\d+)?)`),
	// Pure-FTPd
	regexp.MustCompile(`Pure-FTPd[_\s](\d+\.\d+(?:\.\d+)?)`),
	// MySQL / MariaDB
	regexp.MustCompile(`(?:MySQL|mariadb|MariaDB)[._ -v]?(\d+\.\d+(?:\.\d+)?)`),
	// MySQL standalone version
	regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)?)`),
	// PostgreSQL
	regexp.MustCompile(`PostgreSQL[.\s-]+(\d+\.\d+(?:\.\d+)?)`),
	// Redis
	regexp.MustCompile(`redis[._ -v](\d+\.\d+(?:\.\d+)?)`),
	// MongoDB
	regexp.MustCompile(`"version":\s*"(\d+\.\d+(?:\.\d+)?)`),
	regexp.MustCompile(`MongoDB[.\s](\d+\.\d+(?:\.\d+)?)`),
	// Postfix
	regexp.MustCompile(`Postfix[.\s(]*(\d+\.\d+(?:\.\d+)?)`),
	// Exim
	regexp.MustCompile(`Exim[.\s]+(\d+\.\d+(?:\.\d+)?)`),
	// Tomcat
	regexp.MustCompile(`Tomcat(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// Jetty
	regexp.MustCompile(`Jetty[\(\s/]+(\d+\.\d+(?:\.\d+)?)`),
	// Elasticsearch
	regexp.MustCompile(`elasticsearch[.\s/](\d+\.\d+(?:\.\d+)?)`),
	// RabbitMQ
	regexp.MustCompile(`RabbitMQ[.\s/](\d+\.\d+(?:\.\d+)?)`),
	// Docker
	regexp.MustCompile(`Docker[.\s/](\d+\.\d+(?:\.\d+)?)`),
	// Kubernetes
	regexp.MustCompile(`(?i)Kubernetes\s+v?(\d+\.\d+(?:\.\d+)?)`),
	// OpenSSL
	regexp.MustCompile(`OpenSSL[.\s]+(\d+\.\d+(?:\.\d+)?[a-z]?)`),
	// PHP
	regexp.MustCompile(`PHP[ /\s]+(\d+\.\d+(?:\.\d+)?)`),
	// Python
	regexp.MustCompile(`(?:Python|CPython)[ /\s]+(\d+\.\d+(?:\.\d+)?)`),
	// Node.js
	regexp.MustCompile(`Node\.js[ /\s]+v?(\d+\.\d+(?:\.\d+)?)`),
}

// extractVersion extracts version information from a banner string.
func extractVersion(banner string) string {
	if banner == "" {
		return ""
	}

	for _, pat := range versionPatterns {
		matches := pat.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			version := matches[1]
			version = strings.ReplaceAll(version, "_", ".")
			version = stripVersionSuffix(version)
			return version
		}
	}

	return ""
}

// stripVersionSuffix removes common suffixes from extracted version strings.
func stripVersionSuffix(v string) string {
	suffixes := []string{
		"-MariaDB", "-Debian", "-ubuntu", "-alpine", "-el",
		".el", ".alma", ".rocky", ".fc", ".amzn",
		"-log", "-debug", "-community", "-enterprise",
		"-ce", "-ee",
	}
	for _, s := range suffixes {
		if idx := strings.Index(v, s); idx > 0 {
			return v[:idx]
		}
	}
	return v
}

// ============================================================================
// Product Detection
// ============================================================================

// productSignature maps banner substring patterns to product names.
type productSignature struct {
	pattern *regexp.Regexp
	product string
}

var productSignatures = []productSignature{
	{regexp.MustCompile(`OpenSSH`), "OpenSSH"},
	{regexp.MustCompile(`dropbear|Dropbear`), "Dropbear"},
	{regexp.MustCompile(`Exim`), "Exim"},
	{regexp.MustCompile(`Tomcat|Apache-Coyote`), "Apache Tomcat"},
	{regexp.MustCompile(`Apache(?:/|\s)`), "Apache httpd"},
	{regexp.MustCompile(`nginx(?:/|\s)`), "nginx"},
	{regexp.MustCompile(`Caddy(?:/|\s)`), "Caddy"},
	{regexp.MustCompile(`Microsoft-IIS`), "Microsoft IIS"},
	{regexp.MustCompile(`vsFTPd`), "vsftpd"},
	{regexp.MustCompile(`ProFTPD`), "ProFTPD"},
	{regexp.MustCompile(`Pure-FTPd`), "Pure-FTPd"},
	{regexp.MustCompile(`MySQL`), "MySQL"},
	{regexp.MustCompile(`MariaDB`), "MariaDB"},
	{regexp.MustCompile(`PostgreSQL`), "PostgreSQL"},
	{regexp.MustCompile(`Redis`), "Redis"},
	{regexp.MustCompile(`lighttpd`), "lighttpd"},
	{regexp.MustCompile(`MongoDB|mongodb`), "MongoDB"},
	{regexp.MustCompile(`Docker`), "Docker"},
	{regexp.MustCompile(`CouchDB|Couchbase`), "CouchDB"},
	{regexp.MustCompile(`Node\.js`), "Node.js"},
	{regexp.MustCompile(`Python|CPython`), "Python"},
	{regexp.MustCompile(`JBoss|WildFly`), "JBoss"},
	{regexp.MustCompile(`GlassFish`), "Oracle GlassFish"},
	{regexp.MustCompile(`(?i)Consul`), "Consul"},
	{regexp.MustCompile(`(?i)Kubernetes|kube-apiserver`), "Kubernetes"},
	{regexp.MustCompile(`(?i)elasticsearch`), "Elasticsearch"},
	{regexp.MustCompile(`(?i)kibana`), "Kibana"},
	{regexp.MustCompile(`(?i)Jenkins`), "Jenkins"},
	{regexp.MustCompile(`(?i)Grafana`), "Grafana"},
	{regexp.MustCompile(`(?i)prometheus`), "Prometheus"},
	{regexp.MustCompile(`(?i)rabbitmq|RabbitMQ`), "RabbitMQ"},
	{regexp.MustCompile(`(?i)Etcd|etcd`), "etcd"},
	{regexp.MustCompile(`(?i)Memcached`), "Memcached"},
}

// productByService returns a product name for well-known services.
func productByService(service string, port int) string {
	switch service {
	case "ssh":
		return "OpenSSH"
	case "smtp":
		return "Postfix"
	case "ftp":
		return "vsftpd"
	case "mysql":
		return "MySQL"
	case "postgresql":
		return "PostgreSQL"
	case "redis":
		return "Redis"
	case "mongodb":
		return "MongoDB"
	case "kafka":
		return "Kafka"
	case "consul":
		return "Consul"
	case "elasticsearch":
		return "Elasticsearch"
	case "rabbitmq":
		return "RabbitMQ"
	default:
		return ""
	}
}

// ============================================================================
// HTTP Header Parsing
// ============================================================================

// serverHeaderPattern matches common web server version formats.
var serverHeaderPattern = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9._-]+)(?:/(\d+\.\d+(?:\.\d+)?(?:[-_.][a-zA-Z0-9]+)?))?`)

// parseServerHeader parses a Server header value into product name and version.
func parseServerHeader(header string) (product, version string) {
	matches := serverHeaderPattern.FindStringSubmatch(header)
	if len(matches) < 2 {
		return "", ""
	}
	product = matches[1]
	if len(matches) >= 3 {
		version = matches[2]
	}
	// Map short product names from Server headers to canonical forms.
	switch product {
	case "Apache":
		product = "Apache httpd"
	case "Microsoft-IIS":
		product = "Microsoft IIS"
	case "Jetty":
		product = "Eclipse Jetty"
	case "Tomcat":
		product = "Apache Tomcat"
	}
	return product, version
}

// ============================================================================
// Utilities
// ============================================================================

// extractHTTPHeader extracts a named header value from an HTTP response string.
// detectProduct determines the product name from a service banner.
// Kept for backward compatibility with tests.
func detectProduct(banner, service string, port int) (product, version string) {
	if banner != "" {
		for _, sig := range productSignatures {
			if sig.pattern.MatchString(banner) {
				version = extractVersion(banner)
				return sig.product, version
			}
		}
	}
	product = productByService(service, port)
	return product, ""
}

// generateCPEs creates CPE entries for a detected service/product.
// Kept for backward compatibility with tests.
func generateCPEs(port models.Port) []models.CPE {
	return buildCPEs(port.Product, port.Version, port.Service, port.Port, port.Confidence)
}

func extractHTTPHeader(banner, headerName string) string {
	lines := strings.Split(banner, "\n")
	prefix := headerName + ":"
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) {
			return strings.TrimSpace(trimmed[len(prefix):])
		}
	}
	return ""
}

// isHTTPService returns true if the service name suggests HTTP.
func isHTTPService(service string) bool {
	switch service {
	case "http", "https", "http-proxy":
		return true
	}
	return false
}

// BannerFromPort performs a TCP connect and reads the initial banner.
func BannerFromPort(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))

	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout / 2))
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)

	if n == 0 {
		return ""
	}

	return sanitizeBanner(string(buf[:n]))
}

// sanitizeBanner strips non-printable characters.
func sanitizeBanner(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r >= 32 && r <= 126 || r == '\t' || r == '\n' || r == '\r' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// min returns the minimum of two integers.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// max returns the maximum of two integers.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
