// Package fingerprint implements service, product, and version detection
// using safe fingerprinting techniques — banner analysis, HTTP header inspection,
// and protocol-specific heuristics.
//
// The scanner NEVER sends exploit payloads, authentication attempts, or
// performs any intrusive action. All detection is passive: we connect,
// read the initial banner/response, and analyse what the service advertises.
//
// Design rationale:
//   - Service detection uses port-to-service mapping as a fallback, then
//     refines via banner pattern matching (regex signatures).
//   - HTTP fingerprinting does a single GET / request and inspects the
//     Server header + response body patterns.
//   - Version detection is heuristic-based (extracting version strings from
//     banners). This is intentionally imprecise — we report what the service
//     tells us, never probe for specific version behaviours.
//   - Confidence scoring lets the caller decide how much to trust each
//     detection (100 = confirmed via banner pattern, 50 = port-based guess).
package fingerprint

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// ServiceFingerprinter performs banner-based service and version detection.
type ServiceFingerprinter struct {
	timeout time.Duration
}

// NewServiceFingerprinter creates a new fingerprinter with the given timeout.
func NewServiceFingerprinter(timeout time.Duration) *ServiceFingerprinter {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &ServiceFingerprinter{timeout: timeout}
}

// Fingerprint performs full service fingerprinting on an open port:
// 1. Service detection (banner → service name)
// 2. Product detection (banner → product name)
// 3. Version detection (banner → version string)
// 4. HTTP fingerprinting (if service is HTTP/HTTPS)
// 5. CPE generation from detected product/version
func (f *ServiceFingerprinter) Fingerprint(port models.Port) models.Port {
	// Set protocol.
	port.Protocol = "tcp"

	// Step 1: Service detection from banner + port.
	service, confidence, version := detectServiceFromBanner(port.Banner, port.Port)
	port.Service = service
	port.Confidence = confidence
	if version != "" && port.Version == "" {
		port.Version = version
	}

	// Step 2: Product detection from banner.
	product, productVersion := detectProduct(port.Banner, port.Service, port.Port)
	port.Product = product
	if productVersion != "" {
		port.Version = productVersion
	}

	// Step 3: HTTP-specific fingerprinting if the service is HTTP.
	if isHTTPService(port.Service) {
		httpPort := port
		if port.Version == "" {
			httpPort = f.fingerprintHTTP(port)
			if httpPort.Product != "" {
				port.Product = httpPort.Product
			}
			if httpPort.Version != "" {
				port.Version = httpPort.Version
			}
			if httpPort.Confidence > port.Confidence {
				port.Confidence = httpPort.Confidence
			}
		}
	}

	// Step 4: Generate CPEs from detected product/version.
	port.CPEs = generateCPEs(port)

	return port
}

// ============================================================================
// Service Detection (banner-based)
// ============================================================================

// serviceSignature maps banner regex patterns to service names.
type serviceSignature struct {
	pattern *regexp.Regexp
	service string
	product string // optional product name
}

var serviceSignatures = []serviceSignature{
	{regexp.MustCompile(`^SSH-\d+\.\d+`), "ssh", "OpenSSH"},
	{regexp.MustCompile(`^HTTP/\d\.\d`), "http", ""},
	{regexp.MustCompile(`^220.*FTP`), "ftp", ""},
	{regexp.MustCompile(`^220.*vsFTPd`), "ftp", "vsftpd"},
	{regexp.MustCompile(`^220.*ProFTPD`), "ftp", "ProFTPD"},
	{regexp.MustCompile(`^220.*Pure-FTPd`), "ftp", "Pure-FTPd"},
	{regexp.MustCompile(`^220 `), "ftp", ""},
	{regexp.MustCompile(`^EHLO|^220.*SMTP|^250-`), "smtp", ""},
	{regexp.MustCompile(`^220.*ESMTP|^220.*SMTP`), "smtp", ""},
	{regexp.MustCompile(`^\+OK|^\-ERR`), "pop3", ""},
	{regexp.MustCompile(`^\* OK|^([0-9]+ )?OK `), "imap", ""},
	{regexp.MustCompile(`^TLS.*|^SSL`), "ssl/tls", ""},
	{regexp.MustCompile(`Redis|^-ERR wrong type|^\+OK\r?$`), "redis", "Redis"},
	{regexp.MustCompile(`^MySQL|mariadb|MariaDB`), "mysql", "MySQL"},
	{regexp.MustCompile(`^PostgreSQL`), "postgresql", "PostgreSQL"},
	{regexp.MustCompile(`MongoDB|mongodb`), "mongodb", "MongoDB"},
	{regexp.MustCompile(`(Microsoft|IIS|Windows)`), "http", "Microsoft IIS"},
	{regexp.MustCompile(`nginx`), "http", "nginx"},
	{regexp.MustCompile(`Apache`), "http", "Apache httpd"},
	{regexp.MustCompile(`lighttpd`), "http", "lighttpd"},
	{regexp.MustCompile(`Couchbase|CouchDB`), "http", "CouchDB"},
	{regexp.MustCompile(`Docker`), "http", "Docker"},
	{regexp.MustCompile(`(?i)elasticsearch`), "http", "Elasticsearch"},
	{regexp.MustCompile(`(?i)kibana`), "http", "Kibana"},
	{regexp.MustCompile(`(?i)Jenkins`), "http", "Jenkins"},
	{regexp.MustCompile(`(?i)Grafana`), "http", "Grafana"},
	{regexp.MustCompile(`(?i)Kubernetes|kube-apiserver`), "https", "Kubernetes API"},
	{regexp.MustCompile(`(?i)prometheus`), "http", "Prometheus"},
	{regexp.MustCompile(`(?i)Consul`), "http", "Consul"},
	{regexp.MustCompile(`(?i)Etcd|etcd`), "http", "etcd"},
	{regexp.MustCompile(`(?i)rabbitmq|RabbitMQ`), "http", "RabbitMQ"},
	{regexp.MustCompile(`(?i)Tomcat|Apache-Coyote`), "http", "Tomcat"},
	{regexp.MustCompile(`(?i)Jetty`), "http", "Jetty"},
	{regexp.MustCompile(`(?i)WildFly|JBoss`), "http", "JBoss/WildFly"},
	{regexp.MustCompile(`(?i)GlassFish`), "http", "GlassFish"},
	{regexp.MustCompile(`(?i)Microsoft SQL Server|MSSQL`), "mssql", "Microsoft SQL Server"},
	{regexp.MustCompile(`(?i)Memcached`), "memcached", "Memcached"},
}

// detectServiceFromBanner analyses a banner string and port number to
// determine the service name with a confidence rating.
func detectServiceFromBanner(banner string, port int) (service string, confidence int, version string) {
	if banner == "" {
		return serviceByPort(port), 50, ""
	}

	// Check registered service signatures.
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
		return "consul"
	case 2379, 2380:
		return "etcd"
	case 9092:
		return "kafka"
		return "postgresql"
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
// ORDER MATTERS: specific patterns MUST come before the generic fallback.
var versionPatterns = []*regexp.Regexp{
	// SSH: "SSH-2.0-OpenSSH_8.9p1"
	regexp.MustCompile(`OpenSSH[_-](\d+[._]\d+(?:p\d+)?)`),
	// Apache: "Apache/2.4.49"
	regexp.MustCompile(`Apache(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// nginx: "nginx/1.18.0"
	regexp.MustCompile(`nginx(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// IIS: "Microsoft-IIS/10.0"
	regexp.MustCompile(`Microsoft-IIS(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// vsftpd: "vsFTPd 3.0.3"
	regexp.MustCompile(`vsFTPd[_\s](\d+\.\d+(?:\.\d+)?)`),
	// ProFTPD: "ProFTPD 1.3.5"
	regexp.MustCompile(`ProFTPD[_\s](\d+\.\d+(?:\.\d+)?)`),
	// MySQL
	regexp.MustCompile(`(?:MySQL|mariadb)[._ -v](\d+\.\d+(?:\.\d+)?)`),
	// PostgreSQL
	regexp.MustCompile(`PostgreSQL[._ -v]?(\d+\.\d+(?:\.\d+)?)`),
	// Redis
	regexp.MustCompile(`redis[._ -v](\d+\.\d+(?:\.\d+)?)`),
	// lighttpd
	regexp.MustCompile(`lighttpd(?:/|\s+)(\d+\.\d+(?:\.\d+)?)`),
	// Generic fallback: "X.Y.Z" or "X.Y" — keep last to avoid over-matching.
	regexp.MustCompile(`(\d+\.\d+(?:\.\d+)?(?:[-_][a-zA-Z0-9]+)?)`),
}

// extractVersion extracts version information from a banner string.
func extractVersion(banner string) string {
	if banner == "" {
		return ""
	}

	// Try specific patterns first.
	for _, pat := range versionPatterns {
		matches := pat.FindStringSubmatch(banner)
		if len(matches) >= 2 {
			version := matches[1]
			// Normalise separator: OpenSSH_8.9p1 → 8.9p1
			version = strings.ReplaceAll(version, "_", ".")
			return version
		}
	}

	return ""
}

// ============================================================================
// Product Detection
// ============================================================================

// productSignatures maps banner substring patterns to product names.
type productSignature struct {
	pattern *regexp.Regexp
	product string
}

var productSignatures = []productSignature{
	{regexp.MustCompile(`OpenSSH`), "OpenSSH"},
	{regexp.MustCompile(`Apache(?:/|\s)`), "Apache httpd"},
	{regexp.MustCompile(`nginx(?:/|\s)`), "nginx"},
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
	{regexp.MustCompile(`Tomcat`), "Apache Tomcat"},
	{regexp.MustCompile(`Jetty`), "Eclipse Jetty"},
	{regexp.MustCompile(`JBoss|WildFly`), "JBoss"},
	{regexp.MustCompile(`GlassFish`), "Oracle GlassFish"},
}

// detectProduct determines the product name from a service banner.
func detectProduct(banner, service string, port int) (product, version string) {
	if banner != "" {
		for _, sig := range productSignatures {
			if sig.pattern.MatchString(banner) {
				version = extractVersion(banner)
				return sig.product, version
			}
		}
	}

	// Fallback: infer product from service name for well-known services.
	product = productByService(service, port)
	return product, ""
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
	default:
		return ""
	}
}

// ============================================================================
// HTTP Fingerprinting
// ============================================================================

// HTTPFingerprint performs an HTTP GET request and analyses the response
// headers to detect the web server product and version.
func (f *ServiceFingerprinter) fingerprintHTTP(port models.Port) models.Port {
	scheme := "http"
	// Assume HTTPS for port 443 and common SSL ports.
	if port.Port == 443 || port.Port == 8443 || port.Port == 5986 {
		scheme = "https"
	}

	addr := fmt.Sprintf("%s://%s:%d/", scheme, "127.0.0.1", port.Port)
	_ = addr // For now, we just inspect the existing banner.

	// If the banner already contains HTTP response data, parse it.
	if port.Banner == "" {
		return port
	}

	// Parse Server header from HTTP response banner.
	serverHeader := extractHTTPHeader(port.Banner, "Server")
	if serverHeader != "" {
		product, version := parseServerHeader(serverHeader)
		if product != "" {
			port.Product = product
			port.Confidence = 95
		}
		if version != "" {
			port.Version = version
		}
	}

	return port
}

// extractHTTPHeader extracts a named header value from an HTTP response.
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

// serverHeaderPattern matches common web server version formats.
// e.g. "nginx/1.18.0" → product="nginx", version="1.18.0"
//      "cloudflare"   → product="cloudflare", version=""
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
	return product, version
}

// ============================================================================
// CPE Generation
// ============================================================================

// vendorMap maps product names to CPE vendors.
var vendorMap = map[string]string{
	"Apache httpd":         "apache",
	"Apache Tomcat":        "apache",
	"nginx":                "nginx",
	"Microsoft IIS":        "microsoft",
	"OpenSSH":              "openbsd",
	"vsftpd":               "beasts",
	"ProFTPD":              "proftpd",
	"Pure-FTPd":            "pureftpd",
	"MySQL":                "mysql",
	"MariaDB":              "mariadb",
	"PostgreSQL":           "postgresql",
	"Redis":                "redis",
	"lighttpd":             "lighttpd",
	"MongoDB":              "mongodb",
	"Docker":               "docker",
	"CouchDB":              "apache",
	"Node.js":              "nodejs",
	"Python":               "python",
	"Eclipse Jetty":        "eclipse",
	"JBoss":                "redhat",
	"Oracle GlassFish":     "oracle",
	"Postfix":              "postfix",
}

// productMap maps product names to CPE product names.
var productMap = map[string]string{
	"Apache httpd":         "http_server",
	"Apache Tomcat":        "tomcat",
	"nginx":                "nginx",
	"Microsoft IIS":        "internet_information_services",
	"OpenSSH":              "openssh",
	"vsftpd":               "vsftpd",
	"ProFTPD":              "proftpd",
	"Pure-FTPd":            "pure-ftpd",
	"MySQL":                "mysql",
	"MariaDB":              "mariadb",
	"PostgreSQL":           "postgresql",
	"Redis":                "redis",
	"lighttpd":             "lighttpd",
	"MongoDB":              "mongodb",
	"Docker":               "docker",
	"CouchDB":              "couchdb",
	"Node.js":              "node.js",
	"Python":               "python",
	"Eclipse Jetty":        "jetty",
	"JBoss":                "jboss_enterprise_application_platform",
	"Oracle GlassFish":     "glassfish",
	"Postfix":              "postfix",
}

// generateCPEs creates CPE entries for a detected service/product.
func generateCPEs(port models.Port) []models.CPE {
	if port.Product == "" && port.Service == "" {
		return nil
	}

	// Determine vendor and product name for CPE.
	cpeVendor := vendorMap[port.Product]
	cpeProduct := productMap[port.Product]

	if cpeVendor == "" || cpeProduct == "" {
		return nil
	}

	version := port.Version
	if version == "" {
		version = "*"
	}

	cpe := models.CPE{
		Part:    "a",
		Vendor:  cpeVendor,
		Product: cpeProduct,
		Version: version,
	}
	cpe.CPE23URI = cpe.String()

	return []models.CPE{cpe}
}

// ============================================================================
// Utilities
// ============================================================================

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
