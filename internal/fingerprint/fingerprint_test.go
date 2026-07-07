package fingerprint

import (
	"testing"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

func TestNewServiceFingerprinter(t *testing.T) {
	f := NewServiceFingerprinter(5 * time.Second)
	if f.timeout != 5*time.Second {
		t.Errorf("expected 5s timeout, got %s", f.timeout)
	}
}

func TestNewServiceFingerprinterDefaults(t *testing.T) {
	f := NewServiceFingerprinter(0)
	if f.timeout != 3*time.Second {
		t.Errorf("expected default 3s timeout, got %s", f.timeout)
	}
}

func TestDetectServiceFromBannerSSH(t *testing.T) {
	service, confidence, version := detectServiceFromBanner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3", 22)
	if service != "ssh" {
		t.Errorf("expected ssh, got %s", service)
	}
	if confidence < 80 {
		t.Errorf("expected high confidence, got %d", confidence)
	}
	if version == "" {
		t.Error("expected a version string")
	}
}

func TestDetectServiceFromBannerHTTP(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n"
	service, confidence, version := detectServiceFromBanner(banner, 80)
	if service != "http" {
		t.Errorf("expected http, got %s", service)
	}
	if confidence < 80 {
		t.Errorf("expected high confidence, got %d", confidence)
	}
	if version == "" {
		t.Error("expected version from HTTP banner")
	}
}

func TestDetectServiceFromBannerFTP(t *testing.T) {
	service, confidence, _ := detectServiceFromBanner("220 vsFTPd 3.0.3 ready...", 21)
	if service != "ftp" {
		t.Errorf("expected ftp, got %s", service)
	}
	if confidence < 80 {
		t.Errorf("expected high confidence, got %d", confidence)
	}
}

func TestDetectServiceFromBannerEmpty(t *testing.T) {
	service, confidence, version := detectServiceFromBanner("", 80)
	if service != "http" {
		t.Errorf("expected http (port guess), got %s", service)
	}
	if confidence != 50 {
		t.Errorf("expected confidence 50 for port guess, got %d", confidence)
	}
	if version != "" {
		t.Errorf("expected empty version for empty banner, got %s", version)
	}
}

func TestServiceByPort(t *testing.T) {
	tests := []struct {
		port    int
		want    string
	}{
		{22, "ssh"},
		{80, "http"},
		{443, "https"},
		{3306, "mysql"},
		{5432, "postgresql"},
		{99999, "unknown"},
	}
	for _, tc := range tests {
		got := serviceByPort(tc.port)
		if got != tc.want {
			t.Errorf("serviceByPort(%d) = %q, want %q", tc.port, got, tc.want)
		}
	}
}

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		banner string
		want   string
	}{
		{"OpenSSH_8.9p1", "8.9p1"},
		{"SSH-2.0-OpenSSH_7.4", "7.4"},
		{"Apache/2.4.49 (Unix)", "2.4.49"},
		{"nginx/1.18.0", "1.18.0"},
		{"Microsoft-IIS/10.0", "10.0"},
		{"vsFTPd 3.0.3", "3.0.3"},
		{"ProFTPD 1.3.5", "1.3.5"},
		{"MySQL 8.0.28", "8.0.28"},
		{"", ""},
		{"no version here", ""},
		{"random text 1.2.3", "1.2.3"},
	}
	for _, tc := range tests {
		got := extractVersion(tc.banner)
		if got != tc.want {
			t.Errorf("extractVersion(%q) = %q, want %q", tc.banner, got, tc.want)
		}
	}
}

func TestDetectProduct(t *testing.T) {
	tests := []struct {
		banner  string
		service string
		port    int
		wantProduct string
	}{
		{"Apache/2.4.49 (Unix)", "http", 80, "Apache httpd"},
		{"nginx/1.18.0", "http", 80, "nginx"},
		{"Microsoft-IIS/10.0", "http", 443, "Microsoft IIS"},
		{"OpenSSH_8.9p1 Ubuntu-3", "ssh", 22, "OpenSSH"},
		{"MySQL 8.0.28", "mysql", 3306, "MySQL"},
		{"", "http", 80, ""},
	}
	for _, tc := range tests {
		product, _ := detectProduct(tc.banner, tc.service, tc.port)
		if product != tc.wantProduct {
			t.Errorf("detectProduct(%q, %q, %d) = %q, want %q",
				tc.banner, tc.service, tc.port, product, tc.wantProduct)
		}
	}
}

func TestParseServerHeader(t *testing.T) {
	tests := []struct {
		header       string
		wantProduct  string
		wantVersion  string
	}{
		{"nginx/1.18.0", "nginx", "1.18.0"},
		{"Apache/2.4.49 (Unix)", "Apache", "2.4.49"},
		{"Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"},
		{"cloudflare", "cloudflare", ""},
		{"", "", ""},
	}
	for _, tc := range tests {
		product, version := parseServerHeader(tc.header)
		if product != tc.wantProduct {
			t.Errorf("parseServerHeader(%q) product = %q, want %q", tc.header, product, tc.wantProduct)
		}
		if version != tc.wantVersion {
			t.Errorf("parseServerHeader(%q) version = %q, want %q", tc.header, version, tc.wantVersion)
		}
	}
}

func TestExtractHTTPHeader(t *testing.T) {
	banner := "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Type: text/html\r\n"
	server := extractHTTPHeader(banner, "Server")
	if server != "nginx/1.18.0" {
		t.Errorf("expected 'nginx/1.18.0', got %q", server)
	}
	contentType := extractHTTPHeader(banner, "Content-Type")
	if contentType != "text/html" {
		t.Errorf("expected 'text/html', got %q", contentType)
	}
	missing := extractHTTPHeader(banner, "X-Missing")
	if missing != "" {
		t.Errorf("expected empty for missing header, got %q", missing)
	}
}

func TestGenerateCPEs(t *testing.T) {
	tests := []struct {
		product string
		version string
		wantURI string
	}{
		{"Apache httpd", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*"},
		{"nginx", "1.18.0", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*"},
		{"OpenSSH", "8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*"},
		{"UnknownProduct", "", ""},
	}
	for _, tc := range tests {
		port := models.Port{Product: tc.product, Version: tc.version}
		cpes := generateCPEs(port)
		if tc.wantURI == "" {
			if len(cpes) != 0 {
				t.Errorf("expected no CPEs for %s, got %d", tc.product, len(cpes))
			}
			continue
		}
		if len(cpes) != 1 {
			t.Errorf("expected 1 CPE for %s, got %d", tc.product, len(cpes))
			continue
		}
		if cpes[0].CPE23URI != tc.wantURI {
			t.Errorf("generateCPEs(%q) URI = %q, want %q", tc.product, cpes[0].CPE23URI, tc.wantURI)
		}
	}
}

func TestFingerprintPort(t *testing.T) {
	f := NewServiceFingerprinter(time.Second)

	// SSH banner.
	port := models.Port{
		Port:    22,
		Banner:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3",
		State:   "open",
	}
	result := f.Fingerprint(port)
	if result.Service != "ssh" {
		t.Errorf("expected service ssh, got %s", result.Service)
	}
	if result.Product != "OpenSSH" {
		t.Errorf("expected product OpenSSH, got %s", result.Product)
	}
	if result.Version == "" {
		t.Error("expected a version")
	}
	if len(result.CPEs) == 0 {
		t.Error("expected at least one CPE")
	}
}

func TestFingerprintHTTPBanner(t *testing.T) {
	f := NewServiceFingerprinter(time.Second)

	port := models.Port{
		Port:    80,
		Banner:  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49 (Unix)\r\n",
		State:   "open",
	}
	result := f.Fingerprint(port)
	if result.Product != "Apache httpd" {
		t.Errorf("expected Apache httpd, got %s", result.Product)
	}
	if result.Version != "2.4.49" {
		t.Errorf("expected version 2.4.49, got %s", result.Version)
	}
	cpes := result.CPEs
	if len(cpes) == 0 {
		t.Fatal("expected CPEs")
	}
	if cpes[0].Vendor != "apache" {
		t.Errorf("expected vendor apache, got %s", cpes[0].Vendor)
	}
}

func TestFingerprintNoBanner(t *testing.T) {
	f := NewServiceFingerprinter(time.Second)

	port := models.Port{
		Port:  8080,
		State: "open",
	}
	result := f.Fingerprint(port)
	if result.Service != "http" {
		t.Errorf("expected http from port guess, got %s", result.Service)
	}
	if result.Confidence != 50 {
		t.Errorf("expected confidence 50 for port guess, got %d", result.Confidence)
	}
}

func TestIsHTTPService(t *testing.T) {
	if !isHTTPService("http") {
		t.Error("expected http to be HTTP service")
	}
	if !isHTTPService("https") {
		t.Error("expected https to be HTTP service")
	}
	if isHTTPService("ssh") {
		t.Error("expected ssh not to be HTTP service")
	}
}

func TestSanitizeBanner(t *testing.T) {
	got := sanitizeBanner("Hello\x00World\nTest\x01\x02End")
	want := "HelloWorld\nTestEnd"
	if got != want {
		t.Errorf("sanitizeBanner = %q, want %q", got, want)
	}
}

func TestBannerFromPortClosed(t *testing.T) {
	// Port 1 is unlikely to be open.
	banner := BannerFromPort("127.0.0.1", 1, 100*time.Millisecond)
	if banner != "" {
		t.Errorf("expected empty banner from closed port, got %q", banner)
	}
}

func TestVendorMap(t *testing.T) {
	// Verify all entries in productMap have a corresponding vendorMap entry.
	for product := range productMap {
		if _, ok := vendorMap[product]; !ok {
			t.Errorf("product %q has productMap entry but no vendorMap entry", product)
		}
	}
}
