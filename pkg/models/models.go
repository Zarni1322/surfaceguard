// Package models defines the core domain types used throughout the scanner.
// These types carry no external dependencies — they are pure data structures
// that flow through every layer of the application.
package models

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"
)

// Target represents a scan target — domain, IPv4, or CIDR range.
type Target struct {
	Raw     string   // original input (e.g. "example.com", "10.0.0.0/24")
	Hosts   []string // resolved IP addresses
	IsCIDR  bool     // true if input was a CIDR range
	IsIPv4  bool     // true if the raw input is an IPv4 address
	ResolvedAt time.Time
}

// NewTargetFromDomain creates a Target from a domain string by resolving it.
func NewTargetFromDomain(domain string) (*Target, error) {
	ips, err := net.LookupHost(domain)
	if err != nil {
		return nil, fmt.Errorf("dns resolution failed for %s: %w", domain, err)
	}
	return &Target{
		Raw:      domain,
		Hosts:    ips,
		IsCIDR:   false,
		IsIPv4:   net.ParseIP(domain) != nil && strings.ContainsRune(domain, '.'),
		ResolvedAt: time.Now(),
	}, nil
}

// NewTargetFromIP creates a Target from a raw IP string.
func NewTargetFromIP(ip string) (*Target, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}
	return &Target{
		Raw:      ip,
		Hosts:    []string{ip},
		IsCIDR:   false,
		IsIPv4:   strings.ContainsRune(ip, '.'),
		ResolvedAt: time.Now(),
	}, nil
}

// Port represents an open TCP port with detected service information.
type Port struct {
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`    // "tcp"
	Service    string `json:"service"`     // detected service name (e.g. "http", "ssh")
	Product    string `json:"product"`     // product name (e.g. "Apache httpd")
	Version    string `json:"version"`     // detected version string
	Banner     string `json:"banner"`      // raw banner text
	CPEs       []CPE  `json:"cpes"`        // matched CPEs
	State      string `json:"state"`       // "open", "filtered"
	Confidence int    `json:"confidence"`  // 0-100 fingerprinting confidence
}

// CPE represents a Common Platform Enumeration entry (CPE 2.3 format).
type CPE struct {
	Part         string `json:"part"`          // a=application, o=os, h=hardware
	Vendor       string `json:"vendor"`
	Product      string `json:"product"`
	Version      string `json:"version"`
	Update       string `json:"update"`
	Edition      string `json:"edition"`
	Language     string `json:"language"`
	TargetSW     string `json:"target_sw"`
	TargetHW     string `json:"target_hw"`
	Other        string `json:"other"`
	CPE23URI     string `json:"cpe_2_3_uri"`    // full CPE 2.3 URI string
}

// String returns the CPE 2.3 formatted URI.
func (c CPE) String() string {
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		c.Part, c.Vendor, c.Product, wildcard(c.Version),
		wildcard(c.Update), wildcard(c.Edition),
		wildcard(c.Language), wildcard(c.TargetSW),
		wildcard(c.TargetHW), wildcard(c.Other))
}

func wildcard(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// CVE represents a Common Vulnerabilities and Exposures entry.
type CVE struct {
	ID               string    `json:"id"`
	Description      string    `json:"description"`
	CVSSv2           *float64  `json:"cvss_v2,omitempty"`
	CVSSv3           *float64  `json:"cvss_v3,omitempty"`
	Severity         string    `json:"severity"` // NONE, LOW, MEDIUM, HIGH, CRITICAL
	PublishedDate    time.Time `json:"published_date"`
	LastModifiedDate time.Time `json:"last_modified_date"`
	References       []string  `json:"references"`
	CPE23URI         string    `json:"cpe_2_3_uri,omitempty"`
	IsInKEV          bool      `json:"is_in_kev"`
	KEVDueDate       *time.Time `json:"kev_due_date,omitempty"`
	EPSSScore        *float64 `json:"epss_score,omitempty"`
	EPSSPercentile   *float64 `json:"epss_percentile,omitempty"`
}

// CVSSSeverity returns a human-readable severity label from a CVSSv3 score.
func CVSSSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score >= 0.1:
		return "LOW"
	default:
		return "NONE"
	}
}

// Finding represents a complete vulnerability finding for a single service.
type Finding struct {
	Host        string   `json:"host"`
	IP          string   `json:"ip"`
	Port        Port     `json:"port"`
	CVE         CVE      `json:"cve"`
	MatchedCPE  CPE      `json:"matched_cpe"`
}

// ScanResult holds the complete output of a scan session.
type ScanResult struct {
	Target      Target            `json:"target"`
	StartedAt   time.Time         `json:"started_at"`
	Duration    time.Duration     `json:"duration"`
	OpenPorts   []Port            `json:"open_ports"`
	Findings    []Finding         `json:"findings"`
	TLSInfo     *TLSResult        `json:"tls_info,omitempty"`
	RiskScore   float64           `json:"risk_score"`
	Errors      []string          `json:"errors,omitempty"`
}

// Summary returns a high-level summary string.
func (r *ScanResult) Summary() string {
	sevCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
	for _, f := range r.Findings {
		sevCounts[f.CVE.Severity]++
	}
	return fmt.Sprintf("Scanned %s (%s): %d open ports, %d vulnerabilities (CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d)",
		r.Target.Raw, r.Target.Hosts[0], len(r.OpenPorts), len(r.Findings),
		sevCounts["CRITICAL"], sevCounts["HIGH"], sevCounts["MEDIUM"], sevCounts["LOW"])
}

// ScanOptions configures the scanner behaviour.
type ScanOptions struct {
	Ports           []int    // specific ports (default: top 1000)
	PortRange       string   // "1-65535" or "80,443,8080"
	Workers         int      // concurrent port scan workers (default: 100)
	Timeout         time.Duration // connection timeout (default: 3s)
	BannerSize      int      // max banner bytes to read (default: 2048)
	FingerprintHTTP bool     // perform HTTP fingerprinting on port 80/443
	CVSSThreshold   float64  // minimum CVSSv3 score to report (default: 0)
	OutputFormat    string   // "console", "json", "html"
	OutputFile      string   // write report to file (optional)
}

// DefaultScanOptions returns sensible defaults.
func DefaultScanOptions() ScanOptions {
	return ScanOptions{
		Workers:         100,
		Timeout:         3 * time.Second,
		BannerSize:      2048,
		FingerprintHTTP: true,
		CVSSThreshold:   0,
		OutputFormat:    "console",
	}
}

// MarshalJSON implements json.Marshaler for ScanResult with human-readable duration.
func (r ScanResult) MarshalJSON() ([]byte, error) {
	type Alias ScanResult
	return json.Marshal(&struct {
		Duration string `json:"duration"`
		*Alias
	}{
		Duration: r.Duration.Round(time.Millisecond).String(),
		Alias:    (*Alias)(&r),
	})
}

// TLSResult holds TLS certificate analysis for a target.
type TLSResult struct {
	Host             string   `json:"host"`
	Port             int      `json:"port"`
	Version          string   `json:"version"`
	CertificateCN    string   `json:"certificate_cn"`
	CertificateIssuer string  `json:"certificate_issuer"`
	CertificateExpiry time.Time `json:"certificate_expiry"`
	DaysUntilExpiry  int      `json:"days_until_expiry"`
	SelfSigned       bool     `json:"self_signed"`
	WeakCipher       bool     `json:"weak_cipher"`
	DeprecatedProto  bool     `json:"deprecated_protocol"`
	SANs             []string `json:"sans,omitempty"`
}

// InfraCheck represents a single infrastructure security check result.
type InfraCheck struct {
	CheckID      string `json:"check_id"`
	Name         string `json:"name"`
	Severity     string `json:"severity"`
	Status       string `json:"status"` // pass, warn, fail
	Evidence     string `json:"evidence,omitempty"`
	Port         int    `json:"port,omitempty"`
	Service      string `json:"service,omitempty"`
}

// RiskScore calculates a weighted risk score from findings.
func CalculateRiskScore(findings []Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	score := 0.0
	for _, f := range findings {
		if f.CVE.CVSSv3 != nil {
			score += *f.CVE.CVSSv3
		} else if f.CVE.CVSSv2 != nil {
			score += *f.CVE.CVSSv2 * 0.8
		}
		if f.CVE.IsInKEV {
			score *= 1.3
		}
	}
	// Normalise to 0-100.
	if score > 100 {
		score = 100
	}
	return score
}

// RiskLabel returns a human-readable risk label.
func RiskLabel(score float64) string {
	switch {
	case score >= 70:
		return "CRITICAL"
	case score >= 40:
		return "HIGH"
	case score >= 20:
		return "MEDIUM"
	case score >= 1:
		return "LOW"
	default:
		return "NONE"
	}
}

// DatabaseInfo holds metadata about the local CVE database.
type DatabaseInfo struct {
	SchemaVersion int       `json:"schema_version"`
	LastUpdated   time.Time `json:"last_updated"`
	CVECount      int       `json:"cve_count"`
	CPECount      int       `json:"cpe_count"`
	ProductCount  int       `json:"product_count"`
	VendorCount   int       `json:"vendor_count"`
	KEVCount      int       `json:"kev_count"`
	EPSSCount     int       `json:"epss_count"`
	IntegrityOK   bool      `json:"integrity_ok"`
}

// ============================================================================
// Authenticated Assessment Types
// ============================================================================

// Protocol enumerates supported authentication protocols.
type Protocol string

const (
	ProtocolSSH   Protocol = "ssh"
	ProtocolWinRM Protocol = "winrm"
	ProtocolSNMP  Protocol = "snmp"
)

// CredentialProfile holds reusable credentials for authenticated scanning.
// Secrets are always encrypted at rest (AES-GCM) and never logged.
type CredentialProfile struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Protocol    Protocol  `json:"protocol"`
	Host        string    `json:"host"`
	Port        int       `json:"port"`
	Username    string    `json:"username,omitempty"`
	AuthMethod  string    `json:"auth_method"` // password, key, key+passphrase, community, snmpv3
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ValidationResult holds the outcome of a credential validation (test connection).
type ValidationResult struct {
	Status      string              `json:"status"` // SUCCESS, WARNING, FAILED
	Checks      []ValidationCheck   `json:"checks"`
	TestedAt    time.Time           `json:"tested_at"`
	ProfileID   int64               `json:"profile_id"`
	Target      string              `json:"target"`
}

// ValidationCheck is one check within a credential validation.
type ValidationCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"` // pass, warn, fail
	Message string `json:"message,omitempty"`
}

// AssetInfo holds inventory information about a scanned host.
type AssetInfo struct {
	ID            int64     `json:"id"`
	Hostname      string    `json:"hostname"`
	IP            string    `json:"ip"`
	OS            string    `json:"os"`
	Distro        string    `json:"distro,omitempty"`
	KernelVersion string    `json:"kernel_version,omitempty"`
	Architecture  string    `json:"architecture,omitempty"`
	AssetType     string    `json:"asset_type"` // linux, windows, network_device
	RiskScore     float64   `json:"risk_score"`
	LastSeen      time.Time `json:"last_seen"`
	LastScan      time.Time `json:"last_scan"`
}

// InstalledPackage represents a package discovered on a Linux host.
type InstalledPackage struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Arch       string `json:"arch,omitempty"`
	CPE23URI   string `json:"cpe_2_3_uri,omitempty"`
	Status     string `json:"status"` // installed, removed, changed
}

// InstalledSoftware represents installed software on a Windows host.
type InstalledSoftware struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Vendor       string `json:"vendor,omitempty"`
	InstallDate  string `json:"install_date,omitempty"`
	CPE23URI     string `json:"cpe_2_3_uri,omitempty"`
}

// SecurityFinding represents a security configuration check result.
type SecurityFinding struct {
	CheckID   string `json:"check_id"`
	Name      string `json:"name"`
	Severity  string `json:"severity"`
	Status    string `json:"status"` // pass, warn, fail
	Evidence  string `json:"evidence,omitempty"`
}

// ScanProgress represents a real-time progress update during an assessment scan.
// Used for SSE streaming to the frontend.
type ScanProgress struct {
	Step     string  `json:"step"`     // connecting, collecting, packages, cves, done, failed
	Progress float64 `json:"progress"` // 0.0 - 100.0
	Message  string  `json:"message"`
}

// AssessmentResult holds the output of an authenticated assessment scan.
type AssessmentResult struct {
	ID           int64                `json:"id"`
	Target       string               `json:"target"`
	ProfileID    int64                `json:"profile_id"`
	ProfileName  string               `json:"profile_name,omitempty"`
	Protocol     Protocol             `json:"protocol"`
	StartedAt    time.Time            `json:"started_at"`
	Duration     string               `json:"duration"`
	Asset        *AssetInfo           `json:"asset,omitempty"`
	Packages     []InstalledPackage   `json:"packages,omitempty"`
	Software     []InstalledSoftware  `json:"software,omitempty"`
	Findings     []SecurityFinding    `json:"findings,omitempty"`
	CVEs         []CVE                `json:"cves,omitempty"`
	RiskScore    float64              `json:"risk_score"`
	Validation   *ValidationResult    `json:"validation,omitempty"`
	Status       string               `json:"status"`
}
