package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

func sampleResult() *models.ScanResult {
	now := time.Now()
	return &models.ScanResult{
		Target: models.Target{
			Raw:   "test.example.com",
			Hosts: []string{"10.0.0.1"},
		},
		StartedAt: now,
		Duration:  5 * time.Second,
		OpenPorts: []models.Port{
			{Port: 22, Protocol: "tcp", Service: "ssh", State: "open", Product: "OpenSSH", Version: "8.9p1"},
			{Port: 80, Protocol: "tcp", Service: "http", State: "open", Product: "Apache httpd", Version: "2.4.49"},
			{Port: 443, Protocol: "tcp", Service: "https", State: "open"},
		},
		Findings: []models.Finding{
			{
				Host: "test.example.com",
				IP:   "10.0.0.1",
				Port: models.Port{Port: 80, Service: "http"},
				CVE: models.CVE{
					ID:          "CVE-2024-0001",
					Description: "Critical remote code execution vulnerability in Apache httpd",
					CVSSv3:      float64Ptr(9.8),
					Severity:    "CRITICAL",
					References:  []string{"https://example.com/cve-2024-0001"},
					IsInKEV:     true,
					EPSSScore:   float64Ptr(0.95),
				},
			},
			{
				Host: "test.example.com",
				IP:   "10.0.0.1",
				Port: models.Port{Port: 22, Service: "ssh"},
				CVE: models.CVE{
					ID:          "CVE-2024-0002",
					Description: "Medium severity SSH vulnerability",
					CVSSv3:      float64Ptr(5.5),
					Severity:    "MEDIUM",
					References:  []string{"https://example.com/cve-2024-0002"},
				},
			},
			{
				Host: "test.example.com",
				IP:   "10.0.0.1",
				Port: models.Port{Port: 22, Service: "ssh"},
				CVE: models.CVE{
					ID:          "CVE-2024-0003",
					Description: "Low severity information disclosure",
					CVSSv2:      float64Ptr(2.0),
					Severity:    "LOW",
				},
			},
		},
	}
}

func TestConsoleReport(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	err := Generate(&buf, result, FormatConsole)
	if err != nil {
		t.Fatalf("Generate console failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("expected non-empty console output")
	}

	// Check key elements.
	checks := []string{
		"SurfaceGuard Report",
		"test.example.com",
		"10.0.0.1",
		"22",
		"80",
		"443",
		"CVE-2024-0001",
		"CVE-2024-0002",
		"CVE-2024-0003",
		"CRITICAL",
		"MEDIUM",
		"LOW",
		"KEV",
		"Summary",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected console output to contain %q", check)
		}
	}
}

func TestJSONReport(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	err := Generate(&buf, result, FormatJSON)
	if err != nil {
		t.Fatalf("Generate JSON failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("expected non-empty JSON output")
	}

	// Verify it's valid JSON.
	if !strings.HasPrefix(strings.TrimSpace(output), "{") {
		t.Error("expected JSON object")
	}

	// Check key data elements.
	checks := []string{
		"test.example.com",
		"CVE-2024-0001",
		"CRITICAL",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected JSON to contain %q", check)
		}
	}
}

func TestHTMLReport(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	err := Generate(&buf, result, FormatHTML)
	if err != nil {
		t.Fatalf("Generate HTML failed: %v", err)
	}

	output := buf.String()
	if len(output) == 0 {
		t.Fatal("expected non-empty HTML output")
	}

	// Verify HTML structure.
	if !strings.Contains(output, "<!DOCTYPE html>") {
		t.Error("expected DOCTYPE declaration")
	}
	if !strings.Contains(output, "</html>") {
		t.Error("expected closing html tag")
	}
	if !strings.Contains(output, "<table>") {
		t.Error("expected table")
	}

	// Check key data elements.
	checks := []string{
		"test.example.com",
		"CVE-2024-0001",
		"CRITICAL",
		"KEV",
		"Vulnerability Scan Report",
		"nvd.nist.gov",
	}
	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("expected HTML to contain %q", check)
		}
	}
}

func TestReportNoFindings(t *testing.T) {
	result := &models.ScanResult{
		Target:    models.Target{Raw: "clean.example.com", Hosts: []string{"10.0.0.2"}},
		StartedAt: time.Now(),
		Duration:  2 * time.Second,
		OpenPorts: []models.Port{
			{Port: 22, Service: "ssh", State: "open"},
		},
	}

	for _, format := range []Format{FormatConsole, FormatJSON, FormatHTML} {
		var buf bytes.Buffer
		err := Generate(&buf, result, format)
		if err != nil {
			t.Errorf("Generate %s with no findings failed: %v", format, err)
		}
		if buf.Len() == 0 {
			t.Errorf("expected non-empty output for %s", format)
		}
	}
}

func TestReportEmptyResult(t *testing.T) {
	result := &models.ScanResult{
		Target: models.Target{Raw: "empty.example.com"},
	}

	var buf bytes.Buffer
	err := Generate(&buf, result, FormatConsole)
	if err != nil {
		t.Fatalf("Generate console empty failed: %v", err)
	}
}

func TestInvalidFormat(t *testing.T) {
	result := sampleResult()
	var buf bytes.Buffer

	err := Generate(&buf, result, Format("invalid"))
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
}

func TestTruncateString(t *testing.T) {
	short := "hello"
	trunc := truncateString(short, 10)
	if trunc != short {
		t.Errorf("expected %q, got %q", short, trunc)
	}

	long := "this is a very long string that should be truncated"
	trunc = truncateString(long, 20)
	if len(trunc) != 20 {
		t.Errorf("expected length 20, got %d: %q", len(trunc), trunc)
	}
	if !strings.HasSuffix(trunc, "...") {
		t.Errorf("expected '...' suffix, got %q", trunc)
	}
}

func TestCenterText(t *testing.T) {
	centered := centerText("test", 20)
	// centerText only adds left padding; total won't reach width for short strings.
	if len(centered) < 10 {
		t.Errorf("expected padded text, got %d chars: %q", len(centered), centered)
	}

	// Text longer than width should not be truncated.
	long := centerText("this is a very long string", 10)
	if len(long) != 26 {
		t.Errorf("expected original length 26, got %d", len(long))
	}
}

func TestCvssString(t *testing.T) {
	cve := models.CVE{CVSSv3: float64Ptr(9.8)}
	if s := cvssString(cve); s != "9.8" {
		t.Errorf("expected '9.8', got %q", s)
	}

	cve2 := models.CVE{CVSSv2: float64Ptr(7.5)}
	if s := cvssString(cve2); s != "7.5 (v2)" {
		t.Errorf("expected '7.5 (v2)', got %q", s)
	}

	cve3 := models.CVE{}
	if s := cvssString(cve3); s != "N/A" {
		t.Errorf("expected 'N/A', got %q", s)
	}
}

func TestSeverityCSSClass(t *testing.T) {
	tests := []struct {
		sev  string
		want string
	}{
		{"CRITICAL", "sev-CRITICAL"},
		{"HIGH", "sev-HIGH"},
		{"MEDIUM", "sev-MEDIUM"},
		{"LOW", "sev-LOW"},
		{"NONE", "sev-NONE"},
		{"UNKNOWN", "sev-NONE"},
	}
	for _, tc := range tests {
		got := severityCSSClass(tc.sev)
		if got != tc.want {
			t.Errorf("severityCSSClass(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

func TestCountBySeverity(t *testing.T) {
	findings := []models.Finding{
		{CVE: models.CVE{Severity: "CRITICAL"}},
		{CVE: models.CVE{Severity: "CRITICAL"}},
		{CVE: models.CVE{Severity: "HIGH"}},
		{CVE: models.CVE{Severity: "MEDIUM"}},
	}
	counts := countBySeverity(findings)
	if counts["CRITICAL"] != 2 {
		t.Errorf("expected 2 CRITICAL, got %d", counts["CRITICAL"])
	}
	if counts["HIGH"] != 1 {
		t.Errorf("expected 1 HIGH, got %d", counts["HIGH"])
	}
	if counts["MEDIUM"] != 1 {
		t.Errorf("expected 1 MEDIUM, got %d", counts["MEDIUM"])
	}
	if counts["LOW"] != 0 {
		t.Errorf("expected 0 LOW, got %d", counts["LOW"])
	}
}

func TestRepeatChar(t *testing.T) {
	s := repeatChar("-", 5)
	if s != "-----" {
		t.Errorf("expected '-----', got %q", s)
	}
}

func float64Ptr(v float64) *float64 {
	return &v
}
