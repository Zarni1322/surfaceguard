package models

import (
	"testing"
	"time"
)

func TestNewTargetFromDomain(t *testing.T) {
	// This test depends on DNS — use a known-safe domain or mock.
	target, err := NewTargetFromDomain("localhost")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if target.Raw != "localhost" {
		t.Errorf("expected Raw 'localhost', got %q", target.Raw)
	}
	if len(target.Hosts) == 0 {
		t.Error("expected at least one resolved IP")
	}
	if target.IsCIDR {
		t.Error("expected IsCIDR=false for domain")
	}
}

func TestNewTargetFromIP(t *testing.T) {
	target, err := NewTargetFromIP("192.168.1.1")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if target.Raw != "192.168.1.1" {
		t.Errorf("expected Raw '192.168.1.1', got %q", target.Raw)
	}
	if !target.IsIPv4 {
		t.Error("expected IsIPv4=true")
	}

	_, err = NewTargetFromIP("invalid-ip")
	if err == nil {
		t.Fatal("expected error for invalid IP")
	}
}

func TestCPEString(t *testing.T) {
	cpe := CPE{
		Part:    "a",
		Vendor:  "apache",
		Product: "http_server",
		Version: "2.4.49",
	}
	expected := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*"
	if s := cpe.String(); s != expected {
		t.Errorf("expected %q, got %q", expected, s)
	}
}

func TestCPEStringWildcards(t *testing.T) {
	cpe := CPE{
		Part:    "a",
		Vendor:  "apache",
		Product: "http_server",
		Version: "2.4.49",
	}
	s := cpe.String()
	if len(s) == 0 {
		t.Fatal("expected non-empty CPE string")
	}
	// All unset fields should be wildcards — verify the last characters
	if s[len(s)-1:] != "*" {
		t.Error("expected trailing wildcard for unset fields")
	}
}

func TestCVSSSeverity(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{9.5, "CRITICAL"},
		{9.0, "CRITICAL"},
		{7.5, "HIGH"},
		{7.0, "HIGH"},
		{5.0, "MEDIUM"},
		{4.0, "MEDIUM"},
		{2.0, "LOW"},
		{0.1, "LOW"},
		{0.0, "NONE"},
	}
	for _, tc := range tests {
		got := CVSSSeverity(tc.score)
		if got != tc.want {
			t.Errorf("CVSSSeverity(%.1f) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestDefaultScanOptions(t *testing.T) {
	opts := DefaultScanOptions()
	if opts.Workers != 100 {
		t.Errorf("expected 100 workers, got %d", opts.Workers)
	}
	if opts.OutputFormat != "console" {
		t.Errorf("expected console output, got %s", opts.OutputFormat)
	}
	if opts.CVSSThreshold != 0 {
		t.Errorf("expected CVSS threshold 0, got %.1f", opts.CVSSThreshold)
	}
}

func TestScanResultSummary(t *testing.T) {
	result := &ScanResult{
		Target: Target{Raw: "test.example.com", Hosts: []string{"10.0.0.1"}},
		OpenPorts: []Port{
			{Port: 80, Service: "http"},
		},
		Findings: []Finding{
			{CVE: CVE{ID: "CVE-2024-0001", Severity: "CRITICAL"}},
			{CVE: CVE{ID: "CVE-2024-0002", Severity: "HIGH"}},
		},
	}
	summary := result.Summary()
	if len(summary) == 0 {
		t.Fatal("expected non-empty summary")
	}
}

func TestScanResultMarshalJSON(t *testing.T) {
	result := &ScanResult{
		Target:    Target{Raw: "test.example.com"},
		StartedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		Duration:  5 * time.Second,
	}
	data, err := result.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("expected non-empty JSON")
	}
}

func TestTargetIsIPv4(t *testing.T) {
	target := &Target{Raw: "10.0.0.1", IsIPv4: true}
	if !target.IsIPv4 {
		t.Error("expected IsIPv4=true")
	}
	target.IsIPv4 = false
	if target.IsIPv4 {
		t.Error("expected IsIPv4=false")
	}
}

func TestPortHasExpectedFields(t *testing.T) {
	p := Port{
		Port:     443,
		Protocol: "tcp",
		Service:  "https",
		Product:  "nginx",
		Version:  "1.24.0",
		State:    "open",
	}
	if p.Port != 443 {
		t.Errorf("expected port 443, got %d", p.Port)
	}
	if p.State != "open" {
		t.Errorf("expected state open, got %s", p.State)
	}
}
