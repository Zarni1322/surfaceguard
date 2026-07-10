// Package cpe tests verify that all CPE mappings use authoritative NVD vendor
// names and that the fingerprint and EASM pipelines produce identical CPE URIs
// for the same detected software.
package cpe

import (
	"fmt"
	"testing"
)

func TestFromProductReturnsValidCPE(t *testing.T) {
	tests := []struct {
		product string
		version string
		wantURI string
	}{
		// Fingerprint pipeline: product names with explicit versions.
		{"Apache httpd", "2.4.49", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"nginx", "1.18.0", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"},
		{"OpenSSH", "8.9p1", "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"},
		{"Microsoft IIS", "10.0", "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*"},
		{"MySQL", "8.0.28", "cpe:2.3:a:oracle:mysql:8.0.28:*:*:*:*:*:*:*"},
		{"Python", "3.11.0", "cpe:2.3:a:python_software_foundation:python:3.11.0:*:*:*:*:*:*:*"},
		// HTTP server on port 443 uses "https" service name.
		{"Apache httpd", "", "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
		// Empty version should become "*".
		{"nginx", "", "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"},
	}
	for _, tc := range tests {
		t.Run(tc.product, func(t *testing.T) {
			c := FromProduct(tc.product, tc.version)
			if c == nil {
				t.Fatalf("FromProduct(%q, %q) returned nil, expected CPE", tc.product, tc.version)
			}
			if c.URI != tc.wantURI {
				t.Errorf("URI = %q, want %q", c.URI, tc.wantURI)
			}
			// Verify CPE.String() matches for good measure.
			if c.String() != tc.wantURI {
				t.Errorf("String() = %q, want %q", c.String(), tc.wantURI)
			}
		})
	}
}

func TestFromProductNilForUnknown(t *testing.T) {
	c := FromProduct("BogusProduct", "1.0")
	if c != nil {
		t.Errorf("expected nil for unknown product, got %v", c)
	}
}

func TestFromProductNilForEmpty(t *testing.T) {
	c := FromProduct("", "1.0")
	if c != nil {
		t.Errorf("expected nil for empty product, got %v", c)
	}
}

// TestVendorAuthorityNVD verifies that our vendor names match the NVD CPE
// dictionary. These were verified at the time of writing; if NVD changes
// a vendor name in the future, this test will need updating.
func TestVendorAuthorityNVD(t *testing.T) {
	tests := []struct {
		key        string // product or service name
		wantVendor string // authoritative NVD vendor
	}{
		// ---- Fingerprint products ----
		{"Apache httpd", "apache"},
		{"Apache Tomcat", "apache"},
		{"nginx", "nginx"},
		{"Microsoft IIS", "microsoft"},
		{"OpenSSH", "openbsd"},
		{"vsftpd", "beasts"},
		{"ProFTPD", "proftpd"},
		{"Pure-FTPd", "pureftpd"},
		{"MySQL", "oracle"},       // NVD: oracle (Oracle Corporation)
		{"MariaDB", "mariadb"},
		{"PostgreSQL", "postgresql"},
		{"Redis", "redis"},
		{"lighttpd", "lighttpd"},
		{"MongoDB", "mongodb"},
		{"Docker", "docker"},
		{"CouchDB", "apache"},
		{"Node.js", "nodejs"},
		{"Python", "python_software_foundation"}, // NVD: python_software_foundation
		{"Eclipse Jetty", "eclipse"},
		{"JBoss", "redhat"},
		{"Oracle GlassFish", "oracle"},
		{"Postfix", "postfix"},

		// ---- EASM service names ----
		{"ssh", "openbsd"},
		{"http", "apache"},
		{"https", "apache"},
		{"ftp", "beasts"},
		{"smtp", "postfix"},
		{"mysql", "oracle"},
		{"postgresql", "postgresql"},
		{"redis", "redis"},
		{"mongodb", "mongodb"},
		{"elasticsearch", "elastic"},
		{"tomcat", "apache"},
		{"jetty", "eclipse"},
		{"kibana", "elastic"},
		{"kafka", "apache"},
		{"rabbitmq", "pivotal_software"},
		{"consul", "hashicorp"},
		{"etcd", "etcd"},
		{"dns", "isc"},
		{"smb", "samba"},
		{"winrm", "microsoft"},
		{"telnet", "linux"},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			got, ok := ProductVendor[tc.key]
			if !ok {
				t.Fatalf("key %q not found in ProductVendor", tc.key)
			}
			if got != tc.wantVendor {
				t.Errorf("ProductVendor[%q] = %q, want NVD vendor %q", tc.key, got, tc.wantVendor)
			}
		})
	}
}

// TestMapCompleteness verifies that every entry in ProductVendor has a
// corresponding entry in ProductName and vice versa.
func TestMapCompleteness(t *testing.T) {
	for k := range ProductVendor {
		if _, ok := ProductName[k]; !ok {
			t.Errorf("ProductVendor has key %q but ProductName does not", k)
		}
	}
	for k := range ProductName {
		if _, ok := ProductVendor[k]; !ok {
			t.Errorf("ProductName has key %q but ProductVendor does not", k)
		}
	}
}

// TestFingerprintEASMConvergence verifies that both the old fingerprint
// path and the EASM path now produce identical CPE URIs for the same
// detected software. This is the core of Fix 3.
func TestFingerprintEASMConvergence(t *testing.T) {
	tests := []struct {
		product string
		service string
		version string
		port    int
	}{
		// Common scenarios shared by both pipelines.
		{"Apache httpd", "http", "2.4.49", 80},
		{"Apache httpd", "https", "2.4.50", 443},
		{"nginx", "http", "1.18.0", 8080},
		{"nginx", "https", "1.22.0", 8443},
		{"OpenSSH", "ssh", "8.9p1", 22},
		{"Microsoft IIS", "http", "10.0", 443},
		{"vsftpd", "ftp", "3.0.3", 21},
		{"MySQL", "mysql", "8.0.28", 3306},
		{"PostgreSQL", "postgresql", "14.0", 5432},
		{"Redis", "redis", "7.0.0", 6379},
		{"MongoDB", "mongodb", "6.0.0", 27017},
		{"Docker", "docker", "20.10.0", 2375},
		{"Elasticsearch", "elasticsearch", "8.0.0", 9200},
		{"RabbitMQ", "rabbitmq", "3.11.0", 5672},
		// Empty version (should produce wildcard).
		{"Apache httpd", "http", "", 80},
		{"nginx", "http", "", 80},
		{"OpenSSH", "ssh", "", 22},
	}
	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.product, tc.service), func(t *testing.T) {
			// Fingerprint path: FromProduct with the product name.
			fpCPE := FromProduct(tc.product, tc.version)
			if fpCPE == nil {
				t.Fatalf("FromProduct(%q, %q) returned nil", tc.product, tc.version)
			}

			// EASM path: FromServiceOrProduct with product + service + port.
			easmCPE := FromServiceOrProduct(tc.service, tc.product, tc.version, tc.port)
			if easmCPE == nil {
				t.Fatalf("FromServiceOrProduct(%q, %q, %q, %d) returned nil",
					tc.service, tc.product, tc.version, tc.port)
			}

			// Both paths must produce identical URIs.
			if fpCPE.URI != easmCPE.URI {
				t.Errorf("CPE mismatch:\n  fingerprint: %s\n  easm:       %s",
					fpCPE.URI, easmCPE.URI)
			}
		})
	}
}

// TestFromServiceOrProductFallbacks verifies the fallback chain:
// product → service. Port-based fallback is disabled (Phase 1 FP fix).
func TestFromServiceOrProductFallbacks(t *testing.T) {
	tests := []struct {
		name    string
		service string
		product string
		version string
		port    int
		wantURI string
	}{
		// Product takes precedence over service.
		{"product wins", "http", "nginx", "1.18.0", 80, "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"},
		// Service name lookup.
		{"service name", "ssh", "", "8.9p1", 22, "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"},
		// Port-based fallback is disabled — returns nil.
		{"port fallback disabled", "", "", "*", 3306, ""},
		// Unknown everything returns nil.
		{"unknown returns nil", "unknown", "", "1.0", 99999, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := FromServiceOrProduct(tc.service, tc.product, tc.version, tc.port)
			if tc.wantURI == "" {
				if c != nil {
					t.Errorf("expected nil, got %s", c.URI)
				}
				return
			}
			if c == nil {
				t.Fatalf("expected URI %q, got nil", tc.wantURI)
			}
			if c.URI != tc.wantURI {
				t.Errorf("URI = %q, want %q", c.URI, tc.wantURI)
			}
		})
	}
}

// TestAllMappedProducts verifies that every key with a vendor also has a
// product-name mapping (and produces a non-nil CPE).
func TestAllMappedProducts(t *testing.T) {
	for _, p := range AllMappedProducts() {
		c := FromProduct(p, "1.0")
		if c == nil {
			t.Errorf("key %q has vendor/name mapping but FromProduct returned nil", p)
		}
	}
}

// TestNormalizeVendor tests vendor normalisation utilities.
func TestNormalizeVendor(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Apache", "apache"},
		{"APACHE", "apache"},
		{"  nginx  ", "nginx"},
		{"", ""},
		{"The Apache Software Foundation", "apache"},
	}
	for _, tc := range tests {
		got := NormalizeVendor(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestNormalizeProduct tests product name normalisation.
func TestNormalizeProduct(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http_server", "http_server"},
		{"Internet Information Services", "internet_information_services"},
		{"", ""},
	}
	for _, tc := range tests {
		got := NormalizeProduct(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeProduct(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

// TestStringFormat verifies CPE.String() produces the CPE 2.3 format.
func TestStringFormat(t *testing.T) {
	c := &CPE{
		Part:    "a",
		Vendor:  "apache",
		Product: "http_server",
		Version: "2.4.49",
	}
	expected := "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"
	if c.String() != expected {
		t.Errorf("String() = %q, want %q", c.String(), expected)
	}
}
