// Package cpe provides a single authoritative source for CPE vendor/product
// mappings used throughout SurfaceGuard. All CPE URIs are generated through
// this package so that Vulnerability Assessment (fingerprint-based) and EASM
// (service-based) pipelines produce identical results for the same software.
//
// Vendor names follow the official NVD CPE dictionary. When in doubt, look up
// the product at https://nvd.nist.gov/products/cpe/search — the "vendor" field
// there is the authoritative spelling.
//
// Two lookup paths are available:
//   - FromProduct(product, version) — used by the fingerprint engine when a
//     detected product name is known (e.g. "Apache httpd", "nginx").
//   - FromServiceOrProduct(service, product, version, port) — used by EASM
//     when only a service name or port number may be available.
package cpe

import (
	"fmt"
	"sort"
	"strings"
)

// CPE holds the components of a CPE 2.3 URI.
// The CPE 2.3 specification defines 11 content fields:
//
//	part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// Full URI:  cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
//
// All fields default to "*" (wildcard) when empty. The 11-field format
// matches the NVD CPE 2.3 standard used by the vulnerability database.
// See: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
type CPE struct {
	Part     string // a=application, o=os, h=hardware
	Vendor   string
	Product  string
	Version  string
	Update   string
	Edition  string
	Language string
	SWEdition string // software edition (CPE 2.3 field 8, between language and target_sw)
	TargetSW string
	TargetHW string
	Other    string
	URI      string // full CPE 2.3 URI (if pre-computed)
}

// String returns the CPE 2.3 URI conforming to the NVD standard.
// The CPE 2.3 specification defines 11 content fields:
//
//	part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
//
// All fields default to "*" (wildcard) when empty. This matches the format
// used by the NVD API and stored in the local vulnerability database.
// Without the sw_edition field, generated CPE URIs would have only 10 fields
// and never match database entries (pre-Phase-1.5 bug).
func (c CPE) String() string {
	if c.URI != "" {
		return c.URI
	}
	return fmt.Sprintf("cpe:2.3:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s:%s",
		c.Part, c.Vendor, c.Product, wildcard(c.Version),
		wildcard(c.Update), wildcard(c.Edition),
		wildcard(c.Language), wildcard(c.SWEdition),
		wildcard(c.TargetSW), wildcard(c.TargetHW),
		wildcard(c.Other))
}

func wildcard(s string) string {
	if s == "" {
		return "*"
	}
	return s
}

// ProductVendor maps display / detected product names to NVD CPE vendor names.
// Key: the human-readable product name (e.g. "Apache httpd").
// Value: the NVD CPE vendor field (e.g. "apache").
var ProductVendor = map[string]string{
	"Apache httpd":     "apache",
	"Apache Tomcat":    "apache",
	"nginx":            "nginx",
	"Microsoft IIS":    "microsoft",
	"OpenSSH":          "openbsd",
	"vsftpd":           "beasts",
	"ProFTPD":          "proftpd",
	"Pure-FTPd":        "pureftpd",
	"MySQL":            "oracle",
	"MariaDB":          "mariadb",
	"PostgreSQL":       "postgresql",
	"Redis":            "redis",
	"lighttpd":         "lighttpd",
	"MongoDB":          "mongodb",
	"Docker":           "docker",
	"CouchDB":          "apache",
	"Node.js":          "nodejs",
	"Python":           "python_software_foundation",
	"Eclipse Jetty":    "eclipse",
	"JBoss":            "redhat",
	"Oracle GlassFish": "oracle",
	"Postfix":          "postfix",
	"Caddy":           "caddyserver",
	"Consul":          "hashicorp",
	"Dropbear":        "dropbear_ssh",
	"Kafka":           "apache",
	"Kibana":          "elastic",
	"Prometheus":      "prometheus",
	"Grafana":         "grafana",
	"Jenkins":         "jenkins",
	"Kubernetes":      "kubernetes",
	"Memcached":       "memcached",
	"Exim":            "exim",
	// Products only known through EASM service-name maps but also detected
	// as product names in some contexts.
	"Elasticsearch": "elastic",
	"RabbitMQ":      "pivotal_software",
	// Service-name entries (lowercase) so the EASM path can look up by service name.
	"ssh":    "openbsd",
	"http":   "apache",
	"https":  "apache",
	"ftp":    "beasts",
	"smtp":   "postfix",
	"pop3":   "gnu",
	"imap":   "gnu",
	"dns":    "isc",
	"smb":    "samba",
	"winrm":  "microsoft",
	"telnet": "linux",
	"rpcbind": "linux",
	"nfs":    "linux",
	// Service names with matching product-name entries (lowercase).
	"mysql":        "oracle",
	"postgresql":   "postgresql",
	"redis":        "redis",
	"mongodb":      "mongodb",
	"docker":       "docker",
	"elasticsearch": "elastic",
	"tomcat":       "apache",
	"jetty":        "eclipse",
	"kibana":       "elastic",
	"kafka":        "apache",
	"rabbitmq":     "pivotal_software",
	"consul":       "hashicorp",
	"etcd":         "etcd",
	"couchdb":      "apache",
}

// ProductName maps display / detected product names to CPE product names.
// Key: the human-readable product name.
// Value: the NVD CPE product field (lowercase, underscores for spaces).
var ProductName = map[string]string{
	"Apache httpd":     "http_server",
	"Apache Tomcat":    "tomcat",
	"nginx":            "nginx",
	"Microsoft IIS":    "internet_information_services",
	"OpenSSH":          "openssh",
	"vsftpd":           "vsftpd",
	"ProFTPD":          "proftpd",
	"Pure-FTPd":        "pure-ftpd",
	"MySQL":            "mysql",
	"MariaDB":          "mariadb",
	"PostgreSQL":       "postgresql",
	"Redis":            "redis",
	"lighttpd":         "lighttpd",
	"MongoDB":          "mongodb",
	"Docker":           "docker",
	"CouchDB":          "couchdb",
	"Node.js":          "node.js",
	"Python":           "python",
	"Eclipse Jetty":    "jetty",
	"JBoss":            "jboss_enterprise_application_platform",
	"Oracle GlassFish": "glassfish",
	"Postfix":          "postfix",
	"Caddy":           "caddy",
	"Consul":          "consul",
	"Dropbear":        "dropbear",
	"Kafka":           "kafka",
	"Kibana":          "kibana",
	"Prometheus":      "prometheus",
	"Grafana":         "grafana",
	"Jenkins":         "jenkins",
	"Kubernetes":      "kubernetes",
	"Memcached":       "memcached",
	"Exim":            "exim",
	// Products from EASM service-name maps.
	"Elasticsearch": "elasticsearch",
	"RabbitMQ":      "rabbitmq",
	// Service-name entries (lowercase) so the EASM path can look up by service name.
	"ssh":    "openssh",
	"http":   "http_server",
	"https":  "http_server",
	"ftp":    "vsftpd",
	"smtp":   "postfix",
	"pop3":   "pop3",
	"imap":   "imap",
	"dns":    "bind",
	"smb":    "samba",
	"winrm":  "windows_remote_management",
	"telnet": "telnet",
	"rpcbind": "rpcbind",
	"nfs":    "nfs_utils",
	// Service-name entries for known products (lowercase).
	"mysql":        "mysql",
	"postgresql":   "postgresql",
	"redis":        "redis",
	"mongodb":      "mongodb",
	"docker":       "docker",
	"elasticsearch": "elasticsearch",
	"tomcat":       "tomcat",
	"jetty":        "jetty",
	"kibana":       "kibana",
	"kafka":        "kafka",
	"rabbitmq":     "rabbitmq",
	"consul":       "consul",
	"etcd":         "etcd",
	"couchdb":      "couchdb",
}

// ServiceProduct maps service names to default CPE product names when no
// specific product string was detected. Used by EASM to produce a reasonable
// CPE URI from a bare service name.
var ServiceProduct = map[string]string{
	"ssh":           "OpenSSH",
	"http":          "Apache httpd",
	"https":         "Apache httpd",
	"ftp":           "vsftpd",
	"smtp":          "Postfix",
	"mysql":         "MySQL",
	"postgresql":    "PostgreSQL",
	"redis":         "Redis",
	"mongodb":       "MongoDB",
	"elasticsearch": "Elasticsearch",
	"rabbitmq":      "RabbitMQ",
	"kibana":        "Kibana",
	"consul":        "Consul",
}

// ============================================================================
// Lookup functions
// ============================================================================

// FromProduct generates a CPE from a detected product name and optional
// version string. Returns nil if the product is not in the mapping tables.
// This is the preferred path when the fingerprint engine has identified a
// specific product (e.g. "Apache httpd", "nginx").
func FromProduct(product, version string) *CPE {
	if product == "" {
		return nil
	}
	vendor, hasVendor := ProductVendor[product]
	cpeProduct, hasProduct := ProductName[product]
	if !hasVendor || !hasProduct {
		return nil
	}
	if version == "" {
		version = "*"
	}
	c := &CPE{
		Part:    "a",
		Vendor:  vendor,
		Product: cpeProduct,
		Version: version,
	}
	c.URI = c.String()
	return c
}

// FromServiceOrProduct generates a CPE from a service name and/or product
// name. This is the EASM path: it tries product first, then service name.
//
// Port-based CPE generation is disabled — if neither product nor service
// name produce a known CPE mapping, nil is returned. This prevents false
// positives from assuming Apache httpd on port 443 without evidence.
// (Phase 1 FP fix: Task 2)
func FromServiceOrProduct(service, product, version string, _ int) *CPE {
	if version == "" {
		version = "*"
	}

	// 1. Try the product name (most specific).
	if product != "" {
		if c := FromProduct(product, version); c != nil {
			return c
		}
	}

	// 2. Try the service name (e.g. "ssh", "http").
	if service != "" {
		vendor, hasVendor := ProductVendor[service]
		cpeProduct, hasProduct := ProductName[service]
		if hasVendor && hasProduct {
			c := &CPE{
				Part:    "a",
				Vendor:  vendor,
				Product: cpeProduct,
				Version: version,
			}
			c.URI = c.String()
			return c
		}
	}

	// Port-based CPE fallback removed (Phase 1 FP fix).
	// Port-only CPEs generate false positives without banner evidence.
	return nil
}

// ============================================================================
// Utilities
// ============================================================================

// AllProductKeys returns all human-readable product name keys sorted
// alphabetically. Used by tests to verify map completeness.
func AllProductKeys() []string {
	keys := make([]string, 0, len(ProductVendor))
	for k := range ProductVendor {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// AllMappedProducts returns every product that has both a vendor and
// product-name mapping (i.e., can produce a valid CPE URI).
func AllMappedProducts() []string {
	var result []string
	for k, v := range ProductVendor {
		if _, ok := ProductName[k]; ok && v != "" {
			result = append(result, k)
		}
	}
	sort.Strings(result)
	return result
}

// NormalizeVendor normalises a vendor string for CPE matching (lowercase, trim).
func NormalizeVendor(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "the ")
	if strings.Contains(v, " ") {
		parts := strings.Fields(v)
		return parts[0]
	}
	return v
}

// NormalizeProduct normalises a product string for CPE matching (lowercase, underscore).
func NormalizeProduct(p string) string {
	p = strings.ToLower(strings.TrimSpace(p))
	return strings.ReplaceAll(p, " ", "_")
}
