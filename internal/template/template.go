// Package template implements a Nuclei-style template engine for
// vulnerability detection. Templates are YAML files that define:
//   1. Which service/product the template targets
//   2. HTTP/TCP requests to send
//   3. Matchers to check responses against
//   4. The vulnerability info (CVE, severity, description)
//
// If the response matches, the vulnerability is CONFIRMED — near-zero false positives.
// If no template matches, the existing CPE-based matcher is used as fallback.
package template

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ============================================================================
// Template Types
// ============================================================================

// Template represents a single vulnerability check template.
type Template struct {
	// ID is the unique template identifier (e.g. "apache-path-traversal").
	ID string `yaml:"id"`
	// Info contains metadata about the vulnerability.
	Info Info `yaml:"info"`
	// Requests defines the HTTP/TCP requests to send.
	Requests []Request `yaml:"requests,omitempty"`
	// Matchers define how to check responses.
	Matchers []Matcher `yaml:"matchers,omitempty"`
}

// Info contains vulnerability metadata.
type Info struct {
	Name        string `yaml:"name"`
	Severity    string `yaml:"severity"`
	CVE         string `yaml:"cve"`
	Description string `yaml:"description"`
	// Product targets a specific product name (optional — if empty, runs for all services).
	Product string `yaml:"product,omitempty"`
	// Service targets a specific service name (e.g. "http", "ftp").
	Service string `yaml:"service,omitempty"`
	// Reference URLs.
	Reference string `yaml:"reference,omitempty"`
}

// Request defines an HTTP request to send.
type Request struct {
	// Method is the HTTP method (GET, POST, etc.).
	Method string `yaml:"method"`
	// Path is the URL path to request.
	Path []string `yaml:"path"`
	// Headers are additional HTTP headers.
	Headers map[string]string `yaml:"headers,omitempty"`
	// Body is the request body for POST requests.
	Body string `yaml:"body,omitempty"`
}

// Matcher defines how to check a response.
type Matcher struct {
	// Type is "regex", "string", or "status".
	Type string `yaml:"type"`
	// Pattern is the regex pattern (for type: regex).
	Pattern []string `yaml:"pattern,omitempty"`
	// Words is the string to match (for type: string).
	Words []string `yaml:"words,omitempty"`
	// Status codes to match (for type: status).
	Status []int `yaml:"status,omitempty"`
}

// Finding is the result of a template check.
type Finding struct {
	// TemplateID is the template that produced this finding.
	TemplateID string `json:"template_id"`
	// CVE is the CVE identifier.
	CVE string `json:"cve"`
	// Name is the vulnerability name.
	Name string `json:"name"`
	// Severity is the severity level.
	Severity string `json:"severity"`
	// Description is the vulnerability description.
	Description string `json:"description"`
	// MatchedAt is the URL/path where the match occurred.
	MatchedAt string `json:"matched_at"`
	// Confidence is always 100 for template-based findings.
	Confidence int `json:"confidence"`
}

// ============================================================================
// Engine
// ============================================================================

// Engine loads and runs templates against targets.
type Engine struct {
	templates []*Template
	client    *http.Client
	timeout   time.Duration
}

// NewEngine creates a template engine and loads templates from a directory.
func NewEngine(templateDir string, timeout time.Duration) (*Engine, error) {
	e := &Engine{
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 2 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		timeout: timeout,
	}

	if templateDir != "" {
		if err := e.LoadDirectory(templateDir); err != nil {
			return nil, fmt.Errorf("loading templates: %w", err)
		}
	}

	return e, nil
}

// LoadDirectory loads all YAML templates from a directory.
func (e *Engine) LoadDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".yaml") && !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		tmpl, err := LoadFile(path)
		if err != nil {
			continue // skip invalid templates
		}
		e.templates = append(e.templates, tmpl)
	}

	return nil
}

// LoadFile loads a single template from a file path.
func LoadFile(path string) (*Template, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var tmpl Template
	if err := yaml.Unmarshal(data, &tmpl); err != nil {
		return nil, fmt.Errorf("parsing template %s: %w", path, err)
	}

	if tmpl.Info.CVE == "" && tmpl.Info.Name == "" {
		return nil, fmt.Errorf("template %s missing CVE or name", path)
	}

	return &tmpl, nil
}

// TemplatesForService returns templates that match the given service and product.
// A template matches if:
//   - It has no service AND no product requirement (always runs), OR
//   - Its service matches the given service, OR
//   - Its product matches the given product
// Both service AND product must be specified for a template that requires both.
func (e *Engine) TemplatesForService(service, product string) []*Template {
	var matched []*Template
	for _, t := range e.templates {
		// No restrictions: always runs.
		if t.Info.Service == "" && t.Info.Product == "" {
			matched = append(matched, t)
			continue
		}
		// Service matches.
		if t.Info.Service != "" && t.Info.Service == service {
			matched = append(matched, t)
			continue
		}
		// Product matches.
		if t.Info.Product != "" && t.Info.Product == product {
			matched = append(matched, t)
			continue
		}
	}
	return matched
}

// ============================================================================
// Execution
// ============================================================================

// Run executes all templates against a target. Returns confirmed findings.
func (e *Engine) Run(host string, port int, service, product string) []Finding {
	templates := e.TemplatesForService(service, product)
	if len(templates) == 0 {
		return nil
	}

	var findings []Finding

	for _, tmpl := range templates {
		for _, req := range tmpl.Requests {
			// Build the full URL.
			scheme := "http"
			if port == 443 || port == 8443 {
				scheme = "https"
			}
			baseURL := fmt.Sprintf("%s://%s:%d", scheme, host, port)

			for _, path := range req.Path {
				fullURL := baseURL + path

				// Send the request.
				httpReq, err := http.NewRequest(req.Method, fullURL, nil)
				if err != nil {
					continue
				}
				if req.Body != "" {
					httpReq.Body = io.NopCloser(strings.NewReader(req.Body))
				}
				for k, v := range req.Headers {
					httpReq.Header.Set(k, v)
				}
				httpReq.Header.Set("User-Agent", "SurfaceGuard-Template/1.0")

				resp, err := e.client.Do(httpReq)
				if err != nil {
					continue
				}
				defer resp.Body.Close()

				body, err := io.ReadAll(io.LimitReader(resp.Body, 16384))
				if err != nil {
					continue
				}
				bodyStr := string(body)

				// Check matchers.
				if matchesTemplate(resp.StatusCode, bodyStr, tmpl.Matchers) {
					findings = append(findings, Finding{
						TemplateID:  tmpl.ID,
						CVE:         tmpl.Info.CVE,
						Name:        tmpl.Info.Name,
						Severity:    tmpl.Info.Severity,
						Description: tmpl.Info.Description,
						MatchedAt:   fullURL,
						Confidence:  100,
					})
					break // Found a match for this template, move to next
				}
			}
		}
	}

	return findings
}

// matchesTemplate checks if a response matches any of the matchers.
func matchesTemplate(statusCode int, body string, matchers []Matcher) bool {
	for _, m := range matchers {
		switch m.Type {
		case "status":
			for _, s := range m.Status {
				if statusCode == s {
					return true
				}
			}
		case "string":
			for _, word := range m.Words {
				if strings.Contains(body, word) {
					return true
				}
			}
		case "regex":
			for _, pattern := range m.Pattern {
				re, err := regexp.Compile(pattern)
				if err != nil {
					continue
				}
				if re.MatchString(body) {
					return true
				}
			}
		}
	}
	return false
}

// RunTCP executes a raw TCP-based template against a target.
// Used for services like SSH, FTP, SMTP that aren't HTTP.
func RunTCP(host string, port int, timeout time.Duration, sendBytes []byte, expects []string) (bool, string) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return false, ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout / 2))

	// Send probe data if specified.
	if len(sendBytes) > 0 {
		conn.Write(sendBytes)
	}

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if n == 0 {
		return false, ""
	}
	response := string(buf[:n])

	for _, expected := range expects {
		re, err := regexp.Compile(expected)
		if err == nil && re.MatchString(response) {
			return true, response[:min(len(response), 200)]
		}
		if strings.Contains(response, expected) {
			return true, response[:min(len(response), 200)]
		}
	}

	return false, ""
}

// Count returns the number of loaded templates.
func (e *Engine) Count() int {
	return len(e.templates)
}
