// Package scanner orchestrates the end-to-end vulnerability scanning workflow:
//
//	Target → Port Scan → Banner Grab → Service Detection → HTTP Fingerprinting
//	→ Version Detection → CPE Mapping → CVE Matching → Report Generation
//
// This is the use-case layer in Clean Architecture: it wires together the
// domain services (portscan, fingerprint, matcher) and infrastructure
// (database, report) without depending on any specific framework.
package scanner

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/fingerprint"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/internal/report"
	"github.com/evilhunter/surfaceguard/internal/scoring"
	"github.com/evilhunter/surfaceguard/internal/validation"
	"github.com/evilhunter/surfaceguard/pkg/models"
	"github.com/evilhunter/surfaceguard/pkg/portscan"
)

// Scanner is the top-level orchestrator for vulnerability scans.
type Scanner struct {
	cfg          *config.Config
	fingerprinter *fingerprint.ServiceFingerprinter
	matcher      *matcher.Matcher
	logger       *slog.Logger
}

// New creates a new Scanner orchestrator.
func New(cfg *config.Config, m *matcher.Matcher, logger *slog.Logger) *Scanner {
	return &Scanner{
		cfg:           cfg,
		fingerprinter: fingerprint.NewServiceFingerprinter(cfg.Scan.Timeout),
		matcher:       m,
		logger:        logger,
	}
}

// Result holds the output of a scan operation.
type Result struct {
	ScanResult *models.ScanResult
	Error      error
}

// Scan runs the full vulnerability scan workflow for a single target.
func (s *Scanner) Scan(ctx context.Context, target *models.Target, opts models.ScanOptions) (*models.ScanResult, error) {
	startTime := time.Now()
	result := &models.ScanResult{
		Target:    *target,
		StartedAt: startTime,
	}

	s.logger.Info("starting scan",
		"target", target.Raw,
		"hosts", target.Hosts,
		"ports", len(opts.Ports),
		"workers", opts.Workers,
	)

	// Use the first resolved IP for scanning.
	scanIP := target.Hosts[0]

	// Step 1: Port scan.
	openPorts, err := s.scanPorts(ctx, scanIP, opts.Ports)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}
	result.OpenPorts = openPorts
	s.logger.Info("port scan complete", "open_ports", len(openPorts))

	if len(openPorts) == 0 {
		s.logger.Info("no open ports found, scan complete", "target", target.Raw)
		result.Duration = time.Since(startTime)
		return result, nil
	}

	// Step 2: Fingerprint each open port.
	for i, port := range openPorts {
		// If port has no banner yet, grab one.
		if port.Banner == "" {
			banner := fingerprint.BannerFromPort(scanIP, port.Port, s.cfg.Scan.Timeout)
			openPorts[i].Banner = banner
			s.logger.Debug("grabbed banner", "port", port.Port, "banner_len", len(banner))
		}

		// Perform full fingerprinting.
		fingerprinted := s.fingerprinter.Fingerprint(openPorts[i])
		openPorts[i] = fingerprinted

		s.logger.Debug("fingerprinted port",
			"port", port.Port,
			"service", fingerprinted.Service,
			"product", fingerprinted.Product,
			"version", fingerprinted.Version,
			"confidence", fingerprinted.Confidence,
			"cpes", len(fingerprinted.CPEs),
		)
	}
	result.OpenPorts = openPorts

	// Step 3: TLS analysis for HTTPS ports.
	for _, p := range openPorts {
		if p.Port == 443 || p.Service == "https" || p.Port == 8443 {
			if tlsResult := fingerprint.AnalyzeTLS(scanIP, p.Port, s.cfg.Scan.Timeout); tlsResult != nil {
				result.TLSInfo = tlsResult
				break
			}
		}
	}

	// Step 4: CPE → CVE matching for each open port with CPEs.
	for _, p := range openPorts {
		findings := s.matcher.MatchPort(ctx, target.Raw, scanIP, p)
		result.Findings = append(result.Findings, findings...)
	}

	// Deduplicate and sort findings.
	result.Findings = matcher.DeduplicateFindings(result.Findings)
	matcher.SortFindings(result.Findings)

	// Apply CVSS threshold filter.
	if opts.CVSSThreshold > 0 {
		result.Findings = matcher.FilterByCVSS(result.Findings, opts.CVSSThreshold)
	}

	// Phase 4: Finding validation and risk scoring.
	validated, suppressed := validation.ValidateAll(result.Findings, validation.DefaultOptions())
	result.Findings = validated
	if len(suppressed) > 0 {
	s.logger.Debug("validation suppressed findings",
		"total_suppressed", len(suppressed),
		"remaining", len(validated),
	)
	}
	result.RiskScore = scoring.CalculateRiskScore(result.Findings)
	result.Duration = time.Since(startTime)

	s.logger.Info("scan complete",
		"target", target.Raw,
		"duration", result.Duration,
		"open_ports", len(result.OpenPorts),
		"findings", len(result.Findings),
	)

	return result, nil
}

// scanPorts performs port scanning using the portscan package.
func (s *Scanner) scanPorts(ctx context.Context, ip string, ports []int) ([]models.Port, error) {
	scanner := portscan.New(s.cfg.Scan.Timeout, s.cfg.Scan.Workers, s.cfg.Scan.BannerSize)

	resultsChan := scanner.Scan(ctx, ip, ports)

	var results []portscan.ScanResult
	for r := range resultsChan {
		results = append(results, r)
	}

	// Convert to model ports.
	modelPorts := portscan.PortsToModels(results)

	// Sort by port number.
	sort.Slice(modelPorts, func(i, j int) bool {
		return modelPorts[i].Port < modelPorts[j].Port
	})

	return modelPorts, nil
}

// GenerateReport writes the scan result in the specified format to stdout.
func (s *Scanner) GenerateReport(result *models.ScanResult, format string, outputPath string) error {
	var fmtType report.Format
	switch format {
	case "console":
		fmtType = report.FormatConsole
	case "json":
		fmtType = report.FormatJSON
	case "html":
		fmtType = report.FormatHTML
	default:
		fmtType = report.FormatConsole
	}

	if outputPath != "" {
		s.logger.Info("writing report", "path", outputPath, "format", format)
		// File writing handled by CLI layer.
	}

	return report.Generate(os.Stdout, result, fmtType)
}

// GetSummary returns a one-line summary of the scan result.
func (s *Scanner) GetSummary(result *models.ScanResult) string {
	return result.Summary()
}
