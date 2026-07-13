// Package easm implements the External Attack Surface Management (EASM) pipeline.
// It discovers externally exposed assets, identifies services, and correlates
// vulnerabilities by reusing the existing SurfaceGuard scanner components.
package easm

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/easm/discovery"
	"github.com/evilhunter/surfaceguard/internal/fingerprint"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/internal/validation"
	"github.com/evilhunter/surfaceguard/internal/wordlist"
	"github.com/evilhunter/surfaceguard/pkg/cpe"
	"github.com/evilhunter/surfaceguard/pkg/models"
	"github.com/evilhunter/surfaceguard/pkg/portscan"
)

// ProgressFn is a callback for reporting EASM scan progress.
type ProgressFn func(step string, pct int, msg string)

// Orchestrator runs the full EASM discovery and vulnerability assessment pipeline.
type Orchestrator struct {
	cfg           *config.Config
	db            database.Database
	matcher       *matcher.Matcher
	fingerprinter *fingerprint.ServiceFingerprinter
	logger        *slog.Logger
	passiveProvs  []discovery.SubdomainProvider
	wordlistDir   string
}

// NewOrchestrator creates a new EASM orchestrator.
func NewOrchestrator(cfg *config.Config, db database.Database, m *matcher.Matcher, logger *slog.Logger) *Orchestrator {
	return &Orchestrator{
		cfg:           cfg,
		db:            db,
		matcher:       m,
		fingerprinter: fingerprint.NewServiceFingerprinter(cfg.Scan.Timeout),
		logger:        logger,
		passiveProvs:  discovery.DefaultPassiveProviders(),
		wordlistDir:   "assets/wordlists",
	}
}

// SetPassiveProviders allows overriding the default passive subdomain providers.
func (o *Orchestrator) SetPassiveProviders(provs []discovery.SubdomainProvider) {
	if provs != nil {
		o.passiveProvs = provs
	}
}

// EASMResult holds the complete output of an EASM scan.
type EASMResult struct {
	ScanID   int64
	Target   string
	Assets   []models.EASMAsset
	Services []models.EASMService
	Findings []models.EASMFinding
	Scan     models.EASMScan
}

// CreateScanRecord creates a new scan record in the database and returns its ID.
// This allows the API to return the scan ID immediately before running the pipeline.
func (o *Orchestrator) CreateScanRecord(ctx context.Context, req models.EASMScanRequest) (int64, error) {
	dbScan := &database.DBEASMScan{
		Target:      req.Target,
		ScanType:    string(req.ScanType),
		Wordlist:    string(req.Wordlist),
		Ports:       string(req.Ports),
		StartedAt:   time.Now().UTC().Format(time.RFC3339),
		Status:      "running",
		WorkerCount: req.Workers,
		Screenshots: boolToInt(req.Screenshots),
	}
	return o.db.EASMScan().Create(ctx, dbScan)
}

// Run executes the full EASM pipeline for a target. Creates a new scan record.
func (o *Orchestrator) Run(ctx context.Context, req models.EASMScanRequest, progress ProgressFn) (*EASMResult, error) {
	return o.runWithID(ctx, req, 0, progress)
}

// runWithID is the internal implementation that uses an existing scan ID.
func (o *Orchestrator) runWithID(ctx context.Context, req models.EASMScanRequest, existingScanID int64, progress ProgressFn) (*EASMResult, error) {
	if progress == nil {
		progress = func(string, int, string) {}
	}

	startTime := time.Now()
	result := &EASMResult{Target: req.Target}

	// Create or use existing scan record.
	var scanID int64
	if existingScanID > 0 {
		scanID = existingScanID
	} else {
		progress("init", 0, "Creating scan record...")
		dbScan := &database.DBEASMScan{
			Target:      req.Target,
			ScanType:    string(req.ScanType),
			Wordlist:    string(req.Wordlist),
			Ports:       string(req.Ports),
			StartedAt:   startTime.UTC().Format(time.RFC3339),
			Status:      "running",
			WorkerCount: req.Workers,
			Screenshots: boolToInt(req.Screenshots),
		}
		var err error
		scanID, err = o.db.EASMScan().Create(ctx, dbScan)
		if err != nil {
			return nil, fmt.Errorf("create scan: %w", err)
		}
	}
	result.ScanID = scanID

	// Step 1: Parse target.
	progress("parsing", 2, "Parsing target...")
	var scanTargets []string
	switch req.ScanType {
	case models.EASMScanDomain:
		scanTargets = []string{req.Target}
	case models.EASMScanCIDR:
		ips, err := discovery.ExpandCIDR(req.Target)
		if err != nil {
			o.failScan(ctx, scanID, fmt.Sprintf("invalid CIDR: %v", err))
			return nil, err
		}
		scanTargets = ips
	case models.EASMScanIP:
		scanTargets = []string{req.Target}
	default:
		o.failScan(ctx, scanID, "unknown scan type")
		return nil, fmt.Errorf("unknown scan type: %s", req.ScanType)
	}

	// Step 2: Discover subdomains (only for domain scans).
	var subdomainResults []discovery.SubdomainResult
	if req.ScanType == models.EASMScanDomain {
		// Detect wildcard DNS first.
		progress("wildcard", 3, "Checking for wildcard DNS...")
		wildcard, err := discovery.DetectWildcard(ctx, req.Target)
		if err != nil {
			o.logger.Warn("wildcard detection failed", "error", err)
		}

		// Passive discovery.
		progress("passive", 5, "Running passive subdomain discovery...")
		passiveResults, err := discovery.DiscoverPassive(ctx, req.Target, o.passiveProvs)
		if err != nil {
			o.logger.Warn("passive discovery failed", "error", err)
		}
		subdomainResults = append(subdomainResults, passiveResults...)
		progress("passive", 10, fmt.Sprintf("Found %d subdomains via passive sources", len(passiveResults)))

		// Active bruteforce (if requested).
		if string(req.Wordlist) != "" && string(req.Wordlist) != string(models.EASMWordlistPassive) {
			var words []string
			if string(req.Wordlist) == string(models.EASMWordlistCustom) && len(req.CustomWordlist) > 0 {
				words = req.CustomWordlist
			} else {
				// Load from managed wordlist system
				wlManager := wordlist.NewManager(".")
				var wlSize wordlist.WordlistSize
				switch string(req.Wordlist) {
				case "small":
					wlSize = wordlist.SizeSmall
				case "medium":
					wlSize = wordlist.SizeMedium
				case "large":
					wlSize = wordlist.SizeLarge
				default:
					wlSize = wordlist.SizeSmall
				}
				var err error
				words, err = wlManager.LoadWordlist(wlSize)
				if err != nil {
					o.logger.Warn("wordlist not loaded, skipping bruteforce", "size", wlSize, "error", err)
				}
			}

			if len(words) > 0 {
				progress("bruteforce", 15, fmt.Sprintf("DNS bruteforce with %d names...", len(words)))
				bruteResults, err := discovery.DNSBruteforce(ctx, req.Target, words, req.Workers)
				if err != nil {
					o.logger.Warn("dns bruteforce failed", "error", err)
				} else {
					subdomainResults = append(subdomainResults, bruteResults...)
					progress("bruteforce", 20, fmt.Sprintf("Found %d subdomains via bruteforce", len(bruteResults)))
				}
			}
		}

		// Filter wildcard results.
		if wildcard.Detected {
			progress("filter", 22, fmt.Sprintf("Filtering %d wildcard results...", len(wildcard.Addresses)))
			subdomainResults = discovery.FilterWildcardResults(subdomainResults, wildcard.Addresses)
		}

		// Deduplicate subdomains.
		subdomainResults = deduplicateSubdomains(subdomainResults)
		progress("subdomains", 25, fmt.Sprintf("Total unique subdomains: %d", len(subdomainResults)))

		// Add root domain to scan targets.
		scanTargets = append(scanTargets, req.Target)
		for _, sr := range subdomainResults {
			scanTargets = append(scanTargets, sr.Hostname)
		}
	}

	// Remove duplicates from scan targets.
	scanTargets = uniqueStrings(scanTargets)
	result.Scan.TotalAssets = len(scanTargets)

	// Step 3: DNS resolution + alive validation.
	progress("dns", 30, "Resolving DNS and validating alive hosts...")
	var aliveAssets []models.EASMAsset
	var assetDB []database.DBEASMAsset

	for i, target := range scanTargets {
		select {
		case <-ctx.Done():
			o.failScan(ctx, scanID, "cancelled")
			return nil, ctx.Err()
		default:
		}

		progress("dns", 30+percent(i, len(scanTargets), 30), fmt.Sprintf("Processing %s (%d/%d)...", target, i+1, len(scanTargets)))

		// Resolve DNS.
		dnsInfo := discovery.ResolveDNS(ctx, target)
		ip := ""
		if len(dnsInfo.A) > 0 {
			ip = dnsInfo.A[0]
		} else if len(dnsInfo.AAAA) > 0 {
			ip = dnsInfo.AAAA[0]
		}
		if ip == "" {
			continue // unresolvable
		}

		// Alive check.
		alive := false
		if req.ScanType == models.EASMScanDomain {
			ar := discovery.ValidateAlive(ctx, target, ip, 5*time.Second)
			alive = ar.IsAlive
		} else {
			alive = true // assume IP/CIDR targets are alive
		}

		asset := models.EASMAsset{
			Hostname:  target,
			IPAddress: ip,
			IsAlive:   alive,
			Source:    "passive",
			AssetType: "subdomain",
		}
		if len(dnsInfo.AAAA) > 0 {
			asset.IPv6Address = dnsInfo.AAAA[0]
		}
		if dnsInfo.CNAME != "" {
			asset.CNAME = dnsInfo.CNAME
		}

		if alive {
			aliveAssets = append(aliveAssets, asset)
		}

		dbAsset := database.DBEASMAsset{
			ScanID:    scanID,
			Hostname:  target,
			IPAddress: ip,
			IsAlive:   boolToInt(alive),
			Source:    "passive",
			AssetType: "subdomain",
		}
		assetDB = append(assetDB, dbAsset)
	}

	// Persist assets.
	if err := o.db.EASMAsset().BulkInsert(ctx, assetDB); err != nil {
		o.logger.Warn("failed to persist EASM assets", "error", err)
	}
	result.Assets = aliveAssets
	result.Scan.AliveAssets = len(aliveAssets)

	// Step 4: Port discovery + service fingerprinting.
	progress("ports", 60, fmt.Sprintf("Scanning ports on %d alive assets...", len(aliveAssets)))

	// Determine ports to scan.
	var portsToScan []int
	switch req.Ports {
	case models.EASMPortFast:
		portsToScan = portscan.TopPorts(100)
	case models.EASMPortFull:
		portsToScan = portscan.TopPorts(1000)
	default:
		if req.CustomPorts != "" {
			parsed, err := portscan.ParsePorts(req.CustomPorts)
			if err == nil {
				portsToScan = parsed
			}
		}
		if len(portsToScan) == 0 {
			portsToScan = portscan.TopPorts(100)
		}
	}

	var allServices []models.EASMService
	var serviceDB []database.DBEASMService
	var allFindings []models.EASMFinding
	var totalCVEs int
	sevCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}

	for ai, asset := range aliveAssets {
		select {
		case <-ctx.Done():
			o.failScan(ctx, scanID, "cancelled")
			return nil, ctx.Err()
		default:
		}

		basePct := 60 + percent(ai, len(aliveAssets), 35)
		progress("ports", basePct, fmt.Sprintf("Scanning %s (asset %d/%d)...", asset.Hostname, ai+1, len(aliveAssets)))

		// Port scan.
		scanner := portscan.New(o.cfg.Scan.Timeout, req.Workers, o.cfg.Scan.BannerSize)
		portResults := scanner.Scan(ctx, asset.IPAddress, portsToScan)

		var openPorts []models.Port
		for pr := range portResults {
			if pr.State == "open" {
				openPorts = append(openPorts, portscan.PortToModel(pr))
			}
		}

		// Get the DB asset ID for this host.
		dbAsset, err := o.db.EASMAsset().GetByScanAndHost(ctx, scanID, asset.Hostname)
		if err != nil {
			continue
		}

		for _, p := range openPorts {
			p.TargetIP = asset.IPAddress
			// Service fingerprinting (reuse existing engine).
			fp := o.fingerprinter.Fingerprint(p)

			service := models.EASMService{
				AssetID:    dbAsset.ID,
				Hostname:   asset.Hostname,
				Port:       fp.Port,
				Protocol:   fp.Protocol,
				Service:    fp.Service,
				Product:    fp.Product,
				Version:    fp.Version,
				Banner:     fp.Banner,
				Confidence: fp.Confidence,
			}

			// Resolve CPE URI: try fingerprint first, then service-name lookup.
			cpeURI := ""
			if len(fp.CPEs) > 0 {
				cpeURI = fp.CPEs[0].CPE23URI
			}
			if cpeURI == "" {
				cpeURI = resolveCPE(fp.Service, fp.Product, fp.Version, fp.Port)
			}
			if cpeURI == "" {
				o.logger.Debug("no CPE generated for service — CVE correlation skipped",
					"host", asset.Hostname, "port", fp.Port,
					"service", fp.Service, "product", fp.Product,
					"version", fp.Version, "confidence", fp.Confidence,
				)
			}
			service.CPE23URI = cpeURI

			allServices = append(allServices, service)
			serviceDB = append(serviceDB, database.DBEASMService{
				AssetID:    dbAsset.ID,
				Port:       fp.Port,
				Protocol:   fp.Protocol,
				Service:    fp.Service,
				Product:    fp.Product,
				Version:    fp.Version,
				Banner:     fp.Banner,
				Confidence: fp.Confidence,
				Technology: fp.Product,
				CPE23URI:   cpeURI,
			})
		}
	}

	// Persist services.
	if err := o.db.EASMService().BulkInsert(ctx, serviceDB); err != nil {
		o.logger.Warn("failed to persist EASM services", "error", err)
	}
	result.Services = allServices
	result.Scan.TotalServices = len(allServices)

	// Reload services from DB to get actual IDs for finding correlation.
	dbServices, _ := o.db.EASMService().ListByScan(ctx, scanID)
	svcIDMap := make(map[int64]int64) // assetID+port -> actual service ID
	for _, ds := range dbServices {
		key := ds.AssetID*100000 + int64(ds.Port)
		svcIDMap[key] = ds.ID
	}

	// Step 5: CVE correlation (reuse matcher).
	progress("cves", 96, fmt.Sprintf("Correlating %d services against CVE database...", len(allServices)))
	var findingDB []database.DBEASMFinding

	for _, svc := range allServices {
		if svc.CPE23URI == "" {
			continue
		}

		// Parse CPE from the URI — preserve the full CPE23URI so that
		// MatchPort's FindByCPE23URI lookup matches the exact DB entry.
		parts := strings.SplitN(svc.CPE23URI, ":", -1)
		if len(parts) < 6 {
			continue
		}
		cp := models.CPE{
			Part:     parts[2],
			Vendor:   parts[3],
			Product:  parts[4],
			Version:  parts[5],
			CPE23URI: svc.CPE23URI,
		}

		port := models.Port{
			Port:    svc.Port,
			Service: svc.Service,
			Product: svc.Product,
			Version: svc.Version,
			CPEs:    []models.CPE{cp},
		}

		// Use the matcher (same one used by the scanner).
		findings := o.matcher.MatchPort(ctx, svc.Hostname, "", port)

		// Phase 4: Validate findings — suppress weak matches.
		validated, _ := validation.ValidateAll(findings, validation.DefaultOptions())

		for _, f := range validated {
			sev := f.CVE.Severity
			if sev == "" {
				sev = "NONE"
			}
			sevCounts[sev]++
			totalCVEs++

			// Enrich with KEV/EPSS from the existing CVE data.
			isKEV := f.CVE.IsInKEV
			if isKEV {
				sevCounts["KEV"]++
			}

			// Resolve actual DB service ID from asset+port key.
			assetID := svc.AssetID
			svcKey := assetID*100000 + int64(svc.Port)
			svcID := svcIDMap[svcKey]
			cveFinding := models.EASMFinding{
				ServiceID:      svcID,
				ScanID:         scanID,
				CVEID:          f.CVE.ID,
				CVSSv3:         f.CVE.CVSSv3,
				CVSSv2:         f.CVE.CVSSv2,
				Severity:       sev,
				Description:    f.CVE.Description,
				IsKEV:          isKEV,
				EPSSScore:      f.CVE.EPSSScore,
				EPSSPercentile: f.CVE.EPSSPercentile,
				MatchedCPE:     svc.CPE23URI,
				MatchedVersion: svc.Version,
			}
			if svcID > 0 {
				allFindings = append(allFindings, cveFinding)
			}
		}
	}

	// Persist findings.
	if len(allFindings) > 0 {
		for _, fi := range allFindings {
			findingDB = append(findingDB, database.DBEASMFinding{
				ServiceID:      fi.ServiceID,
				ScanID:         scanID,
				CVEID:          fi.CVEID,
				CVSSv3:         fi.CVSSv3,
				CVSSv2:         fi.CVSSv2,
				Severity:       fi.Severity,
				Description:    fi.Description,
				IsKEV:          boolToInt(fi.IsKEV),
				EPSSScore:      fi.EPSSScore,
				EPSSPercentile: fi.EPSSPercentile,
				MatchedCPE:     fi.MatchedCPE,
				MatchedVersion: fi.MatchedVersion,
			})
		}
		if err := o.db.EASMFinding().BulkInsert(ctx, findingDB); err != nil {
			o.logger.Warn("failed to persist EASM findings", "error", err)
		}
	}
	result.Findings = allFindings
	result.Scan.TotalCVEs = totalCVEs

	// Build scan summary.
	scan := models.EASMScan{
		ID:            scanID,
		Target:        req.Target,
		ScanType:      req.ScanType,
		Wordlist:      req.Wordlist,
		Ports:         req.Ports,
		Status:        "completed",
		TotalAssets:   len(scanTargets),
		AliveAssets:   len(aliveAssets),
		TotalServices: len(allServices),
		TotalCVEs:     totalCVEs,
		CriticalCVEs:  sevCounts["CRITICAL"],
		HighCVEs:      sevCounts["HIGH"],
		MediumCVEs:    sevCounts["MEDIUM"],
		LowCVEs:       sevCounts["LOW"],
		KEVCVEs:       sevCounts["KEV"],
	}
	result.Scan = scan

	// Update scan record.
	durMs := time.Since(startTime).Milliseconds()
	completedAt := time.Now().UTC().Format(time.RFC3339)
	o.db.EASMScan().UpdateStatus(ctx, scanID, "completed", completedAt, durMs, "")
	o.db.EASMScan().UpdateStats(ctx, scanID, scan.TotalAssets, scan.AliveAssets, scan.TotalServices,
		scan.TotalCVEs, scan.CriticalCVEs, scan.HighCVEs, scan.MediumCVEs, scan.LowCVEs, scan.KEVCVEs, 0)

	progress("done", 100, fmt.Sprintf("EASM scan complete: %d assets, %d services, %d CVEs",
		scan.AliveAssets, scan.TotalServices, scan.TotalCVEs))

	return result, nil
}

// RunWithScanID runs the EASM pipeline using an existing scan record.
func (o *Orchestrator) RunWithScanID(ctx context.Context, req models.EASMScanRequest, scanID int64, progress ProgressFn) (*EASMResult, error) {
	return o.runWithID(ctx, req, scanID, progress)
}

func (o *Orchestrator) failScan(ctx context.Context, scanID int64, errMsg string) {
	now := time.Now().UTC().Format(time.RFC3339)
	o.db.EASMScan().UpdateStatus(ctx, scanID, "failed", now, 0, errMsg)
}

// ============================================================================
// CPE Resolution for EASM Services
// ============================================================================

// resolveCPE generates a CPE URI for a service using the shared cpe package.
// This ensures the EASM pipeline produces the same CPE URIs as the Vulnerability
// Assessment pipeline for the same detected software.
func resolveCPE(service, product, version string, port int) string {
	c := cpe.FromServiceOrProduct(service, product, version, port)
	if c == nil {
		return ""
	}
	return c.URI
}

// ============================================================================
// Helpers
// ============================================================================

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func percent(current, total, max int) int {
	if total == 0 {
		return 0
	}
	return (current * max) / total
}

func uniqueStrings(s []string) []string {
	seen := make(map[string]bool)
	var res []string
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			res = append(res, v)
		}
	}
	return res
}

func deduplicateSubdomains(results []discovery.SubdomainResult) []discovery.SubdomainResult {
	seen := make(map[string]bool)
	var res []discovery.SubdomainResult
	for _, r := range results {
		if !seen[r.Hostname] {
			seen[r.Hostname] = true
			res = append(res, r)
		}
	}
	return res
}

// ScannerVersion returns the current scanner version string.
var ScannerVersion = "1.0.0"

// DBVersion returns the database schema version string.
var DBVersion = "6"

// reportMu guards report serialization.
var reportMu sync.Mutex
