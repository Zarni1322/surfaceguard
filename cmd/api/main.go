package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/internal/assessment"
	"github.com/evilhunter/surfaceguard/internal/assessment/auth"
	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/easm"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/internal/wordlist"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

type scanRecord struct {
	Target     string    `json:"target"`
	StartedAt  time.Time `json:"started_at"`
	Duration   string    `json:"duration"`
	PortsFound int       `json:"ports_found"`
	Findings   int       `json:"findings"`
	RiskScore  float64   `json:"risk_score"`
	Status     string    `json:"status"`
	Critical   int       `json:"critical"`
	High       int       `json:"high"`
	Medium     int       `json:"medium"`
	Low        int       `json:"low"`
	Info       int       `json:"info"`
}

var scanHistory []scanRecord
var historyMu sync.Mutex

func main() {
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	mux := http.NewServeMux()
	handler := corsMiddleware(mux)

	// DB Info
	mux.HandleFunc("/api/db/info", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		db := openDB(cfg, ctx, w)
		if db == nil {
			return
		}
		defer db.Close()
		info, err := db.Info(ctx)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, info)
	})

	// Host Discovery — fast TCP ping sweep
	mux.HandleFunc("/api/host-discovery", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "target required", 400)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		// Parse subnet — single-pass IP generation
		_, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 50, "text": "Checking host..."}))
			flusher.Flush()
			alive := fastPing(target)
			hosts := []string{}
			if alive {
				hosts = append(hosts, target)
			}
			fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "hosts": hosts, "count": len(hosts)}))
			flusher.Flush()
			return
		}

		// Build IP list in a single pass
		start := time.Now()
		var ips []string
		for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			ips = append(ips, ip.String())
		}
		total := len(ips)

		// For subnets larger than /24, report progress in batches
		batchSize := 10
		if total > 256 {
			batchSize = 100
		}

		var mu sync.Mutex
		var wg sync.WaitGroup
		var hosts []string
		sem := make(chan struct{}, 500) // 500 concurrent probes
		done := 0
		lastReport := 0

		for _, ip := range ips {
			wg.Add(1)
			sem <- struct{}{}
			go func(ipStr string) {
				defer func() { <-sem; wg.Done() }()
				if fastPing(ipStr) {
					mu.Lock()
					hosts = append(hosts, ipStr)
					mu.Unlock()
				}
				mu.Lock()
				done++
				// Only send progress updates in batches to reduce flooding
				if done-lastReport >= batchSize || done == total {
					lastReport = done
					pct := done * 100 / total
					elapsed := time.Since(start).Seconds()
					eta := "—"
					if done > 0 && done < total {
						remaining := int((elapsed / float64(done)) * float64(total-done))
						eta = fmt.Sprintf("%ds", remaining)
					}
					fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": pct, "text": fmt.Sprintf("Scanning %d/%d hosts (ETA: %s)", done, total, eta)}))
					flusher.Flush()
				}
				mu.Unlock()
			}(ip)
		}
		wg.Wait()

		sort.Strings(hosts)
		elapsed := time.Since(start).Round(time.Millisecond).String()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "hosts": hosts, "count": len(hosts), "duration": elapsed}))
		flusher.Flush()
	})

	// CVE Discovery — scan target and return CVEs
	mux.HandleFunc("/api/cve-discovery", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		ports := r.URL.Query().Get("ports")
		selectedPlatform := r.URL.Query().Get("platform")
		if target == "" {
			http.Error(w, "target required", 400)
			return
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 5, "text": "Resolving target..."}))
		flusher.Flush()

		args := []string{"scan", target, "--format", "json", "--no-banner"}
		if ports != "" {
			args = append(args, "--ports", ports)
		}

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 20, "text": "Scanning ports..."}))
		flusher.Flush()

		output, err := runSurfaceGuard(args...)
		if err != nil {
			fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "error", "message": fmt.Sprintf("%v", err)}))
			flusher.Flush()
			return
		}

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 80, "text": "Processing results..."}))
		flusher.Flush()

		// Extract raw JSON from output (skip log lines)
		jsonStart := strings.Index(output, "{")
		if jsonStart < 0 {
			fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "error", "message": "no JSON in output"}))
			flusher.Flush()
			return
		}
		rawJSON := output[jsonStart:]

		// Parse for history tracking using raw message to avoid Duration issues
		var rawResult map[string]interface{}
		json.Unmarshal([]byte(rawJSON), &rawResult)

		// Send raw JSON to frontend
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 100, "text": "Scan complete"}))
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "scan": json.RawMessage(rawJSON)}))
		flusher.Flush()

		// Record to history (in-memory + persistent)
		started, _ := time.Parse(time.RFC3339, getStr(rawResult, "started_at"))
		portsFound := 0
		if portsRaw, ok := rawResult["open_ports"].([]interface{}); ok {
			portsFound = len(portsRaw)
		}
		riskScore := getFloat(rawResult, "risk_score")
		durStr := getStr(rawResult, "duration")

		// Extract severity counts from findings in the raw result.
		findingsCount := 0
		crit, hi, med, lo, inf := 0, 0, 0, 0, 0
		if findingsRaw, ok := rawResult["findings"].([]interface{}); ok {
			findingsCount = len(findingsRaw)
			for _, f := range findingsRaw {
				if fm, ok := f.(map[string]interface{}); ok {
					if cve, ok := fm["cve"].(map[string]interface{}); ok {
						sev, _ := cve["severity"].(string)
						switch sev {
						case "CRITICAL":
							crit++
						case "HIGH":
							hi++
						case "MEDIUM":
							med++
						case "LOW":
							lo++
						default:
							inf++
						}
					}
				}
			}
		}

		// Platform-aware confidence adjustment
		// Adjust findings confidence based on selected platform vs detected services.
		// This does NOT filter CVEs — only sets MatchConfidence and MatchEvidence.
		if selectedPlatform != "" && selectedPlatform != "None" && selectedPlatform != "Auto Detect" {
			if findingsRaw, ok := rawResult["findings"].([]interface{}); ok {
				for _, f := range findingsRaw {
					if fm, ok := f.(map[string]interface{}); ok {
						service := ""
						if p, ok := fm["port"].(map[string]interface{}); ok {
							service, _ = p["service"].(string)
						}
						platformMatch := checkPlatformMatch(service, selectedPlatform)
						conf := 90
						if !platformMatch {
							conf = 65
						}
						// Add platform info to the finding
						if existing, ok := fm["match_evidence"].(string); ok && existing != "" {
							fm["match_evidence"] = existing + "; " + platformEvidence(service, selectedPlatform, platformMatch)
						} else {
							fm["match_evidence"] = platformEvidence(service, selectedPlatform, platformMatch)
						}
						fm["match_confidence"] = float64(conf)
						// Update matched_cpe within finding if present
						if mc, ok := fm["matched_cpe"].(map[string]interface{}); ok {
							mc["platform_match"] = platformMatch
						}
					}
				}
			}
		}
		// Tag the result with the selected platform
		rawResult["selected_platform"] = selectedPlatform
		rawResult["platform"] = selectedPlatform

		// Persist to scan_history table synchronously (single source of truth)
		jsonBytes, _ := json.Marshal(rawResult)
		func() {
			db := openDB(cfg, context.Background(), nil)
			if db == nil {
				log.Printf("ERROR: openDB returned nil in scan persistence — database may be unreachable")
				return
			}
			defer db.Close()
			if _, err := db.ScanHistory().Insert(context.Background(), &database.DBScanHistory{
				Target:     target,
				StartedAt:  started.Format(time.RFC3339),
				Duration:   durStr,
				PortsFound: portsFound,
				Findings:   findingsCount,
				RiskScore:  riskScore,
				Status:     "completed",
				Critical:   crit,
				High:       hi,
				Medium:     med,
				Low:        lo,
				Info:       inf,
				ResultJSON: string(jsonBytes),
			}); err != nil {
				log.Printf("ERROR: failed to save scan history: %v", err)
			}
		}()

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 100, "text": "Scan complete"}))
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "scan": json.RawMessage(rawJSON)}))
		flusher.Flush()
	})

	// Scan History — reads from scan_history table (single source of truth)
	mux.HandleFunc("/api/scan-history", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		db := openDB(cfg, ctx, w)
		if db == nil {
			return
		}
		defer db.Close()
		if r.Method == "DELETE" {
			db.ScanHistory().DeleteAll(ctx)
			writeJSON(w, map[string]string{"status": "ok"})
			return
		}
		records, err := db.ScanHistory().List(ctx, 100)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		if records == nil {
			writeJSON(w, []database.DBScanHistory{})
		} else {
			writeJSON(w, records)
		}
	})

		// GET /api/scan-detail?id=X — single scan with full result
		mux.HandleFunc("/api/scan-detail", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			db := openDB(cfg, ctx, w)
			if db == nil { return }
			defer db.Close()
			idStr := r.URL.Query().Get("id")
			if idStr == "" { http.Error(w, "id required", 400); return }
			id, err := strconv.ParseInt(idStr, 10, 64)
			if err != nil { http.Error(w, "invalid id", 400); return }
			record, err := db.ScanHistory().GetByID(ctx, id)
			if err != nil { http.Error(w, "scan not found", 404); return }
			var result interface{} = map[string]interface{}{}
			if record.ResultJSON != "" && record.ResultJSON != "{}" {
				json.Unmarshal([]byte(record.ResultJSON), &result)
			}
			writeJSON(w, map[string]interface{}{
				"id": record.ID, "target": record.Target,
				"started_at": record.StartedAt, "duration": record.Duration,
				"ports_found": record.PortsFound, "findings": record.Findings,
				"risk_score": record.RiskScore, "status": record.Status,
				"critical": record.Critical, "high": record.High,
				"medium": record.Medium, "low": record.Low, "info": record.Info,
				"result": result,
			})
		})

	// Trigger update
	mux.HandleFunc("/api/update", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", 500)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 2, "text": "Starting update..."}))
		flusher.Flush()

		// Run update synchronously, capture real-time output
		cmd := exec.Command("./surfaceguard", "update")
		stdout, _ := cmd.StdoutPipe()
		cmd.Stderr = cmd.Stdout
		cmd.Start()

		// Use a custom scanner that splits on both \n and \r to get real-time progress.
		scanner := bufio.NewScanner(stdout)
		scanner.Split(scanLinesOrCarriageReturn)
		for scanner.Scan() {
			line := scanner.Text()
			// NVD progress: "  NVD: [=> ] 2% (page 76/3639, 521 inserted)"
			if strings.Contains(line, "NVD:") && strings.Contains(line, "%") {
				pct := 10
				text := "Downloading CVEs..."
				if idx := strings.Index(line, "%"); idx >= 2 {
					end := idx
					start := end
					for start > 0 && line[start-1] >= '0' && line[start-1] <= '9' {
						start--
					}
					if start < end {
						if p, err := strconv.Atoi(strings.TrimSpace(line[start:end])); err == nil && p > 0 {
							pct = p
						}
					}
				}
				if pIdx := strings.Index(line, "page "); pIdx >= 0 {
					if endIdx := strings.Index(line[pIdx:], "/"); endIdx >= 0 {
						pageNum := strings.TrimSpace(line[pIdx+5 : pIdx+endIdx])
						text = "Downloading CVEs... (page " + pageNum + ")"
					}
				}
				if pct > 95 {
					pct = 95
				}
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": pct, "text": text}))
				flusher.Flush()
			} else if strings.Contains(line, "KEV") && strings.Contains(line, "Already") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 96, "text": "KEV up to date"}))
				flusher.Flush()
			} else if strings.Contains(line, "EPSS") && strings.Contains(line, "inserted") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 98, "text": "EPSS scores downloaded"}))
				flusher.Flush()
			} else if strings.Contains(line, "NVD: Import complete") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 95, "text": line}))
				flusher.Flush()
			} else if strings.Contains(line, "Updating SQLite") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 98, "text": "Processing database..."}))
				flusher.Flush()
			}
		}
		cmd.Wait()

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 100, "text": "Update complete"}))
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "status": "completed"}))
		flusher.Flush()
	})

	// Report Generation — generates reports from stored scan data only.
	// Uses scan_id to load exactly one completed scan from the database.
	// Never calls runSurfaceGuard() — all formats are generated from stored result_json.
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		scanIDStr := r.URL.Query().Get("scan_id")
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "html"
		}
		if scanIDStr == "" {
			http.Error(w, "scan_id required", 400)
			return
		}
		scanID, err := strconv.ParseInt(scanIDStr, 10, 64)
		if err != nil {
			http.Error(w, "invalid scan_id", 400)
			return
		}

		ctx := r.Context()
		db := openDB(cfg, ctx, w)
		if db == nil {
			return
		}
		defer db.Close()

		record, err := db.ScanHistory().GetByID(ctx, scanID)
		if err != nil {
			log.Printf("ERROR: scan_id=%d not found in scan_history: %v", scanID, err)
			http.Error(w, "scan not found", 404)
			return
		}
		if record.ResultJSON == "" || record.ResultJSON == "{}" {
			http.Error(w, "no scan data stored for this record", 404)
			return
		}

		var result map[string]interface{}
		if err := json.Unmarshal([]byte(record.ResultJSON), &result); err != nil {
			http.Error(w, fmt.Sprintf("failed to parse scan data: %v", err), 500)
			return
		}

		switch format {
		case "json":
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.json\"", record.Target))
			w.Write([]byte(record.ResultJSON))

		case "html":
			html := generateHTMLReport(record.Target, record.StartedAt, record.Duration,
				result, record.PortsFound, record.Findings,
				record.Critical, record.High, record.Medium, record.Low, record.Info, record.RiskScore)
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.html\"", record.Target))
			w.Write([]byte(html))

		case "csv", "xlsx":
			csv := "Host,Port,Service,Version,CVE,CVSS,Severity,KEV,EPSS\n"
			if findingsRaw, ok := result["findings"].([]interface{}); ok {
				for _, f := range findingsRaw {
					if fm, ok := f.(map[string]interface{}); ok {
						host, _ := fm["host"].(string)
						port := 0
						service := ""
						version := ""
						if p, ok := fm["port"].(map[string]interface{}); ok {
							port = int(getFloat(p, "port"))
							service, _ = p["service"].(string)
							version, _ = p["version"].(string)
						}
						cveID := ""
						cvss := 0.0
						severity := ""
						kev := false
						epss := 0.0
						if cve, ok := fm["cve"].(map[string]interface{}); ok {
							cveID, _ = cve["id"].(string)
							cvss = getFloat(cve, "cvss_v3")
							if cvss == 0 { cvss = getFloat(cve, "cvss_v2") }
							severity, _ = cve["severity"].(string)
							kev, _ = cve["is_in_kev"].(bool)
							if s, ok := cve["epss_score"].(float64); ok { epss = s }
						}
						csv += fmt.Sprintf("%s,%d,%s,%s,%s,%.1f,%s,%v,%.4f\n", host, port, service, version, cveID, cvss, severity, kev, epss)
					}
				}
			}
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.csv\"", record.Target))
			w.Write([]byte(csv))

		case "pdf":
			// Generate a real PDF placeholder (Content-Type application/pdf).
			// For now, serve HTML with .pdf extension since a PDF library is not included.
			html := generateHTMLReport(record.Target, record.StartedAt, record.Duration,
				result, record.PortsFound, record.Findings,
				record.Critical, record.High, record.Medium, record.Low, record.Info, record.RiskScore)
			w.Header().Set("Content-Type", "application/pdf")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.pdf\"", record.Target))
			w.Write([]byte(html))

		default:
			http.Error(w, fmt.Sprintf("unsupported format: %s", format), 400)
		}
	})
	// Settings — get current config
	mux.HandleFunc("/api/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" {
			// Settings save — parse and update config file
			var updates map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
				http.Error(w, err.Error(), 400)
				return
			}
			// Apply updates to config file
			applyConfigUpdates(cfg, updates)
			writeJSON(w, map[string]string{"status": "saved"})
			return
		}

		// GET — return current config
		writeJSON(w, map[string]interface{}{
			"scan": map[string]interface{}{
				"workers":     cfg.Scan.Workers,
				"timeout":     cfg.Scan.Timeout.String(),
				"banner_size": cfg.Scan.BannerSize,
				"fingerprint": cfg.Scan.Fingerprint,
				"rate_limit":  cfg.Scan.RateLimit,
			},
			"database": map[string]interface{}{
				"path": cfg.Database.Path,
			},
			"update": map[string]interface{}{
				"enabled":      cfg.Update.Enabled,
				"http_timeout": cfg.Update.HTTPTimeout,
				"retry_count":  cfg.Update.RetryCount,
				"incremental":  cfg.Update.Incremental,
			},
			"logging": map[string]interface{}{
				"level":  cfg.Logging.Level,
				"format": cfg.Logging.Format,
			},
			"report": map[string]interface{}{
				"default_format": cfg.Report.DefaultFormat,
				"cvss_threshold": cfg.Report.CVSSThreshold,
			},
			"show_banner": cfg.ShowBanner,
		})
	})

	// System info
	mux.HandleFunc("/api/system", func(w http.ResponseWriter, r *http.Request) {
		version := "1.0.0"
		dbInfo := getDBInfo(cfg, r.Context())
		feedStatus := "Up-to-date"
		lastUpdate := ""
		if dbInfo != nil {
			if !dbInfo.LastUpdated.IsZero() && dbInfo.LastUpdated.Year() > 1 {
				lastUpdate = dbInfo.LastUpdated.Format(time.RFC3339)
			}
		}
		writeJSON(w, map[string]interface{}{
			"version":     version,
			"build_date":  "2026-07-07",
			"db_version":  fmt.Sprintf("%d", 3),
			"feed_status": feedStatus,
			"last_update": lastUpdate,
			"cve_count":   getVal(dbInfo, "cve_count"),
			"kev_count":   getVal(dbInfo, "kev_count"),
			"epss_count":  getVal(dbInfo, "epss_count"),
		})
	})

	// Assessment API routes
	mux.HandleFunc("/api/credentials/profiles", handleCredProfiles)
	mux.HandleFunc("/api/credentials/profile", handleCredProfile)
	mux.HandleFunc("/api/credentials/validate", handleValidateCredentials)
	mux.HandleFunc("/api/assessment/scan", handleAssessmentScan)
	mux.HandleFunc("/api/assessment/scan/progress", handleAssessmentScanSSE)
	mux.HandleFunc("/api/assessment/history", handleAssessmentHistory)
	mux.HandleFunc("/api/assessment/history/delete", handleAssessmentHistoryDelete)
	mux.HandleFunc("/api/assets", handleAssets)
	mux.HandleFunc("/api/asset", handleAsset)
	mux.HandleFunc("/api/easm/scan", handleEASMScan)
	mux.HandleFunc("/api/easm/scan/progress", handleEASMScanProgress)
	mux.HandleFunc("/api/easm/scans", handleEASMScanList)
	mux.HandleFunc("/api/easm/scans/delete", handleEASMScansDelete)
	mux.HandleFunc("/api/easm/assets", handleEASMAssets)
	mux.HandleFunc("/api/easm/findings", handleEASMFindings)
	mux.HandleFunc("/api/easm/findings/detail", handleEASMFindingsDetail)
	mux.HandleFunc("/api/easm/asset/detail", handleEASMAssetDetail)
	mux.HandleFunc("/api/easm/dashboard", handleEASMDashboardStats)
	mux.HandleFunc("/api/wordlists/status", handleWordlistStatus)
	mux.HandleFunc("/api/wordlists/download", handleWordlistDownload)
	mux.HandleFunc("/api/wordlists/verify", handleWordlistVerify)
	mux.HandleFunc("/api/wordlists/delete", handleWordlistDelete)
	mux.HandleFunc("/api/wordlists/check-update", handleWordlistCheckUpdate)

	addr := ":8080"
	fmt.Printf("SurfaceGuard API server on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// Wordlist Manager
var wordlistManager = wordlist.NewManager(".")

func handleWordlistStatus(w http.ResponseWriter, r *http.Request) {
	m := wordlistManager
	meta, _ := m.LoadMetadata()
	installed := m.IsInstalled()

	smallCount, mediumCount, largeCount := 0, 0, 0
	if installed {
		smallCount = m.WordlistCount(wordlist.SizeSmall)
		mediumCount = m.WordlistCount(wordlist.SizeMedium)
		largeCount = m.WordlistCount(wordlist.SizeLarge)
	}
	needsUpdate := meta.LatestVersion != "" && meta.LatestVersion != meta.CurrentVersion
	writeJSON(w, map[string]interface{}{
		"installed": installed, "status": m.Status(),
		"current_version": meta.CurrentVersion, "latest_version": meta.LatestVersion,
		"needs_update": needsUpdate,
		"last_updated": meta.LastUpdated, "wordlists": meta.Wordlists,
		"counts": map[string]int{"small": smallCount, "medium": mediumCount, "large": largeCount},
	})
}

func handleWordlistDownload(w http.ResponseWriter, r *http.Request) {
	m := wordlistManager
	count, err := m.DownloadAll(context.Background(), nil)
	if err != nil && count == 0 {
		writeJSON(w, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "downloaded": count})
}

func handleWordlistVerify(w http.ResponseWriter, r *http.Request) {
	results, err := wordlistManager.VerifyIntegrity()
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	allOK := true
	for _, ok := range results {
		if !ok {
			allOK = false
			break
		}
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "valid": allOK, "results": results})
}

func handleWordlistDelete(w http.ResponseWriter, r *http.Request) {
	if err := wordlistManager.DeleteCache(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"status": "ok"})
}

func handleWordlistCheckUpdate(w http.ResponseWriter, r *http.Request) {
	needsUpdate, latestVersion, err := wordlistManager.CheckForUpdates(context.Background())
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "failed", "error": err.Error()})
		return
	}
	meta, _ := wordlistManager.LoadMetadata()
	writeJSON(w, map[string]interface{}{
		"status": "ok", "needs_update": needsUpdate,
		"current_version": meta.CurrentVersion, "latest_version": latestVersion,
	})
}

func fastPing(ip string) bool {
	// TCP connect to common ports — exit early on first success.
	// Uses parallel probes to all ports with a shared 800ms deadline.
	ch := make(chan bool, 5)
	ctx, cancel := context.WithTimeout(context.Background(), 800*time.Millisecond)
	defer cancel()

	ports := []int{80, 443, 22}
	for _, port := range ports {
		go func(p int) {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, p), 400*time.Millisecond)
			if err == nil {
				conn.Close()
				select {
				case ch <- true:
				default:
				}
				return
			}
			select {
			case ch <- false:
			default:
			}
		}(port)
	}

	// Wait for first success or all failures
	for i := 0; i < len(ports); i++ {
		select {
		case result := <-ch:
			if result {
				return true
			}
		case <-ctx.Done():
			return false
		}
	}
	return false
}

func pingHost(ip string) bool {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	err := cmd.Run()
	return err == nil
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type findingRow struct {
	host     string
	port     int
	service  string
	version  string
	cveID    string
	cvss     float64
	severity string
	kev      bool
	epss     float64
}

func getDBInfo(cfg *config.Config, ctx2 context.Context) *models.DatabaseInfo {
	ctx, cancel := context.WithTimeout(ctx2, 3*time.Second)
	defer cancel()
	db := openDB(cfg, ctx, nil)
	if db == nil {
		return nil
	}
	defer db.Close()
	info, err := db.Info(ctx)
	if err != nil {
		return nil
	}
	return info
}

func getVal(info *models.DatabaseInfo, key string) int {
	if info == nil {
		return 0
	}
	switch key {
	case "cve_count":
		return info.CVECount
	case "kev_count":
		return info.KEVCount
	case "epss_count":
		return info.EPSSCount
	}
	return 0
}

func applyConfigUpdates(cfg *config.Config, updates map[string]interface{}) {
	scan, _ := updates["scan"].(map[string]interface{})
	if scan != nil {
		if v, ok := scan["workers"].(float64); ok {
			cfg.Scan.Workers = int(v)
		}
		if v, ok := scan["timeout"].(string); ok {
			if d, e := time.ParseDuration(v); e == nil {
				cfg.Scan.Timeout = d
			}
		}
	}
	logging, _ := updates["logging"].(map[string]interface{})
	if logging != nil {
		if v, ok := logging["level"].(string); ok {
			cfg.Logging.Level = v
		}
		if v, ok := logging["format"].(string); ok {
			cfg.Logging.Format = v
		}
	}
	report, _ := updates["report"].(map[string]interface{})
	if report != nil {
		if v, ok := report["cvss_threshold"].(float64); ok {
			cfg.Report.CVSSThreshold = v
		}
	}
}

func getFindings(result map[string]interface{}) []findingRow {
	var rows []findingRow
	findings, _ := result["findings"].([]interface{})
	for _, f := range findings {
		fm, _ := f.(map[string]interface{})
		if fm == nil {
			continue
		}
		host, _ := fm["host"].(string)
		port, _ := fm["port"].(map[string]interface{})
		cve, _ := fm["cve"].(map[string]interface{})

		portNum := 0
		service := ""
		version := ""
		if port != nil {
			portNum = int(getFloat(port, "port"))
			service, _ = port["service"].(string)
			version, _ = port["version"].(string)
		}

		cveID := ""
		cvss := 0.0
		severity := ""
		kev := false
		epss := 0.0
		if cve != nil {
			cveID, _ = cve["id"].(string)
			cvss = getFloat(cve, "cvss_v3")
			if cvss == 0 {
				cvss = getFloat(cve, "cvss_v2")
			}
			severity, _ = cve["severity"].(string)
			kev, _ = cve["is_in_kev"].(bool)
			if s, ok := cve["epss_score"].(float64); ok {
				epss = s
			}
		}

		rows = append(rows, findingRow{host, portNum, service, version, cveID, cvss, severity, kev, epss})
	}
	return rows
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil {
		return 0
	}
	if v, ok := m[key]; ok && v != nil {
		switch n := v.(type) {
		case float64:
			return n
		case int:
			return float64(n)
		case int64:
			return float64(n)
		}
	}
	return 0
}

// generateHTMLReport builds an HTML report from stored scan data.
// All data comes from the database — no scan is executed.
func generateHTMLReport(target, startedAt, duration string, result map[string]interface{}, portsFound, findings, crit, hi, med, lo, inf int, riskScore float64) string {
	html := "<!DOCTYPE html><html><head><meta charset=\"UTF-8\">"
	html += "<title>SurfaceGuard Report - " + htmlEsc(target) + "</title>"
	html += "<style>body{font-family:sans-serif;margin:40px;background:#0B1220;color:#F8FAFC}"
	html += "h1{color:#3B82F6}.meta{color:#94A3B8;font-size:14px}.sev{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold;margin:1px}"
	html += ".crit{background:#EF4444;color:#fff}.high{background:#F59E0B;color:#000}.med{background:#3B82F6;color:#fff}.low{background:#22C55E;color:#000}.info{background:#64748B;color:#fff}"
	html += "table{width:100%;border-collapse:collapse;margin-top:20px}"
	html += "th,td{text-align:left;padding:8px 12px;border-bottom:1px solid #1E293B;font-size:13px}"
	html += "th{color:#64748B;font-weight:600}td{color:#F8FAFC}.cve-link{color:#3B82F6;text-decoration:none}"
	html += ".cve-link:hover{text-decoration:underline}</style></head><body>"
	html += "<h1>SurfaceGuard Report</h1>"
	html += "<div class=\"meta\">"
	if target != "" { html += "<p><strong>Target:</strong> " + htmlEsc(target) + "</p>" }
	if startedAt != "" { html += "<p><strong>Started:</strong> " + htmlEsc(startedAt) + "</p>" }
	if duration != "" { html += "<p><strong>Duration:</strong> " + htmlEsc(duration) + "</p>" }
	html += "<p><strong>Open Ports:</strong> " + fmt.Sprint(portsFound) + "</p>"
	html += "<p><strong>Total CVEs:</strong> " + fmt.Sprint(findings) + "</p>"
	if riskScore > 0 {
		html += "<p><strong>Risk Score:</strong> " + fmt.Sprintf("%.1f", riskScore) + "/100</p>"
	}
	if findings > 0 {
		html += "<p>"
		if crit > 0 { html += "<span class=\"sev crit\">CRITICAL " + fmt.Sprint(crit) + "</span> " }
		if hi > 0 { html += "<span class=\"sev high\">HIGH " + fmt.Sprint(hi) + "</span> " }
		if med > 0 { html += "<span class=\"sev med\">MEDIUM " + fmt.Sprint(med) + "</span> " }
		if lo > 0 { html += "<span class=\"sev low\">LOW " + fmt.Sprint(lo) + "</span> " }
		if inf > 0 { html += "<span class=\"sev info\">INFO " + fmt.Sprint(inf) + "</span> " }
		html += "</p>"
	}
	html += "</div>"

	if findings > 0 {
		html += "<table><thead><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>Port</th><th>Service</th><th>Description</th></tr></thead><tbody>"
		if findingsRaw, ok := result["findings"].([]interface{}); ok {
			for _, f := range findingsRaw {
				if fm, ok := f.(map[string]interface{}); ok {
					cveID := ""
					cvss := 0.0
					severity := ""
					desc := ""
					port := 0
					service := ""
					if cve, ok := fm["cve"].(map[string]interface{}); ok {
						cveID, _ = cve["id"].(string)
						cvss = getFloat(cve, "cvss_v3")
						if cvss == 0 { cvss = getFloat(cve, "cvss_v2") }
						severity, _ = cve["severity"].(string)
						desc, _ = cve["description"].(string)
						if len(desc) > 120 { desc = desc[:120] + "..." }
					}
					if p, ok := fm["port"].(map[string]interface{}); ok {
						port = int(getFloat(p, "port"))
						service, _ = p["service"].(string)
					}
					sevClass := "info"
					switch severity {
					case "CRITICAL": sevClass = "crit"
					case "HIGH": sevClass = "high"
					case "MEDIUM": sevClass = "med"
					case "LOW": sevClass = "low"
					}
					html += "<tr>"
					if cveID != "" {
						html += "<td><a class=\"cve-link\" href=\"https://nvd.nist.gov/vuln/detail/" + htmlEsc(cveID) + "\" target=\"_blank\">" + htmlEsc(cveID) + "</a></td>"
					} else {
						html += "<td>—</td>"
					}
					html += "<td><span class=\"sev " + sevClass + "\">" + htmlEsc(severity) + "</span></td>"
					html += "<td>" + fmt.Sprintf("%.1f", cvss) + "</td>"
					html += "<td>" + fmt.Sprint(port) + "</td>"
					html += "<td>" + htmlEsc(service) + "</td>"
					html += "<td>" + htmlEsc(desc) + "</td>"
					html += "</tr>"
				}
			}
		}
		html += "</tbody></table>"
	} else {
		html += "<p style=\"color:#64748B;margin-top:20px\">No vulnerabilities found.</p>"
	}
	html += "</body></html>"
	return html
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}


// checkPlatformMatch returns true if the detected service is expected
// on the selected platform. This is a heuristic used to adjust confidence,
// never to filter or remove findings.
func checkPlatformMatch(service, platform string) bool {
	switch platform {
	case "Linux":
		// Services commonly found on Linux
		switch service {
		case "ssh", "http", "https", "ftp", "smtp", "dns",
			"mysql", "postgresql", "redis", "mongodb",
			"pop3", "imap", "rpcbind", "nfs":
			return true
		}
		return false
	case "Windows":
		// Services commonly found on Windows
		switch service {
		case "msrpc", "smb", "winrm", "mssql", "rdp",
			"http", "https":
			return true
		}
		return false
	default:
		// Unknown platform — assume match
		return true
	}
}

// platformEvidence returns a human-readable string describing platform match status.
func platformEvidence(service, platform string, matched bool) string {
	if matched {
		return fmt.Sprintf("Platform verified (%s)", platform)
	}
	return fmt.Sprintf("Platform mismatch (%s selected, %s service detected)", platform, service)
}

func runSurfaceGuard(args ...string) (string, error) {
	cmd := exec.Command("./surfaceguard", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %s", err, string(output))
	}
	return string(output), nil
}

// scanLinesOrCarriageReturn is a bufio.SplitFunc that splits on both \n and \r.
// Required to read real-time NVD download progress (uses \r for in-place updates).
func scanLinesOrCarriageReturn(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i := 0; i < len(data); i++ {
		if data[i] == '\n' || data[i] == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func openDB(cfg *config.Config, ctx context.Context, w http.ResponseWriter) database.Database {
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return nil
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return nil
	}
	return db
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonStr(v interface{}) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ============================================================================
// Assessment API Handlers
// ============================================================================

var assessEngine *assessment.Engine

func initAssessmentEngine(cfg *config.Config, ctx context.Context) *assessment.Engine {
	if assessEngine != nil {
		return assessEngine
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return nil
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return nil
	}
	m := matcher.New(db)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	assessEngine = assessment.NewEngine(&cfg.Assessment, db, m, logger)
	return assessEngine
}

// Credential Profiles
func handleCredProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	switch r.Method {
	case "GET":
		profiles, err := eng.ListProfiles(ctx)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, profiles)

	case "POST":
		var req struct {
			Name       string `json:"name"`
			Protocol   string `json:"protocol"`
			Host       string `json:"host"`
			Port       int    `json:"port"`
			Username   string `json:"username"`
			AuthMethod string `json:"auth_method"`
			Password   string `json:"password,omitempty"`
			PrivateKey string `json:"private_key,omitempty"`
			Passphrase string `json:"passphrase,omitempty"`
			Community  string `json:"community,omitempty"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		profile := &auth.Profile{
			Name:       req.Name,
			Protocol:   models.Protocol(req.Protocol),
			Host:       req.Host,
			Port:       req.Port,
			Username:   req.Username,
			AuthMethod: req.AuthMethod,
			Password:   req.Password,
			PrivateKey: req.PrivateKey,
			Community:  req.Community,
		}
		id, err := eng.CreateProfile(ctx, profile)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		writeJSON(w, map[string]int64{"id": id})

	default:
		http.Error(w, "method not allowed", 405)
	}
}

func handleCredProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	if r.Method == "DELETE" {
		id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
		if err != nil {
			http.Error(w, "invalid id", 400)
			return
		}
		if err := eng.DeleteProfile(ctx, id); err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		writeJSON(w, map[string]string{"status": "deleted"})
		return
	}
	http.Error(w, "method not allowed", 405)
}

// Credential Validation (Test Connection)
func handleValidateCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	var req struct {
		ProfileID int64 `json:"profile_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	result, err := eng.ValidateCredentials(ctx, req.ProfileID)
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "FAILED", "error": err.Error()})
		return
	}
	writeJSON(w, result)
}

// Authenticated Assessment
func handleAssessmentScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	profileID, err := strconv.ParseInt(r.URL.Query().Get("profile_id"), 10, 64)
	if err != nil {
		http.Error(w, "profile_id required", 400)
		return
	}

	result, err := eng.RunAssessment(ctx, profileID)
	if err != nil {
		http.Error(w, fmt.Sprintf("assessment failed: %v", err), 500)
		return
	}
	writeJSON(w, result)
}

// handleAssessmentScanSSE streams assessment progress via Server-Sent Events.
func handleAssessmentScanSSE(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	profileID, err := strconv.ParseInt(r.URL.Query().Get("profile_id"), 10, 64)
	if err != nil {
		http.Error(w, "profile_id required", 400)
		return
	}

	// Set SSE headers.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	// Send a progress event as a JSON string over SSE.
	sendProgress := func(step string, pct float64, msg string) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, _ := json.Marshal(map[string]interface{}{
			"step":     step,
			"progress": pct,
			"message":  msg,
		})
		fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
		flusher.Flush()
	}

	// Send initial event.
	sendProgress("starting", 0, "Starting assessment...")

	// Run the assessment with progress in the same goroutine (it's async to
	// the HTTP handler because we stream). The SSE connection stays open.
	result, err := eng.RunAssessmentWithProgress(ctx, profileID, sendProgress)
	if err != nil {
		errData, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errData)
		flusher.Flush()
		return
	}

	// Send final result as a "result" event.
	resultData, _ := json.Marshal(result)
	fmt.Fprintf(w, "event: result\ndata: %s\n\n", resultData)
	flusher.Flush()
}

// Assessment History
func handleAssessmentHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 20
	if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
		limit = l
	}

	results, err := eng.ListHistory(ctx, limit)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, results)
}

// Asset Inventory
func handleAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	eng := initAssessmentEngine(loadConfigOrPanic(), ctx)
	if eng == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	db := openDB(loadConfigOrPanic(), ctx, w)
	if db == nil {
		return
	}
	assets, err := db.AssetInventory().List(ctx)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Convert DB types to domain models (with JSON tags) before returning.
	domainAssets := make([]models.AssetInfo, 0, len(assets))
	for _, a := range assets {
		lastSeen, _ := time.Parse(time.RFC3339, a.LastSeen)
		lastScan, _ := time.Parse(time.RFC3339, a.LastScan)
		domainAssets = append(domainAssets, models.AssetInfo{
			ID:            a.ID,
			Hostname:      a.Hostname,
			IP:            a.IP,
			OS:            a.OS,
			Distro:        a.Distro,
			KernelVersion: a.KernelVersion,
			Architecture:  a.Architecture,
			AssetType:     a.AssetType,
			RiskScore:     a.RiskScore,
			LastSeen:      lastSeen,
			LastScan:      lastScan,
		})
	}
	writeJSON(w, domainAssets)
}

func handleAsset(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id, err := strconv.ParseInt(r.URL.Query().Get("id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid id", 400)
		return
	}

	db := openDB(loadConfigOrPanic(), ctx, w)
	if db == nil {
		return
	}

	asset, err := db.AssetInventory().Get(ctx, id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}

	// Gather packages, software, findings.
	packages, _ := db.InstalledPackage().ListByAsset(ctx, id)
	software, _ := db.InstalledSoftware().ListByAsset(ctx, id)

	lastSeen, _ := time.Parse(time.RFC3339, asset.LastSeen)
	lastScan, _ := time.Parse(time.RFC3339, asset.LastScan)
	domainAsset := models.AssetInfo{
		ID:            asset.ID,
		Hostname:      asset.Hostname,
		IP:            asset.IP,
		OS:            asset.OS,
		Distro:        asset.Distro,
		KernelVersion: asset.KernelVersion,
		Architecture:  asset.Architecture,
		AssetType:     asset.AssetType,
		RiskScore:     asset.RiskScore,
		LastSeen:      lastSeen,
		LastScan:      lastScan,
	}

	// Convert packages and software to domain models too
	domainPkgs := make([]models.InstalledPackage, len(packages))
	for i, p := range packages {
		domainPkgs[i] = models.InstalledPackage{
			Name: p.Name, Version: p.Version, Arch: p.Arch,
			CPE23URI: p.CPE23URI, Status: p.Status,
		}
	}
	domainSW := make([]models.InstalledSoftware, len(software))
	for i, s := range software {
		domainSW[i] = models.InstalledSoftware{
			Name: s.Name, Version: s.Version, Vendor: s.Vendor,
			InstallDate: s.InstallDate, CPE23URI: s.CPE23URI,
		}
	}

	writeJSON(w, map[string]interface{}{
		"asset":    domainAsset,
		"packages": domainPkgs,
		"software": domainSW,
	})
}

func loadConfigOrPanic() *config.Config {
	cfg, err := config.LoadConfig("")
	if err != nil {
		log.Printf("config: %v", err)
	}
	return cfg
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(200)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ============================================================================
// EASM API Handlers
// ============================================================================

var easmOrchestrator *easm.Orchestrator
var easmOrchestratorMu sync.Mutex

func initEASMEngine(cfg *config.Config, ctx context.Context) *easm.Orchestrator {
	easmOrchestratorMu.Lock()
	defer easmOrchestratorMu.Unlock()
	if easmOrchestrator != nil {
		return easmOrchestrator
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		return nil
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		return nil
	}
	m := matcher.New(db)
	easmOrchestrator = easm.NewOrchestrator(cfg, db, m, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	return easmOrchestrator
}

func handleEASMScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	cfg := loadConfigOrPanic()
	orch := initEASMEngine(cfg, ctx)
	if orch == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	var req models.EASMScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", 400)
		return
	}
	if req.Workers <= 0 {
		req.Workers = cfg.EASM.Workers
	}
	if req.Ports == "" {
		req.Ports = models.EASMPortFast
	}

	// Create the scan record immediately so we always have a valid scan ID.
	scanID, err := orch.CreateScanRecord(ctx, req)
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "failed", "error": fmt.Sprintf("create scan: %v", err)})
		return
	}

	// Run the full pipeline in background using the pre-created scan ID.
	go func(sid int64) {
		bgCtx := context.Background()
		orch.RunWithScanID(bgCtx, req, sid, nil)
	}(scanID)

	// Return immediately with the scan ID so the frontend can navigate to the detail page.
	writeJSON(w, map[string]interface{}{
		"status":  "running",
		"scan_id": scanID,
		"scan": map[string]interface{}{
			"id": scanID, "target": req.Target,
			"scan_type": req.ScanType, "wordlist": req.Wordlist,
			"ports": req.Ports, "status": "running",
			"total_assets": 0, "alive_assets": 0,
			"total_services": 0, "total_cves": 0,
		},
	})
}

func handleEASMScanProgress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != "POST" {
		http.Error(w, "method not allowed", 405)
		return
	}
	cfg := loadConfigOrPanic()
	orch := initEASMEngine(cfg, ctx)
	if orch == nil {
		http.Error(w, "engine init failed", 500)
		return
	}

	var req models.EASMScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	if req.Target == "" {
		http.Error(w, "target is required", 400)
		return
	}
	if req.Workers <= 0 {
		req.Workers = cfg.EASM.Workers
	}
	if req.Ports == "" {
		req.Ports = models.EASMPortFast
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", 500)
		return
	}

	sendProgress := func(step string, pct int, msg string) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		data, _ := json.Marshal(models.EASMScanProgress{Step: step, Progress: pct, Message: msg})
		fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
		flusher.Flush()
	}

	sendProgress("starting", 0, "Starting EASM scan...")
	result, err := orch.Run(ctx, req, sendProgress)
	if err != nil {
		errData, _ := json.Marshal(map[string]string{"error": err.Error()})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errData)
		flusher.Flush()
		return
	}
	resultData, _ := json.Marshal(map[string]interface{}{"status": "completed", "scan": result.Scan})
	fmt.Fprintf(w, "event: result\ndata: %s\n\n", resultData)
	flusher.Flush()
}

func handleEASMScanList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()
	scans, err := db.EASMScan().List(ctx, 50)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	result := make([]models.EASMScan, 0, len(scans))
	for _, s := range scans {
		result = append(result, *dbEASMScanToModel(&s))
	}
	writeJSON(w, result)
}

func handleEASMAssets(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	scanID, err := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	if err != nil {
		http.Error(w, "scan_id required", 400)
		return
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()
	assets, err := db.EASMAsset().ListByScan(ctx, scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var result []models.EASMAsset
	for _, a := range assets {
		result = append(result, *dbEASMAssetToModel(&a))
	}
	writeJSON(w, result)
}

func handleEASMFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	scanID, err := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	if err != nil {
		http.Error(w, "scan_id required", 400)
		return
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()
	findings, err := db.EASMFinding().ListByScan(ctx, scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	var result []models.EASMFinding
	for _, f := range findings {
		result = append(result, *dbEASMFindingToModel(&f))
	}
	writeJSON(w, result)
}

func handleEASMFindingsDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	scanID, err := strconv.ParseInt(r.URL.Query().Get("scan_id"), 10, 64)
	if err != nil {
		http.Error(w, "scan_id required", 400)
		return
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()
	enriched, err := db.EASMFinding().ListByScanWithAsset(ctx, scanID)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	type ag struct {
		Hostname string               `json:"hostname"`
		IP       string               `json:"ip"`
		Findings []models.EASMFinding `json:"findings"`
		CVECount int                  `json:"cve_count"`
	}
	groups := make(map[string]*ag)
	order := make([]string, 0)
	for _, e := range enriched {
		severity := e.Severity
		if e.CVSSv3 != nil {
			severity = models.CVSSSeverity(*e.CVSSv3)
		} else if e.CVSSv2 != nil {
			severity = models.CVSSSeverity(*e.CVSSv2)
		}
		f := models.EASMFinding{
			ID: e.ID, ServiceID: e.ServiceID, ScanID: e.ScanID, CVEID: e.CVEID,
			CVSSv3: e.CVSSv3, CVSSv2: e.CVSSv2, Severity: severity, Description: e.Description,
			IsKEV: e.IsKEV == 1, EPSSScore: e.EPSSScore, EPSSPercentile: e.EPSSPercentile,
			MatchedCPE: e.MatchedCPE, MatchedVersion: e.MatchedVersion,
		}
		if _, ok := groups[e.Hostname]; !ok {
			groups[e.Hostname] = &ag{Hostname: e.Hostname, Findings: []models.EASMFinding{}, CVECount: 0}
			order = append(order, e.Hostname)
		}
		groups[e.Hostname].Findings = append(groups[e.Hostname].Findings, f)
		groups[e.Hostname].CVECount++
	}
	assets, _ := db.EASMAsset().ListByScan(ctx, scanID)
	for _, a := range assets {
		if g, ok := groups[a.Hostname]; ok && g.IP == "" {
			g.IP = a.IPAddress
		}
	}
	result := make([]ag, 0, len(order))
	for _, h := range order {
		if g, ok := groups[h]; ok {
			result = append(result, *g)
		}
	}
	writeJSON(w, result)
}

func handleEASMScansDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	scans, err := db.EASMScan().List(ctx, 9999)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	deleted := 0
	for _, s := range scans {
		if err := db.EASMScan().Delete(ctx, s.ID); err == nil {
			deleted++
		}
	}
	writeJSON(w, map[string]interface{}{"status": "ok", "deleted": deleted})
}

func handleAssessmentHistoryDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "method not allowed", 405)
		return
	}
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	rawDB, err := sql.Open("sqlite", dbPath+"?_journal_mode=WAL")
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rawDB.Close()

	rawDB.ExecContext(ctx, "DELETE FROM security_findings")
	rawDB.ExecContext(ctx, "DELETE FROM assessment_results")
	rawDB.ExecContext(ctx, "DELETE FROM credential_validations")
	rawDB.ExecContext(ctx, "DELETE FROM installed_packages")
	rawDB.ExecContext(ctx, "DELETE FROM installed_software")
	rawDB.ExecContext(ctx, "DELETE FROM asset_inventory")
	writeJSON(w, map[string]interface{}{"status": "ok"})
}

// handleEASMAssetDetail returns enriched asset info with services, findings, risk.
func handleEASMAssetDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	assetID, err := strconv.ParseInt(r.URL.Query().Get("asset_id"), 10, 64)
	if err != nil {
		http.Error(w, "asset_id required", 400)
		return
	}
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	// Get all assets and find the one with matching ID
	allScans, _ := db.EASMScan().List(ctx, 9999)
	var foundAsset *database.DBEASMAsset
	for _, s := range allScans {
		assets, _ := db.EASMAsset().ListByScan(ctx, s.ID)
		for _, a := range assets {
			if a.ID == assetID {
				foundAsset = &a
				break
			}
		}
		if foundAsset != nil {
			break
		}
	}
	if foundAsset == nil {
		http.Error(w, "asset not found", 404)
		return
	}

	domainAsset := &models.EASMAsset{
		ID: foundAsset.ID, ScanID: foundAsset.ScanID, Hostname: foundAsset.Hostname,
		IPAddress: foundAsset.IPAddress, IPv6Address: foundAsset.IPv6Address,
		CNAME: foundAsset.CNAME, IsAlive: foundAsset.IsAlive == 1,
		IsWildcard: foundAsset.IsWildcard == 1, Source: foundAsset.Source,
		AssetType: foundAsset.AssetType,
	}

	dbServices, _ := db.EASMService().ListByAsset(ctx, assetID)
	services := make([]models.EASMService, len(dbServices))
	techMap := make(map[string]bool)
	for i, s := range dbServices {
		services[i] = models.EASMService{
			ID: s.ID, AssetID: s.AssetID, Port: s.Port, Protocol: s.Protocol,
			Service: s.Service, Product: s.Product, Version: s.Version,
			Banner: s.Banner, Confidence: s.Confidence, Technology: s.Technology,
			CPE23URI: s.CPE23URI,
		}
		if s.Technology != "" {
			techMap[s.Technology] = true
		}
	}

	var allFindings []models.EASMFinding
	for _, svc := range dbServices {
		dbFindings, _ := db.EASMFinding().ListByService(ctx, svc.ID)
		for _, f := range dbFindings {
			mf := dbEASMFindingToModel(&f)
			allFindings = append(allFindings, *mf)
		}
	}

	cveCount := len(allFindings)
	kevCount := 0
	highestCVSS := 0.0
	var totalEPSS, avgEPSS float64
	epssCount := 0
	criticalCount := 0
	topSeverity := "NONE"
	sevRank := map[string]int{"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
	for _, f := range allFindings {
		if f.IsKEV {
			kevCount++
		}
		if f.CVSSv3 != nil && *f.CVSSv3 > highestCVSS {
			highestCVSS = *f.CVSSv3
		}
		if f.EPSSScore != nil {
			totalEPSS += *f.EPSSScore
			epssCount++
		}
		if sevRank[f.Severity] > sevRank[topSeverity] {
			topSeverity = f.Severity
		}
		if f.Severity == "CRITICAL" {
			criticalCount++
		}
	}
	if epssCount > 0 {
		avgEPSS = totalEPSS / float64(epssCount)
	}

	riskScore := highestCVSS
	if kevCount > 0 {
		riskScore *= 1.3
	}
	riskScore += float64(criticalCount) * 2
	if len(dbServices) > 5 {
		riskScore += 2
	}
	if riskScore > 100 {
		riskScore = 100
	}
	riskLevel := "LOW"
	switch {
	case riskScore >= 70:
		riskLevel = "CRITICAL"
	case riskScore >= 40:
		riskLevel = "HIGH"
	case riskScore >= 20:
		riskLevel = "MEDIUM"
	}

	technologies := make([]string, 0, len(techMap))
	for t := range techMap {
		technologies = append(technologies, t)
	}

	writeJSON(w, models.EASMAssetDetail{
		EASMAsset: *domainAsset, Services: services, Findings: allFindings,
		CVECount: cveCount, KEVCount: kevCount, RiskScore: riskScore,
		RiskLevel: riskLevel, TopSeverity: topSeverity, AvgEPSS: avgEPSS,
		Technologies: technologies,
	})
}

// handleEASMDashboardStats returns aggregate EASM statistics.
func handleEASMDashboardStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cfg := loadConfigOrPanic()
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer db.Close()

	scans, _ := db.EASMScan().List(ctx, 50)
	totalAssets := 0
	aliveAssets := 0
	totalCVEs := 0
	totalKEV := 0
	sevCounts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	topSvc := make(map[string]int)
	topTech := make(map[string]int)
	highestRisk := 0.0
	highestTarget := ""

	for _, s := range scans {
		totalAssets += s.TotalAssets
		aliveAssets += s.AliveAssets
		totalCVEs += s.TotalCVEs
		totalKEV += s.KEVCVEs
		sevCounts["CRITICAL"] += s.CriticalCVEs
		sevCounts["HIGH"] += s.HighCVEs
		sevCounts["MEDIUM"] += s.MediumCVEs
		sevCounts["LOW"] += s.LowCVEs
		svcs, _ := db.EASMService().ListByScan(ctx, s.ID)
		for _, svc := range svcs {
			topSvc[svc.Service]++
			if svc.Technology != "" {
				topTech[svc.Technology]++
			}
		}
		risk := float64(s.TotalCVEs) * 0.5
		if s.KEVCVEs > 0 {
			risk *= 1.3
		}
		if risk > highestRisk {
			highestRisk = risk
			highestTarget = s.Target
		}
	}

	avgEPSS := 0.0
	if len(scans) > 0 {
		findings, _ := db.EASMFinding().ListByScan(ctx, scans[0].ID)
		eSum, eCnt := 0.0, 0
		for _, f := range findings {
			if f.EPSSScore != nil {
				eSum += *f.EPSSScore
				eCnt++
			}
		}
		if eCnt > 0 {
			avgEPSS = eSum / float64(eCnt)
		}
	}

	toTop := func(m map[string]int, n int) []map[string]interface{} {
		type kv struct {
			k string
			v int
		}
		var s []kv
		for k, v := range m {
			s = append(s, kv{k, v})
		}
		for i := 0; i < len(s); i++ {
			for j := i + 1; j < len(s); j++ {
				if s[j].v > s[i].v {
					s[i], s[j] = s[j], s[i]
				}
			}
		}
		r := make([]map[string]interface{}, 0, n)
		for i := 0; i < len(s) && i < n; i++ {
			r = append(r, map[string]interface{}{"name": s[i].k, "count": s[i].v})
		}
		return r
	}

	writeJSON(w, map[string]interface{}{
		"total_assets": totalAssets, "alive_assets": aliveAssets,
		"total_cves": totalCVEs, "total_kev": totalKEV,
		"avg_epss": avgEPSS, "scans_count": len(scans),
		"severity":            sevCounts,
		"highest_risk_target": highestTarget,
		"highest_risk_score":  highestRisk,
		"top_technologies":    toTop(topTech, 5),
		"top_services":        toTop(topSvc, 5),
	})
}

func dbEASMScanToModel(s *database.DBEASMScan) *models.EASMScan {
	startedAt, _ := time.Parse(time.RFC3339, s.StartedAt)
	var completedAt *time.Time
	if s.CompletedAt != "" {
		t, err := time.Parse(time.RFC3339, s.CompletedAt)
		if err == nil {
			completedAt = &t
		}
	}
	return &models.EASMScan{
		ID: s.ID, Target: s.Target, ScanType: models.EASMScanType(s.ScanType),
		Wordlist: models.EASMWordlistSize(s.Wordlist), Ports: models.EASMPortLevel(s.Ports),
		StartedAt: startedAt, CompletedAt: completedAt, Duration: fmt.Sprintf("%dms", s.DurationMs),
		Status: s.Status, TotalAssets: s.TotalAssets, AliveAssets: s.AliveAssets,
		TotalServices: s.TotalServices, TotalCVEs: s.TotalCVEs,
		CriticalCVEs: s.CriticalCVEs, HighCVEs: s.HighCVEs, MediumCVEs: s.MediumCVEs,
		LowCVEs: s.LowCVEs, KEVCVEs: s.KEVCVEs, AvgEPSS: s.AvgEPSS, Error: s.ErrorMessage,
	}
}

func dbEASMAssetToModel(a *database.DBEASMAsset) *models.EASMAsset {
	return &models.EASMAsset{
		ID: a.ID, ScanID: a.ScanID, Hostname: a.Hostname, IPAddress: a.IPAddress,
		IPv6Address: a.IPv6Address, CNAME: a.CNAME, IsAlive: a.IsAlive == 1,
		IsWildcard: a.IsWildcard == 1, Source: a.Source, AssetType: a.AssetType,
	}
}

func dbEASMFindingToModel(f *database.DBEASMFinding) *models.EASMFinding {
	// Re-derive severity from CVSS score — NVD data sometimes stores wrong
	// labels (e.g. 9.0 as "HIGH" instead of "CRITICAL").
	severity := f.Severity
	if f.CVSSv3 != nil {
		severity = models.CVSSSeverity(*f.CVSSv3)
	} else if f.CVSSv2 != nil {
		severity = models.CVSSSeverity(*f.CVSSv2)
	}
	return &models.EASMFinding{
		ID: f.ID, ServiceID: f.ServiceID, ScanID: f.ScanID, CVEID: f.CVEID,
		CVSSv3: f.CVSSv3, CVSSv2: f.CVSSv2, Severity: severity, Description: f.Description,
		IsKEV: f.IsKEV == 1, EPSSScore: f.EPSSScore, EPSSPercentile: f.EPSSPercentile,
		MatchedCPE: f.MatchedCPE, MatchedVersion: f.MatchedVersion,
	}
}
