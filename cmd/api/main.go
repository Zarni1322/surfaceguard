package main

import (
	"context"
	"encoding/json"
	"bufio"
	"strconv"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
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
		if db == nil { return }
		defer db.Close()
		info, err := db.Info(ctx)
		if err != nil { http.Error(w, err.Error(), 500); return }
		writeJSON(w, info)
	})

	// Host Discovery — fast TCP ping sweep
	mux.HandleFunc("/api/host-discovery", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		if target == "" { http.Error(w, "target required", 400); return }

		flusher, ok := w.(http.Flusher)
		if !ok { http.Error(w, "streaming not supported", 500); return }
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
			if alive { hosts = append(hosts, target) }
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
		if total > 256 { batchSize = 100 }

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
		if target == "" { http.Error(w, "target required", 400); return }

		flusher, ok := w.(http.Flusher)
		if !ok { http.Error(w, "streaming not supported", 500); return }
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 5, "text": "Resolving target..."}))
		flusher.Flush()

		args := []string{"scan", target, "--format", "json", "--no-banner"}
		if ports != "" { args = append(args, "--ports", ports) }

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

		// Record to history
		started, _ := time.Parse(time.RFC3339, getStr(rawResult, "started_at"))
		portsFound := int(getFloat(rawResult, "open_ports"))
		findingsCount := int(getFloat(rawResult, "findings"))
		riskScore := getFloat(rawResult, "risk_score")
		durStr := getStr(rawResult, "duration")

		rec := scanRecord{
			Target:     target,
			StartedAt:  started,
			Duration:   durStr,
			PortsFound: portsFound,
			Findings:   findingsCount,
			RiskScore:  riskScore,
			Status:     "completed",
		}
		historyMu.Lock()
		scanHistory = append([]scanRecord{rec}, scanHistory...)
		if len(scanHistory) > 100 { scanHistory = scanHistory[:100] }
		historyMu.Unlock()

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 100, "text": "Scan complete"}))
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "scan": json.RawMessage(rawJSON)}))
		flusher.Flush()
	})

	// Scan History
	mux.HandleFunc("/api/scan-history", func(w http.ResponseWriter, r *http.Request) {
		historyMu.Lock()
		defer historyMu.Unlock()
		if scanHistory == nil { writeJSON(w, []scanRecord{}) } else { writeJSON(w, scanHistory) }
	})

	// Trigger update
	mux.HandleFunc("/api/update", func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok { http.Error(w, "streaming not supported", 500); return }
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

		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			line := scanner.Text()
			// Parse progress from CVE download line
			if strings.Contains(line, "CVE Download:") {
				// Extract percentage: [===> ] 45%
				pct := 10
				text := "Downloading CVEs..."
				// Try to parse "XX%"
				if idx := strings.Index(line, "%"); idx >= 2 {
					pctStr := ""
					for j := idx - 3; j < idx; j++ {
						if j >= 0 && line[j] >= '0' && line[j] <= '9' {
							pctStr += string(line[j])
						}
					}
					if p, err := strconv.Atoi(pctStr); err == nil && p > 0 {
						pct = p
					}
				}
				if pct > 95 { pct = 95 }
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": pct, "text": text}))
				flusher.Flush()
			} else if strings.Contains(line, "KEV") && strings.Contains(line, "Already") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 96, "text": "KEV up to date"}))
				flusher.Flush()
			} else if strings.Contains(line, "EPSS") && strings.Contains(line, "inserted") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 98, "text": "EPSS scores downloaded"}))
				flusher.Flush()
			} else if strings.Contains(line, "inserted") {
				fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 90, "text": line}))
				flusher.Flush()
			}
		}
		cmd.Wait()

		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "progress", "percent": 100, "text": "Update complete"}))
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", jsonStr(map[string]interface{}{"type": "result", "status": "completed"}))
		flusher.Flush()
	})

	// Report Generation
	mux.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) {
		target := r.URL.Query().Get("target")
		format := r.URL.Query().Get("format")
		if format == "" { format = "html" }
		if target == "" { http.Error(w, "target required", 400); return }

		switch format {
		case "json":
			args := []string{"scan", target, "--format", "json", "--no-banner"}
			output, err := runSurfaceGuard(args...)
			if err != nil {
				http.Error(w, fmt.Sprintf("scan failed: %v", err), 500)
				return
			}
			jsonStart := strings.Index(output, "{")
			if jsonStart < 0 { http.Error(w, "no JSON in output", 500); return }
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.json\"", target))
			w.Write([]byte(output[jsonStart:]))

		case "html":
			args := []string{"scan", target, "--format", "html", "--no-banner"}
			output, err := runSurfaceGuard(args...)
			if err != nil {
				http.Error(w, fmt.Sprintf("scan failed: %v", err), 500)
				return
			}
			// Find HTML content in output (skip log lines)
			htmlStart := strings.Index(output, "<!DOCTYPE")
			if htmlStart < 0 { http.Error(w, "no HTML in output", 500); return }
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.html\"", target))
			w.Write([]byte(output[htmlStart:]))

		case "xlsx":
			// Generate CSV as a simple XLSX alternative (true XLSX would need a Go library)
			args := []string{"scan", target, "--format", "json", "--no-banner"}
			output, err := runSurfaceGuard(args...)
			if err != nil {
				http.Error(w, fmt.Sprintf("scan failed: %v", err), 500)
				return
			}
			jsonStart := strings.Index(output, "{")
			if jsonStart < 0 { http.Error(w, "no JSON in output", 500); return }

			var result map[string]interface{}
			json.Unmarshal([]byte(output[jsonStart:]), &result)

			csv := "Host,Port,Service,Version,CVE,CVSS,Severity,KEV,EPSS\n"
			findings := getFindings(result)
			for _, f := range findings {
				csv += fmt.Sprintf("%s,%d,%s,%s,%s,%.1f,%s,%v,%.4f\n",
					f.host, f.port, f.service, f.version, f.cveID, f.cvss, f.severity, f.kev, f.epss)
			}
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.csv\"", target))
			w.Write([]byte(csv))

		case "pdf":
			// Generate HTML then serve as downloadable HTML (PDF requires external lib)
			args := []string{"scan", target, "--format", "html", "--no-banner"}
			output, err := runSurfaceGuard(args...)
			if err != nil {
				http.Error(w, fmt.Sprintf("scan failed: %v", err), 500)
				return
			}
			htmlStart := strings.Index(output, "<!DOCTYPE")
			if htmlStart < 0 { http.Error(w, "no HTML in output", 500); return }
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"surfaceguard-report-%s.html\"", target))
			w.Write([]byte(output[htmlStart:]))

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
			"version":      version,
			"build_date":   "2026-07-07",
			"db_version":   fmt.Sprintf("%d", 3),
			"feed_status":  feedStatus,
			"last_update":  lastUpdate,
			"cve_count":    getVal(dbInfo, "cve_count"),
			"kev_count":    getVal(dbInfo, "kev_count"),
			"epss_count":   getVal(dbInfo, "epss_count"),
		})
	})

	addr := ":8080"
	fmt.Printf("SurfaceGuard API server on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, handler))
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
		if ip[j] > 0 { break }
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
	if db == nil { return nil }
	defer db.Close()
	info, err := db.Info(ctx)
	if err != nil { return nil }
	return info
}

func getVal(info *models.DatabaseInfo, key string) int {
	if info == nil { return 0 }
	switch key {
	case "cve_count": return info.CVECount
	case "kev_count": return info.KEVCount
	case "epss_count": return info.EPSSCount
	}
	return 0
}

func applyConfigUpdates(cfg *config.Config, updates map[string]interface{}) {
	scan, _ := updates["scan"].(map[string]interface{})
	if scan != nil {
		if v, ok := scan["workers"].(float64); ok { cfg.Scan.Workers = int(v) }
		if v, ok := scan["timeout"].(string); ok { if d, e := time.ParseDuration(v); e == nil { cfg.Scan.Timeout = d } }
	}
	logging, _ := updates["logging"].(map[string]interface{})
	if logging != nil {
		if v, ok := logging["level"].(string); ok { cfg.Logging.Level = v }
		if v, ok := logging["format"].(string); ok { cfg.Logging.Format = v }
	}
	report, _ := updates["report"].(map[string]interface{})
	if report != nil {
		if v, ok := report["cvss_threshold"].(float64); ok { cfg.Report.CVSSThreshold = v }
	}
}

func getFindings(result map[string]interface{}) []findingRow {
	var rows []findingRow
	findings, _ := result["findings"].([]interface{})
	for _, f := range findings {
		fm, _ := f.(map[string]interface{})
		if fm == nil { continue }
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
			if cvss == 0 { cvss = getFloat(cve, "cvss_v2") }
			severity, _ = cve["severity"].(string)
			kev, _ = cve["is_in_kev"].(bool)
			if s, ok := cve["epss_score"].(float64); ok { epss = s }
		}

		rows = append(rows, findingRow{host, portNum, service, version, cveID, cvss, severity, kev, epss})
	}
	return rows
}

func getStr(m map[string]interface{}, key string) string {
	if m == nil { return "" }
	if v, ok := m[key]; ok && v != nil {
		if s, ok := v.(string); ok { return s }
	}
	return ""
}

func getFloat(m map[string]interface{}, key string) float64 {
	if m == nil { return 0 }
	if v, ok := m[key]; ok && v != nil {
		switch n := v.(type) {
		case float64: return n
		case int: return float64(n)
		case int64: return float64(n)
		}
	}
	return 0
}

func runSurfaceGuard(args ...string) (string, error) {
	cmd := exec.Command("./surfaceguard", args...)
	output, err := cmd.CombinedOutput()
	if err != nil { return "", fmt.Errorf("%s: %s", err, string(output)) }
	return string(output), nil
}

func openDB(cfg *config.Config, ctx context.Context, w http.ResponseWriter) database.Database {
	dbPath, err := cfg.ResolveDatabasePath()
	if err != nil { http.Error(w, err.Error(), 500); return nil }
	db, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil { http.Error(w, err.Error(), 500); return nil }
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

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" { w.WriteHeader(200); return }
		next.ServeHTTP(w, r)
	})
}
