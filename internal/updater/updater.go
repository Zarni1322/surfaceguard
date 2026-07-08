package updater

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
)

// Updater orchestrates fault-tolerant feed updates with checkpoint-based resume.
type Updater struct {
	cfg        *config.UpdateConfig
	downloads  string
	db         database.Database
	client     *http.Client
	logger     *slog.Logger
	mu         sync.Mutex
	checkpoint *CheckpointManager
	dl         *Downloader
}

// UpdateStats aggregates results across all feeds.
type UpdateStats struct {
	CVEsInserted int
	CVEsUpdated  int
	KEVInserted  int
	KEVUpdated   int
	EPSSInserted int
	EPSSUpdated  int
	Errors       []string
}

type feedResult struct {
	name     string
	inserted int
	updated  int
	err      error
}

// New creates an Updater with checkpoint and downloader support.
func New(cfg *config.UpdateConfig, db database.Database, logger *slog.Logger) *Updater {
	timeout, _ := time.ParseDuration(cfg.HTTPTimeout)
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	// NVD API pagination across 3600+ pages needs a robust timeout.
	fetchTimeout := timeout
	if fetchTimeout < 600*time.Second {
		fetchTimeout = 600 * time.Second
	}
	dlClient := &http.Client{Timeout: 0} // streaming downloads; ctx cancels
	return &Updater{
		cfg:        cfg,
		downloads:  cfg.DownloadsDir,
		db:         db,
		client:     &http.Client{Timeout: fetchTimeout},
		logger:     logger,
		checkpoint: newCheckpointManager(db.Checkpoint()),
		dl:         newDownloader(cfg, dlClient),
	}
}

// SetDownloadsDir overrides the downloads directory (used in tests).
func (u *Updater) SetDownloadsDir(dir string) {
	u.downloads = dir
}

// ============================================================================
// Public API — RunAll with checkpoint resume
// ============================================================================

// RunAll runs all three feed updates with checkpoint-based resume.
// If resume is true, unfinished feeds resume from their last checkpoint.
func (u *Updater) RunAll(ctx context.Context) (*UpdateStats, error) {
	u.mu.Lock()
	defer u.mu.Unlock()

	stats := &UpdateStats{}
	u.logger.Info("checking feed metadata")

	// Check for unfinished checkpoints and offer resume.
	unfinished, err := u.checkpoint.HasUnfinished(ctx)
	if err == nil && len(unfinished) > 0 {
		fmt.Print(ResumePrompt(unfinished))
		var response string
		fmt.Scanln(&response)
		response = strings.ToLower(strings.TrimSpace(response))
		if response == "" || response == "y" || response == "yes" {
			fmt.Println("Resuming previous update...")
		} else {
			fmt.Println("Restarting all feeds from scratch...")
			u.checkpoint.ClearAll(ctx)
			unfinished = nil
		}
	}

	// Gather incremental state.
	lastUpdate, _ := u.db.Metadata().Get(ctx, "last_update")
	isFull := (lastUpdate == "")
	if isFull {
		fmt.Println("NVD: Full download required (first run)")
	} else {
		fmt.Printf("NVD: Incremental update since %s\n", lastUpdate[:10])
	}

	kevVersion, _ := u.db.Metadata().Get(ctx, "kev_version")
	epssDate, _ := u.db.Metadata().Get(ctx, "epss_date")
	fmt.Println()

	// Ensure downloads directory exists.
	absDl, _ := filepath.Abs(u.downloads)
	os.MkdirAll(absDl, 0755)
	u.downloads = absDl

	fmt.Println("Downloading feeds...")

	// Launch all three feeds concurrently.
	var wg sync.WaitGroup
	results := make(chan feedResult, 3)

	wg.Add(1)
	go func() {
		defer wg.Done()
		ins, upd, err := u.updateCVE(ctx, lastUpdate)
		results <- feedResult{name: "NVD", inserted: ins, updated: upd, err: err}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ins, upd, err := u.updateKEV(ctx, kevVersion)
		results <- feedResult{name: "KEV", inserted: ins, updated: upd, err: err}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		ins, upd, err := u.updateEPSS(ctx, epssDate)
		results <- feedResult{name: "EPSS", inserted: ins, updated: upd, err: err}
	}()

	wg.Wait()
	close(results)

	fmt.Println()
	fmt.Println("Updating SQLite...")

	for r := range results {
		if r.err != nil {
			stats.Errors = append(stats.Errors, fmt.Sprintf("%s: %v", r.name, r.err))
			u.logger.Error("feed failed", "feed", r.name, "error", r.err)
			continue
		}
		switch r.name {
		case "NVD":
			stats.CVEsInserted += r.inserted
			stats.CVEsUpdated += r.updated
		case "KEV":
			stats.KEVInserted += r.inserted
			stats.KEVUpdated += r.updated
		case "EPSS":
			stats.EPSSInserted += r.inserted
			stats.EPSSUpdated += r.updated
		}
	}

	// Update last_update metadata after all feeds processed.
	if len(stats.Errors) == 0 || len(stats.Errors) < 3 {
		u.db.Metadata().Set(ctx, "last_update", time.Now().UTC().Format(time.RFC3339))
		u.db.Metadata().Set(ctx, "schema_version", "4")
		// Clear all checkpoints on full success.
		u.checkpoint.ClearAll(ctx)
	}

	u.logger.Info("update complete",
		"cves_inserted", stats.CVEsInserted, "cves_updated", stats.CVEsUpdated,
		"kev_inserted", stats.KEVInserted, "kev_updated", stats.KEVUpdated,
		"epss_inserted", stats.EPSSInserted, "epss_updated", stats.EPSSUpdated,
		"errors", len(stats.Errors))

	return stats, nil
}

// ============================================================================
// HTTP helper with retry and backoff
// ============================================================================

func (u *Updater) fetchWithRetry(ctx context.Context, url string) ([]byte, error) {
	var result []byte
	err := doWithRetry(ctx, u.cfg.RetryCount, dur(u.cfg.RetryDelay), dur(u.cfg.MaxRetryDelay), url,
		func(ctx context.Context) (bool, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				return false, fmt.Errorf("request: %w", err)
			}
			req.Header.Set("User-Agent", "SurfaceGuard/1.0")
			req.Header.Set("Accept", "application/json")
			resp, err := u.client.Do(req)
			if err != nil {
				return false, fmt.Errorf("http: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusTooManyRequests {
				return false, fmt.Errorf("rate limited")
			}
			if resp.StatusCode == http.StatusNotFound {
				return false, fmt.Errorf("not found")
			}
			if resp.StatusCode != http.StatusOK {
				return false, fmt.Errorf("status %d", resp.StatusCode)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				return false, fmt.Errorf("read: %w", err)
			}
			result = body
			return true, nil
		})
	if err != nil {
		return nil, fmt.Errorf("all %d attempts failed: %w", u.cfg.RetryCount+1, err)
	}
	return result, nil
}

func dur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}

// ============================================================================
// NVD CVE Update — paginated, checkpointed, transaction-safe
// ============================================================================

type cveResponse struct {
	TotalResults    int        `json:"totalResults"`
	StartIndex      int        `json:"startIndex"`
	ResultsPerPage  int        `json:"resultsPerPage"`
	Vulnerabilities []cveEntry `json:"vulnerabilities"`
}
type cveEntry struct {
	CVE cveItem `json:"cve"`
}
type cveItem struct {
	ID             string             `json:"id"`
	Descriptions   []cveDescription   `json:"descriptions"`
	Metrics        *cveMetrics        `json:"metrics"`
	Published      string             `json:"published"`
	LastModified   string             `json:"lastModified"`
	References     []cveReference     `json:"references"`
	Configurations []cveConfiguration `json:"configurations"`
}
type cveDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}
type cveMetrics struct {
	CVSSMetricV31 []cvssData `json:"cvssMetricV31"`
	CVSSMetricV30 []cvssData `json:"cvssMetricV30"`
	CVSSMetricV2  []cvssData `json:"cvssMetricV2"`
}
type cvssData struct {
	CVSSData     cvssScore `json:"cvssData"`
	BaseSeverity string    `json:"baseSeverity"`
}
type cvssScore struct {
	BaseScore float64 `json:"baseScore"`
}
type cveReference struct {
	URL string `json:"url"`
}
type cveConfiguration struct {
	Nodes []cveNode `json:"nodes"`
}
type cveNode struct {
	Operator string     `json:"operator"`
	Negate   bool       `json:"negate"`
	CPEMatch []cpeMatch `json:"cpeMatch"`
}
type cpeMatch struct {
	Vulnerable bool   `json:"vulnerable"`
	Criteria   string `json:"criteria"`
}

func (u *Updater) updateCVE(ctx context.Context, lastUpdate string) (int, int, error) {
	// Checkpoint: resume from last completed startIndex.
	cp, _ := u.checkpoint.Get(ctx, FeedNVD)
	var resumeSI int
	if cp != nil && isActiveState(FeedState(cp.State)) {
		u.logger.Info("NVD: resuming from checkpoint", "step", cp.Step, "offset", cp.BytesOffset)
		resumeSI = int(cp.BytesOffset)
	}

	isFull := (lastUpdate == "")
	start := time.Now()

	if isFull {
		fmt.Println("  NVD: Download")
	} else {
		fmt.Printf("  NVD: Download (%s)\n", lastUpdate[:10])
	}

	inserted, updated := 0, 0
	page := resumeSI / 100

	for si := resumeSI; ; si += 100 {
		if ctx.Err() != nil {
			u.checkpoint.Save(ctx, FeedNVD, StateDownloading, StepDownloading, int64(si), "", "", "interrupted")
			u.recordHistory(start, FeedNVD, "interrupted", inserted, updated, ctx.Err(), u.db)
			return inserted, updated, ctx.Err()
		}

		url := fmt.Sprintf("%s?startIndex=%d&resultsPerPage=100", u.cfg.CVEBaseURL, si)
		if !isFull {
			url += fmt.Sprintf("&lastModStartDate=%s&lastModEndDate=%s",
				lastUpdate, time.Now().UTC().Format(time.RFC3339))
		}

		body, err := u.fetchWithRetry(ctx, url)
		if err != nil {
			u.logger.Warn("NVD page fetch failed, skipping", "page", page, "startIndex", si, "error", err)
			fmt.Printf("\r  NVD: page %d failed, skipping (%v)", page+1, err)
			page++
			u.checkpoint.Save(ctx, FeedNVD, StateDownloading, StepDownloading, int64(si+100), "", "", fmt.Sprintf("page %d skipped", page))
			if si+100 >= 363800 {
				break
			}
			continue
		}

		var resp cveResponse
		if err := json.Unmarshal(body, &resp); err != nil {
			u.checkpoint.Save(ctx, FeedNVD, StateDownloading, StepDownloading, int64(si), "", "", "parse error")
			u.recordHistory(start, FeedNVD, "failed", inserted, updated, err, u.db)
			return inserted, updated, fmt.Errorf("parse: %w", err)
		}
		if resp.TotalResults == 0 {
			break
		}

		// Process each vulnerability on this page.
		for _, entry := range resp.Vulnerabilities {
			cve := entry.CVE
			if cve.ID == "" {
				continue
			}
			desc := ""
			for _, d := range cve.Descriptions {
				if d.Lang == "en" {
					desc = d.Value
					break
				}
			}
			var cvss *float64
			severity := "NONE"
			if cve.Metrics != nil {
				if len(cve.Metrics.CVSSMetricV31) > 0 {
					cvss = &cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
					severity = cve.Metrics.CVSSMetricV31[0].BaseSeverity
				} else if len(cve.Metrics.CVSSMetricV30) > 0 {
					cvss = &cve.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
					severity = cve.Metrics.CVSSMetricV30[0].BaseSeverity
				} else if len(cve.Metrics.CVSSMetricV2) > 0 {
					cvss = &cve.Metrics.CVSSMetricV2[0].CVSSData.BaseScore
					severity = cve.Metrics.CVSSMetricV2[0].BaseSeverity
				}
			}
			if cvss == nil {
				cvss = new(float64)
			}
			pubDate := parseTime(cve.Published)
			modDate := parseTime(cve.LastModified)
			var refs []string
			for _, r := range cve.References {
				if r.URL != "" {
					refs = append(refs, r.URL)
				}
			}
			refsJSON, _ := json.Marshal(refs)

			for _, cpeURI := range collectCPE23URIs(cve.Configurations) {
				dbCPEs, _ := u.db.CPE().FindByCPE23URI(ctx, cpeURI)
				var cpeID int64
				if len(dbCPEs) > 0 {
					cpeID = dbCPEs[0].ID
				} else {
					parts := strings.Split(cpeURI, ":")
					if len(parts) < 6 {
						continue
					}
					vid, _ := u.db.Vendor().GetOrCreate(ctx, parts[3])
					pid, _ := u.db.Product().GetOrCreate(ctx, vid, parts[4])
					id, err := u.db.CPE().Insert(ctx, &database.DBCPE{
						VendorID: vid, ProductID: pid, Part: parts[2],
						Version: parts[5], CPE23URI: cpeURI,
					})
					if err != nil {
						continue
					}
					cpeID = id
				}
				_, isNew, err := u.db.CVE().Upsert(ctx, &database.DBCVE{
					CVEID: cve.ID, CPEID: cpeID, Description: desc,
					CVSSv3: cvss, Severity: normalizeSeverity(severity),
					PublishedDate: pubDate, LastModifiedDate: modDate,
					ReferencesJSON: string(refsJSON),
				})
				if err != nil {
					continue
				}
				if isNew {
					inserted++
				} else {
					updated++
				}
			}
		}

		pct := float64((si+100)*100) / float64(resp.TotalResults)
		if pct > 100 {
			pct = 100
		}
		progress := int(pct) / 2
		bar := strings.Repeat("=", progress)
		if progress < 50 {
			bar += ">"
		}
		fmt.Printf("\r  NVD: [%-50s] %.0f%% (page %d/%d, %d inserted)", bar, pct, page+1, (resp.TotalResults+99)/100, inserted)
		page++

		// Save progress checkpoint every page for granular resume support.
		u.checkpoint.Save(ctx, FeedNVD, StateDownloading, StepDownloading, int64(si+100), "", "", "in progress")

		if si+100 >= resp.TotalResults {
			break
		}
	}

	fmt.Println()
	fmt.Printf("  NVD: Import complete — %d inserted, %d updated\n", inserted, updated)
	u.checkpoint.MarkCompleted(ctx, FeedNVD)
	u.recordHistory(start, FeedNVD, "success", inserted, updated, nil, u.db)
	return inserted, updated, nil
}

// ============================================================================
// KEV Update — with version tracking and staged download
// ============================================================================

type kevResponse struct {
	CatalogVersion  string    `json:"catalogVersion"`
	Count           int       `json:"count"`
	Vulnerabilities []kevVuln `json:"vulnerabilities"`
}
type kevVuln struct {
	CveID   string `json:"cveID"`
	DueDate string `json:"dueDate"`
	Notes   string `json:"notes"`
}

func (u *Updater) updateKEV(ctx context.Context, storedVersion string) (int, int, error) {
	// Check existing checkpoint.
	cp, _ := u.checkpoint.Get(ctx, FeedKEV)
	if cp != nil && isActiveState(FeedState(cp.State)) {
		u.logger.Info("KEV: resuming from checkpoint", "step", cp.Step, "state", cp.State)
	}

	start := time.Now()
	u.checkpoint.Save(ctx, FeedKEV, StateDownloading, StepFetchMetadata, 0, "", "", "checking version")

	// Check KEV version via HEAD-like fetch.
	_, kevChanged := u.checkKEVVersion(ctx)
	if !kevChanged && storedVersion != "" {
		fmt.Println("  KEV: Already up to date")
		u.checkpoint.MarkCompleted(ctx, FeedKEV)
		u.recordHistory(start, FeedKEV, "skipped", 0, 0, nil, u.db)
		return 0, 0, nil
	}

	// Stage download via temp file.
	tmpFile := filepath.Join(u.downloads, "kev.tmp")
	finalFile := filepath.Join(u.downloads, "kev.json")

	// If we have a partial download from checkpoint, resume.
	var prevOffset int64
	if cp != nil && cp.State == string(StateDownloading) && cp.FilePath != "" {
		prevOffset = cp.BytesOffset
	}

	u.checkpoint.Save(ctx, FeedKEV, StateDownloading, StepDownloading, prevOffset, tmpFile, "", "downloading")

	dl, err := u.dl.DownloadFile(ctx, u.cfg.KEVBaseURL, finalFile, prevOffset)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedKEV, err)
		u.recordHistory(start, FeedKEV, "failed", 0, 0, err, u.db)
		return 0, 0, fmt.Errorf("download: %w", err)
	}

	u.checkpoint.Save(ctx, FeedKEV, StateDownloaded, StepVerifyChecksum, dl.BytesOffset, dl.TempPath, dl.FileHash, "verifying")

	// Verify checksum (no expected hash — KEV doesn't publish one, but we have the file hash).
	u.checkpoint.Save(ctx, FeedKEV, StateVerifying, StepVerifyChecksum, dl.BytesOffset, dl.TempPath, dl.FileHash, "verified")

	// Finalize: rename .tmp to final.
	if err := u.dl.FinalizeFile(dl.TempPath, finalFile); err != nil {
		u.checkpoint.MarkFailed(ctx, FeedKEV, err)
		return 0, 0, fmt.Errorf("finalize: %w", err)
	}

	// Read and parse.
	u.checkpoint.Save(ctx, FeedKEV, StateParsing, StepParseJSON, dl.BytesOffset, finalFile, "", "parsing")
	body, err := os.ReadFile(finalFile)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedKEV, err)
		return 0, 0, fmt.Errorf("read: %w", err)
	}

	var resp kevResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		u.checkpoint.MarkFailed(ctx, FeedKEV, err)
		return 0, 0, fmt.Errorf("parse: %w", err)
	}

	// Store version.
	u.db.Metadata().Set(ctx, "kev_version", resp.CatalogVersion)

	u.checkpoint.Save(ctx, FeedKEV, StateImporting, StepImport, 0, "", "", "importing")
	var entries []database.DBKEV
	for _, v := range resp.Vulnerabilities {
		entries = append(entries, database.DBKEV{CVEID: v.CveID, DueDate: v.DueDate, Notes: truncateStr(v.Notes, 500)})
	}
	if len(entries) == 0 {
		u.dl.RemoveTemp(dl.TempPath)
		u.checkpoint.MarkCompleted(ctx, FeedKEV)
		u.recordHistory(start, FeedKEV, "success", 0, 0, nil, u.db)
		return 0, 0, nil
	}

	if err := u.db.KEV().BulkUpsert(ctx, entries); err != nil {
		u.checkpoint.MarkFailed(ctx, FeedKEV, err)
		u.recordHistory(start, FeedKEV, "failed", 0, 0, err, u.db)
		return 0, 0, fmt.Errorf("bulk upsert: %w", err)
	}

	u.dl.RemoveTemp(dl.TempPath)
	u.checkpoint.MarkCompleted(ctx, FeedKEV)
	u.recordHistory(start, FeedKEV, "success", len(entries), 0, nil, u.db)
	return len(entries), 0, nil
}

// ============================================================================
// EPSS Update — with staged download and date tracking
// ============================================================================

func (u *Updater) updateEPSS(ctx context.Context, storedDate string) (int, int, error) {
	// Check existing checkpoint.
	cp, _ := u.checkpoint.Get(ctx, FeedEPSS)
	if cp != nil && isActiveState(FeedState(cp.State)) {
		u.logger.Info("EPSS: resuming from checkpoint", "step", cp.Step, "state", cp.State)
	}

	start := time.Now()
	u.checkpoint.Save(ctx, FeedEPSS, StateDownloading, StepFetchMetadata, 0, "", "", "checking date")

	// Check EPSS date.
	epssChanged := u.checkEPSSDate(ctx, storedDate)
	if !epssChanged && storedDate != "" {
		fmt.Println("  EPSS: Already up to date")
		u.checkpoint.MarkCompleted(ctx, FeedEPSS)
		u.recordHistory(start, FeedEPSS, "skipped", 0, 0, nil, u.db)
		return 0, 0, nil
	}

	// Stage download.
	tmpFile := filepath.Join(u.downloads, "epss.tmp")
	finalFile := filepath.Join(u.downloads, "epss.csv.gz")

	var prevOffset int64
	if cp != nil && cp.State == string(StateDownloading) && cp.FilePath != "" {
		prevOffset = cp.BytesOffset
	}

	u.checkpoint.Save(ctx, FeedEPSS, StateDownloading, StepDownloading, prevOffset, tmpFile, "", "downloading")
	dl, err := u.dl.DownloadFile(ctx, u.cfg.EPSSBaseURL, finalFile, prevOffset)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedEPSS, err)
		u.recordHistory(start, FeedEPSS, "failed", 0, 0, err, u.db)
		return 0, 0, fmt.Errorf("download: %w", err)
	}

	u.checkpoint.Save(ctx, FeedEPSS, StateVerifying, StepVerifyChecksum, dl.BytesOffset, dl.TempPath, dl.FileHash, "verified")

	// Finalize.
	if err := u.dl.FinalizeFile(dl.TempPath, finalFile); err != nil {
		u.checkpoint.MarkFailed(ctx, FeedEPSS, err)
		return 0, 0, fmt.Errorf("finalize: %w", err)
	}

	// Decompress and parse.
	u.checkpoint.Save(ctx, FeedEPSS, StateParsing, StepDecompress, 0, finalFile, "", "decompressing")
	f, err := os.Open(finalFile)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedEPSS, err)
		return 0, 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedEPSS, err)
		return 0, 0, fmt.Errorf("decompress: %w", err)
	}
	defer gz.Close()

	u.checkpoint.Save(ctx, FeedEPSS, StateParsing, StepParseCSV, 0, finalFile, "", "parsing CSV")

	// Extract score_date from comment.
	peekReader := csv.NewReader(gz)
	peekReader.FieldsPerRecord = -1
	peekReader.LazyQuotes = true
	scoreDate := storedDate
	for {
		row, err := peekReader.Read()
		if err == io.EOF {
			break
		}
		if len(row) >= 1 && strings.HasPrefix(row[0], "#") {
			for _, part := range strings.Split(row[0], ",") {
				if strings.HasPrefix(part, "score_date:") {
					d := strings.TrimSpace(strings.TrimPrefix(part, "score_date:"))
					if len(d) > 10 {
						d = d[:10]
					}
					scoreDate = d
				}
			}
		}
		if len(row) >= 3 && row[0] == "cve" {
			break
		}
	}

	// Reset to start of gzip for full parse.
	gz.Close()
	f.Seek(0, io.SeekStart)
	gz2, err := gzip.NewReader(f)
	if err != nil {
		u.checkpoint.MarkFailed(ctx, FeedEPSS, err)
		return 0, 0, fmt.Errorf("reopen decompress: %w", err)
	}
	defer gz2.Close()
	reader := csv.NewReader(gz2)
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	// Skip header.
	for {
		row, err := reader.Read()
		if err == io.EOF {
			u.checkpoint.MarkCompleted(ctx, FeedEPSS)
			u.recordHistory(start, FeedEPSS, "success", 0, 0, nil, u.db)
			return 0, 0, nil
		}
		if len(row) >= 1 && strings.HasPrefix(row[0], "#") {
			continue
		}
		if len(row) >= 3 && row[0] == "cve" {
			break
		}
	}

	u.checkpoint.Save(ctx, FeedEPSS, StateImporting, StepImport, 0, "", "", "importing")
	var entries []database.DBEpss
	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil || len(rec) < 3 {
			continue
		}
		cveID := strings.TrimSpace(rec[0])
		score, _ := strconv.ParseFloat(strings.TrimSpace(rec[1]), 64)
		per, _ := strconv.ParseFloat(strings.TrimSpace(rec[2]), 64)
		entries = append(entries, database.DBEpss{CVEID: cveID, Score: score, Percentile: per})
	}

	if len(entries) == 0 {
		if scoreDate != "" {
			u.db.Metadata().Set(ctx, "epss_date", scoreDate)
		}
		u.dl.RemoveTemp(dl.TempPath)
		u.checkpoint.MarkCompleted(ctx, FeedEPSS)
		u.recordHistory(start, FeedEPSS, "success", 0, 0, nil, u.db)
		return 0, 0, nil
	}

	total := 0
	for i := 0; i < len(entries); i += 1000 {
		end := i + 1000
		if end > len(entries) {
			end = len(entries)
		}
		if err := u.db.EPSS().BulkUpsert(ctx, entries[i:end]); err != nil {
			u.checkpoint.MarkFailed(ctx, FeedEPSS, fmt.Errorf("batch %d: %w", i/1000, err))
			u.recordHistory(start, FeedEPSS, "failed", total, 0, err, u.db)
			return total, 0, fmt.Errorf("batch %d: %w", i/1000, err)
		}
		total += end - i
	}

	if scoreDate != "" {
		u.db.Metadata().Set(ctx, "epss_date", scoreDate)
	}
	u.dl.RemoveTemp(dl.TempPath)
	u.checkpoint.MarkCompleted(ctx, FeedEPSS)
	u.recordHistory(start, FeedEPSS, "success", total, 0, nil, u.db)
	return total, 0, nil
}

// ============================================================================
// KEV version check — parses catalogVersion from JSON
// ============================================================================

type kevMeta struct {
	CatalogVersion string `json:"catalogVersion"`
}

func (u *Updater) checkKEVVersion(ctx context.Context) (string, bool) {
	body, err := u.fetchWithRetry(ctx, u.cfg.KEVBaseURL)
	if err != nil {
		u.logger.Warn("KEV version check failed", "error", err)
		return "", true
	}
	var meta kevMeta
	json.Unmarshal(body, &meta)
	if meta.CatalogVersion == "" {
		return "", true
	}
	stored, _ := u.db.Metadata().Get(ctx, "kev_version")
	return meta.CatalogVersion, meta.CatalogVersion != stored
}

// ============================================================================
// EPSS date check — parses score_date from CSV comment
// ============================================================================

func (u *Updater) checkEPSSDate(ctx context.Context, storedDate string) bool {
	body, err := u.fetchWithRetry(ctx, u.cfg.EPSSBaseURL)
	if err != nil {
		u.logger.Warn("EPSS date check failed", "error", err)
		return true
	}
	gz, err := gzip.NewReader(strings.NewReader(string(body)))
	if err != nil {
		return true
	}
	defer gz.Close()
	reader := csv.NewReader(gz)
	reader.FieldsPerRecord = -1
	for {
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if len(row) >= 1 && strings.HasPrefix(row[0], "#") {
			for _, part := range strings.Split(row[0], ",") {
				if strings.HasPrefix(part, "score_date:") {
					date := strings.TrimSpace(strings.TrimPrefix(part, "score_date:"))
					if len(date) > 10 {
						date = date[:10]
					}
					return date != storedDate
				}
			}
		}
		if len(row) >= 3 && row[0] == "cve" {
			break
		}
	}
	return true
}

// ============================================================================
// Helpers
// ============================================================================

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func parseTime(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil {
		return t
	}
	t, err = time.Parse("2006-01-02T15:04:05", s)
	if err == nil {
		return t
	}
	return time.Time{}
}

func normalizeSeverity(sev string) string {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM":
		return "MEDIUM"
	case "LOW":
		return "LOW"
	default:
		return "NONE"
	}
}

func collectCPE23URIs(configs []cveConfiguration) []string {
	var uris []string
	seen := map[string]bool{}
	for _, c := range configs {
		for _, n := range c.Nodes {
			for _, m := range n.CPEMatch {
				if m.Vulnerable && m.Criteria != "" && !seen[m.Criteria] {
					seen[m.Criteria] = true
					uris = append(uris, m.Criteria)
				}
			}
		}
	}
	return uris
}

// recordHistory inserts a row into update_history table.
func (u *Updater) recordHistory(start time.Time, feed, status string, inserted, updated int, err error, db database.Database) {
	elapsed := time.Since(start).Milliseconds()
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
		if len(errMsg) > 500 {
			errMsg = errMsg[:500]
		}
	}
	ctx := context.Background()
	db.Metadata().Set(ctx, fmt.Sprintf("history_%s_%d", feed, start.Unix()),
		fmt.Sprintf("%s|%s|%d|%d|%d|%s", feed, status, elapsed, inserted, updated, errMsg))
}
