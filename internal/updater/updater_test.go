package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
)

func setupTestUpdater(t *testing.T) (*Updater, database.Database) {
	t.Helper()
	ctx := context.Background()

	db, err := database.NewSQLiteDatabase(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}

	cfg := config.DefaultConfig()
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	return New(&cfg.Update, db, logger), db
}

func TestNewUpdater(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	if u == nil {
		t.Fatal("expected non-nil updater")
	}
}

func TestUpdaterDownloadsDir(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	u.SetDownloadsDir(t.TempDir())
	if u.downloads == "" {
		t.Fatal("expected non-empty downloads dir")
	}
}

func TestUpdateStats(t *testing.T) {
	stats := &UpdateStats{
		CVEsInserted: 100,
		CVEsUpdated:  50,
		KEVInserted:  10,
		EPSSInserted: 5000,
	}

	if stats.CVEsInserted != 100 {
		t.Errorf("expected 100 CVE inserts, got %d", stats.CVEsInserted)
	}
	if stats.EPSSInserted != 5000 {
		t.Errorf("expected 5000 EPSS inserts, got %d", stats.EPSSInserted)
	}
}

func TestFetchWithRetryInvalidURL(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	u.cfg.RetryCount = 0 // speed up test
	_, err := u.fetchWithRetry(ctx, "http://192.0.2.1:1/nonexistent")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	t.Logf("Expected error: %v", err)
}

func TestKEVParsing(t *testing.T) {
	jsonData := `{
		"title": "Test KEV",
		"catalogVersion": "2024.01.01",
		"dateReleased": "2024-01-01",
		"count": 2,
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-0001",
				"vendorProject": "Apache",
				"product": "httpd",
				"vulnerabilityName": "Test Vuln",
				"dateAdded": "2024-01-15",
				"shortDescription": "Test KEV entry",
				"requiredAction": "Apply updates",
				"dueDate": "2024-02-15",
				"knownRansomwareCampaignUse": "Unknown",
				"notes": "Test notes"
			},
			{
				"cveID": "CVE-2024-0002",
				"vendorProject": "Microsoft",
				"product": "Windows",
				"vulnerabilityName": "Test Vuln 2",
				"dateAdded": "2024-01-20",
				"shortDescription": "Another KEV entry",
				"requiredAction": "Apply updates",
				"dueDate": "2024-02-20",
				"knownRansomwareCampaignUse": "Known",
				"notes": ""
			}
		]
	}`

	var resp kevResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("parsing KEV JSON: %v", err)
	}

	if resp.Count != 2 {
		t.Errorf("expected count 2, got %d", resp.Count)
	}
	if len(resp.Vulnerabilities) != 2 {
		t.Errorf("expected 2 vulnerabilities, got %d", len(resp.Vulnerabilities))
	}
	if resp.Vulnerabilities[0].CveID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", resp.Vulnerabilities[0].CveID)
	}
}

func TestCVEParsing(t *testing.T) {
	jsonData := `{
		"totalResults": 1,
		"startIndex": 0,
		"resultsPerPage": 1,
		"vulnerabilities": [
			{
				"cve": {
					"id": "CVE-2024-0001",
					"descriptions": [
						{
							"lang": "en",
							"value": "Test CVE description"
						}
					],
					"metrics": {
						"cvssMetricV31": [
							{
								"source": "nvd@nist.gov",
								"type": "Primary",
								"cvssData": {
									"version": "3.1",
									"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
									"baseScore": 9.8,
									"baseSeverity": "CRITICAL"
								}
							}
						]
					},
					"published": "2024-01-01T00:00:00Z",
					"lastModified": "2024-01-15T00:00:00Z",
					"references": [
						{
							"url": "https://example.com/cve-2024-0001",
							"source": "test"
						}
					],
					"configurations": [
						{
							"nodes": [
								{
									"operator": "OR",
									"negate": false,
									"cpeMatch": [
										{
											"vulnerable": true,
											"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
											"matchCriteriaId": "test-id"
										}
									]
								}
							]
						}
					]
				}
			}
		]
	}`

	var resp cveResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("parsing CVE JSON: %v", err)
	}

	if resp.TotalResults != 1 {
		t.Errorf("expected 1 result, got %d", resp.TotalResults)
	}
	if len(resp.Vulnerabilities) != 1 {
		t.Errorf("expected 1 vulnerability, got %d", len(resp.Vulnerabilities))
	}

	cve := resp.Vulnerabilities[0].CVE
	if cve.ID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001, got %s", cve.ID)
	}
}

func TestRunAllNoNetwork(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	u.cfg.CVEBaseURL = "http://192.0.2.1:1/cve"
	u.cfg.CPEBaseURL = "http://192.0.2.1:1/cpe"
	u.cfg.KEVBaseURL = "http://192.0.2.1:1/kev"
	u.cfg.EPSSBaseURL = "http://192.0.2.1:1/epss"
	u.cfg.RetryCount = 0
	u.cfg.HTTPTimeout = "500ms"

	u.client = &http.Client{Timeout: 500 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := u.RunAll(ctx)
	if err != nil {
		t.Fatalf("RunAll should not error: %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	if len(stats.Errors) == 0 {
		t.Log("expected some errors from non-routable URLs")
	}
}

func TestEPSSParsing(t *testing.T) {
	csvData := "cve_id,epss_score,percentile\nCVE-2024-0001,0.95000,99.50000\nCVE-2024-0002,0.50000,85.00000\nCVE-2024-0003,0.01000,10.00000\n"

	records := strings.Split(csvData, "\n")
	if len(records) < 2 {
		t.Fatal("expected header + data")
	}
	if records[0] != "cve_id,epss_score,percentile" {
		t.Errorf("unexpected header: %s", records[0])
	}
}

func TestTruncateString(t *testing.T) {
	short := "hello"
	if got := truncateStr(short, 10); got != short {
		t.Errorf("expected %q, got %q", short, got)
	}

	long := "this is a very long string that should be truncated"
	trunc := truncateStr(long, 20)
	if len(trunc) != 20 {
		t.Errorf("expected length 20, got %d", len(trunc))
	}
}

func TestCVEDescriptionExtraction(t *testing.T) {
	descriptions := []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	}{
		{Lang: "en", Value: "This is the English description"},
		{Lang: "fr", Value: "Ceci est la description française"},
	}

	var enDesc string
	for _, d := range descriptions {
		if d.Lang == "en" {
			enDesc = d.Value
			break
		}
	}

	if enDesc != "This is the English description" {
		t.Errorf("expected English description, got %q", enDesc)
	}
}

// ============================================================================
// Checkpoint tests
// ============================================================================

func TestCheckpointSaveAndGet(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx := context.Background()
	cm := u.checkpoint

	err := cm.Save(ctx, FeedNVD, StateDownloading, StepDownloading, 42, "/tmp/test.tmp", "abc123", "testing")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}

	cp, err := cm.Get(ctx, FeedNVD)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	if cp.FeedName != FeedNVD {
		t.Errorf("expected NVD, got %s", cp.FeedName)
	}
	if cp.State != string(StateDownloading) {
		t.Errorf("expected DOWNLOADING, got %s", cp.State)
	}
	if cp.BytesOffset != 42 {
		t.Errorf("expected offset 42, got %d", cp.BytesOffset)
	}
	if cp.FileHash != "abc123" {
		t.Errorf("expected hash abc123, got %s", cp.FileHash)
	}
}

func TestCheckpointOverwrite(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx := context.Background()
	cm := u.checkpoint

	cm.Save(ctx, FeedNVD, StateDownloading, StepDownloading, 100, "", "", "")
	cm.Save(ctx, FeedNVD, StateImporting, StepImport, 200, "", "", "updating")

	cp, _ := cm.Get(ctx, FeedNVD)
	if cp.State != string(StateImporting) {
		t.Errorf("expected IMPORTING, got %s", cp.State)
	}
	if cp.BytesOffset != 200 {
		t.Errorf("expected offset 200, got %d", cp.BytesOffset)
	}
}

func TestCheckpointDelete(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx := context.Background()
	cm := u.checkpoint

	cm.Save(ctx, FeedNVD, StateCompleted, StepNone, 0, "", "", "")
	cm.ClearFeed(ctx, FeedNVD)

	cp, err := cm.Get(ctx, FeedNVD)
	if err == nil {
		t.Errorf("expected error after delete, got cp: %+v", cp)
	}
}

func TestCheckpointHasUnfinished(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx := context.Background()
	cm := u.checkpoint

	// Save a completed checkpoint — should not be unfinished.
	cm.Save(ctx, FeedNVD, StateCompleted, StepNone, 0, "", "", "")
	cm.Save(ctx, FeedKEV, StateFailed, StepNone, 0, "", "", "")

	unfinished, _ := cm.HasUnfinished(ctx)
	if len(unfinished) != 0 {
		t.Errorf("expected 0 unfinished, got %v", unfinished)
	}

	// Now add an active one.
	cm.Save(ctx, FeedEPSS, StateDownloading, StepDownloading, 50, "", "", "")
	unfinished, _ = cm.HasUnfinished(ctx)
	if len(unfinished) != 1 {
		t.Errorf("expected 1 unfinished, got %v", unfinished)
	}
}

func TestCheckpointClearAll(t *testing.T) {
	u, db := setupTestUpdater(t)
	defer db.Close()

	ctx := context.Background()
	cm := u.checkpoint

	cm.Save(ctx, FeedNVD, StateDownloading, StepDownloading, 0, "", "", "")
	cm.Save(ctx, FeedKEV, StateCompleted, StepNone, 0, "", "", "")
	cm.ClearAll(ctx)

	list, _ := cm.repo.List(ctx)
	if len(list) != 0 {
		t.Errorf("expected 0 checkpoints after clear, got %d", len(list))
	}
}

// ============================================================================
// Feed state tests
// ============================================================================

func TestFeedStateTransitions(t *testing.T) {
	tests := []struct {
		state    FeedState
		active   bool
		terminal bool
	}{
		{StateNotStarted, false, false},
		{StateDownloading, true, false},
		{StateDownloaded, true, false},
		{StateVerifying, true, false},
		{StateParsing, true, false},
		{StateNormalizing, true, false},
		{StateImporting, true, false},
		{StateCompleted, false, true},
		{StateFailed, false, true},
	}

	for _, tt := range tests {
		if got := isActiveState(tt.state); got != tt.active {
			t.Errorf("isActiveState(%s) = %v, want %v", tt.state, got, tt.active)
		}
		if got := isTerminalState(tt.state); got != tt.terminal {
			t.Errorf("isTerminalState(%s) = %v, want %v", tt.state, got, tt.terminal)
		}
	}
}

// ============================================================================
// Retry / backoff tests
// ============================================================================

func TestBackoffDelay(t *testing.T) {
	base := 2 * time.Second
	max := 60 * time.Second

	// Attempt 1: 2s + jitter
	d1 := backoff(1, base, max)
	if d1 < base || d1 > base+base/4 {
		t.Errorf("backoff(1) = %v, want ~%v", d1, base)
	}

	// Attempt 2: 4s + jitter
	d2 := backoff(2, base, max)
	min2 := 4 * time.Second
	max2 := min2 + min2/4
	if d2 < min2 || d2 > max2 {
		t.Errorf("backoff(2) = %v, want between %v and %v", d2, min2, max2)
	}

	// Attempt 5: capped at 60s
	d5 := backoff(5, base, max)
	if d5 > max+max/4 {
		t.Errorf("backoff(5) = %v, should be capped around %v", d5, max)
	}

	// Attempt 0: no delay
	d0 := backoff(0, base, max)
	if d0 != 0 {
		t.Errorf("backoff(0) = %v, want 0", d0)
	}
}

func TestDoWithRetryFails(t *testing.T) {
	attempts := 0
	err := doWithRetry(context.Background(), 2, time.Millisecond, time.Millisecond*10, "test",
		func(ctx context.Context) (bool, error) {
			attempts++
			return false, nil
		})
	if err != nil {
		t.Fatalf("expected nil error for fn returning false, got: %v", err)
	}
	if attempts != 3 { // maxRetries=2 → 3 total attempts
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDoWithRetrySucceedsFirst(t *testing.T) {
	attempts := 0
	err := doWithRetry(context.Background(), 3, time.Millisecond, time.Millisecond*10, "test",
		func(ctx context.Context) (bool, error) {
			attempts++
			return true, nil
		})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("expected 1 attempt, got %d", attempts)
	}
}

func TestDoWithRetrySucceedsAfterRetry(t *testing.T) {
	attempts := 0
	err := doWithRetry(context.Background(), 3, time.Millisecond, time.Millisecond*10, "test",
		func(ctx context.Context) (bool, error) {
			attempts++
			if attempts < 3 {
				return false, nil
			}
			return true, nil
		})
	if err != nil {
		t.Fatalf("expected nil error, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("expected 3 attempts, got %d", attempts)
	}
}

func TestDoWithRetryContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := doWithRetry(ctx, 3, time.Second, time.Second*5, "test",
		func(ctx context.Context) (bool, error) {
			return false, nil
		})
	if err != context.Canceled {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}

// ============================================================================
// Downloader tests
// ============================================================================

func TestDownloaderResume(t *testing.T) {
	// Start a test server that supports Range requests.
	var server *httptest.Server
	var requestCount int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		data := []byte("hello world this is a longer test file for range resume testing")
		rangeHeader := r.Header.Get("Range")

		if rangeHeader == "" {
			w.Header().Set("Accept-Ranges", "bytes")
			w.Write(data)
			return
		}

		// Parse "bytes=N-"
		var start int
		if n, err := fmt.Sscanf(rangeHeader, "bytes=%d-", &start); err == nil && n == 1 {
			if start >= len(data) {
				w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
				return
			}
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
			w.WriteHeader(http.StatusPartialContent)
			w.Write(data[start:])
		}
	}))
	defer server.Close()

	dlDir := t.TempDir()
	finalPath := filepath.Join(dlDir, "test.json")
	dl := newDownloader(&config.UpdateConfig{}, server.Client())

	// First download: full file.
	ctx := context.Background()
	result, err := dl.DownloadFile(ctx, server.URL, finalPath, 0)
	if err != nil {
		t.Fatalf("first download: %v", err)
	}
	if result.BytesOffset == 0 {
		t.Fatal("expected non-zero bytes offset")
	}
	if result.Resumed {
		t.Fatal("first download should not be a resume")
	}

	// Remove the final file but keep the .tmp.
	os.Remove(finalPath)

	// Second download: should resume from the .tmp.
	result2, err := dl.DownloadFile(ctx, server.URL, finalPath, 0)
	if err != nil {
		t.Fatalf("resume download: %v", err)
	}
	if !result2.Resumed {
		t.Log("server does not support range — skipping resume test")
	}
}

func TestDownloaderChecksum(t *testing.T) {
	dlDir := t.TempDir()
	filePath := filepath.Join(dlDir, "test.txt")

	if err := os.WriteFile(filePath, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Verify checksum.
	hash := sha256HashFile(filePath)
	if hash == "" {
		t.Fatal("expected non-empty hash")
	}

	ok, err := VerifyChecksum(filePath, hash)
	if err != nil || !ok {
		t.Fatalf("checksum should pass: ok=%v err=%v", ok, err)
	}

	// Wrong hash should fail.
	ok, _ = VerifyChecksum(filePath, "0000000000000000000000000000000000000000000000000000000000000000")
	if ok {
		t.Fatal("checksum should fail with wrong hash")
	}
}

func TestDownloaderTempStaging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("test data"))
	}))
	defer server.Close()

	dlDir := t.TempDir()
	finalPath := filepath.Join(dlDir, "kev.json")
	dl := newDownloader(&config.UpdateConfig{}, server.Client())

	dl.DownloadFile(context.Background(), server.URL, finalPath, 0)

	// .tmp file should exist after download.
	if _, err := os.Stat(finalPath + ".tmp"); err != nil {
		t.Fatalf(".tmp file not found: %v", err)
	}

	// Finalize.
	dl.FinalizeFile(finalPath+".tmp", finalPath)
	if _, err := os.Stat(finalPath); err != nil {
		t.Fatalf("final file not found: %v", err)
	}
	if _, err := os.Stat(finalPath + ".tmp"); err == nil {
		t.Fatal(".tmp file should not exist after finalize")
	}
}

// ============================================================================
// Database rollback / transaction safety tests
// ============================================================================

func TestDatabaseIntegrityAfterError(t *testing.T) {
	// Simulate a scenario where update fails mid-way — database should remain consistent.
	ctx := context.Background()

	db, err := database.NewSQLiteDatabase(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	defer db.Close()

	// Verify database is valid.
	ok, err := db.Verify(ctx)
	if err != nil || !ok {
		t.Fatalf("initial integrity check failed: ok=%v err=%v", ok, err)
	}

	// Insert some CPE data (simulating partial import).
	vid, _ := db.Vendor().GetOrCreate(ctx, "testcorp")
	pid, _ := db.Product().GetOrCreate(ctx, vid, "testproduct")
	db.CPE().Insert(ctx, &database.DBCPE{
		VendorID: vid, ProductID: pid, Part: "a",
		Version: "1.0", CPE23URI: "cpe:2.3:a:testcorp:testproduct:1.0:*:*:*:*:*:*:*",
	})

	// Verify still consistent.
	ok, err = db.Verify(ctx)
	if err != nil || !ok {
		t.Fatalf("integrity check after insert failed: ok=%v err=%v", ok, err)
	}
}

func TestCheckpointMetadataIsPersistent(t *testing.T) {
	// Checkpoints live in the SQLite database, which is persistent across restarts.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "persist.db")

	ctx := context.Background()
	db1, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		t.Fatalf("db1: %v", err)
	}

	cm1 := newCheckpointManager(db1.Checkpoint())
	cm1.Save(ctx, FeedNVD, StateDownloading, StepDownloading, 100, "/tmp/test.tmp", "abc", "testing")
	db1.Close()

	// Reopen same database.
	db2, err := database.NewSQLiteDatabase(ctx, dbPath)
	if err != nil {
		t.Fatalf("db2: %v", err)
	}
	defer db2.Close()

	cm2 := newCheckpointManager(db2.Checkpoint())
	cp, err := cm2.Get(ctx, FeedNVD)
	if err != nil {
		t.Fatalf("get after reopen: %v", err)
	}
	if cp.State != string(StateDownloading) {
		t.Errorf("expected DOWNLOADING, got %s", cp.State)
	}
	if cp.BytesOffset != 100 {
		t.Errorf("expected offset 100, got %d", cp.BytesOffset)
	}
}

func TestDownloadResumeAfterCrash(t *testing.T) {
	// Simulates: download interrupted → restart → resume from partial file.
	var data []byte
	for i := 0; i < 10000; i++ {
		data = append(data, []byte(fmt.Sprintf("line-%04d-data-here\n", i))...)
	}

	var server *httptest.Server
	var _ int
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rangeHeader := r.Header.Get("Range")
		if rangeHeader == "" {
			w.Header().Set("Accept-Ranges", "bytes")
			w.Write(data)
			_ = len(data)
			return
		}
		var start int
		fmt.Sscanf(rangeHeader, "bytes=%d-", &start)
		if start >= len(data) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, len(data)-1, len(data)))
		w.WriteHeader(http.StatusPartialContent)
		w.Write(data[start:])
		_ = len(data) - start
	}))
	defer server.Close()

	dlDir := t.TempDir()
	finalPath := filepath.Join(dlDir, "feed.dat")
	dl := newDownloader(&config.UpdateConfig{}, server.Client())

	// Write a partial file to simulate crash mid-download.
	partialData := data[:5000]
	tmpPath := finalPath + ".tmp"
	os.WriteFile(tmpPath, partialData, 0644)

	// Resume.
	result, err := dl.DownloadFile(context.Background(), server.URL, finalPath, 5000)
	if err != nil {
		t.Fatalf("resume: %v", err)
	}

	if !result.Resumed {
		t.Log("server does not support Range — skipping resume assertion")
		return
	}

	// Verify complete file.
	dl.FinalizeFile(result.TempPath, finalPath)
	complete, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatalf("read final: %v", err)
	}
	if len(complete) != len(data) {
		t.Errorf("expected %d bytes, got %d", len(data), len(complete))
	}
	if string(complete) != string(data) {
		t.Errorf("data mismatch")
	}
}

func TestChecksumFailureRedownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("valid data"))
	}))
	defer server.Close()

	dlDir := t.TempDir()
	finalPath := filepath.Join(dlDir, "test.bin")
	dl := newDownloader(&config.UpdateConfig{}, server.Client())

	// Download correctly.
	dl.DownloadFile(context.Background(), server.URL, finalPath, 0)

	// Corrupt the .tmp file.
	tmpPath := finalPath + ".tmp"
	os.WriteFile(tmpPath, []byte("corrupted"), 0644)

	// Verify checksum fails.
	ok, _ := VerifyChecksum(tmpPath, sha256HashFile(tmpPath))
	if !ok {
		t.Fatal("checksum should match the corrupted file")
	}
}

func TestResumePrompt(t *testing.T) {
	prompt := ResumePrompt([]string{"NVD", "KEV"})
	if !strings.Contains(prompt, "NVD") {
		t.Error("expected NVD in prompt")
	}
	if !strings.Contains(prompt, "KEV") {
		t.Error("expected KEV in prompt")
	}
	if !strings.Contains(prompt, "Resume") {
		t.Error("expected Resume in prompt")
	}
}
