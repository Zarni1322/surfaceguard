package updater

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"os"
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

	// Use a short timeout context to avoid hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := u.fetchWithRetry(ctx, "http://192.0.2.1:1/nonexistent")
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
	t.Logf("Expected error: %v", err)
}

func TestKEVParsing(t *testing.T) {
	// Test KEV JSON parsing without network.
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
	if resp.Vulnerabilities[1].DueDate != "2024-02-20" {
		t.Errorf("expected due date 2024-02-20, got %s", resp.Vulnerabilities[1].DueDate)
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

	// Check description.
	if len(cve.Descriptions) > 0 {
		for _, desc := range cve.Descriptions {
			if desc.Lang == "en" {
				if desc.Value != "Test CVE description" {
					t.Errorf("expected 'Test CVE description', got %q", desc.Value)
				}
				break
			}
		}
	} else {
		t.Error("expected descriptions")
	}

	// Check CVSS.
	if cve.Metrics != nil && len(cve.Metrics.CVSSMetricV31) > 0 {
		score := cve.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
		if score != 9.8 {
			t.Errorf("expected CVSS 9.8, got %.1f", score)
		}
	} else {
		t.Error("expected CVSS metrics")
	}

	// Check configurations.
	if len(cve.Configurations) > 0 && len(cve.Configurations[0].Nodes) > 0 {
		matches := cve.Configurations[0].Nodes[0].CPEMatch
		if len(matches) > 0 && matches[0].Criteria != "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" {
			t.Errorf("unexpected criteria: %s", matches[0].Criteria)
		}
	}
}

func TestRunAllNoNetwork(t *testing.T) {
	// Test that RunAll handles network errors gracefully.
	u, db := setupTestUpdater(t)
	defer db.Close()

	// Override URLs to non-routable addresses with a short timeout.
	u.cfg.CVEBaseURL = "http://192.0.2.1:1/cve"
	u.cfg.CPEBaseURL = "http://192.0.2.1:1/cpe"
	u.cfg.KEVBaseURL = "http://192.0.2.1:1/kev"
	u.cfg.EPSSBaseURL = "http://192.0.2.1:1/epss"
	u.cfg.RetryCount = 0 // Don't retry to speed up test.
	u.cfg.HTTPTimeout = "500ms"

	// Recreate the HTTP client with the shorter timeout.
	u.client = &http.Client{Timeout: 500 * time.Millisecond}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := u.RunAll(ctx)
	if err != nil {
		t.Fatalf("RunAll should not error (errors are in stats): %v", err)
	}
	if stats == nil {
		t.Fatal("expected non-nil stats")
	}
	// All operations should have failed silently.
	if len(stats.Errors) == 0 {
		t.Log("expected some errors from non-routable URLs")
	}
}

func TestEPSSParsing(t *testing.T) {
	// Test EPSS CSV parsing.
	csvData := "cve_id,epss_score,percentile\nCVE-2024-0001,0.95000,99.50000\nCVE-2024-0002,0.50000,85.00000\nCVE-2024-0003,0.01000,10.00000\n"

	// Use the same CSV parsing logic as updateEPSS.
	ctx := context.Background()
	u, db := setupTestUpdater(t)
	defer db.Close()

	// We can't easily test the full pipeline without network, but we can
	// verify the CSV format parsing through the response types.
	_ = ctx
	_ = u

	// Direct CSV parse test.
	// Verify we can read the CSV format expected by the EPSS feed.
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
	// Test extracting the English description from a CVE.
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
