package scanner

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/evilhunter/surfaceguard/internal/config"
	"github.com/evilhunter/surfaceguard/internal/database"
	"github.com/evilhunter/surfaceguard/internal/matcher"
	"github.com/evilhunter/surfaceguard/pkg/models"
)

func setupTestScanner(t *testing.T) (*Scanner, database.Database) {
	t.Helper()
	ctx := context.Background()

	// Use config with defaults.
	cfg := config.DefaultConfig()
	cfg.Scan.Timeout = 500 * time.Millisecond

	// Create in-memory database.
	db, err := database.NewSQLiteDatabase(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}

	m := matcher.New(db)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	return New(cfg, m, logger), db
}

func TestNewScanner(t *testing.T) {
	s, db := setupTestScanner(t)
	defer db.Close()

	if s == nil {
		t.Fatal("expected non-nil scanner")
	}
}

func TestScanCancelledContext(t *testing.T) {
	s, db := setupTestScanner(t)
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	target := &models.Target{
		Raw:   "127.0.0.1",
		Hosts: []string{"127.0.0.1"},
	}
	opts := models.DefaultScanOptions()
	opts.Ports = []int{80, 443}

	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		t.Fatalf("Scan with cancelled context should not error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestScanLocalhost(t *testing.T) {
	s, db := setupTestScanner(t)
	defer db.Close()

	ctx := context.Background()
	target := &models.Target{
		Raw:   "127.0.0.1",
		Hosts: []string{"127.0.0.1"},
	}
	opts := models.DefaultScanOptions()
	opts.Ports = []int{22, 80, 443, 8080, 9090}

	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	t.Logf("Scan result: %s", result.Summary())
	t.Logf("Open ports: %d", len(result.OpenPorts))
	for _, p := range result.OpenPorts {
		t.Logf("  Port %d: %s (service=%s, product=%s, version=%s)",
			p.Port, p.State, p.Service, p.Product, p.Version)
	}
}

func TestScanWithDBData(t *testing.T) {
	ctx := context.Background()
	cfg := config.DefaultConfig()
	cfg.Scan.Timeout = 500 * time.Millisecond

	db, err := database.NewSQLiteDatabase(ctx, t.TempDir()+"/test.db")
	if err != nil {
		t.Fatalf("NewSQLiteDatabase: %v", err)
	}
	defer db.Close()

	// Seed vulnerability data.
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "openbsd")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "openssh")
	db.CPE().Insert(ctx, &database.DBCPE{
		VendorID: vendorID, ProductID: productID, Part: "a", Version: "8.9p1",
		CPE23URI: "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*",
	})
	db.CPE().Insert(ctx, &database.DBCPE{
		VendorID: vendorID, ProductID: productID, Part: "a", Version: "*",
		CPE23URI: "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*",
	})

	// Get CPE IDs.
	cpeList, _ := db.CPE().FindByProduct(ctx, "openbsd", "openssh", "8.9p1")
	for _, cpe := range cpeList {
		db.CVE().Upsert(ctx, &database.DBCVE{
			CVEID: "CVE-2024-TEST1", CPEID: cpe.ID,
			Description: "Test SSH vulnerability",
			CVSSv3:      float64Ptr(7.5), Severity: "HIGH",
			PublishedDate: time.Now(), LastModifiedDate: time.Now(),
		})
	}

	m := matcher.New(db)
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := New(cfg, m, logger)

	target := &models.Target{
		Raw:   "127.0.0.1",
		Hosts: []string{"127.0.0.1"},
	}
	opts := models.DefaultScanOptions()
	opts.Ports = []int{22}

	result, err := s.Scan(ctx, target, opts)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	t.Logf("Scan result: %s", result.Summary())
	for _, f := range result.Findings {
		t.Logf("  Finding: %s (CVSS: %.1f, Severity: %s)",
			f.CVE.ID, *f.CVE.CVSSv3, f.CVE.Severity)
	}
}

func TestGetSummary(t *testing.T) {
	s, db := setupTestScanner(t)
	defer db.Close()

	result := &models.ScanResult{
		Target:    models.Target{Raw: "test.example.com", Hosts: []string{"10.0.0.1"}},
		StartedAt: time.Now(),
		Duration:  time.Second,
		OpenPorts: []models.Port{{Port: 80}},
		Findings: []models.Finding{
			{CVE: models.CVE{ID: "CVE-2024-0001", Severity: "CRITICAL"}},
		},
	}

	summary := s.GetSummary(result)
	if len(summary) == 0 {
		t.Fatal("expected non-empty summary")
	}
	if summary != result.Summary() {
		t.Errorf("expected '%s', got '%s'", result.Summary(), summary)
	}
}

func float64Ptr(v float64) *float64 {
	return &v
}
