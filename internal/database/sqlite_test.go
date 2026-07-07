package database
import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)
func setupTestDB(t *testing.T) (Database, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")
	db, err := NewSQLiteDatabase(context.Background(), path)
	if err != nil {
		t.Fatalf("NewSQLiteDatabase failed: %v", err)
	}
	return db, path
}
func TestNewSQLiteDatabase(t *testing.T) {
	db, path := setupTestDB(t)
	defer db.Close()
	// Verify the database file was created.
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatal("database file should exist")
	}
	// Verify metadata was seeded.
	info, err := db.Info(context.Background())
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}
	if info.SchemaVersion != 5 {
		t.Errorf("expected schema version 2, got %d", info.SchemaVersion)
	}
}
func TestVendorGetOrCreate(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	id, err := db.Vendor().GetOrCreate(ctx, "apache")
	if err != nil {
		t.Fatalf("GetOrCreate failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive id, got %d", id)
	}
	// Same name should return same ID.
	id2, err := db.Vendor().GetOrCreate(ctx, "apache")
	if err != nil {
		t.Fatalf("GetOrCreate duplicate failed: %v", err)
	}
	if id != id2 {
		t.Errorf("expected same id %d for duplicate, got %d", id, id2)
	}
	// Case insensitive.
	id3, err := db.Vendor().GetOrCreate(ctx, "APACHE")
	if err != nil {
		t.Fatalf("GetOrCreate case insensitive failed: %v", err)
	}
	if id != id3 {
		t.Errorf("expected same id %d for case-insensitive, got %d", id, id3)
	}
}
func TestVendorListAndCount(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	for _, name := range []string{"apache", "microsoft", "oracle"} {
		_, err := db.Vendor().GetOrCreate(ctx, name)
		if err != nil {
			t.Fatalf("GetOrCreate %s failed: %v", name, err)
		}
	}
	count, err := db.Vendor().Count(ctx)
	if err != nil {
		t.Fatalf("Count failed: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 vendors, got %d", count)
	}
	vendors, err := db.Vendor().List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(vendors) != 3 {
		t.Errorf("expected 3 vendors in list, got %d", len(vendors))
	}
}
func TestProductGetOrCreate(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, err := db.Vendor().GetOrCreate(ctx, "apache")
	if err != nil {
		t.Fatalf("GetOrCreate vendor failed: %v", err)
	}
	prodID, err := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	if err != nil {
		t.Fatalf("GetOrCreate product failed: %v", err)
	}
	if prodID <= 0 {
		t.Errorf("expected positive product id, got %d", prodID)
	}
	// Duplicate should return same ID.
	prodID2, err := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	if err != nil {
		t.Fatalf("GetOrCreate duplicate product failed: %v", err)
	}
	if prodID != prodID2 {
		t.Errorf("expected same product id %d, got %d", prodID, prodID2)
	}
}
func TestCPEInsertAndFind(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpe := &DBCPE{
		VendorID:  vendorID,
		ProductID: productID,
		Part:      "a",
		Version:   "2.4.49",
		CPE23URI:  "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*",
	}
	id, err := db.CPE().Insert(ctx, cpe)
	if err != nil {
		t.Fatalf("Insert CPE failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive CPE id, got %d", id)
	}
	// Duplicate URI should fail.
	_, err = db.CPE().Insert(ctx, cpe)
	if err == nil {
		t.Error("expected error for duplicate CPE URI")
	}
	// Find by product.
	cpes, err := db.CPE().FindByProduct(ctx, "apache", "http_server", "2.4.49")
	if err != nil {
		t.Fatalf("FindByProduct failed: %v", err)
	}
	if len(cpes) != 1 {
		t.Errorf("expected 1 CPE, got %d", len(cpes))
	}
	// Exists by URI.
	exists, err := db.CPE().ExistsByURI(ctx, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("ExistsByURI failed: %v", err)
	}
	if !exists {
		t.Error("expected CPE to exist")
	}
}
func TestCPEBulkInsert(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpes := []DBCPE{
		{VendorID: vendorID, ProductID: productID, Part: "a", Version: "2.4.0", CPE23URI: "cpe:2.3:a:apache:http_server:2.4.0:*:*:*:*:*:*"},
		{VendorID: vendorID, ProductID: productID, Part: "a", Version: "2.4.1", CPE23URI: "cpe:2.3:a:apache:http_server:2.4.1:*:*:*:*:*:*"},
		{VendorID: vendorID, ProductID: productID, Part: "a", Version: "2.4.2", CPE23URI: "cpe:2.3:a:apache:http_server:2.4.2:*:*:*:*:*:*"},
	}
	inserted, err := db.CPE().BulkInsert(ctx, cpes)
	if err != nil {
		t.Fatalf("BulkInsert failed: %v", err)
	}
	if inserted != 3 {
		t.Errorf("expected 3 inserted, got %d", inserted)
	}
	count, _ := db.CPE().Count(ctx)
	if count != 3 {
		t.Errorf("expected 3 CPEs total, got %d", count)
	}
}
func TestCVEUpsert(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	cve := &DBCVE{
		CVEID:            "CVE-2024-0001",
		CPEID:            cpeID,
		Description:      "Test vulnerability",
		CVSSv3:           float64Ptr(9.8),
		Severity:         "CRITICAL",
		PublishedDate:    time.Now().Add(-24 * time.Hour),
		LastModifiedDate: time.Now(),
		ReferencesJSON:   `["https://example.com/cve-2024-0001"]`,
	}
	id, isNew, err := db.CVE().Upsert(ctx, cve)
	if err != nil {
		t.Fatalf("Upsert CVE failed: %v", err)
	}
	if id <= 0 {
		t.Errorf("expected positive id, got %d", id)
	}
	if !isNew {
		t.Error("expected insert, not update")
	}
	// Update.
	cve.Description = "Updated description"
	_, isNew, err = db.CVE().Upsert(ctx, cve)
	if err != nil {
		t.Fatalf("Upsert update failed: %v", err)
	}
	if isNew {
		t.Error("expected update, not insert")
	}
	// Verify update.
	found, err := db.CVE().FindByCVEID(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("FindByCVEID failed: %v", err)
	}
	if found.Description != "Updated description" {
		t.Errorf("expected updated description, got %s", found.Description)
	}
}
func TestFindByCPEID(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-0001", CPEID: cpeID, Description: "Test",
		CVSSv3: float64Ptr(7.5), Severity: "HIGH",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	cves, err := db.CVE().FindByCPEID(ctx, cpeID)
	if err != nil {
		t.Fatalf("FindByCPEID failed: %v", err)
	}
	if len(cves) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(cves))
	}
}
func TestKEV(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-0001", CPEID: cpeID, Severity: "HIGH",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	_, _, err := db.KEV().Upsert(ctx, &DBKEV{CVEID: "CVE-2024-0001", DueDate: "2024-06-01", Notes: "Under active exploit"})
	if err != nil {
		t.Fatalf("KEV Upsert failed: %v", err)
	}
	inKEV, err := db.KEV().IsInKEV(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("IsInKEV failed: %v", err)
	}
	if !inKEV {
		t.Error("expected CVE to be in KEV")
	}
	count, _ := db.KEV().Count(ctx)
	if count != 1 {
		t.Errorf("expected 1 KEV entry, got %d", count)
	}
}
func TestEPSS(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-0001", CPEID: cpeID, Severity: "HIGH",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	_, _, err := db.EPSS().Upsert(ctx, &DBEpss{CVEID: "CVE-2024-0001", Score: 0.95, Percentile: 99.5})
	if err != nil {
		t.Fatalf("EPSS Upsert failed: %v", err)
	}
	epss, err := db.EPSS().GetByCVEID(ctx, "CVE-2024-0001")
	if err != nil {
		t.Fatalf("GetByCVEID failed: %v", err)
	}
	if epss.Score != 0.95 {
		t.Errorf("expected score 0.95, got %f", epss.Score)
	}
	count, _ := db.EPSS().Count(ctx)
	if count != 1 {
		t.Errorf("expected 1 EPSS entry, got %d", count)
	}
}
func TestMetadata(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	err := db.Metadata().Set(ctx, "test_key", "test_value")
	if err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	val, err := db.Metadata().Get(ctx, "test_key")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if val != "test_value" {
		t.Errorf("expected 'test_value', got '%s'", val)
	}
	items, err := db.Metadata().List(ctx)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	found := false
	for _, item := range items {
		if item.Key == "test_key" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected test_key in metadata list")
	}
	err = db.Metadata().Delete(ctx, "test_key")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	_, err = db.Metadata().Get(ctx, "test_key")
	if err == nil {
		t.Error("expected error for deleted key")
	}
}
func TestInfo(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	info, err := db.Info(ctx)
	if err != nil {
		t.Fatalf("Info failed: %v", err)
	}
	if info.SchemaVersion != 5 {
		t.Errorf("expected schema version 2, got %d", info.SchemaVersion)
	}
}
func TestVerify(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	ok, err := db.Verify(ctx)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !ok {
		t.Error("expected integrity check to pass")
	}
}
func TestVacuum(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	if err := db.Vacuum(ctx); err != nil {
		t.Fatalf("Vacuum failed: %v", err)
	}
}
func TestToDomainCVE(t *testing.T) {
	now := time.Now()
	dbCVE := &DBCVE{
		CVEID:       "CVE-2024-0001",
		Description: "Test",
		CVSSv3:      float64Ptr(9.8),
		Severity:    "CRITICAL",
		PublishedDate:    now,
		LastModifiedDate: now,
		ReferencesJSON:   `["https://example.com"]`,
	}
	
	dbKEV := &DBKEV{DueDate: "2024-06-01", Notes: "test"}
	dbEpss := &DBEpss{Score: 0.95, Percentile: 99.0}
	cve := ToDomainCVE(dbCVE, dbKEV, dbEpss)
	if !cve.IsInKEV {
		t.Error("expected IsInKEV=true")
	}
	if cve.EPSSScore == nil || *cve.EPSSScore != 0.95 {
		t.Errorf("expected EPSS score 0.95, got %v", cve.EPSSScore)
	}
	if len(cve.References) != 1 {
		t.Errorf("expected 1 reference, got %d", len(cve.References))
	}
}
func TestConcurrentReads(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	// Seed data.
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "test_vendor")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "test_product")
	cpeID := insertTestCPE(t, db, vendorID, productID, "1.0.0")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-TEST", CPEID: cpeID, Severity: "MEDIUM",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	// Launch concurrent readers.
	done := make(chan bool, 5)
	for i := 0; i < 5; i++ {
		go func() {
			_, err := db.Info(ctx)
			done <- err == nil
		}()
	}
	for i := 0; i < 5; i++ {
		if !<-done {
			t.Error("concurrent read failed")
		}
	}
}
func TestSearchByProduct(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-X1", CPEID: cpeID, Description: "vuln1",
		CVSSv3: float64Ptr(5.0), Severity: "MEDIUM",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-X2", CPEID: cpeID, Description: "vuln2",
		CVSSv3: float64Ptr(9.0), Severity: "CRITICAL",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	// Should find both.
	cves, err := db.CVE().SearchByProduct(ctx, "apache", "http_server")
	if err != nil {
		t.Fatalf("SearchByProduct failed: %v", err)
	}
	if len(cves) != 2 {
		t.Errorf("expected 2 CVEs, got %d", len(cves))
	}
	// First should be the highest CVSS (CRITICAL -> 9.0).
	if cves[0].CVSSv3 == nil || *cves[0].CVSSv3 != 9.0 {
		t.Errorf("expected highest CVSS first, got %v", cves[0].CVSSv3)
	}
}
func TestCVECountBySeverity(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	for i, sev := range []string{"CRITICAL", "HIGH", "CRITICAL", "MEDIUM"} {
		db.CVE().Upsert(ctx, &DBCVE{
			CVEID: fmt.Sprintf("CVE-2024-S%d", i), CPEID: cpeID,
			Severity: sev, PublishedDate: time.Now(), LastModifiedDate: time.Now(),
		})
	}
	counts, err := db.CVE().CountBySeverity(ctx)
	if err != nil {
		t.Fatalf("CountBySeverity failed: %v", err)
	}
	if counts["CRITICAL"] != 2 {
		t.Errorf("expected 2 CRITICAL, got %d", counts["CRITICAL"])
	}
	if counts["HIGH"] != 1 {
		t.Errorf("expected 1 HIGH, got %d", counts["HIGH"])
	}
}
func TestFindByCPE23URI(t *testing.T) {
	db, _ := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	vendorID, _ := db.Vendor().GetOrCreate(ctx, "apache")
	productID, _ := db.Product().GetOrCreate(ctx, vendorID, "http_server")
	cpeID := insertTestCPE(t, db, vendorID, productID, "2.4.49")
	db.CVE().Upsert(ctx, &DBCVE{
		CVEID: "CVE-2024-U1", CPEID: cpeID, Description: "via CPE URI",
		CVSSv3: float64Ptr(7.5), Severity: "HIGH",
		PublishedDate: time.Now(), LastModifiedDate: time.Now(),
	})
	cves, err := db.CVE().FindByCPE23URI(ctx, "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*")
	if err != nil {
		t.Fatalf("FindByCPE23URI failed: %v", err)
	}
	if len(cves) != 1 {
		t.Errorf("expected 1 CVE, got %d", len(cves))
	}
}
// -- Helpers ----------------------------------------------------------------
func insertTestCPE(t *testing.T, db Database, vendorID, productID int64, version string) int64 {
	t.Helper()
	uri := fmt.Sprintf("cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*", version)
	id, err := db.CPE().Insert(context.Background(), &DBCPE{
		VendorID:  vendorID,
		ProductID: productID,
		Part:      "a",
		Version:   version,
		CPE23URI:  uri,
	})
	if err != nil {
		t.Fatalf("insertTestCPE failed: %v", err)
	}
	return id
}
func float64Ptr(v float64) *float64 {
	return &v
}
