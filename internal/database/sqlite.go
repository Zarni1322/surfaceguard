// Package database implements the repository layer using SQLite via
// modernc.org/sqlite (a pure-Go SQLite driver, no CGO dependency).
//
// Schema design rationale:
//   - vendors and products are normalized to reduce storage and improve
//     query performance when matching thousands of CPE/CVE records.
//   - cpe table links to both vendor and product for direct lookups
//     without joins in the common path.
//   - cves references cpe.id, so one CVE appearing for multiple CPEs
//     (different versions, platforms) appears as separate rows — this
//     simplifies matching and preserves the NVD data model.
//   - UNIQUE constraints prevent duplicates during incremental updates.
//   - metadata table uses key-value for schema version, last_update, etc.
//     — flexible and trivially extensible.
package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"

	// Pure-Go SQLite driver (no CGO).
	_ "modernc.org/sqlite"
)

// Compile-time check: *sqliteDB implements Database.
var _ Database = (*sqliteDB)(nil)

// sqliteDB is the concrete SQLite-backed Database implementation.
type sqliteDB struct {
	db *sql.DB

	vendorRepo  *sqliteVendorRepo
	productRepo *sqliteProductRepo
	cpeRepo     *sqliteCPERepo
	cveRepo     *sqliteCVERepo
	kevRepo     *sqliteKEVRepo
	epssRepo    *sqliteEPSSRepo
	metaRepo    *sqliteMetadataRepo

	mu sync.RWMutex
}

// NewSQLiteDatabase opens (or creates) the SQLite database at the given path,
// applies all pending migrations, and returns a fully initialised Database.
func NewSQLiteDatabase(ctx context.Context, path string) (Database, error) {
	dsn := fmt.Sprintf("%s?_journal_mode=WAL&_busy_timeout=5000", path)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	// SQLite-specific pragmas for performance and safety.
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
		"PRAGMA cache_size=-8000",       // 8MB cache
		"PRAGMA temp_store=MEMORY",
	}
	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting pragma %s: %w", pragma, err)
		}
	}

	sqlite := &sqliteDB{db: db}
	sqlite.vendorRepo = &sqliteVendorRepo{db: db}
	sqlite.productRepo = &sqliteProductRepo{db: db}
	sqlite.cpeRepo = &sqliteCPERepo{db: db}
	sqlite.cveRepo = &sqliteCVERepo{db: db}
	sqlite.kevRepo = &sqliteKEVRepo{db: db}
	sqlite.epssRepo = &sqliteEPSSRepo{db: db}
	sqlite.metaRepo = &sqliteMetadataRepo{db: db}

	// Run migrations.
	if err := sqlite.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration: %w", err)
	}

	return sqlite, nil
}

// migrate applies schema migrations incrementally.
func (s *sqliteDB) migrate(ctx context.Context) error {
	// Create the metadata table first (it's referenced in migration tracking).
	if _, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS metadata (
			key   TEXT NOT NULL PRIMARY KEY,
			value TEXT NOT NULL
		)
	`); err != nil {
		return fmt.Errorf("creating metadata table: %w", err)
	}

	// Get current schema version.
	currentVersion := 0
	versionStr, err := s.metaRepo.Get(ctx, "schema_version")
	if err == nil && versionStr != "" {
		fmt.Sscanf(versionStr, "%d", &currentVersion)
	}

	// Apply each pending migration.
	for v := currentVersion + 1; v <= schemaVersion; v++ {
		stmt, ok := schema[v]
		if !ok {
			continue
		}
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("applying migration v%d: %w", v, err)
		}
		if err := s.metaRepo.Set(ctx, "schema_version", fmt.Sprintf("%d", v)); err != nil {
			return fmt.Errorf("updating schema version to %d: %w", v, err)
		}
	}

	return nil
}

// ============================================================================
// Repository accessors
// ============================================================================

func (s *sqliteDB) Vendor() VendorRepository     { return s.vendorRepo }
func (s *sqliteDB) Product() ProductRepository   { return s.productRepo }
func (s *sqliteDB) CPE() CPERepository           { return s.cpeRepo }
func (s *sqliteDB) CVE() CVERepository           { return s.cveRepo }
func (s *sqliteDB) KEV() KEVRepository           { return s.kevRepo }
func (s *sqliteDB) EPSS() EPSSRepository         { return s.epssRepo }
func (s *sqliteDB) Metadata() MetadataRepository { return s.metaRepo }

// Info returns aggregate database statistics.
func (s *sqliteDB) Info(ctx context.Context) (*models.DatabaseInfo, error) {
	info := &models.DatabaseInfo{}

	var err error
	info.VendorCount, err = s.vendorRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting vendors: %w", err)
	}
	info.ProductCount, err = s.productRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting products: %w", err)
	}
	info.CPECount, err = s.cpeRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting cpes: %w", err)
	}
	info.CVECount, err = s.cveRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting cves: %w", err)
	}
	info.KEVCount, err = s.kevRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting kev: %w", err)
	}
	info.EPSSCount, err = s.epssRepo.Count(ctx)
	if err != nil {
		return nil, fmt.Errorf("counting epss: %w", err)
	}

	versionStr, err := s.metaRepo.Get(ctx, "schema_version")
	if err == nil {
		fmt.Sscanf(versionStr, "%d", &info.SchemaVersion)
	}

	lastUpdateStr, err := s.metaRepo.Get(ctx, "last_update")
	if err == nil && lastUpdateStr != "" {
		if t, parseErr := time.Parse(time.RFC3339, lastUpdateStr); parseErr == nil {
			info.LastUpdated = t
		}
	}

	return info, nil
}

// Verify runs SQLite integrity check.
func (s *sqliteDB) Verify(ctx context.Context) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result string
	err := s.db.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&result)
	if err != nil {
		return false, fmt.Errorf("integrity check: %w", err)
	}
	return strings.EqualFold(result, "ok"), nil
}

// Vacuum reclaims unused space.
func (s *sqliteDB) Vacuum(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
		return fmt.Errorf("vacuum: %w", err)
	}
	return nil
}

// Close cleanly shuts down the database.
func (s *sqliteDB) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.db.Close()
}

// ============================================================================
// Repository Implementations
// ============================================================================

// -- Vendor Repository -------------------------------------------------------

type sqliteVendorRepo struct{ db *sql.DB }

func (r *sqliteVendorRepo) GetOrCreate(ctx context.Context, name string) (int64, error) {
	// Try INSERT first to avoid a separate SELECT in the common case.
	result, err := r.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO vendors (name) VALUES (?)", strings.ToLower(name))
	if err != nil {
		return 0, fmt.Errorf("insert vendor: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	if id > 0 {
		return id, nil
	}
	// Already existed — fetch its ID.
	err = r.db.QueryRowContext(ctx, "SELECT id FROM vendors WHERE name = ?",
		strings.ToLower(name)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("select vendor: %w", err)
	}
	return id, nil
}

func (r *sqliteVendorRepo) List(ctx context.Context) ([]DBVendor, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id, name FROM vendors ORDER BY name")
	if err != nil {
		return nil, fmt.Errorf("list vendors: %w", err)
	}
	defer rows.Close()

	var vendors []DBVendor
	for rows.Next() {
		var v DBVendor
		if err := rows.Scan(&v.ID, &v.Name); err != nil {
			return nil, fmt.Errorf("scan vendor: %w", err)
		}
		vendors = append(vendors, v)
	}
	return vendors, rows.Err()
}

func (r *sqliteVendorRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vendors").Scan(&count)
	return count, err
}

// -- Product Repository ------------------------------------------------------

type sqliteProductRepo struct{ db *sql.DB }

func (r *sqliteProductRepo) GetOrCreate(ctx context.Context, vendorID int64, name string) (int64, error) {
	result, err := r.db.ExecContext(ctx,
		"INSERT OR IGNORE INTO products (vendor_id, name) VALUES (?, ?)",
		vendorID, strings.ToLower(name))
	if err != nil {
		return 0, fmt.Errorf("insert product: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("last insert id: %w", err)
	}
	if id > 0 {
		return id, nil
	}
	err = r.db.QueryRowContext(ctx,
		"SELECT id FROM products WHERE vendor_id = ? AND name = ?",
		vendorID, strings.ToLower(name)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("select product: %w", err)
	}
	return id, nil
}

func (r *sqliteProductRepo) List(ctx context.Context, vendorID int64) ([]DBProduct, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT id, vendor_id, name FROM products WHERE vendor_id = ? ORDER BY name", vendorID)
	if err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	defer rows.Close()

	var products []DBProduct
	for rows.Next() {
		var p DBProduct
		if err := rows.Scan(&p.ID, &p.VendorID, &p.Name); err != nil {
			return nil, fmt.Errorf("scan product: %w", err)
		}
		products = append(products, p)
	}
	return products, rows.Err()
}

func (r *sqliteProductRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM products").Scan(&count)
	return count, err
}

// -- CPE Repository ----------------------------------------------------------

type sqliteCPERepo struct{ db *sql.DB }

func (r *sqliteCPERepo) Insert(ctx context.Context, cpe *DBCPE) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO cpe (vendor_id, product_id, part, version, update_, edition,
			language, target_sw, target_hw, other, cpe_2_3_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cpe.VendorID, cpe.ProductID, cpe.Part, cpe.Version, cpe.Update,
		cpe.Edition, cpe.Language, cpe.TargetSW, cpe.TargetHW, cpe.Other, cpe.CPE23URI)
	if err != nil {
		return 0, fmt.Errorf("insert cpe: %w", err)
	}
	return result.LastInsertId()
}

func (r *sqliteCPERepo) FindByProduct(ctx context.Context, vendor, product, version string) ([]DBCPE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id, c.vendor_id, c.product_id, c.part, c.version,
			c.update_, c.edition, c.language, c.target_sw, c.target_hw,
			c.other, c.cpe_2_3_uri
		FROM cpe c
		JOIN vendors v ON v.id = c.vendor_id
		JOIN products p ON p.id = c.product_id
		WHERE v.name = ? AND p.name = ?
			AND (c.version = '*' OR c.version = ?)
	`, strings.ToLower(vendor), strings.ToLower(product), version)
	if err != nil {
		return nil, fmt.Errorf("find cpe by product: %w", err)
	}
	defer rows.Close()

	return scanCPEs(rows)
}

func (r *sqliteCPERepo) FindByCPE23URI(ctx context.Context, uri string) ([]DBCPE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id, c.vendor_id, c.product_id, c.part, c.version,
			c.update_, c.edition, c.language, c.target_sw, c.target_hw,
			c.other, c.cpe_2_3_uri
		FROM cpe c
		WHERE c.cpe_2_3_uri = ?
	`, uri)
	if err != nil {
		return nil, fmt.Errorf("find cpe by uri: %w", err)
	}
	defer rows.Close()

	return scanCPEs(rows)
}

func (r *sqliteCPERepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cpe").Scan(&count)
	return count, err
}

func (r *sqliteCPERepo) ExistsByURI(ctx context.Context, uri string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM cpe WHERE cpe_2_3_uri = ?", uri).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("exists by uri: %w", err)
	}
	return count > 0, nil
}

func (r *sqliteCPERepo) BulkInsert(ctx context.Context, cpes []DBCPE) (int64, error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT OR IGNORE INTO cpe (vendor_id, product_id, part, version, update_, edition,
			language, target_sw, target_hw, other, cpe_2_3_uri)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, fmt.Errorf("prepare bulk insert: %w", err)
	}
	defer stmt.Close()

	var inserted int64
	for _, cpe := range cpes {
		result, err := stmt.ExecContext(ctx,
			cpe.VendorID, cpe.ProductID, cpe.Part, cpe.Version, cpe.Update,
			cpe.Edition, cpe.Language, cpe.TargetSW, cpe.TargetHW, cpe.Other, cpe.CPE23URI)
		if err != nil {
			return inserted, fmt.Errorf("bulk insert cpe: %w", err)
		}
		n, _ := result.RowsAffected()
		inserted += n
	}

	if err := tx.Commit(); err != nil {
		return inserted, fmt.Errorf("commit bulk insert: %w", err)
	}
	return inserted, nil
}

func scanCPEs(rows *sql.Rows) ([]DBCPE, error) {
	var cpes []DBCPE
	for rows.Next() {
		var c DBCPE
		if err := rows.Scan(&c.ID, &c.VendorID, &c.ProductID, &c.Part, &c.Version,
			&c.Update, &c.Edition, &c.Language, &c.TargetSW, &c.TargetHW,
			&c.Other, &c.CPE23URI); err != nil {
			return nil, fmt.Errorf("scan cpe: %w", err)
		}
		cpes = append(cpes, c)
	}
	return cpes, rows.Err()
}

// -- CVE Repository ----------------------------------------------------------

type sqliteCVERepo struct{ db *sql.DB }

func (r *sqliteCVERepo) Insert(ctx context.Context, cve *DBCVE) (int64, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, cpe_id, description, cvss_v2, cvss_v3,
			severity, published_date, last_modified_date, references_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cve.CVEID, cve.CPEID, cve.Description, cve.CVSSv2, cve.CVSSv3,
		cve.Severity, cve.PublishedDate.UTC().Format(time.RFC3339),
		cve.LastModifiedDate.UTC().Format(time.RFC3339), cve.ReferencesJSON)
	if err != nil {
		return 0, fmt.Errorf("insert cve: %w", err)
	}
	return result.LastInsertId()
}

func (r *sqliteCVERepo) Upsert(ctx context.Context, cve *DBCVE) (int64, bool, error) {
	// Check if the CVE already exists.
	var existingID int64
	err := r.db.QueryRowContext(ctx,
		`SELECT id FROM cves WHERE cve_id = ? AND cpe_id = ?`,
		cve.CVEID, cve.CPEID).Scan(&existingID)
	if err == nil {
		// Update existing record.
		_, err := r.db.ExecContext(ctx, `
			UPDATE cves SET
				description = ?, cvss_v2 = ?, cvss_v3 = ?, severity = ?,
				published_date = ?, last_modified_date = ?, references_json = ?
			WHERE id = ?
		`, cve.Description, cve.CVSSv2, cve.CVSSv3, cve.Severity,
			cve.PublishedDate.UTC().Format(time.RFC3339),
			cve.LastModifiedDate.UTC().Format(time.RFC3339),
			cve.ReferencesJSON, existingID)
		if err != nil {
			return 0, false, fmt.Errorf("update cve: %w", err)
		}
		return existingID, false, nil
	}

	// Insert new record.
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, cpe_id, description, cvss_v2, cvss_v3,
			severity, published_date, last_modified_date, references_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cve.CVEID, cve.CPEID, cve.Description, cve.CVSSv2, cve.CVSSv3,
		cve.Severity, cve.PublishedDate.UTC().Format(time.RFC3339),
		cve.LastModifiedDate.UTC().Format(time.RFC3339), cve.ReferencesJSON)
	if err != nil {
		return 0, false, fmt.Errorf("insert cve: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, false, fmt.Errorf("last insert id: %w", err)
	}
	return id, true, nil
}

func (r *sqliteCVERepo) FindByCPEID(ctx context.Context, cpeID int64) ([]DBCVE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, cve_id, cpe_id, description, cvss_v2, cvss_v3,
			severity, published_date, last_modified_date, references_json
		FROM cves WHERE cpe_id = ?
		ORDER BY cvss_v3 DESC NULLS LAST
	`, cpeID)
	if err != nil {
		return nil, fmt.Errorf("find cve by cpe id: %w", err)
	}
	defer rows.Close()
	return scanCVEs(rows)
}

func (r *sqliteCVERepo) FindByCVEID(ctx context.Context, cveID string) (*DBCVE, error) {
	var c DBCVE
	var pubStr, modStr string
	err := r.db.QueryRowContext(ctx, `
		SELECT id, cve_id, cpe_id, description, cvss_v2, cvss_v3,
			severity, published_date, last_modified_date, references_json
		FROM cves WHERE cve_id = ?
	`, cveID).Scan(&c.ID, &c.CVEID, &c.CPEID, &c.Description, &c.CVSSv2, &c.CVSSv3,
		&c.Severity, &pubStr, &modStr, &c.ReferencesJSON)
	if err != nil {
		return nil, fmt.Errorf("find cve by id: %w", err)
	}
	if t, err := time.Parse(time.RFC3339, pubStr); err == nil {
		c.PublishedDate = t
	}
	if t, err := time.Parse(time.RFC3339, modStr); err == nil {
		c.LastModifiedDate = t
	}
	return &c, nil
}

func (r *sqliteCVERepo) FindByCPE23URI(ctx context.Context, cpe23URI string) ([]DBCVE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cv.id, cv.cve_id, cv.cpe_id, cv.description, cv.cvss_v2, cv.cvss_v3,
			cv.severity, cv.published_date, cv.last_modified_date, cv.references_json
		FROM cves cv
		JOIN cpe c ON c.id = cv.cpe_id
		WHERE c.cpe_2_3_uri = ?
		ORDER BY cv.cvss_v3 DESC NULLS LAST
	`, cpe23URI)
	if err != nil {
		return nil, fmt.Errorf("find cve by cpe uri: %w", err)
	}
	defer rows.Close()
	return scanCVEs(rows)
}

func (r *sqliteCVERepo) SearchByProduct(ctx context.Context, vendor, product string) ([]DBCVE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cv.id, cv.cve_id, cv.cpe_id, cv.description, cv.cvss_v2, cv.cvss_v3,
			cv.severity, cv.published_date, cv.last_modified_date, cv.references_json
		FROM cves cv
		JOIN cpe c ON c.id = cv.cpe_id
		JOIN vendors v ON v.id = c.vendor_id
		JOIN products p ON p.id = c.product_id
		WHERE v.name = ? AND p.name = ?
		ORDER BY cv.cvss_v3 DESC NULLS LAST
	`, strings.ToLower(vendor), strings.ToLower(product))
	if err != nil {
		return nil, fmt.Errorf("search cve by product: %w", err)
	}
	defer rows.Close()
	return scanCVEs(rows)
}

func (r *sqliteCVERepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM cves").Scan(&count)
	return count, err
}

func (r *sqliteCVERepo) CountBySeverity(ctx context.Context) (map[string]int, error) {
	rows, err := r.db.QueryContext(ctx,
		"SELECT severity, COUNT(*) FROM cves GROUP BY severity")
	if err != nil {
		return nil, fmt.Errorf("count by severity: %w", err)
	}
	defer rows.Close()

	counts := make(map[string]int)
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, fmt.Errorf("scan severity count: %w", err)
		}
		counts[sev] = count
	}
	return counts, rows.Err()
}

func (r *sqliteCVERepo) LastModifiedCursor(ctx context.Context) (*time.Time, error) {
	var t time.Time
	err := r.db.QueryRowContext(ctx, `
		SELECT MAX(last_modified_date) FROM cves
	`).Scan(&t)
	if err != nil {
		return nil, fmt.Errorf("last modified cursor: %w", err)
	}
	if t.IsZero() {
		return nil, nil
	}
	return &t, nil
}

func scanCVEs(rows *sql.Rows) ([]DBCVE, error) {
	var cves []DBCVE
	for rows.Next() {
		var c DBCVE
		var pubStr, modStr string
		if err := rows.Scan(&c.ID, &c.CVEID, &c.CPEID, &c.Description,
			&c.CVSSv2, &c.CVSSv3, &c.Severity, &pubStr, &modStr, &c.ReferencesJSON); err != nil {
			return nil, fmt.Errorf("scan cve: %w", err)
		}
		if t, err := time.Parse(time.RFC3339, pubStr); err == nil {
			c.PublishedDate = t
		}
		if t, err := time.Parse(time.RFC3339, modStr); err == nil {
			c.LastModifiedDate = t
		}
		cves = append(cves, c)
	}
	return cves, rows.Err()
}

// -- KEV Repository ----------------------------------------------------------

type sqliteKEVRepo struct{ db *sql.DB }

func (r *sqliteKEVRepo) Upsert(ctx context.Context, kev *DBKEV) (int64, bool, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO kev (cve_id, due_date, notes)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			due_date = excluded.due_date,
			notes    = excluded.notes
	`, kev.CVEID, kev.DueDate, kev.Notes)
	if err != nil {
		return 0, false, fmt.Errorf("upsert kev: %w", err)
	}
	id, _ := result.LastInsertId()
	affected, _ := result.RowsAffected()
	return id, affected == 0, nil
}

func (r *sqliteKEVRepo) IsInKEV(ctx context.Context, cveID string) (bool, error) {
	var count int
	err := r.db.QueryRowContext(ctx,
		"SELECT COUNT(*) FROM kev WHERE cve_id = ?", cveID).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("is in kev: %w", err)
	}
	return count > 0, nil
}

func (r *sqliteKEVRepo) GetByCVEID(ctx context.Context, cveID string) (*DBKEV, error) {
	var k DBKEV
	err := r.db.QueryRowContext(ctx,
		"SELECT id, cve_id, due_date, notes FROM kev WHERE cve_id = ?", cveID,
	).Scan(&k.ID, &k.CVEID, &k.DueDate, &k.Notes)
	if err != nil {
		return nil, fmt.Errorf("get kev by cve id: %w", err)
	}
	return &k, nil
}

func (r *sqliteKEVRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM kev").Scan(&count)
	return count, err
}

func (r *sqliteKEVRepo) BulkUpsert(ctx context.Context, entries []DBKEV) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO kev (cve_id, due_date, notes)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			due_date = excluded.due_date,
			notes    = excluded.notes
	`)
	if err != nil {
		return fmt.Errorf("prepare kev bulk upsert: %w", err)
	}
	defer stmt.Close()

	for _, kev := range entries {
		if _, err := stmt.ExecContext(ctx, kev.CVEID, kev.DueDate, kev.Notes); err != nil {
			return fmt.Errorf("kev bulk upsert exec: %w", err)
		}
	}

	return tx.Commit()
}

// -- EPSS Repository ---------------------------------------------------------

type sqliteEPSSRepo struct{ db *sql.DB }

func (r *sqliteEPSSRepo) Upsert(ctx context.Context, epss *DBEpss) (int64, bool, error) {
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO epss (cve_id, epss_score, percentile)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			epss_score = excluded.epss_score,
			percentile = excluded.percentile
	`, epss.CVEID, epss.Score, epss.Percentile)
	if err != nil {
		return 0, false, fmt.Errorf("upsert epss: %w", err)
	}
	id, _ := result.LastInsertId()
	affected, _ := result.RowsAffected()
	return id, affected == 0, nil
}

func (r *sqliteEPSSRepo) GetByCVEID(ctx context.Context, cveID string) (*DBEpss, error) {
	var e DBEpss
	err := r.db.QueryRowContext(ctx,
		"SELECT id, cve_id, epss_score, percentile FROM epss WHERE cve_id = ?", cveID,
	).Scan(&e.ID, &e.CVEID, &e.Score, &e.Percentile)
	if err != nil {
		return nil, fmt.Errorf("get epss by cve id: %w", err)
	}
	return &e, nil
}

func (r *sqliteEPSSRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM epss").Scan(&count)
	return count, err
}

func (r *sqliteEPSSRepo) BulkUpsert(ctx context.Context, entries []DBEpss) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO epss (cve_id, epss_score, percentile)
		VALUES (?, ?, ?)
		ON CONFLICT(cve_id) DO UPDATE SET
			epss_score = excluded.epss_score,
			percentile = excluded.percentile
	`)
	if err != nil {
		return fmt.Errorf("prepare epss bulk upsert: %w", err)
	}
	defer stmt.Close()

	for _, epss := range entries {
		if _, err := stmt.ExecContext(ctx, epss.CVEID, epss.Score, epss.Percentile); err != nil {
			return fmt.Errorf("epss bulk upsert exec: %w", err)
		}
	}

	return tx.Commit()
}

// -- Metadata Repository -----------------------------------------------------

type sqliteMetadataRepo struct{ db *sql.DB }

func (r *sqliteMetadataRepo) Set(ctx context.Context, key, value string) error {
	_, err := r.db.ExecContext(ctx,
		"INSERT INTO metadata (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
		key, value)
	return err
}

func (r *sqliteMetadataRepo) Get(ctx context.Context, key string) (string, error) {
	var value string
	err := r.db.QueryRowContext(ctx,
		"SELECT value FROM metadata WHERE key = ?", key).Scan(&value)
	if err != nil {
		return "", fmt.Errorf("get metadata %s: %w", key, err)
	}
	return value, nil
}

func (r *sqliteMetadataRepo) Delete(ctx context.Context, key string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM metadata WHERE key = ?", key)
	return err
}

func (r *sqliteMetadataRepo) List(ctx context.Context) ([]DBMetadata, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT key, value FROM metadata ORDER BY key")
	if err != nil {
		return nil, fmt.Errorf("list metadata: %w", err)
	}
	defer rows.Close()

	var items []DBMetadata
	for rows.Next() {
		var m DBMetadata
		if err := rows.Scan(&m.Key, &m.Value); err != nil {
			return nil, fmt.Errorf("scan metadata: %w", err)
		}
		items = append(items, m)
	}
	return items, rows.Err()
}

// ============================================================================
// Helper: Convert DBCVE + KEV + EPSS to domain model CVE
// ============================================================================

// ToDomainCVE merges a DBCVE, optional DBKEV, and optional DBEpss into a models.CVE.
func ToDomainCVE(dbCVE *DBCVE, dbKEV *DBKEV, dbEpss *DBEpss) models.CVE {
	var refs []string
	if dbCVE.ReferencesJSON != "" {
		json.Unmarshal([]byte(dbCVE.ReferencesJSON), &refs)
	}

	cve := models.CVE{
		ID:               dbCVE.CVEID,
		Description:      dbCVE.Description,
		CVSSv2:           dbCVE.CVSSv2,
		CVSSv3:           dbCVE.CVSSv3,
		Severity:         dbCVE.Severity,
		PublishedDate:    dbCVE.PublishedDate,
		LastModifiedDate: dbCVE.LastModifiedDate,
		References:       refs,
	}

	if dbKEV != nil {
		cve.IsInKEV = true
		if dbKEV.DueDate != "" {
			if t, err := time.Parse("2006-01-02", dbKEV.DueDate); err == nil {
				cve.KEVDueDate = &t
			}
		}
	}

	if dbEpss != nil {
		cve.EPSSScore = &dbEpss.Score
		cve.EPSSPercentile = &dbEpss.Percentile
	}

	return cve
}
