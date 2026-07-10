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
	versionpkg "github.com/evilhunter/surfaceguard/pkg/version"

	// Pure-Go SQLite driver (no CGO).
	_ "modernc.org/sqlite"
)

// Compile-time check: *sqliteDB implements Database.
var _ Database = (*sqliteDB)(nil)

// sqliteDB is the concrete SQLite-backed Database implementation.
type sqliteDB struct {
	db *sql.DB

	vendorRepo         *sqliteVendorRepo
	productRepo        *sqliteProductRepo
	cpeRepo            *sqliteCPERepo
	cveRepo            *sqliteCVERepo
	kevRepo            *sqliteKEVRepo
	epssRepo           *sqliteEPSSRepo
	metaRepo           *sqliteMetadataRepo
	checkpointRepo     *sqliteCheckpointRepo
	credProfileRepo    *sqliteCredentialProfileRepo
	assetRepo          *sqliteAssetInventoryRepo
	assessResultRepo   *sqliteAssessmentResultRepo
	pkgRepo            *sqliteInstalledPackageRepo
	swRepo             *sqliteInstalledSoftwareRepo
	secFindingRepo     *sqliteSecurityFindingRepo
	credValidationRepo *sqliteCredentialValidationRepo
	easmScanRepo       *sqliteEASMScanRepo
	easmAssetRepo      *sqliteEASMAssetRepo
	easmServiceRepo    *sqliteEASMServiceRepo
	easmFindingRepo    *sqliteEASMFindingRepo
	scanHistoryRepo    *sqliteScanHistoryRepo

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
		"PRAGMA cache_size=-8000", // 8MB cache
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
	sqlite.checkpointRepo = &sqliteCheckpointRepo{db: db}
	sqlite.credProfileRepo = &sqliteCredentialProfileRepo{db: db}
	sqlite.assetRepo = &sqliteAssetInventoryRepo{db: db}
	sqlite.assessResultRepo = &sqliteAssessmentResultRepo{db: db}
	sqlite.pkgRepo = &sqliteInstalledPackageRepo{db: db}
	sqlite.swRepo = &sqliteInstalledSoftwareRepo{db: db}
	sqlite.secFindingRepo = &sqliteSecurityFindingRepo{db: db}
	sqlite.credValidationRepo = &sqliteCredentialValidationRepo{db: db}
	sqlite.easmScanRepo = &sqliteEASMScanRepo{db: db}
	sqlite.easmAssetRepo = &sqliteEASMAssetRepo{db: db}
	sqlite.easmServiceRepo = &sqliteEASMServiceRepo{db: db}
	sqlite.easmFindingRepo = &sqliteEASMFindingRepo{db: db}
	sqlite.scanHistoryRepo = &sqliteScanHistoryRepo{db: db}

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

func (s *sqliteDB) Vendor() VendorRepository                             { return s.vendorRepo }
func (s *sqliteDB) Product() ProductRepository                           { return s.productRepo }
func (s *sqliteDB) CPE() CPERepository                                   { return s.cpeRepo }
func (s *sqliteDB) CVE() CVERepository                                   { return s.cveRepo }
func (s *sqliteDB) KEV() KEVRepository                                   { return s.kevRepo }
func (s *sqliteDB) EPSS() EPSSRepository                                 { return s.epssRepo }
func (s *sqliteDB) Metadata() MetadataRepository                         { return s.metaRepo }
func (s *sqliteDB) Checkpoint() CheckpointRepository                     { return s.checkpointRepo }
func (s *sqliteDB) CredentialProfile() CredentialProfileRepository       { return s.credProfileRepo }
func (s *sqliteDB) AssetInventory() AssetInventoryRepository             { return s.assetRepo }
func (s *sqliteDB) AssessmentResult() AssessmentResultRepository         { return s.assessResultRepo }
func (s *sqliteDB) InstalledPackage() InstalledPackageRepository         { return s.pkgRepo }
func (s *sqliteDB) InstalledSoftware() InstalledSoftwareRepository       { return s.swRepo }
func (s *sqliteDB) SecurityFinding() SecurityFindingRepository           { return s.secFindingRepo }
func (s *sqliteDB) CredentialValidation() CredentialValidationRepository { return s.credValidationRepo }
func (s *sqliteDB) EASMScan() EASMScanRepository                         { return s.easmScanRepo }
func (s *sqliteDB) EASMAsset() EASMAssetRepository                       { return s.easmAssetRepo }
func (s *sqliteDB) EASMService() EASMServiceRepository                   { return s.easmServiceRepo }
func (s *sqliteDB) EASMFinding() EASMFindingRepository                   { return s.easmFindingRepo }
func (s *sqliteDB) ScanHistory() ScanHistoryRepository                     { return s.scanHistoryRepo }

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

func (r *sqliteCPERepo) FindNearbyVersions(ctx context.Context, vendor, product, version string, limit int) ([]DBCPE, error) {
	// Parse the detected version to extract major.minor components.
	// We search for CPEs matching the same vendor+product where the version
	// shares the same major.minor prefix (e.g., "2.4" for "2.4.58").
	// This enables nearby version matching without wildcard fallback.
	parsed := versionpkg.Parse(version)
	if parsed.Unknown || parsed.Wildcard {
		return nil, nil
	}

	var prefix string
	if len(parsed.Segments) >= 2 {
		prefix = fmt.Sprintf("%d.%d", parsed.Segments[0], parsed.Segments[1])
	} else if len(parsed.Segments) == 1 {
		prefix = fmt.Sprintf("%d", parsed.Segments[0])
	} else {
		return nil, nil
	}

	rows, err := r.db.QueryContext(ctx, `
		SELECT c.id, c.vendor_id, c.product_id, c.part, c.version,
			c.update_, c.edition, c.language, c.target_sw, c.target_hw,
			c.other, c.cpe_2_3_uri
		FROM cpe c
		JOIN vendors v ON v.id = c.vendor_id
		JOIN products p ON p.id = c.product_id
		WHERE v.name = ? AND p.name = ?
			AND c.version != '*'
			AND (c.version LIKE ? || '.%' OR c.version = ? OR c.version LIKE ? || '.%.%')
		ORDER BY c.version DESC
		LIMIT ?
	`, strings.ToLower(vendor), strings.ToLower(product), prefix, prefix, prefix, limit)
	if err != nil {
		return nil, fmt.Errorf("find nearby versions: %w", err)
	}
	defer rows.Close()

	return scanCPEs(rows)
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
			severity, published_date, last_modified_date, references_json,
			version_start_including, version_start_excluding,
			version_end_including, version_end_excluding)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cve.CVEID, cve.CPEID, cve.Description, cve.CVSSv2, cve.CVSSv3,
		cve.Severity, cve.PublishedDate.UTC().Format(time.RFC3339),
		cve.LastModifiedDate.UTC().Format(time.RFC3339), cve.ReferencesJSON,
		cve.VersionStartIncluding, cve.VersionStartExcluding,
		cve.VersionEndIncluding, cve.VersionEndExcluding)
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
				published_date = ?, last_modified_date = ?, references_json = ?,
				version_start_including = ?, version_start_excluding = ?,
				version_end_including = ?, version_end_excluding = ?
			WHERE id = ?
		`, cve.Description, cve.CVSSv2, cve.CVSSv3, cve.Severity,
			cve.PublishedDate.UTC().Format(time.RFC3339),
			cve.LastModifiedDate.UTC().Format(time.RFC3339),
			cve.ReferencesJSON,
			cve.VersionStartIncluding, cve.VersionStartExcluding,
			cve.VersionEndIncluding, cve.VersionEndExcluding,
			existingID)
		if err != nil {
			return 0, false, fmt.Errorf("update cve: %w", err)
		}
		return existingID, false, nil
	}

	// Insert new record.
	result, err := r.db.ExecContext(ctx, `
		INSERT INTO cves (cve_id, cpe_id, description, cvss_v2, cvss_v3,
			severity, published_date, last_modified_date, references_json,
			version_start_including, version_start_excluding,
			version_end_including, version_end_excluding)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, cve.CVEID, cve.CPEID, cve.Description, cve.CVSSv2, cve.CVSSv3,
		cve.Severity, cve.PublishedDate.UTC().Format(time.RFC3339),
		cve.LastModifiedDate.UTC().Format(time.RFC3339), cve.ReferencesJSON,
		cve.VersionStartIncluding, cve.VersionStartExcluding,
		cve.VersionEndIncluding, cve.VersionEndExcluding)
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

// SearchByProductName returns all CVEs matching a product name alone,
// ignoring the vendor. This is the fallback when the vendor is unknown.
func (r *sqliteCVERepo) SearchByProductName(ctx context.Context, product string) ([]DBCVE, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT cv.id, cv.cve_id, cv.cpe_id, cv.description, cv.cvss_v2, cv.cvss_v3,
			cv.severity, cv.published_date, cv.last_modified_date, cv.references_json
		FROM cves cv
		JOIN cpe c ON c.id = cv.cpe_id
		JOIN products p ON p.id = c.product_id
		WHERE LOWER(p.name) = ?
		ORDER BY cv.cvss_v3 DESC NULLS LAST
	`, strings.ToLower(product))
	if err != nil {
		return nil, fmt.Errorf("search cve by product name: %w", err)
	}
	defer rows.Close()
	return scanCVEs(rows)
}

func (r *sqliteCVERepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(DISTINCT cve_id) FROM cves").Scan(&count)
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

	items := make([]DBMetadata, 0)
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

// deriveSeverity computes the correct severity from the CVSS score.
// NVD data sometimes stores severities that don't match the CVSS 3.0
// standard thresholds (e.g. a score of 9.0 stored as "HIGH" instead of "CRITICAL").
func deriveSeverity(cvssv3, cvssv2 *float64, fallback string) string {
	if cvssv3 != nil {
		return models.CVSSSeverity(*cvssv3)
	}
	if cvssv2 != nil {
		return models.CVSSSeverity(*cvssv2)
	}
	return fallback
}

// ToDomainCVE merges a DBCVE, optional DBKEV, and optional DBEpss into a models.CVE.
func ToDomainCVE(dbCVE *DBCVE, dbKEV *DBKEV, dbEpss *DBEpss) models.CVE {
	var refs []string
	if dbCVE.ReferencesJSON != "" {
		json.Unmarshal([]byte(dbCVE.ReferencesJSON), &refs)
	}

	cve := models.CVE{
		ID:          dbCVE.CVEID,
		Description: dbCVE.Description,
		CVSSv2:      dbCVE.CVSSv2,
		CVSSv3:      dbCVE.CVSSv3,
		// Re-derive severity from CVSS score — NVD stored severity may
		// not match the CVSS 3.0 standard thresholds (e.g. 9.0 stored as HIGH).
		Severity:         deriveSeverity(dbCVE.CVSSv3, dbCVE.CVSSv2, dbCVE.Severity),
		PublishedDate:    dbCVE.PublishedDate,
		LastModifiedDate: dbCVE.LastModifiedDate,
		References:       refs,
		// Pass through NVD version range fields.
		VersionStartIncluding: dbCVE.VersionStartIncluding,
		VersionStartExcluding: dbCVE.VersionStartExcluding,
		VersionEndIncluding:   dbCVE.VersionEndIncluding,
		VersionEndExcluding:   dbCVE.VersionEndExcluding,
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

// ============================================================================
// Checkpoint Repository — fault-tolerant update tracking
// ============================================================================

type sqliteCheckpointRepo struct{ db *sql.DB }

func (r *sqliteCheckpointRepo) Save(ctx context.Context, cp *DBCheckpoint) error {
	_, err := r.db.ExecContext(ctx, `
		INSERT INTO update_checkpoints (feed_name, state, step, bytes_offset, file_path, file_hash, message, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
		ON CONFLICT(feed_name) DO UPDATE SET
			state       = excluded.state,
			step        = excluded.step,
			bytes_offset = excluded.bytes_offset,
			file_path   = excluded.file_path,
			file_hash   = excluded.file_hash,
			message     = excluded.message,
			updated_at  = excluded.updated_at
	`, cp.FeedName, cp.State, cp.Step, cp.BytesOffset, cp.FilePath, cp.FileHash, cp.Message)
	return err
}

func (r *sqliteCheckpointRepo) Get(ctx context.Context, feedName string) (*DBCheckpoint, error) {
	cp := &DBCheckpoint{}
	err := r.db.QueryRowContext(ctx, `
		SELECT feed_name, state, step, bytes_offset, file_path, file_hash, message, updated_at, created_at
		FROM update_checkpoints WHERE feed_name = ?
	`, feedName).Scan(&cp.FeedName, &cp.State, &cp.Step, &cp.BytesOffset, &cp.FilePath, &cp.FileHash, &cp.Message, &cp.UpdatedAt, &cp.CreatedAt)
	if err != nil {
		return nil, err
	}
	return cp, nil
}

func (r *sqliteCheckpointRepo) List(ctx context.Context) ([]DBCheckpoint, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT feed_name, state, step, bytes_offset, file_path, file_hash, message, updated_at, created_at
		FROM update_checkpoints ORDER BY feed_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var cps []DBCheckpoint
	for rows.Next() {
		var cp DBCheckpoint
		if err := rows.Scan(&cp.FeedName, &cp.State, &cp.Step, &cp.BytesOffset, &cp.FilePath, &cp.FileHash, &cp.Message, &cp.UpdatedAt, &cp.CreatedAt); err != nil {
			return nil, err
		}
		cps = append(cps, cp)
	}
	return cps, rows.Err()
}

func (r *sqliteCheckpointRepo) Delete(ctx context.Context, feedName string) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM update_checkpoints WHERE feed_name = ?", feedName)
	return err
}

func (r *sqliteCheckpointRepo) DeleteAll(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM update_checkpoints")
	return err
}

// ============================================================================
// Credential Profile Repository
// ============================================================================

type sqliteCredentialProfileRepo struct{ db *sql.DB }

func (r *sqliteCredentialProfileRepo) List(ctx context.Context) ([]DBCredentialProfile, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, name, protocol, host, port, username, auth_method, credential_1, credential_2, credential_3, created_at, updated_at FROM credential_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBCredentialProfile, 0)
	for rows.Next() {
		var p DBCredentialProfile
		if err := rows.Scan(&p.ID, &p.Name, &p.Protocol, &p.Host, &p.Port, &p.Username, &p.AuthMethod, &p.Credential1, &p.Credential2, &p.Credential3, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (r *sqliteCredentialProfileRepo) Get(ctx context.Context, id int64) (*DBCredentialProfile, error) {
	p := &DBCredentialProfile{}
	err := r.db.QueryRowContext(ctx, `SELECT id, name, protocol, host, port, username, auth_method, credential_1, credential_2, credential_3, created_at, updated_at FROM credential_profiles WHERE id = ?`, id).
		Scan(&p.ID, &p.Name, &p.Protocol, &p.Host, &p.Port, &p.Username, &p.AuthMethod, &p.Credential1, &p.Credential2, &p.Credential3, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (r *sqliteCredentialProfileRepo) Create(ctx context.Context, p *DBCredentialProfile) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO credential_profiles (name, protocol, host, port, username, auth_method, credential_1, credential_2, credential_3) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Protocol, p.Host, p.Port, p.Username, p.AuthMethod, p.Credential1, p.Credential2, p.Credential3)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *sqliteCredentialProfileRepo) Update(ctx context.Context, p *DBCredentialProfile) error {
	_, err := r.db.ExecContext(ctx, `UPDATE credential_profiles SET name=?, protocol=?, host=?, port=?, username=?, auth_method=?, credential_1=?, credential_2=?, credential_3=?, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id=?`,
		p.Name, p.Protocol, p.Host, p.Port, p.Username, p.AuthMethod, p.Credential1, p.Credential2, p.Credential3, p.ID)
	return err
}

func (r *sqliteCredentialProfileRepo) Delete(ctx context.Context, id int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM credential_profiles WHERE id = ?`, id)
	return err
}

// ============================================================================
// Asset Inventory Repository
// ============================================================================

type sqliteAssetInventoryRepo struct{ db *sql.DB }

func (r *sqliteAssetInventoryRepo) Upsert(ctx context.Context, a *DBAssetInventory) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO asset_inventory (hostname, ip, os, distro, kernel_version, architecture, asset_type, risk_score, last_seen, last_scan) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(hostname, asset_type) DO UPDATE SET ip=excluded.ip, os=excluded.os, distro=excluded.distro, kernel_version=excluded.kernel_version, architecture=excluded.architecture, risk_score=excluded.risk_score, last_seen=excluded.last_seen, last_scan=excluded.last_scan`,
		a.Hostname, a.IP, a.OS, a.Distro, a.KernelVersion, a.Architecture, a.AssetType, a.RiskScore, a.LastSeen, a.LastScan)
	if err != nil {
		return 0, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	if id > 0 {
		return id, nil
	}
	// Already existed — fetch existing ID.
	var existing int64
	err = r.db.QueryRowContext(ctx, `SELECT id FROM asset_inventory WHERE hostname = ? AND asset_type = ?`, a.Hostname, a.AssetType).Scan(&existing)
	return existing, err
}

func (r *sqliteAssetInventoryRepo) Get(ctx context.Context, id int64) (*DBAssetInventory, error) {
	a := &DBAssetInventory{}
	err := r.db.QueryRowContext(ctx, `SELECT id, hostname, ip, os, distro, kernel_version, architecture, asset_type, risk_score, last_seen, last_scan FROM asset_inventory WHERE id = ?`, id).
		Scan(&a.ID, &a.Hostname, &a.IP, &a.OS, &a.Distro, &a.KernelVersion, &a.Architecture, &a.AssetType, &a.RiskScore, &a.LastSeen, &a.LastScan)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *sqliteAssetInventoryRepo) FindByHostname(ctx context.Context, hostname, assetType string) (*DBAssetInventory, error) {
	a := &DBAssetInventory{}
	err := r.db.QueryRowContext(ctx, `SELECT id, hostname, ip, os, distro, kernel_version, architecture, asset_type, risk_score, last_seen, last_scan FROM asset_inventory WHERE hostname = ? AND asset_type = ?`, hostname, assetType).
		Scan(&a.ID, &a.Hostname, &a.IP, &a.OS, &a.Distro, &a.KernelVersion, &a.Architecture, &a.AssetType, &a.RiskScore, &a.LastSeen, &a.LastScan)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (r *sqliteAssetInventoryRepo) List(ctx context.Context) ([]DBAssetInventory, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, hostname, ip, os, distro, kernel_version, architecture, asset_type, risk_score, last_seen, last_scan FROM asset_inventory ORDER BY hostname`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBAssetInventory, 0)
	for rows.Next() {
		var a DBAssetInventory
		if err := rows.Scan(&a.ID, &a.Hostname, &a.IP, &a.OS, &a.Distro, &a.KernelVersion, &a.Architecture, &a.AssetType, &a.RiskScore, &a.LastSeen, &a.LastScan); err != nil {
			return nil, err
		}
		items = append(items, a)
	}
	return items, rows.Err()
}

func (r *sqliteAssetInventoryRepo) UpdateRiskScore(ctx context.Context, id int64, score float64) error {
	_, err := r.db.ExecContext(ctx, `UPDATE asset_inventory SET risk_score = ? WHERE id = ?`, score, id)
	return err
}

func (r *sqliteAssetInventoryRepo) UpdateLastScan(ctx context.Context, id int64, scanTime string) error {
	_, err := r.db.ExecContext(ctx, `UPDATE asset_inventory SET last_scan = ? WHERE id = ?`, scanTime, id)
	return err
}

// ============================================================================
// Assessment Result Repository
// ============================================================================

type sqliteAssessmentResultRepo struct{ db *sql.DB }

func (r *sqliteAssessmentResultRepo) Create(ctx context.Context, ar *DBAssessmentResult) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO assessment_results (target, profile_id, protocol, started_at, duration, result_json, status) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		ar.Target, ar.ProfileID, ar.Protocol, ar.StartedAt, ar.Duration, ar.ResultJSON, ar.Status)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *sqliteAssessmentResultRepo) List(ctx context.Context, limit int) ([]DBAssessmentResult, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, target, profile_id, protocol, started_at, duration, result_json, status FROM assessment_results ORDER BY started_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBAssessmentResult, 0)
	for rows.Next() {
		var ar DBAssessmentResult
		if err := rows.Scan(&ar.ID, &ar.Target, &ar.ProfileID, &ar.Protocol, &ar.StartedAt, &ar.Duration, &ar.ResultJSON, &ar.Status); err != nil {
			return nil, err
		}
		items = append(items, ar)
	}
	return items, rows.Err()
}

func (r *sqliteAssessmentResultRepo) Get(ctx context.Context, id int64) (*DBAssessmentResult, error) {
	ar := &DBAssessmentResult{}
	err := r.db.QueryRowContext(ctx, `SELECT id, target, profile_id, protocol, started_at, duration, result_json, status FROM assessment_results WHERE id = ?`, id).
		Scan(&ar.ID, &ar.Target, &ar.ProfileID, &ar.Protocol, &ar.StartedAt, &ar.Duration, &ar.ResultJSON, &ar.Status)
	if err != nil {
		return nil, err
	}
	return ar, nil
}

func (r *sqliteAssessmentResultRepo) ListByTarget(ctx context.Context, target string) ([]DBAssessmentResult, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, target, profile_id, protocol, started_at, duration, result_json, status FROM assessment_results WHERE target = ? ORDER BY started_at DESC`, target)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBAssessmentResult, 0)
	for rows.Next() {
		var ar DBAssessmentResult
		if err := rows.Scan(&ar.ID, &ar.Target, &ar.ProfileID, &ar.Protocol, &ar.StartedAt, &ar.Duration, &ar.ResultJSON, &ar.Status); err != nil {
			return nil, err
		}
		items = append(items, ar)
	}
	return items, rows.Err()
}

// ============================================================================
// Installed Package Repository (Linux)
// ============================================================================

type sqliteInstalledPackageRepo struct{ db *sql.DB }

func (r *sqliteInstalledPackageRepo) Upsert(ctx context.Context, p *DBInstalledPackage) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO installed_packages (asset_id, name, version, arch, cpe_2_3_uri, status, updated_at) VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		ON CONFLICT(asset_id, name, arch) DO UPDATE SET version=excluded.version, cpe_2_3_uri=excluded.cpe_2_3_uri, status='installed', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')`,
		p.AssetID, p.Name, p.Version, p.Arch, p.CPE23URI, p.Status)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *sqliteInstalledPackageRepo) ListByAsset(ctx context.Context, assetID int64) ([]DBInstalledPackage, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, name, version, arch, cpe_2_3_uri, status, updated_at FROM installed_packages WHERE asset_id = ? ORDER BY name`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBInstalledPackage, 0)
	for rows.Next() {
		var p DBInstalledPackage
		if err := rows.Scan(&p.ID, &p.AssetID, &p.Name, &p.Version, &p.Arch, &p.CPE23URI, &p.Status, &p.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, p)
	}
	return items, rows.Err()
}

func (r *sqliteInstalledPackageRepo) MarkRemoved(ctx context.Context, assetID int64, keptNames []string) error {
	// Build placeholder list for NOT IN clause.
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if len(keptNames) > 0 {
		placeholders := make([]string, len(keptNames))
		args := make([]interface{}, len(keptNames)+1)
		args[0] = assetID
		for i, name := range keptNames {
			placeholders[i] = "?"
			args[i+1] = name
		}
		_, err = tx.ExecContext(ctx, `UPDATE installed_packages SET status='removed', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE asset_id=? AND name NOT IN (`+strings.Join(placeholders, ",")+`)`, args...)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE installed_packages SET status='removed', updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE asset_id=?`, assetID)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (r *sqliteInstalledPackageRepo) DeleteByAsset(ctx context.Context, assetID int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM installed_packages WHERE asset_id = ?`, assetID)
	return err
}

// ============================================================================
// Installed Software Repository (Windows)
// ============================================================================

type sqliteInstalledSoftwareRepo struct{ db *sql.DB }

func (r *sqliteInstalledSoftwareRepo) Upsert(ctx context.Context, s *DBInstalledSoftware) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO installed_software (asset_id, name, version, vendor, install_date, cpe_2_3_uri, updated_at) VALUES (?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))
		ON CONFLICT(asset_id, name, version) DO UPDATE SET vendor=excluded.vendor, install_date=excluded.install_date, cpe_2_3_uri=excluded.cpe_2_3_uri, updated_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')`,
		s.AssetID, s.Name, s.Version, s.Vendor, s.InstallDate, s.CPE23URI)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *sqliteInstalledSoftwareRepo) ListByAsset(ctx context.Context, assetID int64) ([]DBInstalledSoftware, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, asset_id, name, version, vendor, install_date, cpe_2_3_uri, updated_at FROM installed_software WHERE asset_id = ? ORDER BY name`, assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBInstalledSoftware, 0)
	for rows.Next() {
		var s DBInstalledSoftware
		if err := rows.Scan(&s.ID, &s.AssetID, &s.Name, &s.Version, &s.Vendor, &s.InstallDate, &s.CPE23URI, &s.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func (r *sqliteInstalledSoftwareRepo) DeleteByAsset(ctx context.Context, assetID int64) error {
	_, err := r.db.ExecContext(ctx, `DELETE FROM installed_software WHERE asset_id = ?`, assetID)
	return err
}

// ============================================================================
// Security Finding Repository
// ============================================================================

type sqliteSecurityFindingRepo struct{ db *sql.DB }

func (r *sqliteSecurityFindingRepo) BulkInsert(ctx context.Context, findings []DBSecurityFinding) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO security_findings (assessment_id, check_id, name, severity, status, evidence) VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, f := range findings {
		if _, err := stmt.ExecContext(ctx, f.AssessmentID, f.CheckID, f.Name, f.Severity, f.Status, f.Evidence); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *sqliteSecurityFindingRepo) ListByAssessment(ctx context.Context, assessmentID int64) ([]DBSecurityFinding, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, assessment_id, check_id, name, severity, status, evidence FROM security_findings WHERE assessment_id = ? ORDER BY severity DESC`, assessmentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBSecurityFinding, 0)
	for rows.Next() {
		var f DBSecurityFinding
		if err := rows.Scan(&f.ID, &f.AssessmentID, &f.CheckID, &f.Name, &f.Severity, &f.Status, &f.Evidence); err != nil {
			return nil, err
		}
		items = append(items, f)
	}
	return items, rows.Err()
}

// ============================================================================
// Credential Validation Repository
// ============================================================================

type sqliteCredentialValidationRepo struct{ db *sql.DB }

func (r *sqliteCredentialValidationRepo) Create(ctx context.Context, v *DBCredentialValidation) (int64, error) {
	res, err := r.db.ExecContext(ctx, `INSERT INTO credential_validations (profile_id, target, result_json, status) VALUES (?, ?, ?, ?)`,
		v.ProfileID, v.Target, v.ResultJSON, v.Status)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (r *sqliteCredentialValidationRepo) ListByProfile(ctx context.Context, profileID int64, limit int) ([]DBCredentialValidation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT id, profile_id, target, result_json, status, tested_at FROM credential_validations WHERE profile_id = ? ORDER BY tested_at DESC LIMIT ?`, profileID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]DBCredentialValidation, 0)
	for rows.Next() {
		var v DBCredentialValidation
		if err := rows.Scan(&v.ID, &v.ProfileID, &v.Target, &v.ResultJSON, &v.Status, &v.TestedAt); err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	return items, rows.Err()
}

// -- Scan History Repository -------------------------------------------------

type sqliteScanHistoryRepo struct{ db *sql.DB }

func (r *sqliteScanHistoryRepo) Insert(ctx context.Context, s *DBScanHistory) (int64, error) {
	res, err := r.db.ExecContext(ctx, `
		INSERT INTO scan_history (target, started_at, duration, ports_found, findings, risk_score,
			status, critical, high, medium, low, info, result_json)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, s.Target, s.StartedAt, s.Duration, s.PortsFound, s.Findings, s.RiskScore,
		s.Status, s.Critical, s.High, s.Medium, s.Low, s.Info, s.ResultJSON)
	if err != nil {
		return 0, fmt.Errorf("insert scan history: %w", err)
	}
	return res.LastInsertId()
}

func (r *sqliteScanHistoryRepo) List(ctx context.Context, limit int) ([]DBScanHistory, error) {
	rows, err := r.db.QueryContext(ctx, `
		SELECT id, target, started_at, duration, ports_found, findings, risk_score,
			status, critical, high, medium, low, info, result_json
		FROM scan_history ORDER BY started_at DESC LIMIT ?
	`, limit)
	if err != nil {
		return nil, fmt.Errorf("list scan history: %w", err)
	}
	defer rows.Close()
	var items []DBScanHistory
	for rows.Next() {
		var s DBScanHistory
		if err := rows.Scan(&s.ID, &s.Target, &s.StartedAt, &s.Duration,
			&s.PortsFound, &s.Findings, &s.RiskScore, &s.Status,
			&s.Critical, &s.High, &s.Medium, &s.Low, &s.Info, &s.ResultJSON); err != nil {
			return nil, err
		}
		items = append(items, s)
	}
	return items, rows.Err()
}

func (r *sqliteScanHistoryRepo) GetByID(ctx context.Context, id int64) (*DBScanHistory, error) {
	var s DBScanHistory
	err := r.db.QueryRowContext(ctx, `
		SELECT id, target, started_at, duration, ports_found, findings, risk_score,
			status, critical, high, medium, low, info, result_json
		FROM scan_history WHERE id = ?
	`, id).Scan(&s.ID, &s.Target, &s.StartedAt, &s.Duration,
		&s.PortsFound, &s.Findings, &s.RiskScore, &s.Status,
		&s.Critical, &s.High, &s.Medium, &s.Low, &s.Info, &s.ResultJSON)
	if err != nil {
		return nil, fmt.Errorf("get scan history by id: %w", err)
	}
	return &s, nil
}

func (r *sqliteScanHistoryRepo) DeleteAll(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, "DELETE FROM scan_history")
	return err
}

func (r *sqliteScanHistoryRepo) Count(ctx context.Context) (int, error) {
	var count int
	err := r.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM scan_history").Scan(&count)
	return count, err
}
