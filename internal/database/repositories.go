package database

import (
	"context"
	"time"

	"github.com/evilhunter/surfaceguard/pkg/models"
)

// ============================================================================
// Repository Interfaces
// These define the contract between the application and data storage.
// The implementations are in sqlite.go.
// ============================================================================

// VendorRepository handles vendor CRUD operations.
type VendorRepository interface {
	// GetOrCreate returns the ID of a vendor, creating it if it doesn't exist.
	GetOrCreate(ctx context.Context, name string) (int64, error)
	// List returns all vendors.
	List(ctx context.Context) ([]DBVendor, error)
	// Count returns the total number of vendors.
	Count(ctx context.Context) (int, error)
}

// ProductRepository handles product CRUD operations.
type ProductRepository interface {
	// GetOrCreate returns the ID of a product under a vendor, creating if needed.
	GetOrCreate(ctx context.Context, vendorID int64, name string) (int64, error)
	// List returns all products, optionally filtered by vendor.
	List(ctx context.Context, vendorID int64) ([]DBProduct, error)
	// Count returns the total number of products.
	Count(ctx context.Context) (int, error)
}

// CPERepository handles CPE CRUD operations and matching.
type CPERepository interface {
	// Insert adds a new CPE record.
	Insert(ctx context.Context, cpe *DBCPE) (int64, error)
	// FindByProduct attempts to find CPEs matching a vendor, product, and version.
	// Uses LIKE matching with wildcards for flexible version comparison.
	FindByProduct(ctx context.Context, vendor, product, version string) ([]DBCPE, error)
	// FindByCPE23URI finds CPEs by their full CPE 2.3 URI.
	FindByCPE23URI(ctx context.Context, uri string) ([]DBCPE, error)
	// FindNearbyVersions finds CPEs for the same vendor+product within the same
	// major.minor version range (e.g., 2.4.x for a 2.4.58 detected version).
	// This enables nearby version matching without wildcard fallback.
	FindNearbyVersions(ctx context.Context, vendor, product, version string, limit int) ([]DBCPE, error)
	// Count returns the total number of CPE records.
	Count(ctx context.Context) (int, error)
	// ExistsByURI checks if a CPE with the given URI already exists.
	ExistsByURI(ctx context.Context, uri string) (bool, error)
	// BulkInsert inserts multiple CPE records in a single transaction.
	BulkInsert(ctx context.Context, cpes []DBCPE) (int64, error)
}

// CVERepository handles CVE CRUD operations and matching.
type CVERepository interface {
	// Insert adds a new CVE record.
	Insert(ctx context.Context, cve *DBCVE) (int64, error)
	// FindByCPEID returns all CVEs associated with a given CPE.
	FindByCPEID(ctx context.Context, cpeID int64) ([]DBCVE, error)
	// FindByCVEID returns a specific CVE by its CVE-ID string.
	FindByCVEID(ctx context.Context, cveID string) (*DBCVE, error)
	// FindByCPE23URI returns all CVEs matching a CPE 2.3 URI pattern.
	FindByCPE23URI(ctx context.Context, cpe23URI string) ([]DBCVE, error)
	// SearchByProduct returns all CVEs matching a vendor+product combination.
	SearchByProduct(ctx context.Context, vendor, product string) ([]DBCVE, error)
	// SearchByProductName returns all CVEs matching a product name alone
	// (vendor-agnostic). Fallback when the vendor is unknown / wildcard.
	SearchByProductName(ctx context.Context, product string) ([]DBCVE, error)
	// Upsert inserts a CVE or updates it if it already exists (by cve_id + cpe_id).
	Upsert(ctx context.Context, cve *DBCVE) (int64, bool, error)
	// Count returns the total number of CVE records.
	Count(ctx context.Context) (int, error)
	// CountBySeverity returns CVE counts grouped by severity.
	CountBySeverity(ctx context.Context) (map[string]int, error)
	// LastModifiedCursor returns the most recent last_modified_date across all CVEs.
	LastModifiedCursor(ctx context.Context) (*time.Time, error)
}

// KEVRepository handles the CISA Known Exploited Vulnerabilities table.
type KEVRepository interface {
	// Upsert inserts or updates a KEV entry.
	Upsert(ctx context.Context, kev *DBKEV) (int64, bool, error)
	// IsInKEV checks if a CVE ID is in the KEV list.
	IsInKEV(ctx context.Context, cveID string) (bool, error)
	// GetByCVEID returns the KEV entry for a specific CVE.
	GetByCVEID(ctx context.Context, cveID string) (*DBKEV, error)
	// Count returns the total number of KEV entries.
	Count(ctx context.Context) (int, error)
	// BulkUpsert inserts or updates multiple KEV entries in a transaction.
	BulkUpsert(ctx context.Context, entries []DBKEV) error
}

// EPSSRepository handles the EPSS score table.
type EPSSRepository interface {
	// Upsert inserts or updates an EPSS entry.
	Upsert(ctx context.Context, epss *DBEpss) (int64, bool, error)
	// GetByCVEID returns the EPSS entry for a specific CVE.
	GetByCVEID(ctx context.Context, cveID string) (*DBEpss, error)
	// Count returns the total number of EPSS entries.
	Count(ctx context.Context) (int, error)
	// BulkUpsert inserts or updates multiple EPSS entries in a transaction.
	BulkUpsert(ctx context.Context, entries []DBEpss) error
}

// MetadataRepository handles the metadata key-value store.
type MetadataRepository interface {
	// Set stores a metadata value.
	Set(ctx context.Context, key, value string) error
	// Get retrieves a metadata value by key.
	Get(ctx context.Context, key string) (string, error)
	// Delete removes a metadata entry.
	Delete(ctx context.Context, key string) error
	// List returns all metadata entries.
	List(ctx context.Context) ([]DBMetadata, error)
}

// CheckpointRepository tracks fault-tolerant update progress.
type CheckpointRepository interface {
	// Save persists a checkpoint for a feed (insert or update).
	Save(ctx context.Context, cp *DBCheckpoint) error
	// Get returns the checkpoint for a feed, or an error if none exists.
	Get(ctx context.Context, feedName string) (*DBCheckpoint, error)
	// List returns all checkpoints.
	List(ctx context.Context) ([]DBCheckpoint, error)
	// Delete removes a checkpoint for a feed.
	Delete(ctx context.Context, feedName string) error
	// DeleteAll removes all checkpoints.
	DeleteAll(ctx context.Context) error
}

// CredentialProfileRepository manages credential profiles.
type CredentialProfileRepository interface {
	// List returns all credential profiles.
	List(ctx context.Context) ([]DBCredentialProfile, error)
	// Get returns a profile by ID.
	Get(ctx context.Context, id int64) (*DBCredentialProfile, error)
	// Create inserts a new profile.
	Create(ctx context.Context, p *DBCredentialProfile) (int64, error)
	// Update modifies an existing profile.
	Update(ctx context.Context, p *DBCredentialProfile) error
	// Delete removes a profile by ID.
	Delete(ctx context.Context, id int64) error
}

// AssetInventoryRepository manages asset inventory.
type AssetInventoryRepository interface {
	// Upsert creates or updates an asset by hostname+type.
	Upsert(ctx context.Context, a *DBAssetInventory) (int64, error)
	// Get returns an asset by ID.
	Get(ctx context.Context, id int64) (*DBAssetInventory, error)
	// FindByHostname returns an asset by hostname and type.
	FindByHostname(ctx context.Context, hostname, assetType string) (*DBAssetInventory, error)
	// List returns all assets.
	List(ctx context.Context) ([]DBAssetInventory, error)
	// UpdateRiskScore updates the risk score for an asset.
	UpdateRiskScore(ctx context.Context, id int64, score float64) error
	// UpdateLastScan updates the last_scan timestamp.
	UpdateLastScan(ctx context.Context, id int64, scanTime string) error
}

// AssessmentResultRepository manages assessment scan results.
type AssessmentResultRepository interface {
	// Create inserts a new assessment result.
	Create(ctx context.Context, r *DBAssessmentResult) (int64, error)
	// List returns assessment results, most recent first.
	List(ctx context.Context, limit int) ([]DBAssessmentResult, error)
	// Get returns an assessment result by ID.
	Get(ctx context.Context, id int64) (*DBAssessmentResult, error)
	// ListByTarget returns results for a specific target.
	ListByTarget(ctx context.Context, target string) ([]DBAssessmentResult, error)
}

// InstalledPackageRepository manages per-asset installed packages.
type InstalledPackageRepository interface {
	// Upsert inserts or updates a package for an asset.
	Upsert(ctx context.Context, p *DBInstalledPackage) (int64, error)
	// ListByAsset returns all packages for an asset.
	ListByAsset(ctx context.Context, assetID int64) ([]DBInstalledPackage, error)
	// MarkRemoved marks packages not in the current scan as removed.
	MarkRemoved(ctx context.Context, assetID int64, keptNames []string) error
	// DeleteByAsset removes all package records for an asset.
	DeleteByAsset(ctx context.Context, assetID int64) error
}

// InstalledSoftwareRepository manages per-asset installed software (Windows).
type InstalledSoftwareRepository interface {
	// Upsert inserts or updates a software entry for an asset.
	Upsert(ctx context.Context, s *DBInstalledSoftware) (int64, error)
	// ListByAsset returns all software for an asset.
	ListByAsset(ctx context.Context, assetID int64) ([]DBInstalledSoftware, error)
	// DeleteByAsset removes all software records for an asset.
	DeleteByAsset(ctx context.Context, assetID int64) error
}

// ScanHistoryRepository stores completed CVE Discovery scan records.
// This is the single source of truth for all scan history data.
type ScanHistoryRepository interface {
	// Insert saves a completed scan record atomically.
	Insert(ctx context.Context, r *DBScanHistory) (int64, error)
	// List returns scan records ordered by started_at DESC.
	List(ctx context.Context, limit int) ([]DBScanHistory, error)
	// GetByID returns a single scan record by its ID.
	GetByID(ctx context.Context, id int64) (*DBScanHistory, error)
		// Delete removes a single scan record by ID.
		Delete(ctx context.Context, id int64) error
	// DeleteAll removes all scan history records.
	DeleteAll(ctx context.Context) error
	// Count returns the total number of scan records.
	Count(ctx context.Context) (int, error)
}

// SecurityFindingRepository stores security configuration findings.
type SecurityFindingRepository interface {
	// BulkInsert inserts findings for an assessment.
	BulkInsert(ctx context.Context, findings []DBSecurityFinding) error
	// ListByAssessment returns findings for a specific assessment.
	ListByAssessment(ctx context.Context, assessmentID int64) ([]DBSecurityFinding, error)
}

// CredentialValidationRepository stores credential validation history.
type CredentialValidationRepository interface {
	// Create inserts a validation record.
	Create(ctx context.Context, v *DBCredentialValidation) (int64, error)
	// ListByProfile returns validation history for a profile.
	ListByProfile(ctx context.Context, profileID int64, limit int) ([]DBCredentialValidation, error)
}

// EASMScanRepository manages EASM scan records.
type EASMScanRepository interface {
	// Create inserts a new scan record and returns its ID.
	Create(ctx context.Context, s *DBEASMScan) (int64, error)
	// Get returns a scan by ID.
	Get(ctx context.Context, id int64) (*DBEASMScan, error)
	// UpdateStatus updates the scan status and completion stats.
	UpdateStatus(ctx context.Context, id int64, status string, completedAt string, durationMs int64, errMsg string) error
	// UpdateStats updates aggregate counters for a completed scan.
	UpdateStats(ctx context.Context, id int64, totalAssets, aliveAssets, totalServices, totalCVEs int,
		criticalCVEs, highCVEs, mediumCVEs, lowCVEs, kevCVEs int, avgEPSS float64) error
	// List returns all scans, most recent first.
	List(ctx context.Context, limit int) ([]DBEASMScan, error)
	// Delete removes a scan and all related data.
	Delete(ctx context.Context, id int64) error
}

// EASMAssetRepository manages discovered EASM assets.
type EASMAssetRepository interface {
	// Insert adds a new asset.
	Insert(ctx context.Context, a *DBEASMAsset) (int64, error)
	// BulkInsert adds multiple assets in a transaction.
	BulkInsert(ctx context.Context, assets []DBEASMAsset) error
	// ListByScan returns all assets for a scan.
	ListByScan(ctx context.Context, scanID int64) ([]DBEASMAsset, error)
	// CountByScan returns the number of assets for a scan.
	CountByScan(ctx context.Context, scanID int64) (int, error)
	// GetByScanAndHost returns an asset by scan ID and hostname.
	GetByScanAndHost(ctx context.Context, scanID int64, hostname string) (*DBEASMAsset, error)
}

// EASMServiceRepository manages discovered EASM services.
type EASMServiceRepository interface {
	// Insert adds a new service.
	Insert(ctx context.Context, s *DBEASMService) (int64, error)
	// BulkInsert adds multiple services in a transaction.
	BulkInsert(ctx context.Context, services []DBEASMService) error
	// ListByAsset returns all services for an asset.
	ListByAsset(ctx context.Context, assetID int64) ([]DBEASMService, error)
	// ListByScan returns all services for a scan.
	ListByScan(ctx context.Context, scanID int64) ([]DBEASMService, error)
	// CountByScan returns the number of services for a scan.
	CountByScan(ctx context.Context, scanID int64) (int, error)
}

// EASMFindingRepository manages CVE findings for EASM scans.
type EASMFindingRepository interface {
	// Insert adds a new finding.
	Insert(ctx context.Context, f *DBEASMFinding) (int64, error)
	// BulkInsert adds multiple findings in a transaction.
	BulkInsert(ctx context.Context, findings []DBEASMFinding) error
	// ListByScan returns all findings for a scan.
	ListByScan(ctx context.Context, scanID int64) ([]DBEASMFinding, error)
	// ListByService returns all findings for a service.
	ListByService(ctx context.Context, serviceID int64) ([]DBEASMFinding, error)
	// CountByScan returns the number of findings for a scan.
	CountByScan(ctx context.Context, scanID int64) (int, error)
	// ListByScanWithAsset returns findings enriched with asset hostname and port.
	ListByScanWithAsset(ctx context.Context, scanID int64) ([]EnrichedFinding, error)
	// CountBySeverity returns finding counts grouped by severity for a scan.
	CountBySeverity(ctx context.Context, scanID int64) (map[string]int, error)
}

// Database is the top-level interface aggregating all repositories.
type Database interface {
	// Vendor returns the vendor repository.
	Vendor() VendorRepository
	// Product returns the product repository.
	Product() ProductRepository
	// CPE returns the CPE repository.
	CPE() CPERepository
	// CVE returns the CVE repository.
	CVE() CVERepository
	// KEV returns the KEV repository.
	KEV() KEVRepository
	// EPSS returns the EPSS repository.
	EPSS() EPSSRepository
	// Metadata returns the metadata repository.
	Metadata() MetadataRepository
	// Checkpoint returns the checkpoint repository.
	Checkpoint() CheckpointRepository
	// CredentialProfile returns the credential profile repository.
	CredentialProfile() CredentialProfileRepository
	// AssetInventory returns the asset inventory repository.
	AssetInventory() AssetInventoryRepository
	// AssessmentResult returns the assessment result repository.
	AssessmentResult() AssessmentResultRepository
	// InstalledPackage returns the installed package repository.
	InstalledPackage() InstalledPackageRepository
	// InstalledSoftware returns the installed software repository.
	InstalledSoftware() InstalledSoftwareRepository
	// SecurityFinding returns the security finding repository.
	SecurityFinding() SecurityFindingRepository
	// CredentialValidation returns the credential validation repository.
	CredentialValidation() CredentialValidationRepository
	// EASMScan returns the EASM scan repository.
	EASMScan() EASMScanRepository
	// EASMAsset returns the EASM asset repository.
	EASMAsset() EASMAssetRepository
	// EASMService returns the EASM service repository.
	EASMService() EASMServiceRepository
	// EASMFinding returns the EASM finding repository.
	EASMFinding() EASMFindingRepository
	// ScanHistory returns the scan history repository.
	ScanHistory() ScanHistoryRepository

	// Info returns a DatabaseInfo struct with aggregate stats.
	Info(ctx context.Context) (*models.DatabaseInfo, error)
	// Verify runs PRAGMA integrity_check.
	Verify(ctx context.Context) (bool, error)
	// Vacuum reclaims unused space in the database.
	Vacuum(ctx context.Context) error
	// Close cleanly shuts down the database connection.
	Close() error
}
