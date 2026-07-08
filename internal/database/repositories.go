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

	// Info returns a DatabaseInfo struct with aggregate stats.
	Info(ctx context.Context) (*models.DatabaseInfo, error)
	// Verify runs PRAGMA integrity_check.
	Verify(ctx context.Context) (bool, error)
	// Vacuum reclaims unused space in the database.
	Vacuum(ctx context.Context) error
	// Close cleanly shuts down the database connection.
	Close() error
}
