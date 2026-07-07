package database

import "time"

// DBVendor represents a row in the vendors table.
type DBVendor struct {
	ID   int64  `db:"id"`
	Name string `db:"name"` // e.g. "apache", "microsoft"
}

// DBProduct represents a row in the products table.
type DBProduct struct {
	ID       int64  `db:"id"`
	VendorID int64  `db:"vendor_id"`
	Name     string `db:"name"` // e.g. "http_server", "iis"
}

// DBCPE represents a row in the cpe table.
type DBCPE struct {
	ID         int64  `db:"id"`
	VendorID   int64  `db:"vendor_id"`
	ProductID  int64  `db:"product_id"`
	Part       string `db:"part"`        // a, o, h
	Version    string `db:"version"`
	Update     string `db:"update_"`
	Edition    string `db:"edition"`
	Language   string `db:"language"`
	TargetSW   string `db:"target_sw"`
	TargetHW   string `db:"target_hw"`
	Other      string `db:"other"`
	CPE23URI   string `db:"cpe_2_3_uri"` // full CPE 2.3 URI
}

// DBCVE represents a row in the cves table.
type DBCVE struct {
	ID               int64      `db:"id"`
	CVEID            string     `db:"cve_id"`       // e.g. "CVE-2024-1234"
	CPEID            int64      `db:"cpe_id"`
	Description      string     `db:"description"`
	CVSSv2           *float64   `db:"cvss_v2"`
	CVSSv3           *float64   `db:"cvss_v3"`
	Severity         string     `db:"severity"`
	PublishedDate    time.Time  `db:"published_date"`
	LastModifiedDate time.Time  `db:"last_modified_date"`
	ReferencesJSON   string     `db:"references_json"` // JSON array of URLs
}

// DBKEV represents a row in the kev table.
type DBKEV struct {
	ID      int64  `db:"id"`
	CVEID   string `db:"cve_id"`
	DueDate string `db:"due_date"` // ISO 8601 date string
	Notes   string `db:"notes"`
}

// DBEpss represents a row in the epss table.
type DBEpss struct {
	ID         int64   `db:"id"`
	CVEID      string  `db:"cve_id"` // references cves.cve_id
	Score      float64 `db:"epss_score"`
	Percentile float64 `db:"percentile"`
}

// DBMetadata represents a row in the metadata table (key-value store).
type DBMetadata struct {
	Key   string `db:"key"`
	Value string `db:"value"`
}

// DBCheckpoint represents a row in the update_checkpoints table.
type DBCheckpoint struct {
	FeedName    string `db:"feed_name"`
	State       string `db:"state"`
	Step        string `db:"step"`
	BytesOffset int64  `db:"bytes_offset"`
	FilePath    string `db:"file_path"`
	FileHash    string `db:"file_hash"`
	Message     string `db:"message"`
	UpdatedAt   string `db:"updated_at"`
	CreatedAt   string `db:"created_at"`
}

// ============================================================================
// Authenticated Assessment DB Types
// ============================================================================

// DBCredentialProfile represents a row in the credential_profiles table.
type DBCredentialProfile struct {
	ID        int64  `db:"id"`
	Name      string `db:"name"`
	Protocol  string `db:"protocol"`
	Host      string `db:"host"`
	Port      int    `db:"port"`
	Username  string `db:"username"`
	AuthMethod string `db:"auth_method"`
	// Encrypted fields (AES-GCM, hex-encoded)
	Credential1 string `db:"credential_1"` // password, private key, or community string
	Credential2 string `db:"credential_2"` // passphrase (SSH key), or SNMPv3 auth/proto
	Credential3 string `db:"credential_3"` // SNMPv3 priv/proto
	CreatedAt  string `db:"created_at"`
	UpdatedAt  string `db:"updated_at"`
}

// DBAssetInventory represents a row in the asset_inventory table.
type DBAssetInventory struct {
	ID            int64   `db:"id"`
	Hostname      string  `db:"hostname"`
	IP            string  `db:"ip"`
	OS            string  `db:"os"`
	Distro        string  `db:"distro"`
	KernelVersion string  `db:"kernel_version"`
	Architecture  string  `db:"architecture"`
	AssetType     string  `db:"asset_type"`
	RiskScore     float64 `db:"risk_score"`
	LastSeen      string  `db:"last_seen"`
	LastScan      string  `db:"last_scan"`
}

// DBAssessmentResult represents a row in the assessment_results table.
type DBAssessmentResult struct {
	ID          int64  `db:"id"`
	Target      string `db:"target"`
	ProfileID   int64  `db:"profile_id"`
	Protocol    string `db:"protocol"`
	StartedAt   string `db:"started_at"`
	Duration    string `db:"duration"`
	ResultJSON  string `db:"result_json"`
	Status      string `db:"status"`
}

// DBInstalledPackage represents a row in the installed_packages table.
type DBInstalledPackage struct {
	ID        int64  `db:"id"`
	AssetID   int64  `db:"asset_id"`
	Name      string `db:"name"`
	Version   string `db:"version"`
	Arch      string `db:"arch"`
	CPE23URI  string `db:"cpe_2_3_uri"`
	Status    string `db:"status"` // installed, removed, changed
	UpdatedAt string `db:"updated_at"`
}

// DBInstalledSoftware represents a row in the installed_software table.
type DBInstalledSoftware struct {
	ID          int64  `db:"id"`
	AssetID     int64  `db:"asset_id"`
	Name        string `db:"name"`
	Version     string `db:"version"`
	Vendor      string `db:"vendor"`
	InstallDate string `db:"install_date"`
	CPE23URI    string `db:"cpe_2_3_uri"`
	UpdatedAt   string `db:"updated_at"`
}

// DBSecurityFinding represents a row in the security_findings table.
type DBSecurityFinding struct {
	ID           int64  `db:"id"`
	AssessmentID int64  `db:"assessment_id"`
	CheckID      string `db:"check_id"`
	Name         string `db:"name"`
	Severity     string `db:"severity"`
	Status       string `db:"status"`
	Evidence     string `db:"evidence"`
}

// DBCredentialValidation represents a row in the credential_validations table.
type DBCredentialValidation struct {
	ID             int64  `db:"id"`
	ProfileID      int64  `db:"profile_id"`
	Target         string `db:"target"`
	ResultJSON     string `db:"result_json"`
	Status         string `db:"status"`
	TestedAt       string `db:"tested_at"`
}
