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
