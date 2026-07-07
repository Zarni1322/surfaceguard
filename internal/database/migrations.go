package database

const schemaVersion = 4

// schema holds all CREATE TABLE statements. Each migration is a versioned step.
// Always append new migrations; never modify existing ones.
var schema = map[int]string{
	1: schemaV1,
	2: schemaV2,
	3: schemaV3,
	4: schemaV4,
}

const schemaV1 = `
-- Vendors: normalized vendor names (e.g. "apache", "microsoft")
CREATE TABLE IF NOT EXISTS vendors (
    id   INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE
);

-- Products: normalized product names under a vendor
CREATE TABLE IF NOT EXISTS products (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id INTEGER NOT NULL REFERENCES vendors(id),
    name      TEXT NOT NULL COLLATE NOCASE,
    UNIQUE(vendor_id, name)
);

-- CPE: individual CPE 2.3 records linked to vendor+product
CREATE TABLE IF NOT EXISTS cpe (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    vendor_id   INTEGER NOT NULL REFERENCES vendors(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    part        TEXT NOT NULL DEFAULT 'a',
    version     TEXT NOT NULL DEFAULT '*',
    update_     TEXT NOT NULL DEFAULT '*',
    edition     TEXT NOT NULL DEFAULT '*',
    language    TEXT NOT NULL DEFAULT '*',
    target_sw   TEXT NOT NULL DEFAULT '*',
    target_hw   TEXT NOT NULL DEFAULT '*',
    other       TEXT NOT NULL DEFAULT '*',
    cpe_2_3_uri TEXT NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_cpe_vendor_product ON cpe(vendor_id, product_id);
CREATE INDEX IF NOT EXISTS idx_cpe_uri ON cpe(cpe_2_3_uri);

-- CVEs: vulnerability records linked to CPEs
CREATE TABLE IF NOT EXISTS cves (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id             TEXT NOT NULL,
    cpe_id             INTEGER NOT NULL REFERENCES cpe(id),
    description        TEXT NOT NULL DEFAULT '',
    cvss_v2            REAL,
    cvss_v3            REAL,
    severity           TEXT NOT NULL DEFAULT 'NONE',
    published_date     TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    last_modified_date TEXT NOT NULL DEFAULT '1970-01-01T00:00:00Z',
    references_json    TEXT NOT NULL DEFAULT '[]',
    UNIQUE(cve_id, cpe_id)
);
CREATE INDEX IF NOT EXISTS idx_cves_cve_id ON cves(cve_id);
CREATE INDEX IF NOT EXISTS idx_cves_cpe_id ON cves(cpe_id);
CREATE INDEX IF NOT EXISTS idx_cves_severity ON cves(severity);
CREATE INDEX IF NOT EXISTS idx_cves_cvss_v3 ON cves(cvss_v3);

-- KEV: CISA Known Exploited Vulnerabilities
-- cve_id is a logical reference to cves.cve_id (not a FK constraint)
-- because cves.cve_id is part of a composite UNIQUE, not single-column UNIQUE.
CREATE TABLE IF NOT EXISTS kev (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id   TEXT NOT NULL UNIQUE,
    due_date TEXT,
    notes    TEXT NOT NULL DEFAULT ''
);

-- EPSS: Exploit Prediction Scoring System scores
CREATE TABLE IF NOT EXISTS epss (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id      TEXT NOT NULL UNIQUE,
    epss_score  REAL NOT NULL DEFAULT 0.0,
    percentile  REAL NOT NULL DEFAULT 0.0
);

-- Metadata: key-value store for schema version, last update, etc.
CREATE TABLE IF NOT EXISTS metadata (
    key   TEXT NOT NULL PRIMARY KEY,
    value TEXT NOT NULL
);

-- Seed initial metadata
INSERT OR IGNORE INTO metadata (key, value) VALUES ('schema_version', '1');
INSERT OR IGNORE INTO metadata (key, value) VALUES ('created_at', strftime('%Y-%m-%dT%H:%M:%SZ', 'now'));
`

const schemaV2 = `
-- Web rules cache: stores the last-seen state of YAML rules
CREATE TABLE IF NOT EXISTS web_rules (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'INFO',
    category   TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- CWE mapping table for reference
CREATE TABLE IF NOT EXISTS cwe_mapping (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    cwe_id      TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

-- OWASP mapping table for reference
CREATE TABLE IF NOT EXISTS owasp_mapping (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    category    TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT ''
);

-- Seed CWE reference data (web application security weaknesses)
INSERT OR IGNORE INTO cwe_mapping (cwe_id, name, description) VALUES
    ('CWE-20', 'Improper Input Validation', 'Insufficient validation of user-supplied input.'),
    ('CWE-22', 'Path Traversal', 'User input used in file paths without validation.'),
    ('CWE-77', 'Command Injection', 'User input used in OS commands without sanitization.'),
    ('CWE-78', 'OS Command Injection', 'User input passed directly to OS command interpreter.'),
    ('CWE-79', 'Cross-Site Scripting (XSS)', 'User input reflected in web pages without encoding.'),
    ('CWE-89', 'SQL Injection', 'User input used in SQL queries without parameterization.'),
    ('CWE-94', 'Code Injection', 'User input evaluated as code.'),
    ('CWE-120', 'Buffer Overflow', 'Data copied to buffer without size check.'),
    ('CWE-200', 'Information Exposure', 'Sensitive information exposed through error messages or headers.'),
    ('CWE-213', 'Exposure of Debug Info', 'Debug information exposed to end users.'),
    ('CWE-284', 'Improper Access Control', 'Access restrictions not properly enforced.'),
    ('CWE-306', 'Missing Authentication', 'Critical function lacks authentication.'),
    ('CWE-319', 'Cleartext Transmission', 'Missing Strict-Transport-Security header.'),
    ('CWE-326', 'Weak TLS', 'Deprecated TLS version or weak cipher in use.'),
    ('CWE-352', 'CSRF', 'Missing anti-CSRF tokens.'),
    ('CWE-416', 'Use After Free', 'Memory used after being freed.'),
    ('CWE-434', 'Unrestricted File Upload', 'File uploads without proper validation.'),
    ('CWE-476', 'NULL Pointer Dereference', 'NULL pointer accessed.'),
    ('CWE-502', 'Deserialization of Untrusted Data', 'Untrusted data deserialized without validation.'),
    ('CWE-548', 'Directory Listing', 'Directory listing enabled on web server.'),
    ('CWE-614', 'Cookie Without Secure Flag', 'Cookie transmitted without Secure flag.'),
    ('CWE-639', 'Insecure Direct Object Reference', 'Direct object references without access control.'),
    ('CWE-693', 'Missing CSP', 'Content-Security-Policy header not set.'),
    ('CWE-770', 'Resource Allocation Without Limits', 'Resources allocated without limits.'),
    ('CWE-787', 'Out-of-bounds Write', 'Data written past buffer end.'),
    ('CWE-862', 'Missing Authorization', 'Authorization not verified.'),
    ('CWE-863', 'Incorrect Authorization', 'Flawed authorization logic.'),
    ('CWE-918', 'Server-Side Request Forgery', 'Server fetches remote resources from user input.'),
    ('CWE-1004', 'Cookie Without HttpOnly', 'Cookie accessible to client-side scripts.'),
    ('CWE-1021', 'Clickjacking', 'Missing X-Frame-Options header.'),
    ('CWE-1275', 'Cookie Without SameSite', 'Cookie missing SameSite attribute.'),
    ('CWE-1390', 'Authentication Bypass via SQLi', 'SQL injection in authentication logic allows login without valid credentials.');

-- Seed OWASP Top 10 2021 reference data
INSERT OR IGNORE INTO owasp_mapping (category, name, description) VALUES
    ('A1:2021', 'Broken Access Control', 'Failures in access control often lead to unauthorized information disclosure or modification.'),
    ('A2:2021', 'Cryptographic Failures', 'Failures related to cryptography that often lead to exposure of sensitive data.'),
    ('A3:2021', 'Injection', 'Injection flaws such as SQL, NoSQL, OS command, and LDAP injection occur when untrusted data is sent to an interpreter.'),
    ('A4:2021', 'Insecure Design', 'Risks related to design and architecture flaws.'),
    ('A5:2021', 'Security Misconfiguration', 'Security misconfiguration is the most common issue, resulting from insecure default configurations.'),
    ('A6:2021', 'Vulnerable and Outdated Components', 'Using components with known vulnerabilities undermines application security.'),
    ('A7:2021', 'Identification and Authentication Failures', 'Authentication failures can compromise user identities.'),
    ('A8:2021', 'Software and Data Integrity Failures', 'Failures related to software updates, CI/CD pipelines, and signed objects.'),
    ('A9:2021', 'Security Logging and Monitoring Failures', 'Insufficient logging and monitoring can delay breach detection.'),
    ('A10:2021', 'Server-Side Request Forgery (SSRF)', 'SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL.');
`

const schemaV3 = `
-- Update history: tracks each update run for auditing and debugging
CREATE TABLE IF NOT EXISTS update_history (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_time      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    feed          TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'unknown',
    records_inserted INTEGER NOT NULL DEFAULT 0,
    records_updated  INTEGER NOT NULL DEFAULT 0,
    duration_ms   INTEGER NOT NULL DEFAULT 0,
    error_message TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_update_history_time ON update_history(run_time);
CREATE INDEX IF NOT EXISTS idx_update_history_feed ON update_history(feed);
`

const schemaV4 = `
-- Update checkpoints: tracks fault-tolerant feed update progress
CREATE TABLE IF NOT EXISTS update_checkpoints (
    feed_name    TEXT NOT NULL PRIMARY KEY,
    state        TEXT NOT NULL DEFAULT 'NOT_STARTED',
    step         TEXT NOT NULL DEFAULT '',
    bytes_offset INTEGER NOT NULL DEFAULT 0,
    file_path    TEXT NOT NULL DEFAULT '',
    file_hash    TEXT NOT NULL DEFAULT '',
    message      TEXT NOT NULL DEFAULT '',
    updated_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);
`
