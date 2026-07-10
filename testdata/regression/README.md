# SurfaceGuard Golden Test Dataset

## What This Is

The Golden Test Dataset is the authoritative regression baseline for SurfaceGuard's
detection pipeline. It consists of:

- **Banner files** (`testdata/banners/`): Realistic service banners that the scanner
  receives during TCP port scans.
- **Expected results** (`testdata/expected/`): JSON files specifying exactly what
  the detection engine *should* produce for each banner.
- **Regression test runner** (`testdata/regression/regression_test.go`): Automated
  tests that run every banner through the full fingerprint pipeline and compare
  against expected outputs.

Every future detection change must pass all golden tests.

---

## Directory Structure

```
testdata/
├── banners/              # Realistic service banners (one per file)
│   ├── apache_2_4_58.txt
│   ├── nginx_1_26_2.txt
│   ├── openssh_9_8.txt
│   └── ...
├── expected/             # Expected detection results (one JSON per banner)
│   ├── apache_2_4_58.json
│   ├── nginx_1_26_2.json
│   ├── openssh_9_8.json
│   └── ...
├── regression/           # Regression test runner
│   ├── regression_test.go
│   └── README.md
└── golden.md             # This file
```

---

## How to Run

```bash
# Run only the golden tests:
go test ./testdata/regression/ -v

# Run as part of the full test suite:
go test ./...
```

Output format:

```
=== RUN   TestGoldenDataset/apache_2_4_58.txt
--- PASS: TestGoldenDataset/apache_2_4_58.txt (0.00s)
=== RUN   TestGoldenDataset/openssh_9_8.txt
--- PASS: TestGoldenDataset/openssh_9_8.txt (0.00s)

========================================
Golden Test Dataset Summary
========================================
Total:  18
Passed: 18
Failed: 0
========================================
```

---

## How to Add a New Software

**No code changes required.** Adding a new test case only requires two files:

### Step 1: Create a banner file

`testdata/banners/<name>.txt`

```
SSH-2.0-OpenSSH_9.8
```

The banner should be a realistic representation of what the scanner receives
on a TCP connection. Do not include protocol framing bytes — just the text
that would appear in `port.Banner` after sanitization.

### Step 2: Create an expected JSON file

`testdata/expected/<name>.json`

```json
{
  "software": "OpenSSH 9.8",
  "banner_file": "openssh_9_8.txt",
  "port": 22,
  "service": "ssh",
  "vendor": "openbsd",
  "product": "OpenSSH",
  "version": "9.8",
  "cpe": "cpe:2.3:a:openbsd:openssh:9.8:*:*:*:*:*:*",
  "expected_confidence": 90,
  "expected_confidence_min": 80,
  "match_type": "exact",
  "expected_cves": [],
  "tags": ["ssh", "openssh"]
}
```

**Important:** The expected values must match what the current fingerprint
engine *actually* produces. If there is a known limitation (wrong version,
wrong product, wrong CPE), document it in the `notes` field and set the
expected values to match the current output. This creates a baseline that
future fixes can improve upon.

### Step 3: Run the tests

```bash
go test ./testdata/regression/ -v -run "GoldenDataset"
```

---

## Expected JSON Fields

| Field | Required | Description |
|-------|----------|-------------|
| `software` | Yes | Human-readable label (e.g. "Apache HTTP Server 2.4.58") |
| `banner_file` | Yes | Matching banner filename (for cross-reference) |
| `port` | Yes | TCP port number |
| `service` | Yes | Expected detected service name |
| `vendor` | Yes | Expected CPE vendor (empty for unmapped products) |
| `product` | Yes | Expected detected product name |
| `version` | Yes | Expected extracted version (empty if not extracted) |
| `cpe` | Yes | Expected CPE 2.3 URI (empty if no CPE generated) |
| `expected_confidence` | Yes | Typical confidence value |
| `expected_confidence_min` | Yes | Minimum acceptable confidence (for range validation) |
| `match_type` | Yes | Classification of match quality |
| `expected_cves` | Yes | CVE IDs that should be matched (currently unused) |
| `tags` | Yes | Categorisation tags |
| `notes` | No | Explanation of known limitations |

---

## Match Types

| Type | Meaning |
|------|---------|
| `exact` | All detection fields are correct |
| `banner_match` | Service detected by banner regex, product/version may be approximate |
| `wrong_product_fallback` | Product is wrong because of `productByService` fallback |
| `wrong_service_detection` | Service is wrong because of regex ordering |
| `wrong_version_extraction` | Version is wrong because of generic regex over-matching |
| `version_suffix_issue` | Version has extra suffix (e.g., "-log", "-MariaDB") |
| `unmapped_product` | Product has no vendor/product mapping yet |
| `wider_coverage` | Service detected correctly, CPE generated from service-name mapping |

---

## How Regression Tests Work

1. For each `.txt` file in `testdata/banners/`:
   a. Read the banner text
   b. Build a `models.Port` with the banner and port number from the expected JSON
   c. Run `fingerprint.Fingerprint()` on the port (same pipeline as production)
   d. Compare the result against expected JSON fields:
      - Service name
      - Product name
      - Version string
      - CPE URI (first CPE if multiple)
      - CPE vendor (via shared `cpe` package)
      - Confidence (minimum threshold)
   e. Report PASS/FAIL for each check

2. `TestVendorConsistency` validates that the shared CPE maps are internally consistent.

3. `TestCVERegression` is a placeholder for CVE matching tests that require
   a seeded CVE database (to be implemented when version-range validation is added).

---

## CI/CD Integration

```yaml
# .github/workflows/test.yml
- name: Run golden tests
  run: go test ./testdata/regression/ -v

- name: Run full test suite
  run: go test ./...
```

The golden tests run as standard Go tests with no external dependencies.
They do not require a network connection, a database, or any external service.

---

## How Future Fixes Will Be Validated

### Version Range Validation (Future Fix)

When version-range validation is added:

1. An expected CVE database will be seeded via the test framework.
2. `TestCVERegression` will be expanded to seed test CVEs, run `matcher.MatchPort`,
   and validate expected CVEs are returned.
3. The `expected_cves` field in each expected JSON will list the CVEs that
   should apply to this software version.

**Example:** If a CVE affects Apache httpd < 2.4.50 and the banner is
Apache 2.4.58, the test will verify:
- CVE-2024-XXXX is NOT matched (not affected)
- CVE-2024-YYYY IS matched (if it affects all 2.4.x versions)

### Banner Parsing Improvements (Future Fix)

When the version extraction regexes are improved:

1. Update the `expected/<name>.json` with the correct values.
2. Run the golden tests — they should all pass.
3. Old incorrect values in `notes` will become historical documentation.

**Example:** If MariaDB version extraction is fixed to strip `-MariaDB`,
the expected JSON changes from `"10.11.8-MariaDB"` to `"10.11.8"`.

### Exact CPE Matching (Future Fix)

When CPE matching is improved (e.g., adding product-specific entries):

1. Products currently in `unmapped_product` or `wrong_product_fallback`
   status will be moved to `exact` status.
2. The expected JSON is updated with the correct vendor/product/CPE.
3. The golden test ensures the fix works for all previously-known cases.

---

## Current Baseline (v1)

| Software | Match Type | Notes |
|----------|-----------|-------|
| Apache HTTP Server 2.4.58 | ✅ exact | |
| nginx 1.26.2 | ✅ exact | |
| Microsoft IIS 10.0 | ✅ exact | |
| Caddy 2.8.4 | ✅ exact | Fixed in Fix 5 |
| lighttpd 1.4.76 | ✅ exact | |
| OpenSSH 9.8 | ✅ exact | |
| Dropbear 2024.85 | ✅ exact | Fixed in Fix 5 |
| MySQL 8.0.36 | ✅ exact | Fixed in Fix 5 (suffix stripping + version-first pattern) |
| MariaDB 10.11.8 | ✅ exact | Fixed in Fix 5 |
| PostgreSQL 16.4 | ✅ exact | |
| Redis 7.2.6 | ✅ exact | Fixed in Fix 5 (signature ordering) |
| MongoDB 7.0.12 | ✅ exact | |
| Postfix 3.9.0 | ✅ exact | Fixed in Fix 5 |
| Exim 4.98 | ✅ exact | Fixed in Fix 5 |
| Apache Tomcat 10.1.28 | ✅ exact | Fixed in Fix 5 (product signature ordering) |
| Eclipse Jetty 12.0.14 | ✅ exact | Fixed in Fix 5 |
| HashiCorp Consul 1.19 | ⚠️ unmapped_product | Port 8500 detected as http, no product signature |
| Apache Kafka 3.7 | ⚠️ port_based_detection | Port-based detection, no banner signature |
