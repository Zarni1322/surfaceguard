# SurfaceGuard — User Manual

SurfaceGuard identifies exposed services and matches them against known CVEs using safe fingerprinting techniques. that identifies exposed services and matches them against known CVEs using safe fingerprinting techniques.

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Commands Overview](#commands-overview)
4. [Scan Command](#scan-command)
5. [Update Command](#update-command)
6. [Database Commands](#database-commands)
7. [Configuration](#configuration)
8. [Output Formats](#output-formats)
9. [Use Cases](#use-cases)
10. [FAQ](#faq)

---

## Installation

### Prerequisites
- Go 1.21+ (only for building from source)
- Internet access for CVE database updates
- ~100 MB disk space

### Build from Source
```bash
git clone <repo-url> && cd SurfaceGuard
go build -ldflags="-s -w" -o scanner ./cmd/scanner/
```

### Verify Installation
```bash
./surfaceguard --help
./surfaceguard version
```

---

## Quick Start

```bash
# Step 1: Update the CVE database (first run downloads full dataset)
./surfaceguard update

# Step 2: Scan a target
./surfaceguard scan example.com

# Step 3: Check database status
./surfaceguard db info
```

---

## Commands Overview

| Command | Description |
|---------|-------------|
| `scanner scan <target>` | Scan a target for open ports and CVEs |
| `scanner update` | Download/update CVE, KEV, EPSS data |
| `scanner db info` | Show database statistics |
| `scanner db verify` | Run database integrity check |
| `scanner db vacuum` | Optimize database size |
| `scanner version` | Show version information |

---

## Scan Command

```bash
scanner scan <target> [flags]
```

### Arguments
| Argument | Description |
|----------|-------------|
| `<target>` | Domain name (e.g. `example.com`), IPv4 address (e.g. `10.0.0.1`) |

### Flags
| Flag | Default | Description |
|------|---------|-------------|
| `-p, --ports` | Top 30 common ports | Ports to scan (e.g. `80,443` or `1-1000` or `1-65535`) |
| `-w, --workers` | `100` | Number of concurrent scan workers |
| `--timeout` | `3s` | Connection timeout per port |
| `-f, --format` | `console` | Output format: `console`, `json`, `html` |
| `-o, --output` | stdout | Write report to file |
| `--cvss-threshold` | `0.0` | Minimum CVSS score to report (e.g. `7.0` for HIGH+) |
| `--fingerprint` | `true` | Enable HTTP fingerprinting |

### Examples
```bash
# Basic scan
./surfaceguard scan example.com

# Scan specific ports
./surfaceguard scan 10.0.0.1 --ports 80,443,8080

# Scan all ports
./surfaceguard scan 10.0.0.1 --ports 1-65535

# Faster scan with more workers
./surfaceguard scan example.com --workers 500

# Only show CRITICAL and HIGH vulnerabilities
./surfaceguard scan example.com --cvss-threshold 7.0

# Generate HTML report
./surfaceguard scan example.com --format html --output report.html

# Generate JSON output
./surfaceguard scan example.com --format json
```

---

## Update Command

```bash
scanner update
```

Downloads vulnerability intelligence from three sources **concurrently**:

| Source | Data | Records |
|--------|------|---------|
| **NVD** (nvd.nist.gov) | CVE entries with CVSS scores | ~363,000 |
| **CISA KEV** (cisa.gov) | Known Exploited Vulnerabilities | ~1,600 |
| **FIRST EPSS** (first.org) | Exploit Prediction Scores | ~345,000 |

### Behavior
- **First run**: Downloads all data from scratch (may take several hours for NVD)
- **Subsequent runs**: Incremental — only downloads new/changed records
- All three feeds download concurrently
- Database is updated inside transactions (safe if interrupted)

### Example Output
```
Checking feed metadata...
NVD: Full download required (first run)
KEV: First download
EPSS: First download

Downloading feeds...
Normalizing records...
Updating SQLite...

========================================
NVD:   Inserted 1520 / Updated 350
KEV:   Inserted 1631
EPSS:  Inserted 345812
========================================
Database updated successfully.
```

---

## Database Commands

### Show Database Info
```bash
scanner db info
```
Displays:
- Schema version
- Last update timestamp
- Total CVEs, CPEs, Products, Vendors
- KEV entries count
- EPSS entries count
- Integrity check status

### Verify Integrity
```bash
scanner db verify
```
Runs SQLite `PRAGMA integrity_check`.

### Optimize Database
```bash
scanner db vacuum
```
Reclaims unused space. Run after large updates.

---

## Output Formats

### Console (default)
Human-readable terminal output with color-coded severity:
```
[CRITICAL] CVE-2023-38408
CVSS: 9.8 | Severity: CRITICAL | EPSS: 0.7677
OpenSSH 8.7 remote code execution via SSH agent forwarding
References:
  - https://nvd.nist.gov/vuln/detail/CVE-2023-38408
```

### JSON
Structured output for machine parsing:
```bash
./surfaceguard scan example.com --format json
```

### HTML
Self-contained HTML report with dark theme:
```bash
./surfaceguard scan example.com --format html --output report.html
```

---

## Use Cases

### Initial Reconnaissance
```bash
# Discover open ports and services
./surfaceguard scan 10.0.0.1 --ports 1-10000
```

### Vulnerability Assessment
```bash
# Scan common ports and check for CVEs
./surfaceguard scan web-server.company.com
```

### Regular Security Audits
```bash
# Update database first (incremental, fast)
./surfaceguard update

# Scan your infrastructure
./surfaceguard scan 10.0.0.1
./surfaceguard scan 10.0.0.2
```

### CI/CD Pipeline
```bash
./surfaceguard scan staging.example.com --format json --cvss-threshold 7.0
```

---

## Configuration

The scanner uses `configs/surfaceguard.yaml` for default settings. Environment variables with prefix `SURFACEGUARD_` override config values.

### Config File Location
1. `configs/surfaceguard.yaml` (project directory)
2. `~/.surfaceguard.yaml` (home directory)
3. `/etc/surfaceguard/surfaceguard.yaml` (system-wide)

### Key Settings
```yaml
scan:
  workers: 100
  timeout: 3s
  fingerprint: true

database:
  path: "data/cve.db"

update:
  cve_base_url: "https://services.nvd.nist.gov/rest/json/cves/2.0"
  kev_base_url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
  epss_base_url: "https://epss.cyentia.com/epss_scores-current.csv.gz"
  http_timeout: "300s"
  incremental: true

logging:
  level: "info"
  format: "text"
```

### Environment Variables
```bash
export SURFACEGUARD_SCAN_WORKERS=200
export SURFACEGUARD_DATABASE_PATH=/tmp/cve.db
export SURFACEGUARD_LOGGING_LEVEL=debug
```

---

## Architecture

```
Target → Port Scan → Banner Grab → Service Detection
  → HTTP Fingerprinting → Version Detection → CPE Mapping
  → CVE Matching (SQLite) → Report Generation
```

### Data Flow
1. TCP connect to each port (safe, no exploitation)
2. Read service banner
3. Identify service type and version
4. Map to CPE (Common Platform Enumeration)
5. Match CPE against local CVE database
6. Enrich with KEV and EPSS data
7. Generate report

---

## FAQ

### Is the scanner safe to run against production systems?
Yes. The scanner only performs TCP connections and reads initial banners. It never sends exploit payloads, authentication attempts, or modifies server state.

### How long does the first update take?
The first CVE download from NVD takes several hours (~200,000+ CVEs across 2,000+ API pages). KEV and EPSS complete in under a minute. Subsequent updates are incremental and take seconds.

### Can I scan while the database is updating?
Yes. The update runs independently from scanning. The database supports concurrent reads.

### How often should I update?
Run `./surfaceguard update` daily for the most current vulnerability data.

### Why are no CVEs found for my target?
Either:
- The CVE database hasn't been populated yet (run `./surfaceguard update` first)
- The detected software versions don't have known CVEs in the database
- The fingerprinting couldn't determine the exact version (common for non-standard banners)

