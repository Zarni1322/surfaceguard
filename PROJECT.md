# SurfaceGuard — Project Status

**Version:** 1.0.0  
**Phase:** Development / Stable  
**Organization:** Cyber Ops Academy  
**Author:** Han Niux  

---

## Completed Features

| Feature | Status |
|---------|--------|
| Port Scanning (concurrent TCP) | ✅ |
| Banner Grabbing | ✅ |
| Service Detection (20+ signatures) | ✅ |
| Version Detection | ✅ |
| HTTP Fingerprinting | ✅ |
| TLS Certificate Analysis | ✅ |
| CPE Mapping | ✅ |
| CVE Database (SQLite) | ✅ |
| NVD Feed Download | ✅ |
| CISA KEV Integration | ✅ |
| EPSS Scoring Integration | ✅ |
| CVE Matching with Fallback | ✅ |
| Risk Score Calculation | ✅ |
| HTML Reports | ✅ |
| JSON Export | ✅ |
| CSV Export | ✅ |
| CLI Interface | ✅ |
| YAML Configuration | ✅ |
| Structured Logging | ✅ |
| Startup Banner | ✅ |
| Web UI Dashboard | ✅ |
| Host Discovery (ping sweep) | ✅ |
| CVE Discovery (scan target) | ✅ |
| Scan History | ✅ |
| Update Center | ✅ |
| Reports Page | ✅ |
| Settings Page | ✅ |
| Install Script | ✅ |

---

## Current Task

Git initialization and project setup:
- [x] .gitignore
- [x] README.md
- [x] PROJECT.md — this file
- [x] Git init + initial commit
- [x] Branch rename to main
- [ ] Remote origin (waiting for URL)
- [ ] Push to remote

---

## Roadmap

### Short Term
- Multi-host batch scanning (targets file)
- Scan scheduling / automation
- PDF report generation
- Export to Splunk / Elasticsearch
- Asset inventory tracking

### Medium Term
- Vulnerability trending over time
- User authentication for Web UI
- Role-based access control
- API key authentication
- Webhook notifications
- Slack / email alerts

### Long Term
- Distributed scanning architecture
- Cloud asset discovery (AWS, GCP, Azure)
- Container image scanning
- CI/CD pipeline integration
- Integration with SIEM platforms

---

## Architecture

CLI (Cobra) → Scanner (orchestrator)
                ├── Port Scan (concurrent goroutines)
                ├── Banner Grab (TCP connect)
                ├── Fingerprint (regex + version extraction)
                ├── TLS Analysis (crypto/tls)
                ├── CPE Generation (vendor:product:version)
                ├── CVE Matching (SQLite)
                ├── KEV/EPSS Enrichment
                └── Report (console/JSON/HTML)

Web UI (React) → API Server (Go HTTP) → CLI

---

## Database Schema

Current: V3  
Tables: vendors, products, cpe, cves, kev, epss, metadata, update_history, web_rules, cwe_mapping, owasp_mapping

---

## Development Rules

1. Never rewrite existing packages — extend them
2. Never recreate the database — use V3+ migrations
3. Never rename packages or restructure directories
4. All DB operations through repository interfaces
5. Clean Architecture: domain → repository → service → CLI
6. New features get YAML config, CLI flags, and tests
7. Never add web application scanning (removed by design)
