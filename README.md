# SurfaceGuard

**Enterprise Infrastructure Vulnerability Scanner**

Discover. Assess. Protect.

---

## Overview

SurfaceGuard is a production-grade infrastructure vulnerability scanner built with Go. It identifies exposed services, detects software versions, correlates findings with CVE intelligence, and generates professional reports — all through safe, non-destructive fingerprinting techniques.

**Organization:** Cyber Ops Academy  
**Author:** Han Niux

---

## Features

- **Port Scanning** — concurrent TCP scanning with configurable worker pools
- **Service Fingerprinting** — banner analysis, HTTP header inspection, TLS metadata
- **Version Detection** — extract versions from 20+ service types
- **CPE Mapping** — map detected software to Common Platform Enumeration
- **CVE Matching** — correlate findings against local CVE database (161K+ entries)
- **KEV Integration** — CISA Known Exploited Vulnerabilities (1,600+ entries)
- **EPSS Scoring** — Exploit Prediction Scoring System (345K+ scores)
- **TLS Analysis** — certificate validation, weak cipher detection, protocol version
- **Risk Scoring** — weighted score from CVSS + KEV severity
- **HTML Reports** — professional dark-theme reports
- **JSON Export** — machine-readable output
- **Web UI** — enterprise dashboard with live updates

---

## Quick Start

### Install

```bash
./install.sh
```

Then open **http://localhost:3000** in your browser.

### Build Manually

```bash
# Backend
go build -ldflags="-s -w" -o surfaceguard ./cmd/scanner/
go build -ldflags="-s -w" -o surfaceguard-api ./cmd/api/

# Frontend
cd ui/surfaceguard-ui
npm install
npm run dev
```

### Update Database

```bash
./surfaceguard update
```

### Scan a Target

```bash
./surfaceguard scan example.com
./surfaceguard scan 10.0.0.1 --ports 80,443,8080
./surfaceguard scan 10.0.0.1 --format html --output report.html
```

---

## Web UI

The web interface is a React + TypeScript application with:

- Dashboard with live database stats
- Host Discovery (ping sweep with progress)
- CVE Discovery (full port scan + CVE matching)
- Scan History
- Report Generation (HTML, JSON, CSV)
- Update Center
- Settings

---

## Project Structure

```
SurfaceGuard/
├── cmd/
│   ├── api/              # HTTP API server
│   ├── scanner/          # CLI entrypoint
│   └── seed/             # Database seeder
├── internal/
│   ├── banner/           # Startup display
│   ├── config/           # YAML configuration
│   ├── database/         # SQLite repository layer
│   ├── fingerprint/      # Service + TLS fingerprinting
│   ├── matcher/          # CVE matching engine
│   ├── report/           # Report generators
│   ├── scanner/          # Scan orchestrator
│   └── updater/          # Feed download engine
├── pkg/
│   ├── models/           # Shared domain types
│   └── portscan/         # Concurrent port scanner
├── ui/
│   └── surfaceguard-ui/  # React frontend
├── configs/              # YAML configuration files
└── data/                 # SQLite database
```

---

## Safety

SurfaceGuard performs **passive, non-destructive scanning** only. It connects to ports, reads banners, and analyzes service metadata. It never sends exploit payloads, attempts authentication, or modifies server state.

---

## License

MIT
