#!/usr/bin/env bash
set -e

# ============================================================
# SurfaceGuard — Enterprise Infrastructure Vulnerability Scanner
# Install Script
# Organization: Cyber Ops Academy
# Author: Han Niux
# ============================================================

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "  ${GREEN}→${NC} $1"; }
info() { echo -e "  ${BLUE}i${NC} $1"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $1"; }
err()  { echo -e "  ${RED}✗${NC} $1"; }

echo ""
echo "  ${BOLD}SurfaceGuard Installer${NC}"
echo "  ${DIM}Enterprise Infrastructure Vulnerability Scanner${NC}"
echo "  ${DIM}Cyber Ops Academy — Han Niux${NC}"
echo ""

# Check OS
OS="$(uname -s)"
ARCH="$(uname -m)"
log "Detected: ${OS} ${ARCH}"

# ---- Go ----
if command -v go &>/dev/null; then
    GO_VER=$(go version | grep -oP 'go\S+' | head -1)
    log "Go found: ${GO_VER}"
else
    info "Installing Go..."
    if [ "$OS" = "Linux" ]; then
        wget -q https://go.dev/dl/go1.26.4.linux-amd64.tar.gz -O /tmp/go.tar.gz
        tar -C /usr/local -xzf /tmp/go.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
        log "Go installed"
    else
        err "Please install Go manually: https://go.dev/dl/"
        exit 1
    fi
fi

# ---- Node.js ----
if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    log "Node.js found: ${NODE_VER}"
else
    info "Installing Node.js..."
    if [ "$OS" = "Linux" ]; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs 2>/dev/null || yum install -y nodejs 2>/dev/null
        log "Node.js installed"
    else
        err "Please install Node.js manually: https://nodejs.org/"
        exit 1
    fi
fi

# ---- Check npm ----
if ! command -v npm &>/dev/null; then
    err "npm not found. Please install Node.js (includes npm)."
    exit 1
fi
log "npm found: $(npm --version)"

# ---- SurfaceGuard binary ----
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log "Building SurfaceGuard backend..."
go build -ldflags="-s -w -X main.Version=1.0.0" -o surfaceguard ./cmd/scanner/ 2>&1
log "Backend built: surfaceguard"

log "Building API server..."
go build -ldflags="-s -w" -o surfaceguard-api ./cmd/api/ 2>&1
log "API server built: surfaceguard-api"

# ---- Node modules ----
log "Installing frontend dependencies..."
cd ui/surfaceguard-ui
npm install --silent 2>&1 | tail -1
cd "$SCRIPT_DIR"
log "Frontend dependencies installed"

# ---- Summary ----
echo ""
echo "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "  ${BOLD}${GREEN}  SurfaceGuard is ready!${NC}"
echo "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  Starting services..."
echo ""

# Kill existing processes
kill $(lsof -t -i:8080) 2>/dev/null || true
kill $(lsof -t -i:3000) 2>/dev/null || true

# Start API server
./surfaceguard-api > /tmp/surfaceguard-api.log 2>&1 &
API_PID=$!
echo "  API server:      http://localhost:8080 (PID: ${API_PID})"

# Start UI dev server
cd ui/surfaceguard-ui
nohup npm run dev > /tmp/surfaceguard-ui.log 2>&1 &
UI_PID=$!
echo "  Web UI:          http://localhost:3000 (PID: ${UI_PID})"
cd "$SCRIPT_DIR"

echo ""
echo "  ${BOLD}Quick Start:${NC}"
echo "  ─────────────────────────────────────────────"
echo "  Open browser:  ${BOLD}http://localhost:3000${NC}"
echo "  Scan:          ./surfaceguard scan example.com"
echo "  Update:        ./surfaceguard update"
echo "  Stop API:      kill ${API_PID}"
echo "  Logs:          tail -f /tmp/surfaceguard-api.log"
echo ""
echo "  ${BOLD}Services running in background.${NC}"
echo "  To stop everything: kill ${API_PID} ${UI_PID}"
echo ""

# Verify
sleep 2
if curl -s http://localhost:3000 > /dev/null 2>&1; then
    echo "  ${GREEN}✓ Web UI is running at http://localhost:3000${NC}"
else
    warn "Web UI may still be starting. Check: tail -f /tmp/surfaceguard-ui.log"
fi
