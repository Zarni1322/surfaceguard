#!/usr/bin/env bash
set -e

# ============================================================
# SurfaceGuard — Enterprise Infrastructure Vulnerability Scanner
# Start Script
# Organization: Cyber Ops Academy
# Author: Han Niux
# ============================================================

BOLD=''
DIM=''
GREEN=''
BLUE=''
YELLOW=''
RED=''
NC=''

log()  { echo "  → $1"; }
info() { echo "  i $1"; }
warn() { echo "  ⚠ $1"; }
err()  { echo "  ✗ $1"; }

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---- Restart / stop / status helpers ----
stop_surfaceguard() {
    local found=false
    info "Looking for running SurfaceGuard processes..."

    # Kill by process name (surfaceguard-api, surfaceguard, next dev server)
    for PROC in "surfaceguard-api" "surfaceguard$"; do
        local PIDS
        PIDS=$(pgrep -f "$PROC" 2>/dev/null || true)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                # Don't kill ourselves
                [ "$PID" = "$$" ] && continue
                info "Stopping $PROC (PID: $PID)..."
                kill "$PID" 2>/dev/null || true
                found=true
            done
        fi
    done

    # Also kill processes on our ports (in case they have different names)
    for port in 8080 3000; do
        local PID
        PID=$(lsof -ti tcp:"$port" 2>/dev/null) || true
        if [ -n "$PID" ]; then
            info "Stopping process on port $port (PID: $PID)..."
            kill "$PID" 2>/dev/null || true
            found=true
        fi
    done

    if [ "$found" = false ]; then
        info "No SurfaceGuard processes found running."
    else
        sleep 1
        info "All SurfaceGuard processes stopped."
    fi
}

status_surfaceguard() {
    echo ""
    echo "  ${BOLD}SurfaceGuard Status${NC}"
    echo "  ${DIM}$(printf '%*s' 50 | tr ' ' '─')${NC}"

    for PROC in "surfaceguard-api" "surfaceguard$"; do
        local PIDS
        PIDS=$(pgrep -f "$PROC" 2>/dev/null || true)
        if [ -n "$PIDS" ]; then
            for PID in $PIDS; do
                [ "$PID" = "$$" ] && continue
                local RSS
                RSS=$(ps -o rss= -p "$PID" 2>/dev/null | tr -d ' ')
                echo "  ${GREEN}●${NC} $(basename "$PROC" | sed 's/\$//')  running  (PID: $PID, MEM: ${RSS:-?} KB)"
            done
        else
            echo "  ${RED}○${NC} $(basename "$PROC" | sed 's/\$//')  stopped"
        fi
    done

    for port in 8080 3000; do
        local PID
        PID=$(lsof -ti tcp:"$port" 2>/dev/null) || true
        local label="API server"
        [ "$port" = "3000" ] && label="Web UI"
        if [ -n "$PID" ]; then
            echo "  ${GREEN}●${NC} $label        listening  (port $port, PID: $PID)"
        else
            echo "  ${RED}○${NC} $label        not listening  (port $port)"
        fi
    done
    echo ""
}

# ---- Handle restart/stop/status arguments ----
ACTION="${1:-start}"

case "$ACTION" in
    restart)
        echo ""
        echo "  ${BOLD}SurfaceGuard${NC} ${DIM}v1.0.0${NC}"
        echo "  ${DIM}Restarting all services...${NC}"
        echo ""
        cd "$SCRIPT_DIR"
        stop_surfaceguard
        sleep 1
        # Fall through to start below
        ;;
    stop)
        echo ""
        echo "  ${BOLD}SurfaceGuard${NC} ${DIM}v1.0.0${NC}"
        echo "  ${DIM}Stopping all services...${NC}"
        echo ""
        cd "$SCRIPT_DIR"
        stop_surfaceguard
        exit 0
        ;;
    status)
        cd "$SCRIPT_DIR"
        status_surfaceguard
        exit 0
        ;;
    start)
        # Normal start — nothing extra
        ;;
    *)
        err "Unknown action: $ACTION"
        info "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

echo ""
echo "  ${BOLD}SurfaceGuard${NC} ${DIM}v1.0.0${NC}"
echo "  ${DIM}Enterprise Infrastructure Vulnerability Scanner${NC}"
echo "  ${DIM}Cyber Ops Academy — Han Niux${NC}"
echo ""

cd "$SCRIPT_DIR"

# ---- Check prerequisites ----
MISSING=""
command -v go &>/dev/null || MISSING="${MISSING}  - Go (golang)\n"
command -v npm &>/dev/null || MISSING="${MISSING}  - npm (Node.js)\n"

if [ -n "$MISSING" ]; then
    err "Missing dependencies:"
    echo "$MISSING"
    info "Run ./install.sh first to install dependencies."
    exit 1
fi

# ---- Build binaries if missing or stale ----
NEED_BUILD=false

build_if_needed() {
    local binary=$1
    local source=$2
    if [ ! -f "$binary" ]; then
        NEED_BUILD=true
    else
        # Rebuild if source is newer than binary
        local newest_source
        newest_source=$(find "$source" -type f -name '*.go' -newer "$binary" 2>/dev/null | head -1)
        if [ -n "$newest_source" ]; then
            NEED_BUILD=true
        fi
    fi
}

build_if_needed "surfaceguard"   "./cmd/scanner/"
build_if_needed "surfaceguard-api" "./cmd/api/"

if [ "$NEED_BUILD" = true ]; then
    log "Building SurfaceGuard backend..."
    go build -ldflags="-s -w -X main.Version=1.0.0" -o surfaceguard ./cmd/scanner/
    log "Backend built: surfaceguard"

    log "Building API server..."
    go build -ldflags="-s -w" -o surfaceguard-api ./cmd/api/
    log "API server built: surfaceguard-api"
else
    log "Binaries are up to date."
fi

# ---- Check frontend dependencies ----
if [ ! -d "ui/surfaceguard-ui/node_modules" ]; then
    log "Installing frontend dependencies..."
    cd ui/surfaceguard-ui
    npm install --silent 2>&1 | tail -1
    cd "$SCRIPT_DIR"
    log "Frontend dependencies installed"
fi

# ---- Kill existing processes on our ports ----
for port in 8080 3000; do
    PID=$(lsof -ti tcp:"$port" 2>/dev/null) || true
    if [ -n "$PID" ]; then
        info "Stopping existing process on port $port (PID: $PID)..."
        kill "$PID" 2>/dev/null || true
        sleep 1
    fi
done

# ---- Start API server ----
log "Starting API server..."
./surfaceguard-api > /tmp/surfaceguard-api.log 2>&1 &
API_PID=$!
echo "  ${GREEN}→${NC} API server:      http://localhost:8080 (PID: ${API_PID})"

# ---- Start UI dev server ----
log "Starting Web UI..."
cd ui/surfaceguard-ui
nohup npm run dev > /tmp/surfaceguard-ui.log 2>&1 &
UI_PID=$!
cd "$SCRIPT_DIR"
echo "  ${GREEN}→${NC} Web UI:          http://localhost:3000 (PID: ${UI_PID})"

echo ""
echo "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo "  ${BOLD}${GREEN}  SurfaceGuard is running!${NC}"
echo "  ${BOLD}${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  ${BOLD}Open in browser:${NC}  http://localhost:3000"
echo ""
echo "  ${DIM}Quick commands:${NC}"
echo "  ${DIM}  Scan:          ./surfaceguard scan <target>${NC}"
echo "  ${DIM}  Update DB:     ./surfaceguard update${NC}"
echo "  ${DIM}  Restart:       ./main.sh restart${NC}"
echo "  ${DIM}  Stop:          ./main.sh stop${NC}"
echo "  ${DIM}  Status:        ./main.sh status${NC}"
echo "  ${DIM}  API logs:      tail -f /tmp/surfaceguard-api.log${NC}"
echo "  ${DIM}  UI logs:       tail -f /tmp/surfaceguard-ui.log${NC}"
echo ""

# ---- Verify services ----
sleep 2

API_OK=false
if curl -s -o /dev/null -w '' http://localhost:8080/api/system 2>/dev/null; then
    API_OK=true
fi

UI_OK=false
if curl -s -o /dev/null -w '' http://localhost:3000 2>/dev/null; then
    UI_OK=true
fi

echo "  ${BOLD}Status:${NC}"
if [ "$API_OK" = true ]; then
    echo "  ${GREEN}✓${NC} API server      — running on http://localhost:8080"
else
    warn "API server may still be starting. Check: tail -f /tmp/surfaceguard-api.log"
fi

if [ "$UI_OK" = true ]; then
    echo "  ${GREEN}✓${NC} Web UI          — running on http://localhost:3000"
    echo ""
    echo "  ${BOLD}${GREEN}→${NC} Open http://localhost:3000 in your browser${NC}"
else
    warn "Web UI may still be starting. Check: tail -f /tmp/surfaceguard-ui.log"
fi
echo ""
