#!/bin/bash
# ─── Janus Live Demo ──────────────────────────────────────────────────
# Starts the backend, frontend, and runs the simulation.
#
# Usage:
#   ./tests/integration/run_demo.sh
#
# Prerequisites:
#   - Python venv at .venv/ with janus installed
#   - Node.js + npm (for frontend)
#   - Optional: ANTHROPIC_API_KEY for LLM features
# ──────────────────────────────────────────────────────────────────────

set -e

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║          JANUS SECURITY — Live Demo                     ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Shutting down...${NC}"
    [ -n "$BACKEND_PID" ] && kill "$BACKEND_PID" 2>/dev/null
    [ -n "$FRONTEND_PID" ] && kill "$FRONTEND_PID" 2>/dev/null
    wait 2>/dev/null
    echo -e "${GREEN}Done.${NC}"
}
trap cleanup EXIT

# ── 1. Start backend ──────────────────────────────────────────────────
echo -e "${GREEN}[1/3] Starting Janus backend on port 8000...${NC}"

# Use a temp DB so each demo starts fresh
export JANUS_DB_PATH="/tmp/janus-demo-$$.db"

.venv/bin/python -m uvicorn janus.web.app:create_app --factory --host 0.0.0.0 --port 8000 &
BACKEND_PID=$!

# Wait for backend to be ready
echo -n "  Waiting for backend"
for i in $(seq 1 30); do
    if curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
        echo -e " ${GREEN}ready!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

if ! curl -s http://localhost:8000/api/health > /dev/null 2>&1; then
    echo -e " ${RED}FAILED${NC}"
    echo "Backend didn't start. Check logs above."
    exit 1
fi

# ── 2. Start frontend ────────────────────────────────────────────────
echo -e "${GREEN}[2/3] Starting Next.js frontend on port 3000...${NC}"

cd "$ROOT/frontend"
npm run dev -- --port 3000 &
FRONTEND_PID=$!
cd "$ROOT"

# Wait for frontend
echo -n "  Waiting for frontend"
for i in $(seq 1 30); do
    if curl -s http://localhost:3000 > /dev/null 2>&1; then
        echo -e " ${GREEN}ready!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo -e "  Backend:   ${GREEN}http://localhost:8000${NC}"
echo -e "  Dashboard: ${GREEN}http://localhost:3000/dashboard${NC}"
echo -e "  Health:    ${GREEN}http://localhost:8000/api/health${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
echo ""

# ── 3. Run simulation ────────────────────────────────────────────────
echo -e "${GREEN}[3/3] Running live simulation...${NC}"
echo -e "${YELLOW}  Open http://localhost:3000/dashboard NOW to watch events stream in${NC}"
echo ""
sleep 3

.venv/bin/python tests/integration/simulate_dashboard.py

echo ""
echo -e "${CYAN}Demo servers are still running. Press Ctrl+C to stop.${NC}"
echo -e "  Dashboard: ${GREEN}http://localhost:3000/dashboard${NC}"
echo ""

# Keep running until user hits Ctrl+C
wait
