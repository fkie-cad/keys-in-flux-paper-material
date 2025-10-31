#!/usr/bin/env bash
###############################################################################
# Start All SSH Lab Containers
# Starts containers if they're not already running.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

now() { date +%H:%M:%S; }
log()  { printf "%b[%s]%b %s\n" "${GREEN}" "$(now)" "${NC}" "$*"; }
info() { printf "%b[INFO]%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

log "=== Starting SSH Lab Containers ==="
echo ""

# Check current state
info "Checking current state..."
"${COMPOSE[@]}" ps
echo ""

# Start all services
log "Starting all containers..."
"${COMPOSE[@]}" up -d
echo ""

# Wait for initialization
log "Waiting for services to initialize..."
for i in {20..1}; do
  printf "\r  %bWaiting: %d seconds remaining...%b" "${YELLOW}" "${i}" "${NC}"
  sleep 1
done
echo ""
echo ""

# Show final status
log "Container Status:"
"${COMPOSE[@]}" ps
echo ""

log "✓ All containers started"
echo ""
info "Services:"
echo "  - OpenSSH:      localhost:2222"
echo "  - Dropbear:     localhost:2223"
echo "  - wolfSSH:      localhost:2224"
echo "  - Paramiko:     localhost:2225"
echo "  - Groundtruth:  localhost:2226"
echo ""
info "Test connectivity: ./test_basic_connectivity.sh"
echo ""
