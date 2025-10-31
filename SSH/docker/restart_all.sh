#!/usr/bin/env bash
###############################################################################
# Restart All SSH Lab Containers
# Stops, cleans, and restarts all containers for a fresh state.
# Does NOT rebuild images - just restarts existing containers.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[1;33m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

now() { date +%H:%M:%S; }
log()  { printf "%b[%s]%b %s\n" "${GREEN}" "$(now)" "${NC}" "$*"; }
info() { printf "%b[INFO]%b %s\n" "${BLUE}"  "${NC}" "$*"; }
warn() { printf "%b[WARN]%b %s\n" "${YELLOW}" "${NC}" "$*"; }

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

log "=== Restarting SSH Lab Containers ==="
echo ""

# Step 1: Stop all containers
log "Step 1: Stopping all containers..."
"${COMPOSE[@]}" down
echo ""

# Step 2: Clean data directories (optional - preserves old results)
read -p "Clean data directories? (y/N): " -n 1 -r
echo
if [[ ${REPLY} =~ ^[Yy]$ ]]; then
  info "Cleaning data directories..."
  rm -rf data/keylogs/* data/dumps/* data/lldb_results/* data/captures/* 2>/dev/null || true
  mkdir -p data/keylogs data/dumps data/lldb_results data/captures
  chmod -R 0777 data
  log "✓ Data directories cleaned"
else
  info "Keeping existing data (results preserved)"
fi
echo ""

# Step 3: Start all containers
log "Step 2: Starting all containers..."
"${COMPOSE[@]}" up -d
echo ""

# Step 4: Wait for initialization
log "Step 3: Waiting for services to initialize..."
info "SSH servers need time to start (especially with LLDB)..."

for i in {30..1}; do
  printf "\r  %bWaiting: %d seconds remaining...%b" "${YELLOW}" "${i}" "${NC}"
  sleep 1
done
echo ""
echo ""

# Step 5: Show status
log "Step 4: Container Status"
"${COMPOSE[@]}" ps
echo ""

# Step 6: Quick connectivity check
log "Step 5: Quick Health Check"
echo ""

SERVERS=("openssh:2222" "dropbear:2223" "wolfssh:2224" "paramiko:2225")

for server_spec in "${SERVERS[@]}"; do
  IFS=":" read -r server port <<<"${server_spec}"

  # Check if container is running
  if "${COMPOSE[@]}" ps | grep -q "${server}_server.*Up"; then
    info "${server}_server: Container running"

    # Quick port check (not a full SSH test)
    set +e
    "${COMPOSE[@]}" exec -T ssh_client timeout 2 bash -c "echo > /dev/tcp/${server}_server/22" 2>/dev/null
    PORT_CHECK=$?
    set -e

    if [[ ${PORT_CHECK} -eq 0 ]]; then
      log "  ✓ Port 22 reachable"
    else
      warn "  ⚠ Port 22 not responding (may need more time)"
    fi
  else
    warn "${server}_server: Container not running"
  fi
done
echo ""

log "=== Restart Complete ==="
echo ""
info "All containers restarted with fresh state"
echo ""
info "Next steps:"
echo "  - Test connectivity: ./test_basic_connectivity.sh"
echo "  - Manual LLDB workflow: See QUICKSTART.md"
echo "  - View logs: ${COMPOSE[*]} logs <service_name>"
echo ""
