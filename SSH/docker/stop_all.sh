#!/usr/bin/env bash
###############################################################################
# Stop All SSH Lab Containers
# Clean shutdown of all containers, preserving data.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
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

log "=== Stopping SSH Lab Containers ==="
echo ""

# Show what's running
info "Currently running containers:"
"${COMPOSE[@]}" ps
echo ""

# Stop and remove containers
log "Stopping all containers..."
"${COMPOSE[@]}" down 2>/dev/null || true
docker rm -f dropbear_server ssh_client openssh_groundtruth openssh_server wolfssh_server paramiko_server openssh_lldb 2>/dev/null || true

echo ""
log "✓ All containers stopped"
echo ""
info "Data directories preserved in: data/"
info "To restart: ./restart_all.sh"
info "To start fresh: ./restart_all.sh (and choose 'y' to clean data)"
echo ""
