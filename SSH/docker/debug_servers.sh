#!/usr/bin/env bash
###############################################################################
# Debug Server Status
# Quick diagnostic script to check if SSH servers are running and listening.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
RED=$'\033[0;31m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

log()   { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }
error() { printf "%b✗%b %s\n" "${RED}"   "${NC}" "$*"; }
info()  { printf "%b→%b %s\n" "${BLUE}"  "${NC}" "$*"; }

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

echo "══════════════════════════════════════════════════════════════"
echo "  SSH Server Debug Information"
echo "══════════════════════════════════════════════════════════════"
echo ""

echo "=== Checking if SSH processes are running ==="
echo ""

info "Dropbear:"
"${COMPOSE[@]}" exec -T dropbear_server ps aux | grep dropbear | grep -v grep || error "Not running"
echo ""

info "OpenSSH:"
"${COMPOSE[@]}" exec -T openssh_server ps aux | grep sshd | grep -v grep || error "Not running"
echo ""

info "wolfSSH:"
"${COMPOSE[@]}" exec -T wolfssh_server ps aux | grep wolfssh | grep -v grep || error "Not running"
echo ""

info "Paramiko:"
"${COMPOSE[@]}" exec -T paramiko_server ps aux | grep python | grep -v grep || error "Not running"
echo ""

echo "=== Checking if ports are listening ==="
echo ""

info "Dropbear (port 22 inside container):"
"${COMPOSE[@]}" exec -T dropbear_server netstat -tlnp 2>/dev/null | grep :22 || error "Port 22 not listening"
echo ""

info "OpenSSH (port 22 inside container):"
"${COMPOSE[@]}" exec -T openssh_server netstat -tlnp 2>/dev/null | grep :22 || error "Port 22 not listening"
echo ""

info "wolfSSH (port 22 inside container):"
"${COMPOSE[@]}" exec -T wolfssh_server netstat -tlnp 2>/dev/null | grep :22 || error "Port 22 not listening"
echo ""

echo "=== Checking container logs (last 10 lines) ==="
echo ""

info "Dropbear logs:"
docker logs dropbear_server 2>&1 | tail -10
echo ""

info "OpenSSH logs:"
docker logs openssh_server 2>&1 | tail -10
echo ""

info "wolfSSH logs:"
docker logs wolfssh_server 2>&1 | tail -10
echo ""
