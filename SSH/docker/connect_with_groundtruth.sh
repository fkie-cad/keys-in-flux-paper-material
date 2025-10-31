#!/usr/bin/env bash
###############################################################################
# Connect to SSH Server with Groundtruth Key Logging
# Uses OpenSSH client with SSHKEYLOGFILE to record session keys.
###############################################################################

set -Eeuo pipefail
IFS=$'\n\t'

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
NC=$'\033[0m'

info() { printf "%b→%b %s\n" "${BLUE}" "${NC}" "$*"; }
log()  { printf "%b✓%b %s\n" "${GREEN}" "${NC}" "$*"; }

# ── Config ───────────────────────────────────────────────────────────────────
SERVER="${1:-dropbear}"
ACTION="${2:-init}"  # init, rekey, or term
USE_NEW_CONTAINER="${USE_NEW_CONTAINER:-false}"  # Set to 'true' to use 'docker compose run' instead of 'exec'

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  echo "ERROR: Neither 'docker compose' nor 'docker-compose' found." >&2
  exit 1
fi

# Determine port and container name based on server
# NOTE: Script runs inside Docker network via 'docker compose exec ssh_client'
# Internal Docker ports are always 22 (not host-mapped ports like 2222, 2223, etc.)
case "${SERVER}" in
  dropbear)
    PORT=22  # Internal Docker port (host maps 2223->22)
    container_name="dropbear_server"
    ;;
  wolfssh)
    PORT=22  # Internal Docker port (host maps 2224->22)
    container_name="wolfssh_server"
    ;;
  openssh)
    PORT=22  # Internal Docker port (host maps 2222->22)
    container_name="openssh_server"
    ;;
  openssh_groundtruth)
    PORT=22
    container_name="openssh_groundtruth"
    ;;
  *)
    echo "ERROR: Unknown server: ${SERVER}" >&2
    echo "Usage: $0 {dropbear|wolfssh|openssh|openssh_groundtruth} {init|rekey|term}"
    exit 1
    ;;
esac

case "${ACTION}" in
  init)
    echo "══════════════════════════════════════════════════════════════"
    echo "  Connecting to ${SERVER}_server on port ${PORT}"
    echo "  Mode: Ground-Truth Client (openssh_groundtruth)"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    info "Groundtruth keys will be logged to: /data/keylogs/groundtruth_${SERVER}.log"
    echo ""
    info "Using patched OpenSSH client with automatic key extraction"
    echo ""
    info "Password: password"
    echo ""
    info "To trigger rekey after connecting:"
    echo "  Run './connect_with_groundtruth.sh $SERVER rekey' in another terminal"
    echo ""
    info "To terminate: type 'exit' or press ~. (tilde + period)"
    echo ""

    # Choose between exec (reuse container) or run (new container)
    if [ "$USE_NEW_CONTAINER" = "true" ]; then
      info "Creating new container for this connection"
      echo ""
      "${COMPOSE[@]}" run --rm \
        -e MODE=client \
        -e HOST="${container_name}" \
        -e PORT=${PORT} \
        -e USER=testuser \
        -e PASSWORD=password \
        -e SSHKEYLOGFILE="/data/keylogs/groundtruth_${SERVER}.log" \
        -e CAPTURE_TRAFFIC=true \
        openssh_groundtruth
    else
      info "Using existing openssh_groundtruth container"
      echo ""
      "${COMPOSE[@]}" exec openssh_groundtruth bash -c "
export MODE=client
export HOST=${container_name}
export PORT=${PORT}
export USER=testuser
export PASSWORD=password
export SSHKEYLOGFILE=/data/keylogs/groundtruth_${SERVER}.log
export CAPTURE_TRAFFIC=false

# Run SSH connection with groundtruth OpenSSH client
if [ -n \"\$PASSWORD\" ]; then
  sshpass -p \"\$PASSWORD\" ssh -v \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p \${PORT} \${USER}@\${HOST}
else
  ssh -v \
    -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null \
    -p \${PORT} \${USER}@\${HOST}
fi
"
    fi
    ;;

  rekey)
    echo "══════════════════════════════════════════════════════════════"
    echo "  Send Rekey Command"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    info "In your active SSH session, trigger a rekey:"
    echo ""
    echo "  1. Press Enter to get a new line"
    echo "  2. Type ~ (tilde)"
    echo "  3. Type R (capital R)"
    echo ""
    log "You should see: [rekey request sent]"
    echo ""
    info "In LLDB terminal, you'll see new key generation events."
    echo ""
    ;;

  term)
    echo "══════════════════════════════════════════════════════════════"
    echo "  Terminate SSH Connection"
    echo "══════════════════════════════════════════════════════════════"
    echo ""
    info "To close your SSH session:"
    echo ""
    echo "  Option 1: Type 'exit' and press Enter"
    echo ""
    echo "  Option 2: Use escape sequence:"
    echo "    1. Press Enter to get a new line"
    echo "    2. Type ~ (tilde)"
    echo "    3. Type . (period)"
    echo ""
    info "In LLDB terminal, you'll see key clearing events."
    echo ""
    ;;

  *)
    echo "ERROR: Unknown action: ${ACTION}" >&2
    echo "Usage: $0 ${SERVER} {init|rekey|term}"
    exit 1
    ;;
esac
