#!/usr/bin/env bash
###############################################################################
# Basic SSH Connectivity Test (no LLDB) - TTY-safe, Bash 3 compatible
# Tests all SSH servers for basic connectivity using the ssh_client container.
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
log()   { printf "%b[%s]%b %s\n" "${GREEN}" "$(now)" "${NC}" "$*"; }
error() { printf "%b[ERROR]%b %s\n"       "${RED}"   "${NC}" "$*" >&2; }
warn()  { printf "%b[WARN]%b %s\n"        "${YELLOW}" "${NC}" "$*"; }
info()  { printf "%b[INFO]%b %s\n"        "${BLUE}"  "${NC}" "$*"; }

# ── Config ───────────────────────────────────────────────────────────────────
SERVERS=(
  "openssh:2222"
  "dropbear:2223"
  "wolfssh:2224"
  "paramiko:2225"             # demo server typically lacks exec; we skip
  "openssh_groundtruth:2226"
)

TEST_USER="testuser"
TEST_PASS="password"
CLIENT_SERVICE="${CLIENT_SERVICE:-ssh_client}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-5}"
TOTAL_TIMEOUT="${TOTAL_TIMEOUT:-10}"

# Results (indexed arrays to stay Bash 3 compatible)
NAMES=()
CODES=()
MSGS=()

TMPFILE=""
cleanup() {
  [[ -n "${TMPFILE}" && -f "${TMPFILE}" ]] && rm -f "${TMPFILE}" || true
}
trap cleanup EXIT

# Pick compose command
if docker compose version >/dev/null 2>&1; then
  COMPOSE=(docker compose)
elif command -v docker-compose >/dev/null 2>&1; then
  COMPOSE=(docker-compose)
else
  error "Neither 'docker compose' nor 'docker-compose' found."
  exit 1
fi

# Pick timeout command (macOS often needs gtimeout)
TIMEOUT_CMD=()
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(timeout "${TOTAL_TIMEOUT}")
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_CMD=(gtimeout "${TOTAL_TIMEOUT}")
else
  warn "No timeout/gtimeout found; running without outer timeout."
  TIMEOUT_CMD=()
fi

log "=== Basic SSH Connectivity Test ==="
printf "\n"

# Preflight
log "Step 1: Checking compose project status..."
"${COMPOSE[@]}" ps || warn "Unable to list compose services."
printf "\n"

# Ensure client service exists
client_id="$("${COMPOSE[@]}" ps -q "${CLIENT_SERVICE}" || true)"
if [[ -z "${client_id}" ]]; then
  error "Client service '${CLIENT_SERVICE}' not found. Set CLIENT_SERVICE env var if needed."
  exit 1
fi

# SSH options (suppress warnings; non-interactive)
SSH_BASE_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout="${CONNECT_TIMEOUT}"
  -o LogLevel=ERROR
  -o PreferredAuthentications=password
  -o NumberOfPasswordPrompts=1
  -n  # stdin from /dev/null
  -T  # no pseudo-tty
)

log "Step 2: Testing SSH connections..."
printf "\n"

for spec in "${SERVERS[@]}"; do
  IFS=":" read -r server host_port <<<"${spec}"

  if [[ "${server}" == "openssh_groundtruth" ]]; then
    container_name="${server}"
  else
    container_name="${server}_server"
  fi

  info "Testing ${container_name} (host port ${host_port})..."

  # Optional: verify target service exists
  target_id="$("${COMPOSE[@]}" ps -q "${container_name}" || true)"
  if [[ -z "${target_id}" ]]; then
    if [[ "${server}" == "paramiko" ]]; then
      warn "${container_name}: Optional service not running, skipping test."
      NAMES+=("${container_name}"); CODES+=(125); MSGS+=("not running (optional)")
      printf "\n"
      continue
    else
      warn "Service '${container_name}' not found in this compose project."
    fi
  fi

  if [[ "${server}" == "paramiko" ]]; then
    warn "${container_name}: Skipped (Paramiko demo often lacks remote exec)."
    echo "  Try manual login: ssh -p ${host_port} ${TEST_USER}@localhost  (password: ${TEST_PASS})"
    NAMES+=("${container_name}"); CODES+=(125); MSGS+=("skipped")
    printf "\n"
    continue
  fi

  echo "  → Running SSH test${TIMEOUT_CMD:+ (timeout ${TOTAL_TIMEOUT}s)}..."
  set +e
  OUTPUT="$(
    "${TIMEOUT_CMD[@]}" \
    "${COMPOSE[@]}" exec -T "${CLIENT_SERVICE}" \
      sshpass -p "${TEST_PASS}" \
      ssh "${SSH_BASE_OPTS[@]}" \
          -p 22 "${TEST_USER}@${container_name}" \
          "printf 'Connected\n'; hostname; date" \
      </dev/null 2>&1
  )"
  STATUS=$?
  set -e
  echo "  → Command exited with code: ${STATUS}"

  if [[ ${STATUS} -eq 0 ]]; then
    log "✓ ${container_name}: Connection successful"
    echo "  Response:"
    printf "%s\n" "${OUTPUT}" | head -5 | sed 's/^/    /'
    NAMES+=("${container_name}"); CODES+=(0); MSGS+=("ok")
  else
    error "${container_name}: Connection failed (exit code: ${STATUS})"
    echo "  Error (tail):"
    printf "%s\n" "${OUTPUT}" | tail -8 | sed 's/^/    /'
    NAMES+=("${container_name}"); CODES+=("${STATUS}"); MSGS+=("failed")
  fi

  printf "\n"
done

log "=== Test Complete ==="
printf "\n"
info "Summary:"
printf "  %s = Connection successful\n" "✓"
printf "  %s = Connection failed\n"     "✗"
printf "  – = Skipped\n\n"

printf "%-28s  %-8s  %s\n" "Service" "Status" "Detail"
printf "%-28s  %-8s  %s\n" "----------------------------" "--------" "-------------------------"
for i in "${!NAMES[@]}"; do
  name="${NAMES[$i]}"; code="${CODES[$i]}"; msg="${MSGS[$i]}"
  if [[ "${msg}" == "skipped" ]]; then
    icon="–"
  elif [[ "${code}" -eq 0 ]]; then
    icon="✓"
  else
    icon="✗"
  fi
  printf "%-28s  %-8s  %s\n" "${name}" "${icon}" "${msg}"
done

printf "\n"
info "For LLDB monitoring, see manual instructions in MANUAL_LLDB.md"
