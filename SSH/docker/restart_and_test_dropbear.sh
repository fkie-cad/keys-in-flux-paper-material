#!/usr/bin/env bash
###############################################################################
# Complete Dropbear Key Lifecycle Test - Full Automation
#
# This script performs a complete end-to-end test:
# 1. Stops and cleans up old containers
# 2. Cleans old data
# 3. Rebuilds dropbear_server with fixed LLDB monitoring
# 4. Starts services
# 5. Verifies LLDB is running and attached
# 6. Runs non-interactive SSH test
# 7. Analyzes results
# 8. Shows summary
###############################################################################

set -Eeuo pipefail

GREEN=$'\033[0;32m'
BLUE=$'\033[0;34m'
YELLOW=$'\033[1;33m'
RED=$'\033[0;31m'
NC=$'\033[0m'

log()   { printf "%b[✓]%b %s\n" "${GREEN}" "${NC}" "$*"; }
info()  { printf "%b[→]%b %s\n" "${BLUE}"  "${NC}" "$*"; }
warn()  { printf "%b[!]%b %s\n" "${YELLOW}" "${NC}" "$*"; }
error() { printf "%b[✗]%b %s\n" "${RED}"   "${NC}" "$*" >&2; }

echo "════════════════════════════════════════════════════════════════════════"
echo "  Complete Dropbear Key Lifecycle Test - Full Automation"
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Step 1: Stop and clean containers
info "Step 1: Stopping and removing old containers..."
docker compose down 2>/dev/null || true
log "Containers stopped"
echo ""

# Step 2: Clean old data
info "Step 2: Cleaning old experiment data..."
rm -rf data/dumps/* data/keylogs/* data/lldb_results/* data/analysis/* 2>/dev/null || true
log "Old data cleaned"
echo ""

# Step 3: Rebuild dropbear_server
info "Step 3: Rebuilding dropbear_server with fixed LLDB monitoring..."
docker compose build dropbear_server
log "Container rebuilt"
echo ""

# Step 4: Start services
info "Step 4: Starting services..."
docker compose up -d dropbear_server openssh_groundtruth
log "Services started"
echo ""

# Step 5: Wait for services and verify LLDB
info "Step 5: Waiting for services to initialize..."
sleep 5

info "Checking if LLDB is running inside dropbear_server..."
LLDB_CHECK=$(docker compose exec -T dropbear_server ps aux | grep -c "lldb" || true)
LLDB_CHECK=${LLDB_CHECK:-0}
if [[ "$LLDB_CHECK" -gt 0 ]]; then
    log "LLDB is running ✓"
else
    warn "LLDB may not be running (this might be OK if it already attached)"
fi

# Check if LLDB output file exists
if docker compose exec -T dropbear_server test -f /data/lldb_results/lldb_output.log; then
    log "LLDB output file exists ✓"
    info "First 10 lines of LLDB output:"
    docker compose exec -T dropbear_server head -10 /data/lldb_results/lldb_output.log || true
else
    warn "LLDB output file not found yet"
fi

echo ""

# Step 6: Run non-interactive SSH test
info "Step 6: Running non-interactive SSH test..."
info "This will connect to Dropbear, trigger key derivation, and exit automatically..."
echo ""

docker compose exec openssh_groundtruth bash -c '
export MODE=client
export HOST=dropbear_server
export PORT=22
export USER=testuser
export PASSWORD=password
export SSHKEYLOGFILE=/data/keylogs/groundtruth_dropbear.log

echo "Connecting to $HOST:$PORT as $USER..."

# Run command and exit automatically
sshpass -p "$PASSWORD" ssh \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -p ${PORT} ${USER}@${HOST} \
  "hostname && pwd && echo \"Key lifecycle test executed\" && sleep 2 && exit" 2>&1

echo "SSH connection completed"
'

log "SSH test complete"
echo ""

# Give LLDB time to finish processing events
info "Waiting for LLDB to finish processing events..."
sleep 3
echo ""

# Step 7: Check generated data
info "Step 7: Checking generated data..."
echo ""

DUMP_COUNT=$(ls data/dumps/*.{bin,dump} 2>/dev/null | wc -l | xargs)
DUMP_COUNT=${DUMP_COUNT:-0}
echo "  Memory dumps: ${DUMP_COUNT}"

KEYLOG_COUNT=$(ls data/keylogs/*.log 2>/dev/null | wc -l | xargs)
KEYLOG_COUNT=${KEYLOG_COUNT:-0}
echo "  Keylog files: ${KEYLOG_COUNT}"

if [[ -f data/lldb_results/events_dropbear.jsonl ]]; then
    EVENT_COUNT=$(wc -l < data/lldb_results/events_dropbear.jsonl)
    echo "  LLDB events: ${EVENT_COUNT}"

    # Count specific event types
    # Note: grep -c returns 0 and exits with code 1 when no matches found
    # We use || true to prevent exit, then default to 0 if empty
    MONITOR_START=$(grep -c '"MONITOR_START"' data/lldb_results/events_dropbear.jsonl 2>/dev/null || true)
    MONITOR_START=${MONITOR_START:-0}

    KEX_EXIT=$(grep -c '"KEX_EXIT"' data/lldb_results/events_dropbear.jsonl 2>/dev/null || true)
    KEX_EXIT=${KEX_EXIT:-0}

    KEY_EXTRACT=$(grep -c '"KEY_EXTRACT"' data/lldb_results/events_dropbear.jsonl 2>/dev/null || true)
    KEY_EXTRACT=${KEY_EXTRACT:-0}

    WATCHPOINT=$(grep -c '"WATCHPOINT"' data/lldb_results/events_dropbear.jsonl 2>/dev/null || true)
    WATCHPOINT=${WATCHPOINT:-0}

    echo ""
    echo "  Event breakdown:"
    echo "    - MONITOR_START: ${MONITOR_START}"
    echo "    - KEX_EXIT: ${KEX_EXIT}"
    echo "    - KEY_EXTRACT: ${KEY_EXTRACT}"
    echo "    - WATCHPOINT events: ${WATCHPOINT}"
else
    error "No LLDB events file found!"
    echo ""
    warn "This means LLDB did not import ssh_monitor.py successfully"
    warn "Check LLDB output:"
    echo ""
    docker compose exec -T dropbear_server cat /data/lldb_results/lldb_output.log 2>/dev/null || echo "  (no lldb_output.log file)"
fi

echo ""

# Step 8: Run analysis
if [[ ${DUMP_COUNT:-0} -gt 0 && ${KEYLOG_COUNT:-0} -gt 0 ]]; then
    info "Step 8: Running analysis pipeline..."
    ./analyze_dropbear_experiment.sh data/
    log "Analysis complete"
    echo ""

    # Step 9: Show results summary
    info "Step 9: Results Summary"
    echo ""

    if [[ -f data/analysis/secret_presence.txt ]]; then
        echo "Secret presence summary:"
        echo "────────────────────────────────────────────────────────────────────────"
        grep -A 20 "Secret persistence across stages:" data/analysis/secret_presence.txt || true
        echo ""

        SECRETS_FOUND=$(grep -E "^\s+\w+\s+:\s+[1-9]" data/analysis/secret_presence.txt | wc -l | xargs)
        SECRETS_FOUND=${SECRETS_FOUND:-0}

        if [[ ${SECRETS_FOUND} -gt 0 ]]; then
            log "SUCCESS: Found ${SECRETS_FOUND}/7 secrets in memory dumps! ✓"
        else
            error "PROBLEM: Still found 0/7 secrets"
            warn "Check LLDB events to see if breakpoints were hit"
        fi
    fi
else
    error "Step 8: SKIPPED - Not enough data to analyze"
    warn "Dumps: ${DUMP_COUNT}, Keylogs: ${KEYLOG_COUNT}"
fi

echo ""
echo "════════════════════════════════════════════════════════════════════════"
echo "  Test Complete"
echo "════════════════════════════════════════════════════════════════════════"
echo ""

# Final summary
echo "Key files:"
echo "  • data/lldb_results/lldb_output.log - LLDB attach log"
echo "  • data/lldb_results/events_dropbear.jsonl - All LLDB events"
echo "  • data/keylogs/groundtruth_dropbear.log - Ground-truth keys"
echo "  • data/analysis/secret_presence.txt - Secret presence matrix"
echo ""

if [[ ${DUMP_COUNT:-0} -eq 0 ]]; then
    error "PROBLEM: No memory dumps were created"
    echo ""
    echo "Debug steps:"
    echo "  1. Check if LLDB attached: docker compose logs dropbear_server"
    echo "  2. Check LLDB output: cat data/lldb_results/lldb_output.log"
    echo "  3. Check events file: cat data/lldb_results/events_dropbear.jsonl"
    echo ""
fi
