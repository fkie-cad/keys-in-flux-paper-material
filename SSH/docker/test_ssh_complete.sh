#!/bin/bash

###############################################################################
# Simplified SSH Key Extraction Test Suite
# Tests Dropbear and wolfSSH with automatic LLDB key logging
###############################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test configuration
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TEST_DIR="test_results_${TIMESTAMP}"
SERVERS=("dropbear" "wolfssh")
TEST_USER="testuser"
TEST_PASS="password"

# Create test results directory
mkdir -p "${TEST_DIR}"/{logs,analysis}

log() {
    echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

###############################################################################
# Phase 1: Environment Setup (with proper wait time)
###############################################################################

phase1_setup() {
    log "=== PHASE 1: Environment Setup ==="

    # Stop any running containers
    info "Stopping existing containers..."
    docker compose down -v 2>/dev/null || true

    # Clean old data
    info "Cleaning old data directories..."
    rm -rf data/keylogs/* data/dumps/* data/lldb_results/* 2>/dev/null || true
    mkdir -p data/keylogs data/dumps data/lldb_results
    chmod -R 0777 data

    # Start Docker Compose environment
    log "Starting Docker Compose lab..."
    docker compose up -d

    # Wait for LLDB initialization (CRITICAL: need 30-60 seconds)
    info "Waiting 60 seconds for LLDB initialization and SSH daemons..."
    for i in {60..1}; do
        echo -ne "\r  ${YELLOW}$i seconds remaining...${NC}"
        sleep 1
    done
    echo ""

    # Verify containers are running
    log "Verifying container status..."
    docker compose ps

    if ! docker compose ps | grep -q "Up"; then
        error "Some containers failed to start"
        docker compose logs
        exit 1
    fi

    log "✓ Environment ready"
}

###############################################################################
# Phase 2: Connectivity Tests (Keys are automatically logged by LLDB)
###############################################################################

phase2_connectivity() {
    log "=== PHASE 2: Connectivity Tests (with automatic key logging) ==="

    for server in "${SERVERS[@]}"; do
        info "Testing ${server}_server connectivity..."

        # Get server port
        if [ "$server" == "dropbear" ]; then
            port=2223
        elif [ "$server" == "wolfssh" ]; then
            port=2224
        else
            port=2222
        fi

        # Try connecting up to 3 times with delays
        success=false
        for attempt in {1..3}; do
            info "  Attempt $attempt/3..."

            if docker compose exec -T ssh_client sshpass -p "${TEST_PASS}" \
                ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                -p ${port} ${TEST_USER}@${server}_server \
                "echo 'Test connection successful'; hostname; date" \
                > "${TEST_DIR}/logs/${server}_connection_${attempt}.log" 2>&1; then
                log "✓ ${server}_server: Connection successful on attempt $attempt"
                success=true
                break
            else
                warn "${server}_server: Connection failed on attempt $attempt"
                sleep 5
            fi
        done

        if [ "$success" = false ]; then
            error "${server}_server: All connection attempts failed"
            cat "${TEST_DIR}/logs/${server}_connection_3.log"
        fi

        # Give LLDB time to log keys
        sleep 3
    done
}

###############################################################################
# Phase 3: Verify Key Extraction
###############################################################################

phase3_verify_keys() {
    log "=== PHASE 3: Verify Key Extraction ==="

    for server in "${SERVERS[@]}"; do
        info "Checking ${server} key files..."

        # Copy files from container to test directory
        keylog_file="data/keylogs/ssh_keylog_${server}.log"
        timing_file="data/lldb_results/timing_${server}.csv"
        events_file="data/lldb_results/events_${server}.log"

        # Check keylog
        if [ -f "$keylog_file" ] && [ -s "$keylog_file" ]; then
            log "✓ ${server} keylog found"
            cp "$keylog_file" "${TEST_DIR}/logs/"
            info "  Keys extracted:"
            cat "$keylog_file" | head -10
        else
            warn "${server} keylog not found or empty"
        fi

        # Check timing CSV
        if [ -f "$timing_file" ] && [ -s "$timing_file" ]; then
            log "✓ ${server} timing data found"
            cp "$timing_file" "${TEST_DIR}/analysis/"
            info "  Timing data:"
            cat "$timing_file"
        else
            warn "${server} timing data not found or empty"
        fi

        # Check events log
        if [ -f "$events_file" ] && [ -s "$events_file" ]; then
            log "✓ ${server} events log found"
            cp "$events_file" "${TEST_DIR}/logs/"
            info "  Recent events:"
            tail -20 "$events_file"
        else
            warn "${server} events log not found or empty"
        fi

        echo ""
    done
}

###############################################################################
# Phase 4: Lifecycle Analysis
###############################################################################

phase4_lifecycle() {
    log "=== PHASE 4: Key Lifecycle Analysis ==="

    for server in "${SERVERS[@]}"; do
        timing_file="${TEST_DIR}/analysis/timing_${server}.csv"

        if [ -f "$timing_file" ]; then
            info "Analyzing ${server} key lifecycle..."

            echo "=== ${server} Timeline ===" >> "${TEST_DIR}/analysis/${server}_lifecycle.txt"
            cat "$timing_file" >> "${TEST_DIR}/analysis/${server}_lifecycle.txt"
            echo "" >> "${TEST_DIR}/analysis/${server}_lifecycle.txt"

            # Calculate durations with Python
            python3 -c "
import csv
import sys

csv_file = '$timing_file'
try:
    with open(csv_file, 'r') as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    if not rows:
        print('No timing data')
        sys.exit(0)

    keys = {}
    for row in rows:
        key_id = row['key_id']
        event = row['event']
        timestamp = float(row['timestamp'])

        if key_id not in keys:
            keys[key_id] = {}
        keys[key_id][event] = timestamp

    for key_id, events in keys.items():
        print(f'\\nKey: {key_id}')
        if 'generated' in events and 'activated' in events:
            delta = events['activated'] - events['generated']
            print(f'  Generation → Activation: {delta:.6f}s')

        cleared_events = [k for k in events.keys() if 'cleared' in k]
        if cleared_events and 'activated' in events:
            clear_time = max(events[e] for e in cleared_events)
            delta = clear_time - events['activated']
            print(f'  Activation → Clearing: {delta:.6f}s')

        if 'generated' in events and cleared_events:
            clear_time = max(events[e] for e in cleared_events)
            delta = clear_time - events['generated']
            print(f'  Total Lifespan: {delta:.6f}s')

except Exception as e:
    print(f'Error: {e}', file=sys.stderr)
    import traceback
    traceback.print_exc()
" | tee -a "${TEST_DIR}/analysis/${server}_lifecycle.txt"

            log "✓ ${server} lifecycle analysis complete"
        else
            warn "No timing data for ${server}"
        fi
    done
}

###############################################################################
# Phase 5: Generate Report
###############################################################################

phase5_report() {
    log "=== PHASE 5: Generating Test Report ==="

    report="${TEST_DIR}/TEST_REPORT.md"

    cat > "$report" << EOF
# SSH Key Extraction Test Report
Generated: $(date)
Test ID: ${TIMESTAMP}

## Test Summary

### Tested Implementations
$(for server in "${SERVERS[@]}"; do echo "- ${server}"; done)

### Test Phases Completed
1. ✓ Environment Setup (60s initialization wait)
2. ✓ Connectivity Tests (automatic LLDB key logging)
3. ✓ Verify Key Extraction
4. ✓ Key Lifecycle Analysis
5. ✓ Report Generation

## Results

EOF

    for server in "${SERVERS[@]}"; do
        cat >> "$report" << EOF
### ${server}

#### Keylog File
\`\`\`
$(cat "data/keylogs/ssh_keylog_${server}.log" 2>/dev/null || echo "No keylog data")
\`\`\`

#### Lifecycle Timing
\`\`\`
$(cat "${TEST_DIR}/analysis/${server}_lifecycle.txt" 2>/dev/null || echo "No lifecycle data")
\`\`\`

#### Recent Events
\`\`\`
$(tail -30 "data/lldb_results/events_${server}.log" 2>/dev/null || echo "No events")
\`\`\`

---

EOF
    done

    cat >> "$report" << EOF
## Files Generated

- \`data/keylogs/ssh_keylog_*.log\` - Extracted SSH keys
- \`data/lldb_results/timing_*.csv\` - Key lifecycle timing
- \`data/lldb_results/events_*.log\` - LLDB event logs
- \`test_results_${TIMESTAMP}/\` - Analysis and report

## Next Steps

1. Review keys: \`cat data/keylogs/ssh_keylog_*.log\`
2. Check timing: \`cat data/lldb_results/timing_*.csv\`
3. View events: \`tail -100 data/lldb_results/events_*.log\`
4. Decrypt traffic (if captured): Use keys from keylog files

## Notes

- Servers run with LLDB monitoring from startup
- Keys are automatically logged when connections are made
- Timing tracks: generated → activated → cleared
- Hardware watchpoints detect key overwrites

EOF

    log "✓ Report generated: ${report}"
    cat "$report"
}

###############################################################################
# Phase 6: Show Container Logs (for debugging)
###############################################################################

phase6_logs() {
    log "=== PHASE 6: Container Logs (last 50 lines) ==="

    for server in "${SERVERS[@]}"; do
        info "${server}_server logs:"
        docker compose logs --tail=50 ${server}_server 2>&1 | tee "${TEST_DIR}/logs/${server}_docker.log"
        echo ""
    done
}

###############################################################################
# Main Execution
###############################################################################

main() {
    log "Starting Simplified SSH Key Extraction Test Suite"
    log "Test ID: ${TIMESTAMP}"

    phase1_setup
    phase2_connectivity
    phase3_verify_keys
    phase4_lifecycle
    phase5_report
    phase6_logs

    log "=== ALL TESTS COMPLETE ==="
    log "Results directory: ${TEST_DIR}"
    log "Test report: ${TEST_DIR}/TEST_REPORT.md"

    # Copy report to current directory
    cp "${TEST_DIR}/TEST_REPORT.md" "./TEST_REPORT_${TIMESTAMP}.md"
    log "Report also saved to: ./TEST_REPORT_${TIMESTAMP}.md"

    echo ""
    info "Quick summary:"
    echo "  - Keylog files: data/keylogs/"
    echo "  - Timing data: data/lldb_results/"
    echo "  - Full report: ./TEST_REPORT_${TIMESTAMP}.md"
    echo ""
}

# Run main
main "$@"
