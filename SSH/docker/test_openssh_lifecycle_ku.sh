#!/bin/bash
#
# OpenSSH Lifecycle Test - Key Update (KU) Mode
#
# Tests complete SSH lifecycle with key update (rekey):
#   1. Handshake (PRE_CONNECT → KEX_COMPLETE → ACTIVE)
#   2. SSH commands ("ls", "pwd")
#   3. Key Update / Rekey (REKEY_START → REKEY_COMPLETE)
#   4. More SSH commands
#   5. Session close (SESSION_CLOSED → CLEANUP)
#
# Memory dumps are taken before/after each transition.
# Renamed from test_openssh_lifecycle_full.sh for consistency.
#

set -e

# Get absolute path to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo "========================================================================"
echo "  OpenSSH Lifecycle Test - WITH Rekey (Full Experiment)"
echo "========================================================================"
echo ""
echo "This test demonstrates the complete SSH key lifecycle:"
echo "  - Handshake + KEX"
echo "  - Active session with commands"
echo "  - Rekey operation"
echo "  - Session termination"
echo ""
echo "Memory dumps will be captured at each transition."
echo ""
echo "========================================================================"
echo ""
echo "Results will be written to:"
echo "  Directory:  ${SCRIPT_DIR}/data/"
echo "  Keylogs:    ${SCRIPT_DIR}/data/keylogs/"
echo "  Dumps:      ${SCRIPT_DIR}/data/dumps/"
echo "  Captures:   ${SCRIPT_DIR}/data/captures/"
echo ""
echo "========================================================================"
echo ""

# Configuration
OPENSSH_SERVER="openssh_groundtruth"
OPENSSH_CLIENT="openssh_client_lldb"
SSH_USER="testuser"
SSH_PASSWORD="password"
SSH_PORT="22"

# Directories
KEYLOGS_DIR="./data/keylogs"
DUMPS_DIR="./data/dumps"
CAPTURES_DIR="./data/captures"

# Clean previous run
echo -e "${YELLOW}[CLEANUP]${NC} Removing old logs, dumps, and captures..."
rm -f ${KEYLOGS_DIR}/openssh_client_keylog*.log
rm -f ${DUMPS_DIR}/*.dump
rm -f ${DUMPS_DIR}/ssh_events.jsonl
rm -f ${CAPTURES_DIR}/openssh_lifecycle_*.pcap
echo -e "${GREEN}[CLEANUP] ✓ Clean${NC}"
echo ""

# Ensure directories exist
mkdir -p ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}
chmod -R 777 ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}

# Start OpenSSH server
echo -e "${YELLOW}[SERVER]${NC} Starting ${OPENSSH_SERVER}..."
docker compose up -d ${OPENSSH_SERVER}
sleep 5

# Check server is running
if ! docker compose ps | grep -q "${OPENSSH_SERVER}.*Up"; then
    echo -e "${RED}[SERVER] ✗ Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}[SERVER] ✓ Server running${NC}"
echo ""


# Start packet capture from SERVER container (already running)
echo -e "${YELLOW}[PCAP]${NC} Starting packet capture from server..."
PCAP_FILE="${CAPTURES_DIR}/openssh_lifecycle_ku_$(date +%Y%m%d_%H%M%S).pcap"

# Capture from server container's network namespace
docker run --rm -d --name openssh_lifecycle_ku_pcap_$$     --net=container:${OPENSSH_SERVER}     --cap-add NET_ADMIN     -v "${PWD}/${CAPTURES_DIR}:/captures"     nicolaka/netshoot     tcpdump -i any -w /captures/$(basename ${PCAP_FILE}) "port ${SSH_PORT}"     > /dev/null 2>&1 || echo -e "${YELLOW}[PCAP] ⚠️  Could not start capture (non-critical)${NC}"

TCPDUMP_CONTAINER="openssh_lifecycle_ku_pcap_$$"
sleep 2

if docker ps | grep -q ${TCPDUMP_CONTAINER}; then
    echo -e "${GREEN}[PCAP] ✓ Packet capture running${NC}"
else
    echo -e "${YELLOW}[PCAP] ⚠️  Packet capture not available (non-critical)${NC}"
    TCPDUMP_CONTAINER=""
fi
echo ""

# Run OpenSSH client with LLDB monitoring + lifecycle experiment
# Note: Packet capture removed to avoid timing issues with container creation
echo -e "${YELLOW}[CLIENT]${NC} Running OpenSSH client with LLDB lifecycle monitoring..."
echo -e "${YELLOW}[CLIENT]${NC} Using custom client script: openssh_client_rekey"
echo -e "${YELLOW}[CLIENT]${NC} Environment:"
echo "  - LLDB_ENABLE_MEMORY_DUMPS=true"
echo "  - LLDB_DUMP_TYPE=heap"
echo "  - SSH_SERVER_HOST=${OPENSSH_SERVER}"
echo "  - SSH_SERVER_PORT=${SSH_PORT}"
echo "  - Rekey: ${CYAN}ENABLED${NC} (~R escape sequence)"
echo ""

# OLD CODE - No longer needed
if false; then
# Use expect to automate SSH session with rekey
cat > /tmp/openssh_lifecycle_full_exp.sh << 'EXPECT_SCRIPT'
#!/usr/bin/expect -f
#
# Expect script for OpenSSH lifecycle with rekey
#

set timeout 30
set server [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set password [lindex $argv 3]

puts "\n[EXPECT] Starting SSH session to ${user}@${server}:${port}"
puts "[EXPECT] Will perform: connect → commands → rekey → commands → exit\n"

# Spawn SSH connection
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET -p ${port} ${user}@${server}

# Handle password prompt
expect {
    "password:" {
        send "${password}\r"
        puts "[EXPECT] ✓ Password sent"
    }
    timeout {
        puts "\n[EXPECT] ✗ Password prompt timeout"
        exit 1
    }
}

# Wait for shell prompt
expect {
    -re "\\$|#" {
        puts "[EXPECT] ✓ Shell prompt received - connection established\n"
    }
    timeout {
        puts "\n[EXPECT] ✗ Shell prompt timeout"
        exit 1
    }
}

# Phase 1: Initial commands (after KEX)
puts "[EXPECT] === PHASE 1: Initial SSH commands ==="
sleep 1

send "hostname\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: hostname"
sleep 0.5

send "pwd\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: pwd"
sleep 0.5

send "ls -la /tmp | head -5\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: ls -la /tmp | head -5"
sleep 1

# Phase 2: Trigger rekey
puts "\n[EXPECT] === PHASE 2: Triggering SSH rekey ==="
puts "[EXPECT] Sending escape sequence: ~R"
sleep 1

# OpenSSH escape sequence for rekey: Enter, ~, Shift+R
send "\r~R"
sleep 2
puts "[EXPECT] ✓ Rekey sequence sent (waiting for completion...)"
sleep 3

# Phase 3: Post-rekey commands
puts "\n[EXPECT] === PHASE 3: Post-rekey SSH commands ==="
sleep 1

send "echo 'Post-rekey test'\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: echo 'Post-rekey test'"
sleep 0.5

send "date\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: date"
sleep 0.5

send "uptime\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: uptime"
sleep 1

# Phase 4: Clean exit
puts "\n[EXPECT] === PHASE 4: Session termination ==="
send "exit\r"

expect {
    eof {
        puts "[EXPECT] ✓ SSH session closed cleanly\n"
    }
    timeout {
        puts "[EXPECT] ⚠️  Exit timeout (connection may have closed)\n"
    }
}

puts "[EXPECT] Lifecycle experiment complete"
exit 0
EXPECT_SCRIPT

chmod +x /tmp/openssh_lifecycle_full_exp.sh
fi  # Close "if false" - old code no longer used

# Cleanup function for client container
cleanup_client() {
    echo -e "${YELLOW}[CLEANUP]${NC} Stopping and removing client container..."
    docker compose stop ${OPENSSH_CLIENT} 2>/dev/null || true
    sleep 1
    docker compose rm -f ${OPENSSH_CLIENT} 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] ✓ Client container cleaned${NC}"
}

# Set up trap to ensure cleanup on error or interrupt
trap cleanup_client ERR INT TERM

# Run client with lifecycle monitoring using custom client script (5 minute timeout to prevent hanging)
# NOTE: Uses openssh_client_rekey WITH --with-rekey flag (KU mode - explicit rekey via ~R)
# NOTE: Not using --rm to avoid Docker cleanup hangs
timeout 300 docker compose run \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_DUMPS_DIR=/data/dumps \
    -e LLDB_ENABLE_ENTRY_DUMPS=true \
    -e KEEP_ALIVE_SECONDS=15 \
    -e SSH_SERVER_HOST=${OPENSSH_SERVER} \
    -e SSH_SERVER_PORT=${SSH_PORT} \
    -e SSH_USER=${SSH_USER} \
    -e SSH_PASSWORD=${SSH_PASSWORD} \
    -e SSH_CMD="/usr/local/bin/openssh_client_rekey ${OPENSSH_SERVER} ${SSH_PORT} ${SSH_USER} ${SSH_PASSWORD} --with-rekey --keep-alive" \
    ${OPENSSH_CLIENT}

CLIENT_EXIT_CODE=$?

# Clean up client container explicitly
cleanup_client
trap - ERR INT TERM  # Clear trap after successful cleanup

echo ""
echo "========================================================================"


# Stop server
echo -e "${YELLOW}[SERVER]${NC} Stopping ${OPENSSH_SERVER}..."
docker compose stop ${OPENSSH_SERVER}
echo ""

# Verify experiment results
echo "========================================================================"
echo "  EXPERIMENT RESULTS"
echo "========================================================================"
echo ""

# Check keylog
if [ -f "${KEYLOGS_DIR}/openssh_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/openssh_client_keylog.log" ]; then
    KEY_COUNT=$(grep -c "DERIVE_KEY" "${KEYLOGS_DIR}/openssh_client_keylog.log" || echo "0")
    echo -e "${GREEN}[KEYLOG] ✓ Keys extracted: ${KEY_COUNT}${NC}"

    # Should have 12 keys if rekey succeeded (6 initial + 6 rekey)
    if [ "$KEY_COUNT" -ge 12 ]; then
        echo -e "${GREEN}[KEYLOG] ✓ Rekey detected (≥12 keys logged)${NC}"
    else
        echo -e "${YELLOW}[KEYLOG] ⚠️  Rekey may not have occurred (only ${KEY_COUNT} keys)${NC}"
    fi

    echo ""
    echo "First 5 keylog entries:"
    head -5 "${KEYLOGS_DIR}/openssh_client_keylog.log"
else
    echo -e "${RED}[KEYLOG] ✗ No keys extracted${NC}"
fi

echo ""

# Convert to Wireshark format (if keylog and PCAP exist)
if [ -f "${KEYLOGS_DIR}/openssh_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/openssh_client_keylog.log" ]; then
    # Check if PCAP exists
    if [ -f "${PCAP_FILE}" ] || ls ${CAPTURES_DIR}/openssh_lifecycle_*.pcap 1> /dev/null 2>&1; then
        echo -e "${YELLOW}[CONVERT]${NC} Generating Wireshark-compatible keylog..."

        # Run converter
        ./convert_ssh_to_wireshark.py \
            --ssh-keylog "${KEYLOGS_DIR}/openssh_client_keylog.log" \
            --pcap "${PCAP_FILE}" \
            --out "${KEYLOGS_DIR}/wireshark_keylog.txt" \
            --implementation openssh 2>&1 | grep -E "Detected|Parsed|Selected|Extracted|Wrote|ERROR|WARNING" || true

        if [ -f "${KEYLOGS_DIR}/wireshark_keylog.txt" ]; then
            echo -e "${GREEN}[CONVERT] ✓ Wireshark keylog created: ${KEYLOGS_DIR}/wireshark_keylog.txt${NC}"
            echo ""
            echo "Wireshark keylog content:"
            cat "${KEYLOGS_DIR}/wireshark_keylog.txt"
        else
            echo -e "${YELLOW}[CONVERT] ⚠️  Wireshark keylog creation failed (non-critical)${NC}"
        fi
    else
        echo -e "${YELLOW}[CONVERT] ⚠️  No PCAP file found - skipping Wireshark conversion${NC}"
    fi
fi

echo ""

# Check memory dumps
if [ -d "${DUMPS_DIR}" ]; then
    DUMP_COUNT=$(find ${DUMPS_DIR} -name "*.dump" -type f 2>/dev/null | wc -l)

    if [ "$DUMP_COUNT" -gt 0 ]; then
        echo -e "${GREEN}[DUMPS] ✓ Memory dumps created: ${DUMP_COUNT}${NC}"
        echo ""
        echo "Dump files:"
        ls -lh ${DUMPS_DIR}/*.dump 2>/dev/null | head -10
    else
        echo -e "${YELLOW}[DUMPS] ⚠️  No memory dumps found${NC}"
        echo "  (This is expected if LLDB_ENABLE_MEMORY_DUMPS=false)"
    fi
else
    echo -e "${RED}[DUMPS] ✗ Dumps directory not found${NC}"
fi

echo ""

# Check event log
if [ -f "${DUMPS_DIR}/ssh_events.jsonl" ] && [ -s "${DUMPS_DIR}/ssh_events.jsonl" ]; then
    EVENT_COUNT=$(wc -l < "${DUMPS_DIR}/ssh_events.jsonl")
    echo -e "${GREEN}[EVENTS] ✓ State transitions logged: ${EVENT_COUNT}${NC}"
    echo ""
    echo "Event summary:"
    grep "event_type" "${DUMPS_DIR}/ssh_events.jsonl" | head -10
else
    echo -e "${YELLOW}[EVENTS] ⚠️  No event log found${NC}"
fi

echo ""
echo "========================================================================"
echo "  TEST SUMMARY"
echo "========================================================================"
echo ""
echo "Mode:         WITH REKEY (KU)"
echo ""
echo "Results location (absolute paths):"
echo "  Keylog:     ${SCRIPT_DIR}/${KEYLOGS_DIR}/openssh_client_keylog.log"
echo "  Debug Log:  ${SCRIPT_DIR}/${KEYLOGS_DIR}/openssh_client_keylog_debug.log"
echo "  Event Log:  ${SCRIPT_DIR}/${DUMPS_DIR}/ssh_events.jsonl"
echo "  Dumps:      ${SCRIPT_DIR}/${DUMPS_DIR}/*.dump"
echo "  PCAP:       ${SCRIPT_DIR}/${PCAP_FILE}"
echo ""
echo "Quick check commands:"
echo "  # View keylog entries"
echo "  cat ${SCRIPT_DIR}/data/keylogs/openssh_client_keylog.log"
echo ""
echo "  # Count keys extracted"
echo "  grep -c 'DERIVE_KEY' ${SCRIPT_DIR}/data/keylogs/openssh_client_keylog.log"
echo ""
echo "  # Check for rekey (should see KEX1 and KEX2)"
echo "  grep -E 'KEX[12]' ${SCRIPT_DIR}/data/keylogs/openssh_client_keylog.log"
echo ""
echo "  # View timing data (if watchpoints enabled)"
echo "  cat ${SCRIPT_DIR}/data/lldb_results/timing_openssh.csv"
echo ""

if [ "$CLIENT_EXIT_CODE" -eq 0 ] && [ "$KEY_COUNT" -ge 6 ]; then
    echo -e "${GREEN}✓ TEST PASSED - OpenSSH lifecycle experiment completed successfully${NC}"
    echo ""
    echo "Expected lifecycle flow:"
    echo "  1. PRE_CONNECT → KEX_COMPLETE (6 keys)"
    echo "  2. KEX_COMPLETE → ACTIVE"
    echo "  3. [SSH commands]"
    echo "  4. ACTIVE → REKEY_START (key 7)"
    echo "  5. REKEY_START → REKEY_COMPLETE (key 12)"
    echo "  6. [More SSH commands]"
    echo "  7. SESSION_CLOSED → CLEANUP"
    echo ""
    exit 0
else
    echo -e "${RED}✗ TEST FAILED - Check logs for errors${NC}"
    echo ""
    exit 1
fi
