#!/bin/bash
#
# wolfSSH Lifecycle Test - Key Update (KU) Mode
#
# Tests wolfSSH lifecycle with explicit rekey using wolfSSH_TriggerKeyExchange API:
#   1. Handshake (PRE_CONNECT → KEX_COMPLETE → ACTIVE)
#   2. SSH commands (initial traffic)
#   3. Explicit rekey via wolfSSH_TriggerKeyExchange API
#   4. SSH commands (post-rekey traffic)
#   5. Session close (SESSION_CLOSED → CLEANUP)
#
# Memory dumps are taken before/after each transition.
# Uses custom wolfSSH client with programmatic rekey support.
#

set -e

# Get absolute path to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo ""
echo "========================================================================"
echo "  wolfSSH Lifecycle Test - Key Update (KU) Mode"
echo "========================================================================"
echo ""
echo "This test demonstrates wolfSSH key lifecycle with REKEY:"
echo "  - Handshake + KEX (4 KDF calls: A-D for AEAD)"
echo "  - Active session with initial commands"
echo "  - Explicit rekey via wolfSSH_TriggerKeyExchange API"
echo "  - Post-rekey commands"
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
WOLFSSH_SERVER="openssh_wolfssh_compat"
WOLFSSH_CLIENT="wolfssh_client"
SSH_USER="testuser"
SSH_PASSWORD="password"
SSH_PORT="22"

# Directories
KEYLOGS_DIR="./data/keylogs"
DUMPS_DIR="./data/dumps"
CAPTURES_DIR="./data/captures"

# Clean previous run
echo -e "${YELLOW}[CLEANUP]${NC} Removing old logs, dumps, and captures..."
rm -f ${KEYLOGS_DIR}/wolfssh_client_keylog*.log
rm -f ${DUMPS_DIR}/*.dump
rm -f ${DUMPS_DIR}/ssh_events.jsonl
rm -f ${CAPTURES_DIR}/wolfssh_lifecycle_ku_*.pcap
echo -e "${GREEN}[CLEANUP] ✓ Clean${NC}"
echo ""

# Ensure directories exist
mkdir -p ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}
chmod -R 777 ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}

# Start openssh_groundtruth server
echo -e "${YELLOW}[SERVER]${NC} Starting ${WOLFSSH_SERVER}..."
docker compose up -d ${WOLFSSH_SERVER}
sleep 5

# Check server is running
if ! docker compose ps | grep -q "${WOLFSSH_SERVER}.*Up"; then
    echo -e "${RED}[SERVER] ✗ Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}[SERVER] ✓ Server running${NC}"
echo ""

# Start packet capture from SERVER container (already running)
echo -e "${YELLOW}[PCAP]${NC} Starting packet capture from server..."
PCAP_FILE="${CAPTURES_DIR}/wolfssh_lifecycle_ku_$(date +%Y%m%d_%H%M%S).pcap"

# Capture from server container's network namespace
docker run --rm -d --name wolfssh_lifecycle_ku_pcap_$$ \
    --net=container:${WOLFSSH_SERVER} \
    --cap-add NET_ADMIN \
    -v "${PWD}/${CAPTURES_DIR}:/captures" \
    nicolaka/netshoot \
    tcpdump -i any -w /captures/$(basename ${PCAP_FILE}) "port ${SSH_PORT}" \
    > /dev/null 2>&1 || echo -e "${YELLOW}[PCAP] ⚠️  Could not start capture (non-critical)${NC}"

TCPDUMP_CONTAINER="wolfssh_lifecycle_ku_pcap_$$"
sleep 2

if docker ps | grep -q ${TCPDUMP_CONTAINER}; then
    echo -e "${GREEN}[PCAP] ✓ Packet capture running${NC}"
else
    echo -e "${YELLOW}[PCAP] ⚠️  Packet capture not available (non-critical)${NC}"
    TCPDUMP_CONTAINER=""
fi
echo ""

# Run wolfSSH client with LLDB monitoring + lifecycle experiment
echo -e "${YELLOW}[CLIENT]${NC} Running wolfSSH client with LLDB lifecycle monitoring..."
echo -e "${YELLOW}[CLIENT]${NC} Using custom client: wolfssh-client-rekey with --with-rekey"
echo -e "${YELLOW}[CLIENT]${NC} Environment:"
echo "  - LLDB_ENABLE_MEMORY_DUMPS=true"
echo "  - LLDB_DUMP_TYPE=heap"
echo "  - LLDB_ENABLE_ENTRY_DUMPS=true"
echo "  - KEEP_ALIVE_SECONDS=15 (post-session memory dumps)"
echo "  - SSH_SERVER_HOST=${WOLFSSH_SERVER}"
echo "  - SSH_SERVER_PORT=${SSH_PORT}"
echo "  - Rekey: ${CYAN}ENABLED${NC} (KU mode - wolfSSH_TriggerKeyExchange API)"
echo ""

# Cleanup function for client container
cleanup_client() {
    echo -e "${YELLOW}[CLEANUP]${NC} Stopping and removing client container..."
    docker compose stop ${WOLFSSH_CLIENT} 2>/dev/null || true
    sleep 1
    docker compose rm -f ${WOLFSSH_CLIENT} 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] ✓ Client container cleaned${NC}"
}

# Set up trap to ensure cleanup on error or interrupt
trap cleanup_client ERR INT TERM

# Run client with lifecycle monitoring (5 minute timeout to prevent hanging)
# NOTE: Using wolfssh-client-rekey WITH --with-rekey flag (KU mode - programmatic rekey)
# NOTE: Not using --rm to avoid Docker cleanup hangs
timeout 300 docker compose run \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_DUMPS_DIR=/data/dumps \
    -e LLDB_ENABLE_ENTRY_DUMPS=true \
    -e KEEP_ALIVE_SECONDS=15 \
    -e SSH_SERVER_HOST=${WOLFSSH_SERVER} \
    -e SSH_SERVER_PORT=${SSH_PORT} \
    -e SSH_USER=${SSH_USER} \
    -e SSH_PASSWORD=${SSH_PASSWORD} \
    -e WOLFSSH_REKEY_MODE=true \
    ${WOLFSSH_CLIENT}

CLIENT_EXIT_CODE=$?

# Clean up client container explicitly
cleanup_client
trap - ERR INT TERM  # Clear trap after successful cleanup

# Check if timeout occurred
if [ ${CLIENT_EXIT_CODE} -eq 124 ]; then
    echo -e "${RED}[ERROR] Test timed out after 5 minutes${NC}"
    echo -e "${RED}[ERROR] LLDB monitoring may have hung - check LLDB auto-continue loop${NC}"
fi

echo ""
echo "========================================================================"

# Stop packet capture
if [ -n "$TCPDUMP_CONTAINER" ] && docker ps | grep -q ${TCPDUMP_CONTAINER}; then
    echo -e "${YELLOW}[PCAP]${NC} Stopping packet capture..."
    docker stop ${TCPDUMP_CONTAINER} > /dev/null 2>&1 || true
    sleep 1

    if [ -f "${PCAP_FILE}" ]; then
        PCAP_SIZE=$(stat -f%z "${PCAP_FILE}" 2>/dev/null || stat -c%s "${PCAP_FILE}" 2>/dev/null || echo "0")
        echo -e "${GREEN}[PCAP] ✓ Capture saved: ${PCAP_FILE} (${PCAP_SIZE} bytes)${NC}"
    else
        echo -e "${YELLOW}[PCAP] ⚠️  Capture file not created${NC}"
    fi
fi

# Stop server
echo -e "${YELLOW}[SERVER]${NC} Stopping ${WOLFSSH_SERVER}..."
docker compose stop ${WOLFSSH_SERVER}
echo ""

# Verify experiment results
echo "========================================================================"
echo "  EXPERIMENT RESULTS"
echo "========================================================================"
echo ""

# Check keylog
if [ -f "${KEYLOGS_DIR}/wolfssh_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/wolfssh_client_keylog.log" ]; then
    KEY_COUNT=$(grep -c "NEWKEYS" "${KEYLOGS_DIR}/wolfssh_client_keylog.log" || echo "0")
    echo -e "${GREEN}[KEYLOG] ✓ Keys extracted: ${KEY_COUNT}${NC}"

    # Should have 8 keys if rekey succeeded (4 initial + 4 rekey for AEAD)
    # AEAD ciphers (ChaCha20-Poly1305) don't use separate MAC keys (E-F)
    if [ "$KEY_COUNT" -ge 8 ]; then
        echo -e "${GREEN}[KEYLOG] ✓ Rekey detected (≥8 keys logged for AEAD)${NC}"
    elif [ "$KEY_COUNT" -eq 4 ]; then
        echo -e "${YELLOW}[KEYLOG] ⚠️  Only 4 keys - rekey may not have occurred${NC}"
    else
        echo -e "${YELLOW}[KEYLOG] ⚠️  Unexpected key count: ${KEY_COUNT}${NC}"
    fi

    echo ""
    echo "All keylog entries:"
    cat "${KEYLOGS_DIR}/wolfssh_client_keylog.log"
else
    echo -e "${RED}[KEYLOG] ✗ No keys extracted${NC}"
fi

echo ""

# Convert to Wireshark format (if keylog and PCAP exist)
if [ -f "${KEYLOGS_DIR}/wolfssh_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/wolfssh_client_keylog.log" ]; then
    # Check if PCAP exists
    if [ -f "${PCAP_FILE}" ] || ls ${CAPTURES_DIR}/wolfssh_lifecycle_ku_*.pcap 1> /dev/null 2>&1; then
        echo -e "${YELLOW}[CONVERT]${NC} Generating Wireshark-compatible keylog..."

        # Run converter
        ./convert_ssh_to_wireshark.py \
            --ssh-keylog "${KEYLOGS_DIR}/wolfssh_client_keylog.log" \
            --pcap "${PCAP_FILE}" \
            --out "${KEYLOGS_DIR}/wireshark_keylog.txt" \
            --implementation wolfssh 2>&1 | grep -E "Detected|Parsed|Selected|Extracted|Wrote|ERROR|WARNING" || true

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
echo "Mode:         KU (with rekey)"
echo ""
echo "Results location (absolute paths):"
echo "  Keylog:     ${SCRIPT_DIR}/${KEYLOGS_DIR}/wolfssh_client_keylog.log"
echo "  Debug Log:  ${SCRIPT_DIR}/${KEYLOGS_DIR}/wolfssh_client_keylog_debug.log"
echo "  Event Log:  ${SCRIPT_DIR}/${DUMPS_DIR}/ssh_events.jsonl"
echo "  Dumps:      ${SCRIPT_DIR}/${DUMPS_DIR}/*.dump"
echo "  PCAP:       ${SCRIPT_DIR}/${PCAP_FILE}"
echo ""
echo "Quick check commands:"
echo "  # View keylog entries"
echo "  cat ${SCRIPT_DIR}/data/keylogs/wolfssh_client_keylog.log"
echo ""
echo "  # Count keys extracted"
echo "  grep -c '_KEX' ${SCRIPT_DIR}/data/keylogs/wolfssh_client_keylog.log"
echo ""
echo "  # Check for rekey (should see KEX1 and KEX2 if rekey occurred)"
echo "  grep -E '_KEX[12]' ${SCRIPT_DIR}/data/keylogs/wolfssh_client_keylog.log"
echo ""
echo "  # View timing data (if watchpoints enabled)"
echo "  cat ${SCRIPT_DIR}/data/lldb_results/timing_wolfssh.csv"
echo ""

if [ "$CLIENT_EXIT_CODE" -eq 0 ] && [ "$KEY_COUNT" -ge 4 ]; then
    echo -e "${GREEN}✓ TEST PASSED - wolfSSH lifecycle experiment completed successfully${NC}"
    echo ""
    echo "Expected lifecycle flow:"
    echo "  1. PRE_CONNECT → KEX_COMPLETE (4 keys for AEAD)"
    echo "  2. KEX_COMPLETE → ACTIVE"
    echo "  3. [SSH commands]"
    echo "  4. ACTIVE → REKEY_START (programmatic trigger)"
    echo "  5. REKEY_START → REKEY_COMPLETE (4 more keys)"
    echo "  6. [More SSH commands]"
    echo "  7. SESSION_CLOSED → CLEANUP"
    echo ""
    exit 0
else
    echo -e "${RED}✗ TEST FAILED - Check logs for errors${NC}"
    echo ""
    exit 1
fi
