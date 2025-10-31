#!/bin/bash
#
# Dropbear Lifecycle Test - Simple Session
#
# Tests basic SSH lifecycle with memory dumps:
#   1. Handshake (PRE_CONNECT → KEX_COMPLETE → ACTIVE)
#   2. SSH commands ("ls", "pwd", etc.)
#   3. Session close (SESSION_CLOSED → CLEANUP)
#
# Memory dumps are taken before/after each transition.
# NO REKEY - Dropbear client does not support rekeying.
#

set -e

# Get absolute path to script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DROPBEAR_WATCHPOINTS="true"
DROPBEAR_WATCHPOINTS="${DROPBEAR_WATCHPOINTS:-$GLOBAL_WATCHPOINTS}"
export LLDB_ENABLE_WATCHPOINTS_DROPBEAR="$DROPBEAR_WATCHPOINTS"

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo "========================================================================"
echo "  Dropbear Lifecycle Test (Simple Experiment)"
echo "========================================================================"
echo ""
echo "This test demonstrates basic SSH key lifecycle with Dropbear:"
echo "  - Handshake + KEX (gen_new_keys extracts ChaCha20 key)"
echo "  - Active session with commands"
echo "  - Session termination (NO REKEY - not supported by Dropbear client)"
echo ""
echo "Memory dumps will be captured at each transition."
echo "Watchpoint Configuration:"
echo "  Dropbear: ${DROPBEAR_WATCHPOINTS}"
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
DROPBEAR_SERVER="openssh_groundtruth"
DROPBEAR_CLIENT="dropbear_client"
SSH_USER="testuser"
SSH_PASSWORD="password"
SSH_PORT="22"

# Directories
KEYLOGS_DIR="./data/keylogs"
DUMPS_DIR="./data/dumps"
CAPTURES_DIR="./data/captures"

# Clean previous run
echo -e "${YELLOW}[CLEANUP]${NC} Removing old logs, dumps, and captures..."
rm -f ${KEYLOGS_DIR}/dropbear_client_keylog*.log
rm -f ${DUMPS_DIR}/*.dump
rm -f ${DUMPS_DIR}/ssh_events.jsonl
rm -f ${CAPTURES_DIR}/dropbear_lifecycle_*.pcap
echo -e "${GREEN}[CLEANUP] ✓ Clean${NC}"
echo ""

# Ensure directories exist
mkdir -p ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}
chmod -R 777 ${KEYLOGS_DIR} ${DUMPS_DIR} ${CAPTURES_DIR}

# Start Dropbear server
echo -e "${YELLOW}[SERVER]${NC} Starting ${DROPBEAR_SERVER}..."
docker compose up -d ${DROPBEAR_SERVER}
sleep 5

# Check server is running
if ! docker compose ps | grep -q "${DROPBEAR_SERVER}.*Up"; then
    echo -e "${RED}[SERVER] ✗ Server failed to start${NC}"
    exit 1
fi
echo -e "${GREEN}[SERVER] ✓ Server running${NC}"
echo ""

# Start packet capture from SERVER container (already running)
echo -e "${YELLOW}[PCAP]${NC} Starting packet capture from server..."
PCAP_FILE="${CAPTURES_DIR}/dropbear_lifecycle_$(date +%Y%m%d_%H%M%S).pcap"

# Capture from server container's network namespace
docker run --rm -d --name dropbear_pcap_$$ \
    --net=container:${DROPBEAR_SERVER} \
    --cap-add NET_ADMIN \
    -v "${PWD}/${CAPTURES_DIR}:/captures" \
    nicolaka/netshoot \
    tcpdump -i any -w /captures/$(basename ${PCAP_FILE}) "port ${SSH_PORT}" \
    > /dev/null 2>&1 || echo -e "${YELLOW}[PCAP] ⚠️  Could not start capture (non-critical)${NC}"

TCPDUMP_CONTAINER="dropbear_pcap_$$"
sleep 2

if docker ps | grep -q ${TCPDUMP_CONTAINER}; then
    echo -e "${GREEN}[PCAP] ✓ Packet capture running${NC}"
else
    echo -e "${YELLOW}[PCAP] ⚠️  Packet capture not available (non-critical)${NC}"
    TCPDUMP_CONTAINER=""
fi
echo ""

# Run Dropbear client with LLDB monitoring + lifecycle experiment
echo -e "${YELLOW}[CLIENT]${NC} Running Dropbear client with LLDB lifecycle monitoring..."
echo -e "${YELLOW}[CLIENT]${NC} Using custom client script: dropbear_client_rekey"
echo -e "${YELLOW}[CLIENT]${NC} Environment:"
echo "  - LLDB_ENABLE_MEMORY_DUMPS=true"
echo "  - LLDB_DUMP_TYPE=heap"
echo "  - SSH_SERVER_HOST=${DROPBEAR_SERVER}"
echo "  - SSH_SERVER_PORT=${SSH_PORT}"
echo "  - Rekey: DISABLED (base lifecycle test)"
echo ""

# Cleanup function for client container
cleanup_client() {
    echo -e "${YELLOW}[CLEANUP]${NC} Stopping and removing client container..."
    docker compose stop ${DROPBEAR_CLIENT} 2>/dev/null || true
    sleep 1
    docker compose rm -f ${DROPBEAR_CLIENT} 2>/dev/null || true
    echo -e "${GREEN}[CLEANUP] ✓ Client container cleaned${NC}"
}

# Set up trap to ensure cleanup on error or interrupt
trap cleanup_client ERR INT TERM

# Run client with lifecycle monitoring using custom client script (5 minute timeout to prevent hanging)
# NOTE: Using dropbear_client_rekey WITHOUT --with-rekey flag (base lifecycle test)
# NOTE: Not using --rm to avoid Docker cleanup hangs
timeout 300 docker compose run \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_DUMPS_DIR=/data/dumps \
    -e LLDB_ENABLE_ENTRY_DUMPS=true \
    -e SSH_SERVER_HOST=${DROPBEAR_SERVER} \
    -e SSH_SERVER_PORT=${SSH_PORT} \
    -e SSH_USER=${SSH_USER} \
    -e SSH_PASSWORD=${SSH_PASSWORD} \
    -e SSH_CMD="/usr/local/bin/dropbear_client_rekey ${DROPBEAR_SERVER} ${SSH_PORT} ${SSH_USER} ${SSH_PASSWORD}" \
    ${DROPBEAR_CLIENT}

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
if [ -n "$TCPDUMP_CONTAINER" ] && docker ps -q -f name=${TCPDUMP_CONTAINER} > /dev/null 2>&1; then
    echo -e "${YELLOW}[PCAP]${NC} Stopping packet capture..."
    docker stop ${TCPDUMP_CONTAINER} > /dev/null 2>&1 || true
    sleep 1

    if [ -f "${PCAP_FILE}" ]; then
        PCAP_SIZE=$(ls -lh "${PCAP_FILE}" | awk '{print $5}')
        echo -e "${GREEN}[PCAP] ✓ Capture saved: ${PCAP_FILE} (${PCAP_SIZE})${NC}"
    else
        echo -e "${YELLOW}[PCAP] ⚠️  Capture file not found${NC}"
    fi
fi
echo ""

# Stop server
echo -e "${YELLOW}[SERVER]${NC} Stopping ${DROPBEAR_SERVER}..."
docker compose stop ${DROPBEAR_SERVER}
echo ""

# Verify experiment results
echo "========================================================================"
echo "  EXPERIMENT RESULTS"
echo "========================================================================"
echo ""

# Check keylog
if [ -f "${KEYLOGS_DIR}/dropbear_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/dropbear_client_keylog.log" ]; then
    # Count all key types (CLIENT, A_, B_, C_, D_, E_, F_)
    KEY_COUNT=$(grep -c "_KEY\|CLIENT" "${KEYLOGS_DIR}/dropbear_client_keylog.log" || echo "0")
    echo -e "${GREEN}[KEYLOG] ✓ Keys extracted: ${KEY_COUNT}${NC}"

    # Determine extraction mode from environment (default: extended=true)
    EXTRACT_ALL_KEYS=${LLDB_EXTRACT_ALL_KEYS:-true}

    if [ "$EXTRACT_ALL_KEYS" = "true" ]; then
        # Extended mode: expect 1-6 keys (depending on AEAD vs non-AEAD cipher)
        if [ "$KEY_COUNT" -ge 1 ] && [ "$KEY_COUNT" -le 6 ]; then
            echo -e "${GREEN}[KEYLOG] ✓ Expected key count for extended mode (1-6 keys)${NC}"
            if [ "$KEY_COUNT" -eq 1 ]; then
                echo -e "${CYAN}[KEYLOG] ℹ️  Only 1 key - extended mode may have failed, or cipher doesn't support all keys${NC}"
            fi
        else
            echo -e "${YELLOW}[KEYLOG] ⚠️  Unexpected key count: $KEY_COUNT (expected 1-6 for extended mode)${NC}"
        fi
    else
        # Simple mode: expect exactly 1 key
        if [ "$KEY_COUNT" -eq 1 ]; then
            echo -e "${GREEN}[KEYLOG] ✓ Expected key count for simple mode (1 key: trans_cipher_key)${NC}"
        elif [ "$KEY_COUNT" -gt 1 ]; then
            echo -e "${YELLOW}[KEYLOG] ⚠️  More than 1 key in simple mode - check LLDB_EXTRACT_ALL_KEYS setting${NC}"
        else
            echo -e "${YELLOW}[KEYLOG] ⚠️  No keys - KEX may have failed${NC}"
        fi
    fi

    echo ""
    echo "All keylog entries:"
    cat "${KEYLOGS_DIR}/dropbear_client_keylog.log"
else
    echo -e "${RED}[KEYLOG] ✗ No keys extracted${NC}"
fi

echo ""

# Convert to Wireshark format (if keylog and PCAP exist)
if [ -f "${KEYLOGS_DIR}/dropbear_client_keylog.log" ] && [ -s "${KEYLOGS_DIR}/dropbear_client_keylog.log" ]; then
    # Check if PCAP exists
    if [ -f "${PCAP_FILE}" ] || ls ${CAPTURES_DIR}/dropbear_lifecycle_*.pcap 1> /dev/null 2>&1; then
        echo -e "${YELLOW}[CONVERT]${NC} Generating Wireshark-compatible keylog..."

        # Run converter
        ./convert_ssh_to_wireshark.py \
            --ssh-keylog "${KEYLOGS_DIR}/dropbear_client_keylog.log" \
            --pcap "${PCAP_FILE}" \
            --out "${KEYLOGS_DIR}/wireshark_keylog.txt" \
            --implementation dropbear 2>&1 | grep -E "Detected|Parsed|Selected|Extracted|Wrote|ERROR|WARNING" || true

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
echo "Mode:         BASE (no rekey)"
echo ""
echo "Results location (absolute paths):"
echo "  Keylog:     ${SCRIPT_DIR}/${KEYLOGS_DIR}/dropbear_client_keylog.log"
echo "  Event Log:  ${SCRIPT_DIR}/${DUMPS_DIR}/ssh_events.jsonl"
echo "  Dumps:      ${SCRIPT_DIR}/${DUMPS_DIR}/*.dump"
echo "  PCAP:       ${SCRIPT_DIR}/${PCAP_FILE}"
echo ""
echo "Quick check commands:"
echo "  # View keylog entries"
echo "  cat ${SCRIPT_DIR}/data/keylogs/dropbear_client_keylog.log"
echo ""
echo "  # Count keys extracted"
echo "  grep -c '_KEX1' ${SCRIPT_DIR}/data/keylogs/dropbear_client_keylog.log"
echo ""
echo "  # View timing data (if watchpoints enabled)"
echo "  cat ${SCRIPT_DIR}/data/lldb_results/timing_dropbear.csv"
echo ""

EXTRACT_ALL_KEYS=${LLDB_EXTRACT_ALL_KEYS:-true}

# Determine success based on extraction mode
if [ "$EXTRACT_ALL_KEYS" = "true" ]; then
    # Extended mode: accept 1-6 keys
    KEY_CHECK_PASSED=$([ "$KEY_COUNT" -ge 1 ] && [ "$KEY_COUNT" -le 6 ] && echo "true" || echo "false")
    MODE_DESC="extended mode (1-6 keys)"
else
    # Simple mode: accept exactly 1 key
    KEY_CHECK_PASSED=$([ "$KEY_COUNT" -eq 1 ] && echo "true" || echo "false")
    MODE_DESC="simple mode (1 key)"
fi

if [ "$CLIENT_EXIT_CODE" -eq 0 ] && [ "$KEY_CHECK_PASSED" = "true" ]; then
    echo -e "${GREEN}✓ TEST PASSED - Dropbear lifecycle experiment completed successfully${NC}"
    echo ""
    echo "Extraction mode: ${MODE_DESC}"
    echo "Keys extracted: ${KEY_COUNT}"
    echo ""
    echo "Expected lifecycle flow:"
    echo "  1. PRE_CONNECT → KEX_COMPLETE (${KEY_COUNT} key(s))"
    echo "  2. KEX_COMPLETE → ACTIVE"
    echo "  3. [SSH commands]"
    echo "  4. SESSION_CLOSED → CLEANUP"
    echo ""
    exit 0
else
    echo -e "${RED}✗ TEST FAILED - Check logs for errors${NC}"
    echo ""
    echo "Client exit code: ${CLIENT_EXIT_CODE}"
    echo "Keys extracted: ${KEY_COUNT}"
    echo "Expected: ${MODE_DESC}"
    echo ""
    echo ""
    exit 1
fi
