#!/bin/bash
#
# OpenSSH Lifecycle Test (NO REKEY) - Simple Session
#
# Tests basic SSH lifecycle with memory dumps:
#   1. Handshake (PRE_CONNECT → KEX_COMPLETE → ACTIVE)
#   2. SSH commands ("ls", "pwd", etc.)
#   3. Session close (SESSION_CLOSED → CLEANUP)
#
# Memory dumps are taken before/after each transition.
# NO REKEY - simpler test to establish baseline.
#

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo ""
echo "========================================================================"
echo "  OpenSSH Lifecycle Test - NO Rekey (Simple Experiment)"
echo "========================================================================"
echo ""
echo "This test demonstrates basic SSH key lifecycle:"
echo "  - Handshake + KEX"
echo "  - Active session with commands"
echo "  - Session termination (NO REKEY)"
echo ""
echo "Memory dumps will be captured at each transition."
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

# Start packet capture (host-side, if possible)
echo -e "${YELLOW}[PCAP]${NC} Starting packet capture..."
PCAP_FILE="${CAPTURES_DIR}/openssh_lifecycle_no_rekey_$(date +%Y%m%d_%H%M%S).pcap"

# Capture on docker network (requires privilege)
# If this fails, the test will continue without PCAP
timeout 30 docker run --rm --net=container:${OPENSSH_CLIENT} \
    --cap-add NET_ADMIN \
    nicolaka/netshoot \
    tcpdump -i any -w /data/captures/$(basename ${PCAP_FILE}) \
    "host ${OPENSSH_SERVER} and port ${SSH_PORT}" &
TCPDUMP_PID=$!
sleep 2

if ps -p $TCPDUMP_PID > /dev/null 2>&1; then
    echo -e "${GREEN}[PCAP] ✓ Packet capture running (PID ${TCPDUMP_PID})${NC}"
else
    echo -e "${YELLOW}[PCAP] ⚠️  Packet capture not available (requires NET_ADMIN)${NC}"
    TCPDUMP_PID=""
fi
echo ""

# Run OpenSSH client with LLDB monitoring + lifecycle experiment
echo -e "${YELLOW}[CLIENT]${NC} Running OpenSSH client with LLDB lifecycle monitoring..."
echo -e "${YELLOW}[CLIENT]${NC} Environment:"
echo "  - LLDB_ENABLE_MEMORY_DUMPS=true"
echo "  - LLDB_DUMP_TYPE=heap"
echo "  - SSH_SERVER_HOST=${OPENSSH_SERVER}"
echo "  - SSH_SERVER_PORT=${SSH_PORT}"
echo ""

# Use expect to automate SSH session WITHOUT rekey
cat > /tmp/openssh_lifecycle_no_rekey_exp.sh << 'EXPECT_SCRIPT'
#!/usr/bin/expect -f
#
# Expect script for OpenSSH lifecycle WITHOUT rekey
#

set timeout 20
set server [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set password [lindex $argv 3]

puts "\n[EXPECT] Starting SSH session to ${user}@${server}:${port}"
puts "[EXPECT] Will perform: connect → commands → exit (NO REKEY)\n"

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

# Phase 1: SSH commands (no rekey)
puts "[EXPECT] === PHASE 1: SSH commands ==="
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
sleep 0.5

send "date\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: date"
sleep 0.5

send "uptime\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: uptime"
sleep 0.5

send "echo 'Session test complete'\r"
expect -re "\\$|#"
puts "[EXPECT] ✓ Command: echo 'Session test complete'"
sleep 1

# Phase 2: Clean exit
puts "\n[EXPECT] === PHASE 2: Session termination ==="
send "exit\r"

expect {
    eof {
        puts "[EXPECT] ✓ SSH session closed cleanly\n"
    }
    timeout {
        puts "[EXPECT] ⚠️  Exit timeout (connection may have closed)\n"
    }
}

puts "[EXPECT] Lifecycle experiment complete (no rekey)"
exit 0
EXPECT_SCRIPT

chmod +x /tmp/openssh_lifecycle_no_rekey_exp.sh

# Run client with lifecycle monitoring
docker compose run --rm \
    -e LLDB_ENABLE_MEMORY_DUMPS=true \
    -e LLDB_DUMP_TYPE=heap \
    -e LLDB_DUMPS_DIR=/data/dumps \
    -e SSH_SERVER_HOST=${OPENSSH_SERVER} \
    -e SSH_SERVER_PORT=${SSH_PORT} \
    -e SSH_USER=${SSH_USER} \
    -e SSH_PASSWORD=${SSH_PASSWORD} \
    -e SSH_CMD="expect /tmp/openssh_lifecycle_no_rekey_exp.sh ${OPENSSH_SERVER} ${SSH_PORT} ${SSH_USER} ${SSH_PASSWORD}" \
    ${OPENSSH_CLIENT}

CLIENT_EXIT_CODE=$?

echo ""
echo "========================================================================"

# Stop packet capture
if [ -n "$TCPDUMP_PID" ] && ps -p $TCPDUMP_PID > /dev/null 2>&1; then
    echo -e "${YELLOW}[PCAP]${NC} Stopping packet capture..."
    kill $TCPDUMP_PID 2>/dev/null || true
    wait $TCPDUMP_PID 2>/dev/null || true
    sleep 1

    if [ -f "${PCAP_FILE}" ]; then
        PCAP_SIZE=$(stat -f%z "${PCAP_FILE}" 2>/dev/null || stat -c%s "${PCAP_FILE}" 2>/dev/null || echo "0")
        echo -e "${GREEN}[PCAP] ✓ Capture saved: ${PCAP_FILE} (${PCAP_SIZE} bytes)${NC}"
    else
        echo -e "${YELLOW}[PCAP] ⚠️  Capture file not created${NC}"
    fi
fi

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

    # Should have 6 keys (no rekey)
    if [ "$KEY_COUNT" -eq 6 ]; then
        echo -e "${GREEN}[KEYLOG] ✓ Expected key count for no-rekey session (6 keys)${NC}"
    elif [ "$KEY_COUNT" -gt 6 ]; then
        echo -e "${YELLOW}[KEYLOG] ⚠️  More than 6 keys - unexpected rekey may have occurred${NC}"
    else
        echo -e "${YELLOW}[KEYLOG] ⚠️  Fewer than 6 keys - KEX may be incomplete${NC}"
    fi

    echo ""
    echo "All keylog entries:"
    cat "${KEYLOGS_DIR}/openssh_client_keylog.log"
else
    echo -e "${RED}[KEYLOG] ✗ No keys extracted${NC}"
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
echo "Keylog:       ${KEYLOGS_DIR}/openssh_client_keylog.log"
echo "Debug Log:    ${KEYLOGS_DIR}/openssh_client_keylog_debug.log"
echo "Event Log:    ${DUMPS_DIR}/ssh_events.jsonl"
echo "Dumps:        ${DUMPS_DIR}/*.dump"
echo "PCAP:         ${PCAP_FILE}"
echo ""

if [ "$CLIENT_EXIT_CODE" -eq 0 ] && [ "$KEY_COUNT" -eq 6 ]; then
    echo -e "${GREEN}✓ TEST PASSED - OpenSSH lifecycle experiment (no rekey) completed successfully${NC}"
    echo ""
    echo "Expected lifecycle flow:"
    echo "  1. PRE_CONNECT → KEX_COMPLETE (6 keys)"
    echo "  2. KEX_COMPLETE → ACTIVE"
    echo "  3. [SSH commands]"
    echo "  4. SESSION_CLOSED → CLEANUP"
    echo ""
    exit 0
else
    echo -e "${RED}✗ TEST FAILED - Check logs for errors${NC}"
    echo ""
    exit 1
fi
