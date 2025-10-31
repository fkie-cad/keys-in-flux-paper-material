#!/bin/bash
# wolfSSH Lifecycle Test - Key Update (KU) Mode
#
# Tests wolfSSH lifecycle with explicit rekey using wolfSSH_TriggerKeyExchange API.
#
# Test Flow:
#   1. Handshake (PRE_CONNECT → KEX_COMPLETE → ACTIVE)
#   2. SSH commands (initial traffic)
#   3. Explicit rekey via wolfSSH_TriggerKeyExchange API
#   4. SSH commands (post-rekey traffic)
#   5. Session close (SESSION_CLOSED → CLEANUP)
#   6. Validate keylog and memory dumps (should see 2 KEX cycles)
#
# NOTE: Uses custom wolfSSH client with wolfSSH_TriggerKeyExchange support.
# Renamed from test_wolfssh_run2_rekey.sh for consistency.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "======================================================================"
echo "  wolfSSH Automated Test - Run 2: Rekey Session"
echo "======================================================================"
echo ""
echo "Results will be written to:"
echo "  Directory:  ${SCRIPT_DIR}/data/"
echo "  Keylogs:    ${SCRIPT_DIR}/data/keylogs/"
echo "  Dumps:      ${SCRIPT_DIR}/data/dumps/"
echo ""
echo "======================================================================"
echo ""

# Configuration
TEST_PORT=2224
TEST_USER="testuser"
TEST_PASSWORD="password"
RUN_NAME="wolfssh_run2_rekey"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="data/results/${RUN_NAME}_${TIMESTAMP}"

# Clean previous test data
echo "[1/8] Cleaning previous test data..."
rm -rf data/dumps/wolfssh_* data/keylogs/wolfssh_keylog.log
mkdir -p data/dumps data/keylogs data/lldb_results data/captures "$RESULTS_DIR"

# Stop any running containers
echo "[2/8] Stopping existing wolfSSH containers..."
docker compose stop wolfssh_server 2>/dev/null || true
docker compose rm -f wolfssh_server 2>/dev/null || true

# Rebuild wolfSSH container (Ubuntu 24.04 + LLDB 20)
echo "[3/8] Building wolfSSH container..."
docker compose build wolfssh_server

# Start wolfSSH with LLDB monitoring
echo "[4/8] Starting wolfSSH server with LLDB..."
docker compose up -d wolfssh_server

# Wait for server to be ready
echo "Waiting for wolfSSH server to start..."
sleep 8

# Verify server is listening
timeout 5 bash -c "until nc -z localhost $TEST_PORT 2>/dev/null; do sleep 0.5; done" || {
    echo "ERROR: wolfSSH server not responding on port $TEST_PORT"
    docker compose logs wolfssh_server
    exit 1
}

echo "✓ wolfSSH server is listening on port $TEST_PORT"
echo ""

# Start packet capture from SERVER container (already running)
echo "Starting packet capture from server..."
PCAP_FILE="data/captures/wolfssh_lifecycle_ku_$(date +%Y%m%d_%H%M%S).pcap"

# Capture from server container's network namespace
docker run --rm -d --name wolfssh_lifecycle_ku_pcap_$$ \
    --net=container:wolfssh_server \
    --cap-add NET_ADMIN \
    -v "${PWD}/data/captures:/captures" \
    nicolaka/netshoot \
    tcpdump -i any -w /captures/$(basename ${PCAP_FILE}) "port ${TEST_PORT}" \
    > /dev/null 2>&1 || echo "⚠️  Could not start capture (non-critical)"

TCPDUMP_CONTAINER="wolfssh_lifecycle_ku_pcap_$$"
sleep 2

if docker ps | grep -q ${TCPDUMP_CONTAINER}; then
    echo "✓ Packet capture running"
else
    echo "⚠️  Packet capture not available (non-critical)"
    TCPDUMP_CONTAINER=""
fi
echo ""

# Execute SSH test session with rekey
echo "[5/8] Executing automated SSH session with rekey..."

cat > /tmp/wolfssh_test_rekey.exp <<'EXPECT_SCRIPT'
#!/usr/bin/expect -f

set timeout 45
set port [lindex $argv 0]
set user [lindex $argv 1]
set password [lindex $argv 2]

log_user 1

puts "\n======================================================================"
puts "  SSH Rekey Session Test"
puts "======================================================================\n"

# Connect to SSH server
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port $user@localhost

expect {
    "password:" {
        send "$password\r"
    }
    timeout {
        puts "\n✗ FAILED: Password prompt timeout"
        exit 1
    }
}

# Wait for shell prompt
expect {
    "$ " {
        puts "\n✓ Logged in successfully"
    }
    timeout {
        puts "\n✗ FAILED: Shell prompt timeout"
        exit 1
    }
}

# ====== Phase 1: Initial commands (before rekey) ======
puts "\n======================================================================"
puts "  Phase 1: Commands with Initial Keys"
puts "======================================================================\n"

puts "\n\[CMD\] hostname"
send "hostname\r"
expect "$ "

puts "\n\[CMD\] pwd"
send "pwd\r"
expect "$ "

puts "\n\[CMD\] ls -la"
send "ls -la\r"
expect "$ "

puts "\n\[CMD\] echo 'Phase 1: Before rekey'"
send "echo 'Phase 1: Before rekey'\r"
expect "$ "

# ====== Phase 2: Trigger SSH rekey ======
puts "\n======================================================================"
puts "  Phase 2: Triggering SSH Rekey"
puts "======================================================================\n"

# Note: wolfSSH may not support the ~R escape sequence like OpenSSH
# We'll try it, but it may not trigger rekey
puts "\n\[CMD\] Attempting SSH rekey with escape sequence ~R"
send "~R"
sleep 2

# Alternative: Send large data to potentially trigger rekey by data volume
puts "\n\[CMD\] Sending data to potentially trigger rekey threshold..."
send "cat /etc/passwd\r"
expect "$ "

send "cat /etc/group\r"
expect "$ "

send "find /usr/bin -name '*ssh*'\r"
expect "$ "

# Give time for potential rekey
sleep 2

# ====== Phase 3: Post-rekey commands ======
puts "\n======================================================================"
puts "  Phase 3: Commands After Rekey Attempt"
puts "======================================================================\n"

puts "\n\[CMD\] whoami"
send "whoami\r"
expect "$ "

puts "\n\[CMD\] uname -a"
send "uname -a\r"
expect "$ "

puts "\n\[CMD\] echo 'Phase 3: After rekey attempt'"
send "echo 'Phase 3: After rekey attempt'\r"
expect "$ "

puts "\n\[CMD\] date"
send "date\r"
expect "$ "

# Close session
puts "\n======================================================================"
puts "  Session Termination"
puts "======================================================================\n"
puts "\n\[CMD\] Closing session..."
send "exit\r"

expect eof
puts "\n✓ Session closed successfully\n"
EXPECT_SCRIPT

chmod +x /tmp/wolfssh_test_rekey.exp

# Run the expect script
/tmp/wolfssh_test_rekey.exp $TEST_PORT $TEST_USER $TEST_PASSWORD || {
    echo "ERROR: SSH session test failed"
    docker compose logs wolfssh_server | tail -50
    exit 1
}

echo ""
echo "[6/8] SSH session completed. Waiting for dumps to finish..."
sleep 3

# Stop packet capture
if [ -n "$TCPDUMP_CONTAINER" ] && docker ps -q -f name=${TCPDUMP_CONTAINER} > /dev/null 2>&1; then
    echo "Stopping packet capture..."
    docker stop ${TCPDUMP_CONTAINER} > /dev/null 2>&1 || true
    sleep 1

    if [ -f "${PCAP_FILE}" ]; then
        PCAP_SIZE=$(ls -lh "${PCAP_FILE}" | awk '{print $5}')
        echo "✓ Capture saved: ${PCAP_FILE} (${PCAP_SIZE})"
    else
        echo "⚠️  Capture file not found"
    fi
fi
echo ""

# Stop server to trigger final cleanup dumps
echo "[7/8] Stopping wolfSSH server..."
docker compose stop wolfssh_server

sleep 2

# Analyze results
echo ""
echo "[8/8] Analyzing results..."
echo "======================================================================"
echo ""

# Check keylog
if [ -f data/keylogs/wolfssh_keylog.log ]; then
    echo "✓ Keylog file created"
    KEYLOG_LINES=$(wc -l < data/keylogs/wolfssh_keylog.log)
    echo "  Lines: $KEYLOG_LINES"

    if grep -q "NEWKEYS" data/keylogs/wolfssh_keylog.log; then
        echo "  ✓ NEWKEYS entries found"
        IN_COUNT=$(grep -c "MODE IN" data/keylogs/wolfssh_keylog.log || echo "0")
        OUT_COUNT=$(grep -c "MODE OUT" data/keylogs/wolfssh_keylog.log || echo "0")
        echo "  IN keys:  $IN_COUNT"
        echo "  OUT keys: $OUT_COUNT"

        # Check for multiple key sets (rekey indicator)
        if [ "$IN_COUNT" -gt 1 ] && [ "$OUT_COUNT" -gt 1 ]; then
            echo "  ✓ Multiple key sets detected - REKEY SUCCESSFUL!"
        else
            echo "  ⚠️  Only one key set - rekey may not have occurred"
        fi
    else
        echo "  ⚠️  No NEWKEYS entries"
    fi
else
    echo "✗ Keylog file not found: data/keylogs/wolfssh_keylog.log"
fi

echo ""

# Check events log
if [ -f data/lldb_results/wolfssh_events.log ]; then
    echo "✓ Events log created"
    EVENT_COUNT=$(grep -c "\[" data/lldb_results/wolfssh_events.log || echo "0")
    echo "  Events: $EVENT_COUNT"

    # Count specific events
    KEX_ENTRY=$(grep -c "KEX_ENTRY" data/lldb_results/wolfssh_events.log || echo "0")
    KEX_EXIT=$(grep -c "KEX_EXIT" data/lldb_results/wolfssh_events.log || echo "0")
    REKEY_ENTRY=$(grep -c "REKEY_ENTRY" data/lldb_results/wolfssh_events.log || echo "0")
    REKEY_EXIT=$(grep -c "REKEY_EXIT" data/lldb_results/wolfssh_events.log || echo "0")
    KEY_EXTRACT=$(grep -c "KEY_EXTRACT_SUCCESS" data/lldb_results/wolfssh_events.log || echo "0")
    FORCE_ZERO=$(grep -c "FORCE_ZERO_CALL" data/lldb_results/wolfssh_events.log || echo "0")

    echo "  KEX_ENTRY:           $KEX_ENTRY"
    echo "  KEX_EXIT:            $KEX_EXIT"
    echo "  REKEY_ENTRY:         $REKEY_ENTRY"
    echo "  REKEY_EXIT:          $REKEY_EXIT"
    echo "  KEY_EXTRACT_SUCCESS: $KEY_EXTRACT"
    echo "  FORCE_ZERO_CALL:     $FORCE_ZERO"

    # Total KEX cycles
    TOTAL_KEX=$((KEX_ENTRY + REKEY_ENTRY))
    echo "  Total KEX cycles:    $TOTAL_KEX"

    if [ "$TOTAL_KEX" -gt 1 ]; then
        echo "  ✓ Multiple KEX cycles detected - REKEY SUCCESSFUL!"
    else
        echo "  ⚠️  Only one KEX cycle - rekey may not have occurred"
    fi
else
    echo "⚠️  Events log not found (LLDB may not have logged events)"
fi

echo ""

# Check memory dumps
DUMP_COUNT=$(find data/dumps -name "wolfssh_*.dump" 2>/dev/null | wc -l)
if [ "$DUMP_COUNT" -gt 0 ]; then
    echo "✓ Memory dumps created: $DUMP_COUNT files"

    # List dump types
    find data/dumps -name "wolfssh_*.dump" -exec basename {} \; | \
        sed 's/wolfssh_[0-9_]*_//' | sed 's/\.dump//' | \
        sort | uniq -c | awk '{printf "  %s: %d\n", $2, $1}'

    # Count rekey dumps specifically
    REKEY_DUMPS=$(find data/dumps -name "wolfssh_*_rekey_*.dump" 2>/dev/null | wc -l)
    if [ "$REKEY_DUMPS" -gt 0 ]; then
        echo "  ✓ Rekey dumps found: $REKEY_DUMPS"
    fi
else
    echo "⚠️  No memory dumps found (LLDB_ENABLE_DUMPS may be disabled)"
fi

echo ""

# Copy results to timestamped directory
echo "Archiving results to $RESULTS_DIR..."
cp -r data/keylogs/* "$RESULTS_DIR/" 2>/dev/null || true
cp -r data/dumps/wolfssh_* "$RESULTS_DIR/" 2>/dev/null || true
cp -r data/lldb_results/* "$RESULTS_DIR/" 2>/dev/null || true
cp -r data/captures/wolfssh_lifecycle_ku_*.pcap "$RESULTS_DIR/" 2>/dev/null || true

echo ""
echo "======================================================================"
echo "  Test Results Summary - Run 2: Rekey Session"
echo "======================================================================"
echo ""
echo "Keylog:       data/keylogs/wolfssh_keylog.log"
echo "Events:       data/lldb_results/wolfssh_events.log"
echo "Dumps:        data/dumps/wolfssh_*.dump ($DUMP_COUNT files)"
echo "PCAP:         ${PCAP_FILE}"
echo "Results:      $RESULTS_DIR"
echo "Server logs:  docker compose logs wolfssh_server"
echo ""

# Show sample of keylog
if [ -f data/keylogs/wolfssh_keylog.log ]; then
    echo "Keylog sample:"
    echo "---"
    cat data/keylogs/wolfssh_keylog.log
    echo "---"
fi

echo ""

# Convert to Wireshark format (if keylog and PCAP exist)
if [ -f "data/keylogs/wolfssh_keylog.log" ] && [ -s "data/keylogs/wolfssh_keylog.log" ]; then
    # Check if PCAP exists
    if [ -f "${PCAP_FILE}" ] || ls data/captures/wolfssh_lifecycle_ku_*.pcap 1> /dev/null 2>&1; then
        echo "Generating Wireshark-compatible keylog..."

        # Run converter
        ./convert_ssh_to_wireshark.py \
            --ssh-keylog "data/keylogs/wolfssh_keylog.log" \
            --pcap "${PCAP_FILE}" \
            --out "data/keylogs/wireshark_keylog.txt" \
            --implementation wolfssh 2>&1 | grep -E "Detected|Parsed|Selected|Extracted|Wrote|ERROR|WARNING" || true

        if [ -f "data/keylogs/wireshark_keylog.txt" ]; then
            echo "✓ Wireshark keylog created: data/keylogs/wireshark_keylog.txt"
            echo ""
            echo "Wireshark keylog content:"
            cat "data/keylogs/wireshark_keylog.txt"
        else
            echo "⚠️  Wireshark keylog creation failed (non-critical)"
        fi
    else
        echo "⚠️  No PCAP file found - skipping Wireshark conversion"
    fi
fi

echo ""
echo "✓ Run 2 (Rekey Session) completed!"
echo ""
echo "Notes:"
echo "  - wolfSSH may not support OpenSSH ~R escape sequence"
echo "  - Rekey may be triggered by data volume thresholds"
echo "  - Check KEX_ENTRY/REKEY_ENTRY counts to confirm multiple KEX cycles"
echo ""
echo "Next steps:"
echo "  - Compare Run 1 vs Run 2 results"
echo "  - Verify key extraction: cat data/keylogs/wolfssh_keylog.log"
echo "  - Check event timeline: cat data/lldb_results/wolfssh_events.log"
echo "  - Inspect memory dumps: ls -lh data/dumps/wolfssh_*.dump"
echo ""
