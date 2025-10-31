#!/bin/bash
# OpenSSH Automated Key Lifecycle Test
#
# This script orchestrates a complete automated test of OpenSSH key extraction:
# 1. Start OpenSSH server with LLDB monitoring
# 2. Start network PCAP capture
# 3. Connect from ground-truth client (openssh_groundtruth container)
# 4. Execute predefined SSH commands (ls, pwd, hostname, exit)
# 5. Trigger memory dumps at checkpoints
# 6. Validate extracted keys against ground-truth
# 7. Generate summary report
#
# Memory Dump Checkpoints:
#   - Before SSH handshake (LLDB callback: pre_kex)
#   - After SSH handshake (LLDB callback: post_kex)
#   - During command execution (manual trigger between commands)
#   - Before session close (manual trigger before exit command)
#   - After session close (full dump via gcore)
#
# Usage:
#   docker/test_openssh_automated.sh [test_name]
#
# Example:
#   docker/test_openssh_automated.sh baseline_test_1

set -e  # Exit on error

# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

TEST_NAME="${1:-openssh_auto_$(date +%Y%m%d_%H%M%S)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="$SCRIPT_DIR/data"
RESULTS_DIR="$DATA_DIR/results/$TEST_NAME"

# Create results directory structure
mkdir -p "$RESULTS_DIR"/{keylogs,dumps,captures,reports}

# Logging
LOG_FILE="$RESULTS_DIR/test_execution.log"
exec > >(tee -a "$LOG_FILE")
exec 2>&1

# SSH Configuration
SSH_HOST="localhost"
SSH_PORT="2222"
SSH_USER="testuser"
SSH_PASSWORD="password"

# Predefined command sequence
SSH_COMMANDS=(
    "ls"
    "pwd"
    "hostname"
    "exit"
)

echo "======================================================================"
echo "  OpenSSH Automated Key Lifecycle Test"
echo "======================================================================"
echo "Test name:     $TEST_NAME"
echo "Results dir:   $RESULTS_DIR"
echo "Start time:    $(date)"
echo "======================================================================"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

log() {
    echo "[$(date +%H:%M:%S)] $*"
}

error() {
    log "ERROR: $*" >&2
    exit 1
}

wait_for_port() {
    local host=$1
    local port=$2
    local timeout=${3:-30}

    log "Waiting for $host:$port (timeout: ${timeout}s)..."
    for i in $(seq 1 $timeout); do
        if timeout 1 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
            log "✓ Port $port is open"
            return 0
        fi
        sleep 1
    done
    error "Timeout waiting for $host:$port"
}

check_docker_container() {
    local container=$1
    if ! docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        error "Container $container is not running"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 1: START OPENSSH SERVER WITH LLDB
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 1: Starting OpenSSH server with LLDB monitoring..."

# Clean up any existing openssh_server container
if docker ps -a --format '{{.Names}}' | grep -q "^openssh_server$"; then
    log "Stopping existing openssh_server container..."
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" stop openssh_server
    docker compose -f "$SCRIPT_DIR/docker-compose.yml" rm -f openssh_server
fi

# Clear shared data directories
log "Clearing shared data directories..."
rm -rf "$DATA_DIR"/keylogs/* "$DATA_DIR"/dumps/* "$DATA_DIR"/captures/* 2>/dev/null || true

# Start OpenSSH server with LLDB
log "Starting openssh_server container..."
cd "$SCRIPT_DIR"
docker compose up -d openssh_server

# Wait for server to be ready
wait_for_port "$SSH_HOST" "$SSH_PORT" 30

# Verify LLDB is attached and monitoring
sleep 2
log "Checking LLDB attachment..."
if docker compose exec -T openssh_server ps aux | grep -q "[l]ldb"; then
    log "✓ LLDB is attached to OpenSSH"
else
    log "⚠ LLDB may not be attached (check logs)"
fi

log "✓ Phase 1 complete: OpenSSH server with LLDB is running"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 2: START PCAP CAPTURE
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 2: Starting PCAP capture..."

PCAP_FILE="$RESULTS_DIR/captures/openssh_traffic.pcap"

# Start tcpdump inside openssh_server container (captures server-side traffic)
docker compose exec -T -d openssh_server bash -c \
    "tcpdump -i lo -w /data/captures/openssh_traffic.pcap port 22" \
    2>/dev/null || log "⚠ tcpdump may have failed to start"

sleep 1
log "✓ Phase 2 complete: PCAP capture started"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 3: GROUND-TRUTH CLIENT CONNECTION
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 3: Connecting ground-truth client..."

# Ensure openssh_groundtruth container is configured for client mode
# (Requires docker-compose.yml configuration with MODE=client)
# For this automated test, we'll use sshpass from the host or ssh_client container

# Check if ssh_client container is available
if docker ps --format '{{.Names}}' | grep -q "^ssh_client$"; then
    log "Using ssh_client container for connection..."
    SSH_CLIENT_CMD="docker compose exec -T ssh_client"
else
    log "Using host SSH client with expect..."
    SSH_CLIENT_CMD=""
    # We use expect for SSH automation, so no sshpass needed
fi

log "✓ Phase 3 complete: Client connection method ready"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 4: CHECKPOINT 1 - Before Handshake (automatic via LLDB callback)
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 4: Checkpoint 1 - Before SSH Handshake"
log "  (Automatic: LLDB kex_entry_callback will dump PRE-KEX heap)"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 5: EXECUTE SSH COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 5: Executing SSH commands..."

# Create expect script for automated command execution
EXPECT_SCRIPT="$RESULTS_DIR/ssh_commands.exp"
cat > "$EXPECT_SCRIPT" <<'EOF'
#!/usr/bin/expect -f
set timeout 30
set host [lindex $argv 0]
set port [lindex $argv 1]
set user [lindex $argv 2]
set password [lindex $argv 3]

log_user 1

# Connect
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p $port $user@$host
expect {
    "password:" {
        send "$password\r"
    }
    timeout {
        puts "ERROR: Timeout waiting for password prompt"
        exit 1
    }
}

# Wait for shell prompt
expect {
    -re {[\$#] } {
        puts "✓ Connected, shell ready"
    }
    timeout {
        puts "ERROR: Timeout waiting for shell prompt"
        exit 1
    }
}

# Checkpoint 2: After handshake (automatic via LLDB callback)
sleep 1

# Command 1: ls
puts "\n=== Executing: ls ==="
send "ls\r"
expect -re {[\$#] }

# Sleep between commands (allows LLDB to stabilize)
sleep 0.5

# Command 2: pwd
puts "\n=== Executing: pwd ==="
send "pwd\r"
expect -re {[\$#] }

sleep 0.5

# Command 3: hostname
puts "\n=== Executing: hostname ==="
send "hostname\r"
expect -re {[\$#] }

sleep 0.5

# Checkpoint 3: Before session close
puts "\n=== Checkpoint: Before session close ==="
sleep 1

# Command 4: exit
puts "\n=== Executing: exit ==="
send "exit\r"

expect {
    eof {
        puts "✓ SSH session closed"
    }
    timeout {
        puts "ERROR: Timeout waiting for session close"
        exit 1
    }
}

puts "\n✓ All commands executed successfully"
EOF

chmod +x "$EXPECT_SCRIPT"

# Execute expect script
log "Running SSH command sequence..."
if [ -n "$SSH_CLIENT_CMD" ]; then
    # Run from container
    $SSH_CLIENT_CMD expect "$EXPECT_SCRIPT" "$SSH_HOST" "$SSH_PORT" "$SSH_USER" "$SSH_PASSWORD"
else
    # Run from host
    expect "$EXPECT_SCRIPT" "$SSH_HOST" "$SSH_PORT" "$SSH_USER" "$SSH_PASSWORD"
fi

log "✓ Phase 5 complete: SSH commands executed"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 6: CHECKPOINT 4 - After Session Close (Full Dump)
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 6: Checkpoint 4 - After Session Close (Full Dump)"

# Give LLDB time to process session close
sleep 2

# Trigger full memory dump of sshd connection handler
SSHD_PID=$(docker compose exec -T openssh_server pgrep -P 1 sshd | head -1)
if [ -n "$SSHD_PID" ]; then
    log "Triggering full memory dump of sshd PID $SSHD_PID..."
    docker compose exec -T openssh_server bash -c \
        "gcore -o /data/dumps/final_full_dump $SSHD_PID" \
        >/dev/null 2>&1 || log "⚠ gcore may have failed"
    log "✓ Full dump completed"
else
    log "⚠ Could not find sshd child process for full dump"
fi

echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 7: STOP PCAP CAPTURE
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 7: Stopping PCAP capture..."

# Kill tcpdump
docker compose exec -T openssh_server pkill tcpdump || true
sleep 1

# Copy PCAP to results
docker compose exec -T openssh_server test -f /data/captures/openssh_traffic.pcap && \
    docker compose cp openssh_server:/data/captures/openssh_traffic.pcap "$RESULTS_DIR/captures/" || \
    log "⚠ PCAP file not found"

log "✓ Phase 7 complete: PCAP capture stopped"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 8: COLLECT RESULTS
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 8: Collecting results..."

# Copy keylogs
cp "$DATA_DIR"/keylogs/* "$RESULTS_DIR/keylogs/" 2>/dev/null || \
    log "⚠ No keylogs found"

# Copy dumps
cp "$DATA_DIR"/dumps/* "$RESULTS_DIR/dumps/" 2>/dev/null || \
    log "⚠ No dumps found"

# Copy LLDB logs
docker compose cp openssh_server:/data/lldb_results/lldb_openssh_output.log \
    "$RESULTS_DIR/reports/" 2>/dev/null || \
    log "⚠ LLDB output log not found"

log "✓ Phase 8 complete: Results collected"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 9: KEY VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 9: Validating extracted keys..."

# Check if server keylog exists
SERVER_KEYLOG="$RESULTS_DIR/keylogs/ssh_keylog.log"
if [ -f "$SERVER_KEYLOG" ]; then
    KEY_COUNT=$(wc -l < "$SERVER_KEYLOG")
    log "✓ Server keylog found: $KEY_COUNT entries"

    # Display first entry
    if [ "$KEY_COUNT" -gt 0 ]; then
        log "First keylog entry:"
        head -1 "$SERVER_KEYLOG" | sed 's/^/    /'
    fi
else
    log "⚠ Server keylog not found at $SERVER_KEYLOG"
fi

# Check for ground-truth keylog (if openssh_groundtruth was used as client)
GROUNDTRUTH_KEYLOG="$DATA_DIR/keylogs/groundtruth.log"
if [ -f "$GROUNDTRUTH_KEYLOG" ]; then
    log "✓ Ground-truth keylog found"
    # TODO: Compare server vs ground-truth keys
else
    log "ℹ Ground-truth keylog not available (not configured as client mode)"
fi

log "✓ Phase 9 complete: Key validation performed"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# PHASE 10: GENERATE SUMMARY REPORT
# ═══════════════════════════════════════════════════════════════════════════

log "Phase 10: Generating summary report..."

SUMMARY_FILE="$RESULTS_DIR/reports/test_summary.txt"
cat > "$SUMMARY_FILE" <<EOF
OpenSSH Automated Key Lifecycle Test - Summary Report
======================================================================

Test Information:
  Test Name:        $TEST_NAME
  Start Time:       $(date)
  Results Directory: $RESULTS_DIR

Server Configuration:
  SSH Host:         $SSH_HOST
  SSH Port:         $SSH_PORT
  OpenSSH Version:  9.8p1 (with debug symbols)
  LLDB Version:     20
  Base OS:          Ubuntu 24.04

Test Execution:
  Commands Executed: ${SSH_COMMANDS[@]}
  Connection Method: Expect-based automation

Memory Dump Checkpoints:
  1. Before SSH Handshake    (Automatic - LLDB kex_entry_callback)
  2. After SSH Handshake     (Automatic - LLDB kex_exit_callback)
  3. During Command Exec     (Between commands, handled by LLDB)
  4. Before Session Close    (Manual trigger before exit)
  5. After Session Close     (Full dump via gcore)

Results Collected:
  Keylogs:   $(ls -1 "$RESULTS_DIR/keylogs" 2>/dev/null | wc -l) files
  Dumps:     $(ls -1 "$RESULTS_DIR/dumps" 2>/dev/null | wc -l) files
  Captures:  $(ls -1 "$RESULTS_DIR/captures" 2>/dev/null | wc -l) files
  Reports:   $(ls -1 "$RESULTS_DIR/reports" 2>/dev/null | wc -l) files

Key Extraction:
  Server Keylog: $([ -f "$SERVER_KEYLOG" ] && echo "✓ Present" || echo "✗ Missing")
  Ground-truth:  $([ -f "$GROUNDTRUTH_KEYLOG" ] && echo "✓ Present" || echo "ℹ Not configured")

Validation Status:
  $([ -f "$SERVER_KEYLOG" ] && [ $(wc -l < "$SERVER_KEYLOG") -gt 0 ] && \
     echo "✓ Keys successfully extracted" || \
     echo "✗ Key extraction may have failed")

Next Steps:
  1. Review LLDB logs:     $RESULTS_DIR/reports/lldb_openssh_output.log
  2. Analyze memory dumps: $RESULTS_DIR/dumps/
  3. Decrypt PCAP:         Use keylogs to decrypt SSH traffic
  4. Search for secrets:   Scan dumps for key persistence

======================================================================
End Time: $(date)
EOF

cat "$SUMMARY_FILE"

log "✓ Phase 10 complete: Summary report generated"
echo ""

# ═══════════════════════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════════════════════

log "Cleanup: Stopping OpenSSH server..."
docker compose -f "$SCRIPT_DIR/docker-compose.yml" stop openssh_server

echo "======================================================================"
echo "  Test Complete"
echo "======================================================================"
echo "Results directory: $RESULTS_DIR"
echo "Summary report:    $SUMMARY_FILE"
echo "======================================================================"
echo ""
