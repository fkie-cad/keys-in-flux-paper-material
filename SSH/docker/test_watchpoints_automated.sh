#!/bin/bash
# Automated watchpoint test for Dropbear
# Captures all LLDB output to log file for analysis

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/data/watchpoint_test_logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$LOG_DIR/test_${TIMESTAMP}.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${BLUE}[INFO]${NC} $1" | tee -a "$LOG_FILE"
}

echo_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" | tee -a "$LOG_FILE"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1" | tee -a "$LOG_FILE"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" | tee -a "$LOG_FILE"
}

# Create log directory
mkdir -p "$LOG_DIR"

echo_info "=========================================="
echo_info "Dropbear Watchpoint Automated Test"
echo_info "Timestamp: $TIMESTAMP"
echo_info "Log file: $LOG_FILE"
echo_info "=========================================="

# Step 1: Ensure container is running
echo_info "Step 1: Checking Dropbear container status..."
if ! docker ps | grep -q dropbear_server; then
    echo_info "Container not running, starting..."
    docker compose up -d dropbear_server >> "$LOG_FILE" 2>&1
    sleep 2
fi

CONTAINER_ID=$(docker ps | grep dropbear_server | awk '{print $1}')
echo_success "Container running: $CONTAINER_ID"

# Step 2: Copy test scripts into container
echo_info "Step 2: Copying test scripts to container..."
docker cp lldb/dropbear_test_minimal.py dropbear_server:/opt/lldb/ >> "$LOG_FILE" 2>&1
docker cp lldb/dropbear_test_option_c.py dropbear_server:/opt/lldb/ >> "$LOG_FILE" 2>&1
echo_success "Scripts copied"

# Step 3: Get Dropbear PID
echo_info "Step 3: Finding Dropbear parent process..."
DROPBEAR_PID=$(docker compose exec -T dropbear_server pgrep -x dropbear | head -1 | tr -d '\r')
if [ -z "$DROPBEAR_PID" ]; then
    echo_error "Could not find Dropbear process"
    exit 1
fi
echo_success "Dropbear PID: $DROPBEAR_PID"

# Step 4: Create LLDB command script
echo_info "Step 4: Creating LLDB command script..."
LLDB_SCRIPT="/tmp/lldb_test_${TIMESTAMP}.txt"
cat > "$LLDB_SCRIPT" << 'LLDB_EOF'
# LLDB commands for automated test
process attach --pid DROPBEAR_PID_PLACEHOLDER
settings set target.process.follow-fork-mode child
settings set target.process.stop-on-exec false
settings set stop-line-count-before 3
settings set stop-line-count-after 3
command script import /opt/lldb/dropbear_test_minimal.py
continue
LLDB_EOF

# Replace PID placeholder
sed "s/DROPBEAR_PID_PLACEHOLDER/$DROPBEAR_PID/" "$LLDB_SCRIPT" > "${LLDB_SCRIPT}.tmp"
mv "${LLDB_SCRIPT}.tmp" "$LLDB_SCRIPT"

echo_success "LLDB script created: $LLDB_SCRIPT"

# Step 5: Start LLDB in background with full logging
echo_info "Step 5: Starting LLDB monitoring in background..."
LLDB_LOG="/tmp/lldb_output_${TIMESTAMP}.log"

# Copy LLDB script into container
docker cp "$LLDB_SCRIPT" dropbear_server:/tmp/lldb_commands.txt >> "$LOG_FILE" 2>&1

# Start LLDB in background
docker compose exec -T dropbear_server bash -c "lldb -s /tmp/lldb_commands.txt > $LLDB_LOG 2>&1 &"
sleep 3

echo_success "LLDB started, output logging to container:$LLDB_LOG"

# Step 6: Make SSH connection to trigger KEX
echo_info "Step 6: Making SSH connection to trigger KEX..."
echo_info "Waiting 2 seconds for LLDB to attach..."
sleep 2

# SSH connection with timeout
echo_info "Connecting via SSH..."
{
    timeout 10 sshpass -p password ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -p 2223 \
        testuser@localhost \
        "echo 'SSH connection successful'; hostname; exit" >> "$LOG_FILE" 2>&1 && \
        echo_success "SSH connection completed successfully"
} || {
    echo_warn "SSH connection timed out or failed (this may be expected if watchpoint stopped execution)"
}

# Step 7: Wait for watchpoint event
echo_info "Step 7: Waiting 3 seconds for watchpoint events..."
sleep 3

# Step 8: Copy LLDB output from container
echo_info "Step 8: Retrieving LLDB output from container..."
docker cp dropbear_server:$LLDB_LOG "$LOG_DIR/lldb_full_output_${TIMESTAMP}.log" >> "$LOG_FILE" 2>&1

# Also get current LLDB results if any
docker cp dropbear_server:/data/lldb_results/ "$LOG_DIR/lldb_results_${TIMESTAMP}/" >> "$LOG_FILE" 2>&1 || true

echo_success "LLDB output saved to: $LOG_DIR/lldb_full_output_${TIMESTAMP}.log"

# Step 9: Analyze results
echo_info "=========================================="
echo_info "Step 9: Analyzing Results"
echo_info "=========================================="

LLDB_OUTPUT="$LOG_DIR/lldb_full_output_${TIMESTAMP}.log"

if [ ! -f "$LLDB_OUTPUT" ]; then
    echo_error "LLDB output file not found"
    exit 1
fi

# Check for key indicators
echo ""
echo_info "Searching for key events in LLDB output..."

if grep -q "WATCHPOINT] Set on trans_cipher_key" "$LLDB_OUTPUT"; then
    echo_success "✓ Watchpoint was SET successfully"
    WP_ADDR=$(grep "WATCHPOINT] Set on trans_cipher_key" "$LLDB_OUTPUT" | grep -oE '0x[0-9a-f]+' | head -1)
    echo_info "  Address: $WP_ADDR"
else
    echo_error "✗ Watchpoint was NOT set"
fi

if grep -q "WATCHPOINT HIT" "$LLDB_OUTPUT"; then
    echo_success "✓ Watchpoint HIT detected!"
    grep "WATCHPOINT HIT" "$LLDB_OUTPUT" | while read -r line; do
        echo_info "  $line"
    done
else
    echo_warn "✗ Watchpoint never fired (or callback didn't execute)"
fi

if grep -q "stop reason = trace" "$LLDB_OUTPUT"; then
    echo_error "✗ Process entered trace mode (watchpoint callback issue)"
    echo_info "  This means watchpoint fired but process didn't continue properly"
fi

if grep -q "KEY_EXTRACT_SUCCESS" "$LLDB_OUTPUT"; then
    echo_success "✓ Key extraction successful"
    KEY_PREVIEW=$(grep "KEY_EXTRACT_SUCCESS" "$LLDB_OUTPUT" | grep -oE '[0-9a-f]{32,}' | head -1)
    echo_info "  Key preview: ${KEY_PREVIEW:0:32}..."
fi

if grep -q "FORK] fork()" "$LLDB_OUTPUT"; then
    echo_success "✓ Fork detection working"
fi

# Step 10: Print summary
echo ""
echo_info "=========================================="
echo_info "Test Summary"
echo_info "=========================================="
echo_info "Full logs available at:"
echo_info "  - Main log:  $LOG_FILE"
echo_info "  - LLDB log:  $LLDB_OUTPUT"
echo_info "  - Results:   $LOG_DIR/lldb_results_${TIMESTAMP}/"
echo ""

# Print last 50 lines of LLDB output
echo_info "Last 50 lines of LLDB output:"
echo_info "----------------------------------------"
tail -50 "$LLDB_OUTPUT" | tee -a "$LOG_FILE"
echo_info "----------------------------------------"

echo ""
echo_info "Test completed at $(date)"

# Cleanup
rm -f "$LLDB_SCRIPT"

# Return status based on watchpoint hit
if grep -q "WATCHPOINT HIT" "$LLDB_OUTPUT"; then
    echo_success "=========================================="
    echo_success "WATCHPOINT TEST: PASSED"
    echo_success "=========================================="
    exit 0
else
    echo_error "=========================================="
    echo_error "WATCHPOINT TEST: INCONCLUSIVE"
    echo_error "Check logs for details"
    echo_error "=========================================="
    exit 1
fi
