#!/bin/bash
# Test wolfSSH Debug Container
# Connects to debug container on port 2229 and analyzes verbose logs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo "  wolfSSH Debug Container Test"
echo "========================================================================"
echo ""
echo "This will:"
echo "  1. Build and start the debug container (port 2229)"
echo "  2. Connect via SSH to trigger KEX"
echo "  3. Analyze debug logs to identify KEX functions"
echo ""
echo "========================================================================"
echo ""

# Ensure data directory exists
mkdir -p data/debug_logs

# Build and start debug container
echo "Building debug container..."
docker compose build wolfssh_debug

echo ""
echo "Starting debug container..."
docker compose up -d wolfssh_debug

echo ""
echo "Waiting for server to start..."
sleep 5

# Get initial log file
LATEST_LOG=$(docker compose exec wolfssh_debug ls -t /data/debug_logs/*.log 2>/dev/null | head -1 || echo "")

if [ -z "$LATEST_LOG" ]; then
    echo "Waiting for log file to be created..."
    sleep 2
    LATEST_LOG=$(docker compose exec wolfssh_debug ls -t /data/debug_logs/*.log 2>/dev/null | head -1 || echo "")
fi

echo "Debug log: $LATEST_LOG"
echo ""

# Test connection with expect
echo "========================================================================"
echo "  Testing SSH Connection (Port 2229)"
echo "========================================================================"
echo ""

expect << 'EOF'
set timeout 15
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2229 testuser@localhost
expect {
    "password:" {
        send "password\r"
        expect {
            "$ " {
                send "hostname\r"
                expect "$ "
                send "exit\r"
                puts "\n✓ SSH connection successful!"
            }
            timeout { puts "\n✗ Shell prompt timeout" }
        }
    }
    timeout { puts "\n✗ Password prompt timeout" }
}
expect eof
EOF

echo ""
echo "========================================================================"
echo "  Analyzing Debug Logs"
echo "========================================================================"
echo ""

# Wait for logs to flush
sleep 2

# Find latest log file (in host volume)
HOST_LOG=$(ls -t data/debug_logs/*.log 2>/dev/null | head -1)

if [ -z "$HOST_LOG" ]; then
    echo "⚠️  No log file found in data/debug_logs/"
    echo ""
    echo "Checking container logs instead:"
    docker compose logs wolfssh_debug --tail 100
    exit 1
fi

echo "Analyzing: $HOST_LOG"
echo ""

# Search for KEX-related function calls
echo "=== KEX-Related Functions ==="
grep -i "kex\|derive\|generate.*key" "$HOST_LOG" | head -20 || echo "No KEX functions found"

echo ""
echo "=== Key Generation Functions ==="
grep -i "generatekey\|wolfSSH_KDF\|DeriveKey" "$HOST_LOG" | head -20 || echo "No key generation functions found"

echo ""
echo "=== All Function Calls (sample) ==="
grep -E "entering|leaving|calling" "$HOST_LOG" | head -30 || echo "No function trace found"

echo ""
echo "========================================================================"
echo "  Summary"
echo "========================================================================"
echo ""

# Count unique function names
echo "Unique functions mentioned:"
grep -oE "[a-zA-Z_][a-zA-Z0-9_]*\(" "$HOST_LOG" | sort -u | wc -l

echo ""
echo "Full debug log available at:"
echo "  $HOST_LOG"
echo ""
echo "To view entire log:"
echo "  less $HOST_LOG"
echo ""
echo "To search for specific function:"
echo "  grep -i 'function_name' $HOST_LOG"
echo ""
echo "To view live logs:"
echo "  docker compose logs -f wolfssh_debug"
echo ""
