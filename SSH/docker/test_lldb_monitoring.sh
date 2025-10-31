#!/bin/bash
# Test LLDB key lifecycle monitoring
# This script demonstrates the complete key lifecycle: derivation → usage → destruction

set -e

echo "======================================================================"
echo "  SSH LLDB Key Lifecycle Monitoring Test"
echo "======================================================================"
echo ""

# Start LLDB-monitored OpenSSH server
echo "[1/5] Starting LLDB-monitored OpenSSH server..."
docker compose up -d openssh_lldb
sleep 3

# Check if server started
if ! docker compose ps | grep openssh_lldb | grep -q "Up"; then
    echo "❌ ERROR: openssh_lldb container failed to start"
    docker compose logs openssh_lldb | tail -20
    exit 1
fi

echo "✅ openssh_lldb started on port 2227"
echo ""

# Connect from openssh_groundtruth client to trigger key derivation
echo "[2/5] Connecting to LLDB-monitored server to trigger key derivation..."
docker compose run --rm \
  -e MODE=client \
  -e HOST=openssh_lldb \
  -e PORT=22 \
  -e USER=testuser \
  -e PASSWORD=password \
  -e SSH_CMD="echo 'LLDB test successful' && hostname && sleep 2" \
  -e SSHKEYLOGFILE=/data/keylogs/lldb_test.log \
  openssh_groundtruth

echo ""
echo "[3/5] SSH connection completed"
echo ""

# Give LLDB time to process events
sleep 2

# Check LLDB results
echo "[4/5] Checking LLDB monitoring results..."
echo ""

if [ -f "data/lldb_results/timing_openssh.csv" ]; then
    echo "✅ Timing data file created"
    echo "--- CSV Contents ---"
    cat data/lldb_results/timing_openssh.csv
    echo ""
else
    echo "⚠️  No timing data file found (LLDB may need symbol information)"
fi

if [ -f "data/lldb_results/events_openssh.log" ]; then
    echo "✅ Event log file created"
    echo "--- Recent Events ---"
    tail -20 data/lldb_results/events_openssh.log
    echo ""
else
    echo "⚠️  No event log found"
fi

echo "[5/5] LLDB container logs:"
echo "--- Container Logs (last 30 lines) ---"
docker compose logs openssh_lldb | tail -30
echo ""

echo "======================================================================"
echo "  Test Complete"
echo "======================================================================"
echo ""
echo "LLDB monitoring results:"
echo "  Location: data/lldb_results/"
echo "  Files:"
echo "    - timing_openssh.csv   : Key lifecycle timing"
echo "    - events_openssh.log   : Human-readable events"
echo "    - events_openssh.jsonl : Machine-readable events"
echo ""
echo "Next steps:"
echo "  1. Analyze timing data: python3 analyze_lldb_timing.py"
echo "  2. Compare with PCAP:   python3 correlate_pcap.py"
echo "  3. Visualize lifecycle: python3 visualize_lifecycle.py"
echo ""
echo "To stop the LLDB server:"
echo "  docker compose stop openssh_lldb"
