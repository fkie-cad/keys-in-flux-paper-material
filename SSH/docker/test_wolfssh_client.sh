#!/bin/bash
set -e

echo "========================================================================"
echo "  wolfSSH Client-Side Monitoring Test"
echo "========================================================================"
echo ""
echo "This test will:"
echo "  1. Start openssh_groundtruth server"
echo "  2. Run wolfssh_client under LLDB monitoring"
echo "  3. Extract client-side KEX keys using DoNewKeys discovery"
echo "  4. Leverage findings from wolfSSH investigation"
echo ""
echo "========================================================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Clean up old data
echo "[TEST] Cleaning up old keylogs and dumps..."
rm -f data/keylogs/wolfssh_client_keylog.log
rm -f data/keylogs/groundtruth.log
rm -rf data/dumps/*
rm -rf data/lldb_results/*

echo "[TEST] Starting openssh_groundtruth server..."
docker compose up -d openssh_groundtruth

# Wait for server to be ready
echo "[TEST] Waiting for server to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    # Check if SSH port is open using netcat from host
    if nc -z localhost 2226 2>/dev/null; then
        echo -e "${GREEN}[TEST] ✓ Server is ready!${NC}"
        break
    fi
    attempt=$((attempt + 1))
    echo "[TEST] Attempt $attempt/$max_attempts..."
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo -e "${RED}[TEST] ✗ Server failed to start${NC}"
    docker compose logs openssh_groundtruth --tail 20
    exit 1
fi

# Give server a moment to fully initialize
sleep 2

echo ""
echo "[TEST] Running wolfSSH client with LLDB monitoring..."
echo "[TEST] This leverages the DoNewKeys discovery from investigation..."
echo ""

# Run the client (will exit after SSH session completes)
docker compose --profile client-testing run --rm wolfssh_client

echo ""
echo "========================================================================"
echo "  Test Results"
echo "========================================================================"
echo ""

# Check if keylog was created
if [ -f data/keylogs/wolfssh_client_keylog.log ]; then
    echo -e "${GREEN}[TEST] ✓ Client keylog created${NC}"
    echo "[TEST] Client keylog contents:"
    cat data/keylogs/wolfssh_client_keylog.log
    echo ""
else
    echo -e "${YELLOW}[TEST] ⚠️  Client keylog NOT created${NC}"
    echo "[TEST] Key extraction may have failed"
    echo "[TEST] Note: DoNewKeys is a static function - may need pattern matching"
fi

# Check if groundtruth keylog exists
if [ -f data/keylogs/groundtruth.log ]; then
    echo -e "${GREEN}[TEST] ✓ Server groundtruth keylog created${NC}"
    echo "[TEST] Server keylog contents:"
    cat data/keylogs/groundtruth.log
    echo ""
else
    echo -e "${YELLOW}[TEST] ⚠️  Server groundtruth keylog not found${NC}"
fi

# Check LLDB results
if [ -d data/lldb_results ] && [ "$(ls -A data/lldb_results)" ]; then
    echo -e "${GREEN}[TEST] ✓ LLDB results directory has content${NC}"
    echo "[TEST] LLDB result files:"
    ls -lh data/lldb_results/
    echo ""
else
    echo -e "${YELLOW}[TEST] ⚠️  No LLDB results found${NC}"
fi

# Check memory dumps
if [ -d data/dumps ] && [ "$(ls -A data/dumps)" ]; then
    echo -e "${GREEN}[TEST] ✓ Memory dumps created${NC}"
    echo "[TEST] Dump files:"
    ls -lh data/dumps/ | head -10
    echo ""
else
    echo -e "${YELLOW}[TEST] ⚠️  No memory dumps found${NC}"
fi

echo "========================================================================"
echo "  Important Notes - wolfSSH DoNewKeys Discovery"
echo "========================================================================"
echo ""
echo "From wolfSSH investigation:"
echo "  ✓ DoNewKeys fires successfully at KEX #4"
echo "  ✓ ForceZero active (50+ memory dumps in server investigation)"
echo "  ⚠️  DoNewKeys is a STATIC function (lowercase 't' in nm)"
echo ""
echo "LLDB may have difficulty setting breakpoints on static functions by name."
echo "If DoNewKeys breakpoint fails, key extraction will not work."
echo ""
echo "Alternative approaches:"
echo "  1. Pattern matching (bytecode signature)"
echo "  2. Source code injection (like openssh_groundtruth)"
echo "  3. LD_PRELOAD hooking"
echo ""

echo "========================================================================"
echo "  Cleanup"
echo "========================================================================"
echo ""

# Stop server
echo "[TEST] Stopping openssh_groundtruth server..."
docker compose stop openssh_groundtruth

echo ""
echo "[TEST] Test complete!"
echo ""
echo "To re-run this test: ./test_wolfssh_client.sh"
echo "To manually inspect: docker compose run --rm wolfssh_client"
echo ""
echo ""
