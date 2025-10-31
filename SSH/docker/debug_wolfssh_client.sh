#!/bin/bash
#
# wolfSSH Client Debug Script
# Systematically tests wolfSSH client connectivity and authentication
#

set +e  # Don't exit on errors - we want to see all test results

echo "========================================================================"
echo "  wolfSSH Client Debug Script"
echo "========================================================================"
echo ""
echo "This script tests wolfSSH client connectivity with different:"
echo "  - Target servers (OpenSSH vs wolfSSH)"
echo "  - Authentication methods (password, publickey)"
echo "  - Connection modes (with/without LLDB)"
echo ""
echo "========================================================================"
echo ""

# Configuration
OPENSSH_HOST="openssh_groundtruth"
OPENSSH_PORT="22"
WOLFSSH_HOST="localhost"
WOLFSSH_PORT="2224"
USER="testuser"
PASS="password"
TIMEOUT=10

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_test() {
    echo ""
    echo "========================================================================"
    echo -e "${BLUE}TEST: $1${NC}"
    echo "========================================================================"
}

print_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✓ SUCCESS${NC}: $2"
    else
        echo -e "${RED}✗ FAILED${NC}: $2 (exit code: $1)"
    fi
}

# Ensure ground-truth server is running
echo "Starting openssh_groundtruth server..."
docker compose up -d openssh_groundtruth
sleep 3

# =============================================================================
# TEST 1: Verify wolfSSH binary exists and is correct type
# =============================================================================
print_test "1. Verify wolfSSH Client Binary"

docker compose run --rm wolfssh_client bash -c "
    echo 'Binary path: /usr/local/bin/wolfssh-client'
    file /usr/local/bin/wolfssh-client
    echo ''
    echo 'Binary size:'
    ls -lh /usr/local/bin/wolfssh-client
    echo ''
    echo 'Symbols available:'
    nm /usr/local/bin/wolfssh-client | grep -i 'wolfSSH_KDF\|DoNewKeys' | head -5
"

# =============================================================================
# TEST 2: wolfSSH Client Help/Version
# =============================================================================
print_test "2. wolfSSH Client Help Output"

docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    wolfssh-client -?
" 2>&1 | head -20

# =============================================================================
# TEST 3: Test OpenSSH Ground-Truth Server (Baseline)
# =============================================================================
print_test "3. Baseline: Standard SSH Client to OpenSSH Server"

timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    sshpass -p '${PASS}' ssh -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -p ${OPENSSH_PORT} ${USER}@${OPENSSH_HOST} \
        'echo \"Connection successful from standard SSH client\"'
" 2>&1
print_result $? "Standard SSH client → OpenSSH server"

# =============================================================================
# TEST 4: wolfSSH Client to OpenSSH Server (Password - Interactive)
# =============================================================================
print_test "4. wolfSSH Client → OpenSSH Server (Password via stdin)"

timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    echo '${PASS}' | wolfssh-client -u ${USER} -h ${OPENSSH_HOST} -p ${OPENSSH_PORT}
" 2>&1 | tee /tmp/wolfssh_test4.log | tail -30
result4=$?
print_result $result4 "wolfSSH client → OpenSSH server (stdin password)"

# =============================================================================
# TEST 5: wolfSSH Client to OpenSSH Server (Password via -P flag)
# =============================================================================
print_test "5. wolfSSH Client → OpenSSH Server (Password via -P flag)"

timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    wolfssh-client -u ${USER} -h ${OPENSSH_HOST} -p ${OPENSSH_PORT} -P '${PASS}'
" 2>&1 | tee /tmp/wolfssh_test5.log | tail -30
result5=$?
print_result $result5 "wolfSSH client → OpenSSH server (-P flag)"

# =============================================================================
# TEST 6: Start wolfSSH Server and Test Client Connection
# =============================================================================
print_test "6. wolfSSH Client → wolfSSH Server"

echo "Starting wolfSSH server..."
docker compose up -d wolfssh_server
sleep 3

echo "Testing connection from wolfSSH client to wolfSSH server..."
timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    wolfssh-client -u ${USER} -h wolfssh_server -p 22 -P '${PASS}'
" 2>&1 | tee /tmp/wolfssh_test6.log | tail -30
result6=$?
print_result $result6 "wolfSSH client → wolfSSH server"

# =============================================================================
# TEST 7: Check LLDB Availability in Container
# =============================================================================
print_test "7. LLDB Availability Check"

docker compose run --rm wolfssh_client bash -c "
    echo 'LLDB version:'
    lldb --version
    echo ''
    echo 'Python lldb module:'
    python3 -c 'import lldb; print(f\"lldb.SBDebugger available: {lldb.SBDebugger}\")'
"
print_result $? "LLDB and Python bindings"

# =============================================================================
# TEST 8: Minimal LLDB Test (No Breakpoints)
# =============================================================================
print_test "8. LLDB Launch Test (No Breakpoints)"

timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    echo 'Testing LLDB launch without breakpoints...'
    lldb -o 'file /usr/local/bin/wolfssh-client' \
         -o 'process launch -- -u ${USER} -h ${OPENSSH_HOST} -p ${OPENSSH_PORT} -P ${PASS}' \
         -o 'quit'
" 2>&1 | tail -40
print_result $? "LLDB launch (no breakpoints)"

# =============================================================================
# TEST 9: LLDB with Callback Script (Actual Test)
# =============================================================================
print_test "9. LLDB with wolfSSH_KDF Breakpoint"

timeout ${TIMEOUT} docker compose run --rm wolfssh_client bash -c "
    cd /build/wolfssh-1.4.20-stable
    echo 'Testing LLDB with breakpoint...'
    lldb -o 'command script import /opt/lldb/wolfssh_client_callbacks.py' \
         -o 'file /usr/local/bin/wolfssh-client' \
         -o 'wolfssh_setup_monitoring' \
         -o 'process launch -- -u ${USER} -h ${OPENSSH_HOST} -p ${OPENSSH_PORT} -P ${PASS}' \
         -o 'quit'
" 2>&1 | tee /tmp/wolfssh_test9.log | tail -50
print_result $? "LLDB with breakpoints"

# =============================================================================
# Analysis and Summary
# =============================================================================
echo ""
echo "========================================================================"
echo "  Test Summary"
echo "========================================================================"
echo ""

# Count successes
success_count=0
[ $result4 -eq 0 ] && ((success_count++))
[ $result5 -eq 0 ] && ((success_count++))
[ $result6 -eq 0 ] && ((success_count++))

echo "Tests passed: $success_count / 3"
echo ""

echo "========================================================================"
echo "  Detailed Analysis"
echo "========================================================================"
echo ""

if [ $result4 -eq 0 ] || [ $result5 -eq 0 ]; then
    echo -e "${GREEN}✓ wolfSSH client CAN connect to OpenSSH server${NC}"
    echo "  This means the authentication issue might be specific to LLDB monitoring"
elif [ $result6 -eq 0 ]; then
    echo -e "${YELLOW}⚠ wolfSSH client only works with wolfSSH server${NC}"
    echo "  Recommendation: Change docker-compose.yml to use wolfssh_server as target"
else
    echo -e "${RED}✗ wolfSSH client cannot authenticate with any server${NC}"
    echo "  This indicates a fundamental authentication configuration issue"
fi

echo ""
echo "========================================================================"
echo "  Debug Logs Location"
echo "========================================================================"
echo ""
echo "Test 4 (stdin password):    /tmp/wolfssh_test4.log"
echo "Test 5 (-P flag password):   /tmp/wolfssh_test5.log"
echo "Test 6 (wolfSSH server):     /tmp/wolfssh_test6.log"
echo "Test 9 (LLDB breakpoint):    /tmp/wolfssh_test9.log"
echo ""
echo "To view logs:"
echo "  cat /tmp/wolfssh_test5.log | grep -E 'DISCONNECT|USERAUTH|error'"
echo ""

echo "========================================================================"
echo "  Next Steps"
echo "========================================================================"
echo ""

if [ $result5 -eq 0 ]; then
    echo "1. ✓ Password authentication works without LLDB"
    echo "2. Check why LLDB monitoring causes auth failure (Test 9 log)"
    echo "3. Possible causes:"
    echo "   - LLDB interfering with password passing"
    echo "   - Timing issues (process exits before auth completes)"
    echo "   - Need to use stdin redirect instead of -P flag with LLDB"
elif [ $result6 -eq 0 ]; then
    echo "1. Switch docker-compose.yml target to wolfssh_server:"
    echo "   SSH_SERVER_HOST=wolfssh_server"
    echo "2. Rebuild and retest with LLDB monitoring"
else
    echo "1. Check wolfSSH client configuration"
    echo "2. Verify password authentication is enabled on server"
    echo "3. Try generating SSH keys for public key auth"
    echo "4. Check wolfSSH documentation for client requirements"
fi

echo ""
echo "========================================================================"
echo "  Debug Script Complete"
echo "========================================================================"
