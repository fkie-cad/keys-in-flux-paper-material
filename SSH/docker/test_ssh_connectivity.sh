set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "SSH Connectivity Verification Suite"
echo "=========================================="
echo ""

# Test counter
PASS=0
FAIL=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        ((PASS++))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        ((FAIL++))
    fi
}

# Test 1: Container status
echo "TEST 1: Container Status"
docker compose ps | grep -q "Up"
test_result $? "Containers are running"
echo ""

# Test 2: Network connectivity
echo "TEST 2: Network Connectivity"
docker compose exec -T ssh_client ping -c 1 -W 2 dropbear_server > /dev/null 2>&1
test_result $? "Ping dropbear_server"

docker compose exec -T ssh_client ping -c 1 -W 2 wolfssh_server > /dev/null 2>&1
test_result $? "Ping wolfssh_server"

docker compose exec -T ssh_client ping -c 1 -W 2 openssh_server > /dev/null 2>&1
test_result $? "Ping openssh_server"


docker compose exec -T ssh_client ping -c 1 -W 2 paramiko_server > /dev/null 2>&1
test_result $? "Ping paramiko_server"
echo ""

# Test 3: SSH port listening
echo "TEST 3: SSH Ports Listening"
docker compose exec -T ssh_client timeout 3 nc -zv dropbear_server 22 > /dev/null 2>&1
test_result $? "Dropbear port 22 open"

docker compose exec -T ssh_client timeout 3 nc -zv wolfssh_server 22 > /dev/null 2>&1
test_result $? "wolfSSH port 22 open"

docker compose exec -T ssh_client timeout 3 nc -zv openssh_server 22 > /dev/null 2>&1
test_result $? "OpenSSH port 22 open"

docker compose exec -T ssh_client timeout 3 nc -zv paramiko_server 2222 > /dev/null 2>&1
test_result $? "Paramiko port 2222 open"
echo ""

# Test 4: SSH authentication
echo "TEST 4: SSH Authentication"
docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  testuser@dropbear_server "echo test" > /dev/null 2>&1
test_result $? "Dropbear authentication"

docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  testuser@openssh_server "echo test" > /dev/null 2>&1
test_result $? "OpenSSH authentication"

docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  testuser@wolfssh_server "echo test" > /dev/null 2>&1
test_result $? "wolfSSH authentication"

docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  -p 2222 testuser@paramiko_server "echo test" > /dev/null 2>&1
test_result $? "Paramiko authentication"
echo ""

# Test 5: Command execution
 echo "TEST 5: Command Execution"
RESULT=$(docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  testuser@dropbear_server "echo 'Hello World'" 2>/dev/null)
if [ "$RESULT" = "Hello World" ]; then
    test_result 0 "Command execution and output"
else
    test_result 1 "Command execution (got: '$RESULT')"
fi
echo ""

# Test 6: Data transfer
echo "TEST 6: Data Transfer"
BYTES=$(docker compose exec -T ssh_client timeout 10 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  testuser@dropbear_server "dd if=/dev/zero bs=1M count=1 2>/dev/null | wc -c" 2>/dev/null)
if [ "$BYTES" = "1048576" ]; then
    test_result 0 "Large data transfer (1 MB)"
else
    test_result 1 "Large data transfer (got $BYTES bytes)"
fi
echo ""

# Test 7: Session duration
echo "TEST 7: Session Duration"
START=$(date +%s)
docker compose exec -T ssh_client timeout 15 sshpass -p password ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ServerAliveInterval=5 \
  testuser@dropbear_server "sleep 10" > /dev/null 2>&1
END=$(date +%s)
DURATION=$((END - START))
if [ $DURATION -ge 10 ] && [ $DURATION -le 12 ]; then
    test_result 0 "Long session (${DURATION}s)"
else
    test_result 1 "Long session (expected ~10s, got ${DURATION}s)"
fi
echo ""

# Test 8: Wrong password
echo "TEST 8: Authentication Rejection"
docker compose exec -T ssh_client timeout 10 sshpass -p wrongpassword ssh \
  -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  -o ConnectTimeout=5 \
  testuser@dropbear_server "echo test" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    test_result 0 "Wrong password rejected"
else
    test_result 1 "Wrong password (should have failed)"
fi
echo ""

# Summary
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "${GREEN}Passed: $PASS${NC}"
echo -e "${RED}Failed: $FAIL${NC}"
echo "Total:  $((PASS + FAIL))"
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! SSH connectivity is working correctly.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Check the output above.${NC}"
    exit 1
fi
