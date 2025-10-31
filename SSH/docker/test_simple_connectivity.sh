#!/bin/bash
# Simple connectivity test for all 4 SSH servers

echo "=== Testing SSH Server Connectivity ==="
echo ""

# Test OpenSSH
echo "[1/4] Testing openssh_server:22..."
docker compose run --rm openssh_groundtruth \
  bash -c 'sshpass -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 testuser@openssh_server "echo OpenSSH OK"' 2>&1 | grep -E "(OK|failed|refused)"

# Test Dropbear
echo "[2/4] Testing dropbear_server:22..."
docker compose run --rm openssh_groundtruth \
  bash -c 'sshpass -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 testuser@dropbear_server "echo Dropbear OK"' 2>&1 | grep -E "(OK|failed|refused)"

# Test wolfSSH
echo "[3/4] Testing wolfssh_server:22..."
docker compose run --rm openssh_groundtruth \
  bash -c 'sshpass -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 testuser@wolfssh_server "echo wolfSSH OK"' 2>&1 | grep -E "(OK|failed|refused)"

# Test Paramiko
echo "[4/4] Testing paramiko_server:22..."
docker compose run --rm openssh_groundtruth \
  bash -c 'sshpass -p password ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 testuser@paramiko_server "echo Paramiko OK"' 2>&1 | grep -E "(OK|failed|refused)"

echo ""
echo "=== Connectivity Test Complete ==="
