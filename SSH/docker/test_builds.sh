#!/bin/bash
set -e

echo "=== Testing SSH Lab Container Builds ==="
echo ""

services="openssh_server dropbear_server wolfssh_server paramiko_server openssh_groundtruth ssh_client"

for svc in $services; do
    echo "[BUILD] $svc..."
    docker compose build $svc
    echo "[OK] $svc built successfully"
    echo ""
done

echo ""
echo "✅ All containers built successfully"
echo ""
echo "Next steps:"
echo "  1. Start servers: docker compose up -d"
echo "  2. Test connectivity: ./test_connectivity.sh"
echo "  3. Run experiments: python3 orchestrate_experiment.py --all"
