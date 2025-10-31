#!/bin/bash
set -e

echo "=== Testing SSH Server Connectivity ==="
echo ""

# Ensure data directories exist
mkdir -p data/keylogs data/captures
chmod -R 777 data

# Start all servers
echo "[SETUP] Starting SSH servers..."
docker compose up -d openssh_server dropbear_server wolfssh_server paramiko_server
echo "[SETUP] Waiting for servers to be ready..."
sleep 5

# Define test matrix
declare -A servers=(
    ["openssh"]="openssh_server:22"
    ["dropbear"]="dropbear_server:22"
    ["wolfssh"]="wolfssh_server:22"
    ["paramiko"]="paramiko_server:22"
)

# Test each server
success_count=0
total_count=${#servers[@]}

for name in "${!servers[@]}"; do
    IFS=':' read -r host port <<< "${servers[$name]}"
    echo ""
    echo "[TEST] Connecting to $name ($host:$port)..."

    # Clean up previous test keylog
    rm -f data/keylogs/test_${name}.log

    # Run openssh_groundtruth as client
    if docker compose run --rm \
        -e MODE=client \
        -e HOST=$host \
        -e PORT=$port \
        -e USER=testuser \
        -e PASSWORD=password \
        -e SSH_CMD="echo 'SUCCESS: $name connection works' && hostname && pwd" \
        -e SSHKEYLOGFILE=/data/keylogs/test_${name}.log \
        -e CAPTURE_TRAFFIC=false \
        openssh_groundtruth > /tmp/test_${name}.log 2>&1; then

        # Check if test succeeded
        if grep -q "SUCCESS: $name connection works" /tmp/test_${name}.log; then
            echo "[OK] $name connection successful"

            # Check if keys were extracted
            if [ -f "data/keylogs/test_${name}.log" ] && [ -s "data/keylogs/test_${name}.log" ]; then
                key_count=$(grep -c "NEWKEYS" data/keylogs/test_${name}.log || echo "0")
                echo "[OK] Extracted $key_count key entries"
            else
                echo "[WARN] No keys extracted (keylog empty or missing)"
            fi

            ((success_count++))
        else
            echo "[FAIL] $name connection test did not return success message"
            echo "=== Output ==="
            cat /tmp/test_${name}.log
            echo "============="
        fi
    else
        echo "[FAIL] $name connection failed (command returned non-zero)"
        echo "=== Output ==="
        cat /tmp/test_${name}.log
        echo "============="
    fi
done

echo ""
echo "=== TEST SUMMARY ==="
echo "Successful: $success_count/$total_count"

if [ "$success_count" -eq "$total_count" ]; then
    echo "✅ All connectivity tests passed"
    echo ""
    echo "Next steps:"
    echo "  1. Run full experiment: python3 orchestrate_experiment.py --all"
    echo "  2. View keylogs: cat data/keylogs/test_*.log"
    exit 0
else
    echo "❌ Some connectivity tests failed"
    exit 1
fi
