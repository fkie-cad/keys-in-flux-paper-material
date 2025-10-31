#!/bin/bash
# extract_artifacts.sh - Extract binaries and libraries from SSH containers for analysis
# Usage: ./extract_artifacts.sh [container_name]

set -e

CONTAINER="${1:-openssh_server}"
OUTPUT_DIR="./artifacts/$(date +%Y%m%d_%H%M%S)"

echo "========================================="
echo "SSH Container Artifact Extractor"
echo "========================================="
echo "Container: $CONTAINER"
echo "Output: $OUTPUT_DIR"
echo ""

# Check if container is running
if ! docker compose ps --status running | grep -q "$CONTAINER"; then
    echo "ERROR: Container $CONTAINER is not running"
    echo "Start it with: docker compose up -d $CONTAINER"
    exit 1
fi

# Create output directories
mkdir -p "$OUTPUT_DIR"/{binaries,libraries,dumps,logs}

echo "[1/6] Extracting SSH daemon binary..."
docker compose cp "${CONTAINER}:/usr/sbin/sshd" "$OUTPUT_DIR/binaries/sshd"
if [ -f "$OUTPUT_DIR/binaries/sshd" ]; then
    echo "  ✓ Binary extracted: $(file "$OUTPUT_DIR/binaries/sshd" | cut -d: -f2-)"
    echo "  ✓ Symbols: $(nm "$OUTPUT_DIR/binaries/sshd" 2>/dev/null | grep -c 'T ' || echo '0') functions"

    # Check for key functions
    if nm "$OUTPUT_DIR/binaries/sshd" 2>/dev/null | grep -q "kex_derive_keys"; then
        KEX_ADDR=$(nm "$OUTPUT_DIR/binaries/sshd" 2>/dev/null | grep " T kex_derive_keys" | awk '{print $1}')
        echo "  ✓ kex_derive_keys found at: 0x${KEX_ADDR}"
    fi
else
    echo "  ✗ Failed to extract binary"
fi

echo ""
echo "[2/6] Extracting OpenSSL libraries..."

# Detect architecture
ARCH=$(docker compose exec -T "$CONTAINER" uname -m)
if [ "$ARCH" = "aarch64" ]; then
    LIB_PATH="aarch64-linux-gnu"
elif [ "$ARCH" = "x86_64" ]; then
    LIB_PATH="x86_64-linux-gnu"
else
    echo "  ⚠ Unknown architecture: $ARCH, using aarch64-linux-gnu"
    LIB_PATH="aarch64-linux-gnu"
fi

echo "  → Architecture: $ARCH"
echo "  → Library path: /usr/lib/$LIB_PATH"

# Copy libraries
for LIB in libssl.so.1.1 libcrypto.so.1.1; do
    FULL_PATH="/usr/lib/${LIB_PATH}/${LIB}"
    if docker compose exec -T "$CONTAINER" test -f "$FULL_PATH"; then
        docker compose cp "${CONTAINER}:${FULL_PATH}" "$OUTPUT_DIR/libraries/${LIB}" 2>/dev/null || true
        if [ -f "$OUTPUT_DIR/libraries/${LIB}" ]; then
            SIZE=$(ls -lh "$OUTPUT_DIR/libraries/${LIB}" | awk '{print $5}')
            echo "  ✓ $LIB (${SIZE})"
        fi
    else
        echo "  ✗ $LIB not found"
    fi
done

echo ""
echo "[3/6] Extracting recent memory dumps..."

# Get latest 20 dumps
DUMP_COUNT=$(docker compose exec -T "$CONTAINER" sh -c "ls /data/dumps/*.dump 2>/dev/null | wc -l" | tr -d '\r')
if [ "$DUMP_COUNT" -gt 0 ]; then
    echo "  → Found $DUMP_COUNT total dumps"

    # Create tar of latest dumps
    docker compose exec -T "$CONTAINER" sh -c \
        "cd /data/dumps && tar czf /tmp/latest_dumps.tar.gz \$(ls -t *.dump 2>/dev/null | head -20)" \
        2>/dev/null || true

    docker compose cp "${CONTAINER}:/tmp/latest_dumps.tar.gz" "$OUTPUT_DIR/dumps/" 2>/dev/null

    if [ -f "$OUTPUT_DIR/dumps/latest_dumps.tar.gz" ]; then
        cd "$OUTPUT_DIR/dumps" && tar xzf latest_dumps.tar.gz && rm latest_dumps.tar.gz
        EXTRACTED=$(ls *.dump 2>/dev/null | wc -l)
        echo "  ✓ Extracted $EXTRACTED dumps"

        # Show largest dumps (most likely to contain keys)
        echo "  → Largest dumps:"
        ls -lhS *.dump 2>/dev/null | head -5 | awk '{printf "    %s  %s\n", $5, $9}'
    else
        echo "  ✗ Failed to extract dumps"
    fi
else
    echo "  ⚠ No memory dumps found in container"
fi

echo ""
echo "[4/6] Extracting LLDB event logs..."

for LOG_FILE in events_openssh.log events_openssh.jsonl timing_openssh.csv; do
    if docker compose exec -T "$CONTAINER" test -f "/data/lldb_results/${LOG_FILE}"; then
        docker compose cp "${CONTAINER}:/data/lldb_results/${LOG_FILE}" "$OUTPUT_DIR/logs/" 2>/dev/null || true
        if [ -f "$OUTPUT_DIR/logs/${LOG_FILE}" ]; then
            SIZE=$(ls -lh "$OUTPUT_DIR/logs/${LOG_FILE}" | awk '{print $5}')
            LINES=$(wc -l < "$OUTPUT_DIR/logs/${LOG_FILE}" | tr -d ' ')
            echo "  ✓ $LOG_FILE (${SIZE}, ${LINES} lines)"
        fi
    else
        echo "  ✗ $LOG_FILE not found"
    fi
done

echo ""
echo "[5/6] Extracting keylog..."

if docker compose exec -T "$CONTAINER" test -f "/data/keylogs/ssh_keylog.log"; then
    docker compose cp "${CONTAINER}:/data/keylogs/ssh_keylog.log" "$OUTPUT_DIR/logs/" 2>/dev/null || true
    if [ -f "$OUTPUT_DIR/logs/ssh_keylog.log" ]; then
        SIZE=$(ls -lh "$OUTPUT_DIR/logs/ssh_keylog.log" | awk '{print $5}')
        LINES=$(wc -l < "$OUTPUT_DIR/logs/ssh_keylog.log" | tr -d ' ')
        echo "  ✓ ssh_keylog.log (${SIZE}, ${LINES} entries)"
    fi
else
    echo "  ⚠ ssh_keylog.log not found (KEX not captured)"
fi

echo ""
echo "[6/6] Creating metadata file..."

cat > "$OUTPUT_DIR/metadata.txt" << EOF
Artifact Extraction Report
==========================

Date: $(date)
Container: $CONTAINER
Architecture: $ARCH
Library Path: /usr/lib/$LIB_PATH

Binary Information:
$(file "$OUTPUT_DIR/binaries/sshd" 2>/dev/null || echo "  Binary not extracted")

Symbol Count:
$(nm "$OUTPUT_DIR/binaries/sshd" 2>/dev/null | grep -c 'T ' || echo '0') functions

KEX Function:
$(nm "$OUTPUT_DIR/binaries/sshd" 2>/dev/null | grep "kex_derive_keys" || echo "  Not found")

Libraries:
$(ls -lh "$OUTPUT_DIR/libraries/" 2>/dev/null | tail -n +2 | awk '{print "  "$9" ("$5")"}' || echo "  None")

Dumps:
$(ls "$OUTPUT_DIR/dumps/" 2>/dev/null | wc -l || echo '0') files
$(du -sh "$OUTPUT_DIR/dumps/" 2>/dev/null | cut -f1 || echo '0') total

Logs:
$(ls -lh "$OUTPUT_DIR/logs/" 2>/dev/null | tail -n +2 | awk '{print "  "$9" ("$5")"}' || echo "  None")

Container Info:
$(docker compose exec -T "$CONTAINER" sh -c "uname -a" 2>/dev/null || echo "  N/A")
$(docker compose exec -T "$CONTAINER" sh -c "/usr/sbin/sshd -v 2>&1 | head -1" 2>/dev/null || echo "  N/A")
EOF

echo "  ✓ metadata.txt created"

echo ""
echo "========================================="
echo "Extraction Complete!"
echo "========================================="
echo ""
echo "Output directory: $OUTPUT_DIR"
echo ""
echo "Contents:"
echo "  binaries/sshd          - SSH daemon binary for IDA Pro"
echo "  libraries/*.so         - OpenSSL libraries"
echo "  dumps/*.dump           - Memory dumps from LLDB"
echo "  logs/*.log             - Event logs and keylogs"
echo "  metadata.txt           - Extraction report"
echo ""
echo "Next Steps:"
echo "  1. Analyze binary in IDA Pro:"
echo "     → Open: $OUTPUT_DIR/binaries/sshd"
echo "     → Search functions: kex_derive_keys, explicit_bzero"
echo ""
echo "  2. Search for keys in dumps:"
echo "     → hexdump -C $OUTPUT_DIR/dumps/*.dump | grep -i '[0-9a-f]\\{64\\}'"
echo ""
echo "  3. Analyze events:"
echo "     → cat $OUTPUT_DIR/logs/events_openssh.log | grep KEX"
echo "     → python3 -c 'import json; [print(json.dumps(x)) for x in map(json.loads, open(\"$OUTPUT_DIR/logs/events_openssh.jsonl\"))]'"
echo ""
