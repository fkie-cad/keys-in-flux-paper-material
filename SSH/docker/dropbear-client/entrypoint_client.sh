#!/bin/bash
set -e

echo "========================================================================"
echo "  Dropbear Client - LLDB Monitoring"
echo "========================================================================"
echo ""
echo "Target: ${SSH_SERVER_HOST}:${SSH_SERVER_PORT}"
echo "User: ${SSH_USER}"
echo "Keylog: ${LLDB_KEYLOG}"
echo ""
echo "========================================================================"
echo ""

# Wait for server to be ready
echo "[CLIENT] Waiting for ${SSH_SERVER_HOST}:${SSH_SERVER_PORT} to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if nc -z ${SSH_SERVER_HOST} ${SSH_SERVER_PORT} 2>/dev/null; then
        echo "[CLIENT] ✓ Server is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "[CLIENT] Attempt $attempt/$max_attempts..."
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "[CLIENT] ERROR: Server not reachable after $max_attempts attempts"
    exit 1
fi

# Give server a moment to fully initialize
sleep 2

# Prepare directories and files
mkdir -p "$(dirname ${LLDB_KEYLOG})"
mkdir -p "${LLDB_CAPTURES_DIR:-/data/captures}"
mkdir -p "${LLDB_DUMPS_DIR:-/data/dumps}"
mkdir -p "${LLDB_RESULTS_DIR:-/data/lldb_results}"

touch "${LLDB_KEYLOG}"
chmod 666 "${LLDB_KEYLOG}"

# Start packet capture
CAPTURE_FILE="${LLDB_CAPTURES_DIR:-/data/captures}/dropbear_client_$(date +%Y%m%d_%H%M%S).pcap"
echo "[CLIENT] Starting packet capture: $CAPTURE_FILE"

tcpdump -i any -w "$CAPTURE_FILE" "host ${SSH_SERVER_HOST} and port ${SSH_SERVER_PORT}" &
TCPDUMP_PID=$!
sleep 1
echo "[CLIENT] Packet capture running (PID $TCPDUMP_PID)"

echo ""
echo "[CLIENT] Starting dbclient under LLDB monitoring..."
echo "[CLIENT] Command: sshpass -p [password] dbclient -y ${SSH_USER}@${SSH_SERVER_HOST} -p ${SSH_SERVER_PORT}"
echo ""

# Launch dbclient under LLDB monitoring via sshpass
# Configure LLDB to follow child processes so breakpoints work in dbclient
echo "[CLIENT] Launching dbclient under LLDB (with fork-follow enabled)..."

lldb \
  -o "command script import /opt/lldb/dropbear_client_callbacks.py" \
  -o "settings set target.process.follow-fork-mode child" \
  -o "file /usr/bin/sshpass" \
  -o "process launch -- -p ${SSH_PASSWORD} dbclient -y -p ${SSH_SERVER_PORT} ${SSH_USER}@${SSH_SERVER_HOST} 'hostname && pwd && echo Client-side KEX test'" \
  -o "client_setup_monitoring" \
  -o "client_auto_continue"

# Stop packet capture
echo ""
echo "[CLIENT] Stopping packet capture..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# Check capture file size
if [ -f "$CAPTURE_FILE" ]; then
    CAPTURE_SIZE=$(stat -f%z "$CAPTURE_FILE" 2>/dev/null || stat -c%s "$CAPTURE_FILE" 2>/dev/null || echo "0")
    echo "[CLIENT] ✓ Capture saved: $CAPTURE_FILE ($CAPTURE_SIZE bytes)"
else
    echo "[CLIENT] ⚠️  Capture file not created"
fi

echo ""
echo "========================================================================"
echo "  Dropbear Client - Monitoring Complete"
echo "========================================================================"
echo ""

# Display results
if [ -f "${LLDB_KEYLOG}" ]; then
    echo "[CLIENT] Keylog contents:"
    cat "${LLDB_KEYLOG}"
else
    echo "[CLIENT] WARNING: Keylog file not found at ${LLDB_KEYLOG}"
fi

echo ""
echo "[CLIENT] Results written to:"
echo "  - Keylog: ${LLDB_KEYLOG}"
echo "  - Packet capture: $CAPTURE_FILE"
echo "  - Dumps: ${LLDB_DUMPS_DIR}"
echo "  - Results: ${LLDB_RESULTS_DIR}"
echo ""
