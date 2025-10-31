#!/bin/bash
set -e

echo "========================================================================"
echo "  OpenSSH Client - LLDB Monitoring"
echo "========================================================================"
echo ""
echo "Target: ${SSH_SERVER_HOST}:${SSH_SERVER_PORT}"
echo "User: ${SSH_USER}"
echo "Keylog: ${LLDB_KEYLOG}"
echo "OpenSSH Version: 9.8p1 (built with debug symbols)"
echo ""
echo "========================================================================"
echo ""

# Wait for server to be ready
echo "[OPENSSH_CLIENT] Waiting for ${SSH_SERVER_HOST}:${SSH_SERVER_PORT} to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if nc -z ${SSH_SERVER_HOST} ${SSH_SERVER_PORT} 2>/dev/null; then
        echo "[OPENSSH_CLIENT] ✓ Server is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "[OPENSSH_CLIENT] Attempt $attempt/$max_attempts..."
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "[OPENSSH_CLIENT] ERROR: Server not reachable after $max_attempts attempts"
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

# Clear debug keylog from previous runs
LLDB_KEYLOG_DEBUG="${LLDB_KEYLOG_DEBUG:-${LLDB_KEYLOG/.log/_debug.log}}"
> "${LLDB_KEYLOG_DEBUG}"
chmod 666 "${LLDB_KEYLOG_DEBUG}"

# Start packet capture
CAPTURE_FILE="${LLDB_CAPTURES_DIR:-/data/captures}/openssh_client_$(date +%Y%m%d_%H%M%S).pcap"
echo "[OPENSSH_CLIENT] Starting packet capture: $CAPTURE_FILE"

tcpdump -i any -w "$CAPTURE_FILE" "host ${SSH_SERVER_HOST} and port ${SSH_SERVER_PORT}" &
TCPDUMP_PID=$!
sleep 1
echo "[OPENSSH_CLIENT] Packet capture running (PID $TCPDUMP_PID)"

echo ""
echo "[OPENSSH_CLIENT] Starting OpenSSH client under LLDB monitoring..."
echo "[OPENSSH_CLIENT] Command: sshpass -p [password] ssh ${SSH_USER}@${SSH_SERVER_HOST} -p ${SSH_SERVER_PORT}"
echo ""

# Create SSH config to disable host key checking
mkdir -p /root/.ssh
chmod 700 /root/.ssh

cat > /root/.ssh/config << 'EOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
EOF

chmod 600 /root/.ssh/config

# Launch ssh under LLDB monitoring
# Check if SSH_CMD is set (for expect script) or use default sshpass approach
echo "[OPENSSH_CLIENT] Launching ssh under LLDB (with fork-follow enabled)..."

if [ -n "$SSH_CMD" ]; then
    echo "[OPENSSH_CLIENT] Using custom SSH_CMD: $SSH_CMD"
    # Expect script handles password internally, so target expect directly
    lldb \
      -o "command script import /opt/lldb/openssh_client_callbacks.py" \
      -o "settings set target.process.follow-fork-mode child" \
      -o "file /usr/bin/expect" \
      -o "process launch --stop-at-entry -- ${SSH_CMD}" \
      -o "openssh_setup_monitoring" \
      -o "openssh_auto_continue"
else
    echo "[OPENSSH_CLIENT] Using default sshpass command"
    # Default: sshpass with simple SSH command
    lldb \
      -o "command script import /opt/lldb/openssh_client_callbacks.py" \
      -o "settings set target.process.follow-fork-mode child" \
      -o "file /usr/bin/sshpass" \
      -o "process launch --stop-at-entry -- -p ${SSH_PASSWORD} ssh -p ${SSH_SERVER_PORT} ${SSH_USER}@${SSH_SERVER_HOST} 'hostname && pwd && echo \"OpenSSH lifecycle test\" && sleep 2'" \
      -o "openssh_setup_monitoring" \
      -o "openssh_auto_continue"
fi

# Stop packet capture
echo ""
echo "[OPENSSH_CLIENT] Stopping packet capture..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# Check capture file size
if [ -f "$CAPTURE_FILE" ]; then
    CAPTURE_SIZE=$(stat -f%z "$CAPTURE_FILE" 2>/dev/null || stat -c%s "$CAPTURE_FILE" 2>/dev/null || echo "0")
    echo "[OPENSSH_CLIENT] ✓ Capture saved: $CAPTURE_FILE ($CAPTURE_SIZE bytes)"
else
    echo "[OPENSSH_CLIENT] ⚠️  Capture file not created"
fi

echo ""
echo "========================================================================"
echo "  OpenSSH Client - Monitoring Complete"
echo "========================================================================"
echo ""

# Display results
echo "========================================================================"
echo "  Standard Keylog (Wireshark-Compatible Format)"
echo "========================================================================"
if [ -f "${LLDB_KEYLOG}" ] && [ -s "${LLDB_KEYLOG}" ]; then
    cat "${LLDB_KEYLOG}"
    KEY_COUNT=$(grep -c "NEWKEYS\|EVP_KDF" "${LLDB_KEYLOG}" 2>/dev/null || echo "0")
    echo ""
    echo "✓ $KEY_COUNT key entries logged"
else
    echo "⚠️  No keys extracted to ${LLDB_KEYLOG}"
fi

echo ""
echo "========================================================================"
echo "  Debug Keylog (Detailed Intermediate Values)"
echo "========================================================================"
if [ -f "${LLDB_KEYLOG_DEBUG}" ] && [ -s "${LLDB_KEYLOG_DEBUG}" ]; then
    echo "Debug log contains $(wc -l < "${LLDB_KEYLOG_DEBUG}") lines"
    echo "Path: ${LLDB_KEYLOG_DEBUG}"
else
    echo "No debug log generated"
fi

echo ""
echo "========================================================================"
echo "  Session Data Summary"
echo "========================================================================"
echo "Keylog:       ${LLDB_KEYLOG}"
echo "Debug Log:    ${LLDB_KEYLOG_DEBUG}"
echo "Packet Capture: $CAPTURE_FILE"
echo "Dumps:        ${LLDB_DUMPS_DIR}"
echo "Results:      ${LLDB_RESULTS_DIR}"
echo ""
echo "Note: OpenSSH uses dual hybrid extraction:"
echo "  1. derive_key() - Direct key extraction (6 calls: A-F)"
echo "  2. EVP_KDF_derive()  - OpenSSL library hook (fallback)"
echo "Both approaches use symbol-aware + register fallback"
echo ""
