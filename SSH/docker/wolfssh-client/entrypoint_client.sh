#!/bin/bash
set -e

#=============================================================================
# Generic SSH Client LLDB Entrypoint
# Auto-detects client type based on SSH_SERVER_TYPE environment variable
# Supports: openssh, dropbear, wolfssh
#=============================================================================

# Detect client type from SSH_SERVER_TYPE environment variable
# If not set, try to detect from binary names or default to openssh
SSH_CLIENT_TYPE="${SSH_SERVER_TYPE:-openssh}"

echo "========================================================================"
echo "  SSH Client LLDB Monitoring - Auto-Detection"
echo "========================================================================"
echo "  Detected Client Type: ${SSH_CLIENT_TYPE}"
echo "  Target: ${SSH_SERVER_HOST}:${SSH_SERVER_PORT}"
echo "  User: ${SSH_USER}"
echo "  Keylog: ${LLDB_KEYLOG}"
echo "========================================================================"
echo ""

# Configure client-specific settings
case "${SSH_CLIENT_TYPE}" in
    openssh)
        CALLBACK_FILE="/opt/lldb/openssh_client_callbacks.py"
        SETUP_FUNCTION="openssh_setup_monitoring"
        AUTO_CONTINUE_FUNCTION="openssh_auto_continue"
        CLIENT_BINARY="/usr/bin/sshpass"
        PROCESS_ARGS="-p ${SSH_PASSWORD} ssh -p ${SSH_SERVER_PORT} ${SSH_USER}@${SSH_SERVER_HOST} 'hostname && pwd && echo OpenSSH KEX test && sleep 2'"
        FORK_FOLLOW="child"  # OpenSSH uses fork, need to follow child process
        CLIENT_NAME="OpenSSH"
        ;;

    dropbear)
        CALLBACK_FILE="/opt/lldb/dropbear_client_callbacks.py"
        SETUP_FUNCTION="dropbear_setup_monitoring"
        AUTO_CONTINUE_FUNCTION="dropbear_auto_continue"
        CLIENT_BINARY="/usr/bin/dbclient"
        PROCESS_ARGS="-y -p ${SSH_SERVER_PORT} ${SSH_USER}@${SSH_SERVER_HOST}"
        FORK_FOLLOW="parent"  # Dropbear may not fork the same way
        CLIENT_NAME="Dropbear"
        ;;

    wolfssh)
        CALLBACK_FILE="/opt/lldb/wolfssh_client_callbacks.py"
        SETUP_FUNCTION="wolfssh_setup_monitoring"
        AUTO_CONTINUE_FUNCTION="wolfssh_auto_continue"
        # Use custom client binary (built with wolfSSH library)
        CLIENT_BINARY="/usr/local/bin/wolfssh-client-rekey-v2"
        # Pass arguments directly to custom client
        PROCESS_ARGS="${SSH_SERVER_HOST:-openssh_wolfssh_compat} ${SSH_SERVER_PORT:-22} ${SSH_USER:-testuser} ${SSH_PASSWORD:-password}"
        # Add --with-rekey flag if WOLFSSH_REKEY_MODE is enabled
        if [ "${WOLFSSH_REKEY_MODE}" = "true" ]; then
            PROCESS_ARGS="${PROCESS_ARGS} --with-rekey"
        fi
        FORK_FOLLOW="parent"  # Custom client doesn't fork
        CLIENT_NAME="wolfSSH"
        ;;

    *)
        echo "ERROR: Unknown SSH_CLIENT_TYPE: ${SSH_CLIENT_TYPE}"
        echo "Supported types: openssh, dropbear, wolfssh"
        exit 1
        ;;
esac

echo "[${CLIENT_NAME}] Configuration:"
echo "  Callback: ${CALLBACK_FILE}"
echo "  Binary: ${CLIENT_BINARY}"
echo "  Setup Function: ${SETUP_FUNCTION}"
echo "  Auto-Continue: ${AUTO_CONTINUE_FUNCTION}"
echo ""

# Wait for server to be ready
echo "[${CLIENT_NAME}] Waiting for ${SSH_SERVER_HOST}:${SSH_SERVER_PORT} to be ready..."
max_attempts=30
attempt=0

while [ $attempt -lt $max_attempts ]; do
    if nc -z ${SSH_SERVER_HOST} ${SSH_SERVER_PORT} 2>/dev/null; then
        echo "[${CLIENT_NAME}] ✓ Server is ready!"
        break
    fi
    attempt=$((attempt + 1))
    echo "[${CLIENT_NAME}] Attempt $attempt/$max_attempts..."
    sleep 1
done

if [ $attempt -eq $max_attempts ]; then
    echo "[${CLIENT_NAME}] ERROR: Server not reachable after $max_attempts attempts"
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
CAPTURE_FILE="${LLDB_CAPTURES_DIR:-/data/captures}/${SSH_CLIENT_TYPE}_client_$(date +%Y%m%d_%H%M%S).pcap"
echo "[${CLIENT_NAME}] Starting packet capture: $CAPTURE_FILE"

tcpdump -i any -w "$CAPTURE_FILE" "host ${SSH_SERVER_HOST} and port ${SSH_SERVER_PORT}" &
TCPDUMP_PID=$!
sleep 1
echo "[${CLIENT_NAME}] Packet capture running (PID $TCPDUMP_PID)"

echo ""
echo "[${CLIENT_NAME}] Starting ${CLIENT_NAME} client under LLDB monitoring..."
echo "[${CLIENT_NAME}] Binary: ${CLIENT_BINARY}"
echo "[${CLIENT_NAME}] Arguments: ${PROCESS_ARGS}"
echo ""

# Create SSH config to disable host key checking (for OpenSSH)
if [ "${SSH_CLIENT_TYPE}" = "openssh" ]; then
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    cat > /root/.ssh/config << 'EOF'
Host *
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
    LogLevel QUIET
EOF

    chmod 600 /root/.ssh/config
fi

# Launch client under LLDB monitoring
echo "[${CLIENT_NAME}] Launching ${CLIENT_NAME} client under LLDB..."
lldb \
  -o "command script import ${CALLBACK_FILE}" \
  -o "settings set target.process.follow-fork-mode ${FORK_FOLLOW}" \
  -o "file ${CLIENT_BINARY}" \
  -o "process launch --stop-at-entry -- ${PROCESS_ARGS}" \
  -o "${SETUP_FUNCTION}" \
  -o "${AUTO_CONTINUE_FUNCTION}"

# Stop packet capture
echo ""
echo "[${CLIENT_NAME}] Stopping packet capture..."
kill $TCPDUMP_PID 2>/dev/null || true
wait $TCPDUMP_PID 2>/dev/null || true
sleep 1

# Check capture file size
if [ -f "$CAPTURE_FILE" ]; then
    CAPTURE_SIZE=$(stat -f%z "$CAPTURE_FILE" 2>/dev/null || stat -c%s "$CAPTURE_FILE" 2>/dev/null || echo "0")
    echo "[${CLIENT_NAME}] ✓ Capture saved: $CAPTURE_FILE ($CAPTURE_SIZE bytes)"
else
    echo "[${CLIENT_NAME}] ⚠️  Capture file not created"
fi

echo ""
echo "========================================================================"
echo "  ${CLIENT_NAME} Client - Monitoring Complete"
echo "========================================================================"
echo ""

# Display results
echo "========================================================================"
echo "  Standard Keylog (Wireshark-Compatible Format)"
echo "========================================================================"
if [ -f "${LLDB_KEYLOG}" ] && [ -s "${LLDB_KEYLOG}" ]; then
    cat "${LLDB_KEYLOG}"
    KEY_COUNT=$(grep -c "NEWKEYS\|EVP_KDF\|wc_SSH_KDF" "${LLDB_KEYLOG}" 2>/dev/null || echo "0")
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
echo "Client Type:  ${CLIENT_NAME} (${SSH_CLIENT_TYPE})"
echo "Keylog:       ${LLDB_KEYLOG}"
echo "Debug Log:    ${LLDB_KEYLOG_DEBUG}"
echo "Packet Capture: $CAPTURE_FILE"
echo "Dumps:        ${LLDB_DUMPS_DIR}"
echo "Results:      ${LLDB_RESULTS_DIR}"
echo ""
