#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# OpenSSH Standalone Container Entrypoint
#
# Supports dual-mode operation:
#   MODE=server  -> run sshd with key export
#   MODE=client  -> run ssh client with key export
#
# Environment variables:
#   MODE            - server|client (default: server)
#   SSHKEYLOGFILE   - path to keylog output (default: /data/keylogs/ssh_keylog.log)
#   SSH_PORT        - port for sshd to listen on (default: 22)
#   CAPTURE_TRAFFIC - enable/disable pcap capture (default: true)
#   CAPTURE_DIR     - directory for pcap files (default: /data/captures)
#   HOST            - (client mode) target host
#   PORT            - (client mode) target port (default: 22)
#   USER            - (client mode) username (default: testuser)
#   PASSWORD        - (client mode) password (optional)
#   SSH_CMD         - (client mode) command to run (optional)
##############################################################################

MODE="${MODE:-server}"
SSHKEYLOGFILE="${SSHKEYLOGFILE:-/data/keylogs/ssh_keylog.log}"
SSH_PORT="${SSH_PORT:-22}"
CAPTURE_TRAFFIC="${CAPTURE_TRAFFIC:-true}"
CAPTURE_DIR="${CAPTURE_DIR:-/data/captures}"

# Ensure keylog directory exists
KEYLOG_DIR=$(dirname "$SSHKEYLOGFILE")
mkdir -p "$KEYLOG_DIR"
chmod 777 "$KEYLOG_DIR"

# Create empty keylog file if it doesn't exist
touch "$SSHKEYLOGFILE"
chmod 666 "$SSHKEYLOGFILE"

# Ensure capture directory exists
mkdir -p "$CAPTURE_DIR"
chmod 777 "$CAPTURE_DIR"

# Export SSHKEYLOGFILE for OpenSSH to pick up
export SSHKEYLOGFILE

echo "[entrypoint] MODE=$MODE"
echo "[entrypoint] SSHKEYLOGFILE=$SSHKEYLOGFILE"
echo "[entrypoint] CAPTURE_TRAFFIC=$CAPTURE_TRAFFIC"
if [ "$CAPTURE_TRAFFIC" = "true" ]; then
    echo "[entrypoint] CAPTURE_DIR=$CAPTURE_DIR"
fi

# Tail keylog file to stderr in background so keys are visible in docker logs
tail -F "$SSHKEYLOGFILE" 2>/dev/null &
TAIL_PID=$!

# Cleanup function
TCPDUMP_PID=""
cleanup() {
    echo "[entrypoint] Cleaning up..."
    if [ -n "${TAIL_PID:-}" ]; then
        kill "$TAIL_PID" 2>/dev/null || true
    fi
    if [ -n "${TCPDUMP_PID:-}" ]; then
        echo "[entrypoint] Stopping packet capture..."
        kill "$TCPDUMP_PID" 2>/dev/null || true
        # Give tcpdump time to flush buffers
        sleep 1
    fi
}
trap cleanup EXIT INT TERM

# Function to start packet capture
start_capture() {
    local capture_file="$1"
    local filter="$2"

    if [ "$CAPTURE_TRAFFIC" != "true" ]; then
        return
    fi

    echo "[entrypoint] Starting packet capture..."
    echo "[entrypoint] Capture file: $capture_file"
    echo "[entrypoint] Filter: $filter"

    # Start tcpdump in background
    tcpdump -i any -w "$capture_file" "$filter" -U 2>/dev/null &
    TCPDUMP_PID=$!

    # Wait a moment for tcpdump to start
    sleep 1

    # Verify tcpdump is running
    if ps -p "$TCPDUMP_PID" >/dev/null 2>&1; then
        echo "[entrypoint] Packet capture started (PID: $TCPDUMP_PID)"
    else
        echo "[entrypoint] WARNING: Failed to start packet capture"
        TCPDUMP_PID=""
    fi
}

##############################################################################
# SERVER MODE
##############################################################################
if [ "$MODE" = "server" ]; then
    echo "[entrypoint] Running in SERVER mode on port $SSH_PORT"

    # Generate host keys if they don't exist
    KEYDIR=/etc/ssh
    mkdir -p "$KEYDIR"

    for keytype in rsa ecdsa ed25519; do
        keyfile="$KEYDIR/ssh_host_${keytype}_key"
        if [ ! -f "$keyfile" ]; then
            echo "[entrypoint] Generating $keytype host key..."
            ssh-keygen -q -N "" -t "$keytype" -f "$keyfile"
        fi
    done

    # Create test user if it doesn't exist
    if ! id testuser >/dev/null 2>&1; then
        echo "[entrypoint] Creating testuser..."
        useradd -m -s /bin/bash testuser || true
        echo "testuser:password" | chpasswd
    fi

    # Ensure sshd_config allows password auth
    SSHD_CONFIG=/etc/ssh/sshd_config
    if [ -f "$SSHD_CONFIG" ]; then
        sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' "$SSHD_CONFIG"
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/' "$SSHD_CONFIG"
        sed -i 's/^#*ChallengeResponseAuthentication.*/ChallengeResponseAuthentication no/' "$SSHD_CONFIG"
        # Allow TCP forwarding
        sed -i 's/^#*AllowTcpForwarding.*/AllowTcpForwarding yes/' "$SSHD_CONFIG"
    fi

    # Create privilege separation directory
    mkdir -p /var/run/sshd
    chmod 755 /var/run/sshd

    echo "[entrypoint] Starting sshd on port $SSH_PORT..."
    echo "[entrypoint] Keys will be exported to: $SSHKEYLOGFILE"
    echo "[entrypoint] Test credentials: testuser / password"

    # Start packet capture if enabled
    if [ "$CAPTURE_TRAFFIC" = "true" ]; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        CAPTURE_FILE="$CAPTURE_DIR/server_${TIMESTAMP}_port${SSH_PORT}.pcap"
        start_capture "$CAPTURE_FILE" "tcp port $SSH_PORT"
    fi

    # Start sshd in foreground with debug output
    exec /usr/sbin/sshd -D -e -p "$SSH_PORT"

##############################################################################
# CLIENT MODE
##############################################################################
elif [ "$MODE" = "client" ]; then
    echo "[entrypoint] Running in CLIENT mode"

    # Check required parameters
    HOST="${HOST:-}"
    PORT="${PORT:-22}"
    USER="${USER:-testuser}"
    PASSWORD="${PASSWORD:-}"
    SSH_CMD="${SSH_CMD:-}"

    if [ -z "$HOST" ]; then
        echo "[entrypoint] ERROR: HOST environment variable must be set in client mode"
        echo "[entrypoint] Example: docker run -e MODE=client -e HOST=192.168.1.100 ..."
        exit 1
    fi

    echo "[entrypoint] Connecting to: $USER@$HOST:$PORT"
    echo "[entrypoint] Keys will be exported to: $SSHKEYLOGFILE"

    # Start packet capture if enabled
    if [ "$CAPTURE_TRAFFIC" = "true" ]; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        CAPTURE_FILE="$CAPTURE_DIR/client_${TIMESTAMP}_${HOST}_${PORT}.pcap"
        # Capture SSH traffic to/from the target host and port
        start_capture "$CAPTURE_FILE" "tcp port $PORT and host $HOST"
    fi

    # Build SSH command
    SSH_ARGS=(
        -o "StrictHostKeyChecking=no"
        -o "UserKnownHostsFile=/dev/null"
        -o "LogLevel=VERBOSE"
        -p "$PORT"
    )

    # If password is provided, use sshpass
    if [ -n "$PASSWORD" ]; then
        echo "[entrypoint] Using password authentication"
        if ! command -v sshpass >/dev/null 2>&1; then
            echo "[entrypoint] ERROR: sshpass not found but PASSWORD is set"
            exit 1
        fi

        if [ -n "$SSH_CMD" ]; then
            # Run command and exit
            exec sshpass -p "$PASSWORD" ssh "${SSH_ARGS[@]}" "$USER@$HOST" "$SSH_CMD"
        else
            # Interactive session
            exec sshpass -p "$PASSWORD" ssh "${SSH_ARGS[@]}" -tt "$USER@$HOST"
        fi
    else
        # No password, assume key-based auth or will prompt
        echo "[entrypoint] Using key-based authentication or interactive password prompt"
        if [ -n "$SSH_CMD" ]; then
            exec ssh "${SSH_ARGS[@]}" "$USER@$HOST" "$SSH_CMD"
        else
            exec ssh "${SSH_ARGS[@]}" -tt "$USER@$HOST"
        fi
    fi

##############################################################################
# UNKNOWN MODE
##############################################################################
else
    echo "[entrypoint] ERROR: Unknown MODE='$MODE'"
    echo "[entrypoint] Valid modes: server, client"
    exit 1
fi
