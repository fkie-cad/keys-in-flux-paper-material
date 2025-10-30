#!/usr/bin/env bash
# setup_left.sh - Start libreswan pluto in left namespace
# Adapted from strongswan setup_left.sh
set -euo pipefail

LEFT_NS=left
LEFT_IP=10.0.0.1
RIGHT_IP=10.0.0.2

# Create config directory
mkdir -p /etc/ipsec-left

# Create ipsec.conf
cat >/etc/ipsec-left/ipsec.conf <<'EOF'
# Libreswan IPsec configuration for left (initiator)
config setup
    logfile=/var/log/pluto-left.log
    logtime=yes
    logappend=no
    plutodebug=all
    protostack=netkey

conn net
    left=10.0.0.1
    right=10.0.0.2
    leftid=@left
    rightid=@right
    authby=secret
    auto=add
    type=tunnel
    ike=aes128-sha2_256-modp2048
    phase2=esp
    phase2alg=aes128-sha2_256
    # Child SA traffic selectors
    leftsubnet=10.0.0.1/32
    rightsubnet=10.0.0.2/32
EOF

# Create ipsec.secrets
cat >/etc/ipsec-left/ipsec.secrets <<'EOF'
# Libreswan secrets file for left
@left @right : PSK "test123"
EOF

chmod 600 /etc/ipsec-left/ipsec.secrets

echo "[*] Starting pluto in namespace '$LEFT_NS'..."

# Start pluto in left namespace
# Note: libreswan pluto needs to run as daemon, using nofork for debugging
ip netns exec "$LEFT_NS" bash -c '
    # Set config path
    export IPSEC_CONFS=/etc/ipsec-left

    # Detect pluto path dynamically
    PLUTO_PATH=$(ipsec --directory 2>/dev/null)/pluto
    if [[ ! -x "$PLUTO_PATH" ]]; then
        # Fallback to common locations
        for candidate in /usr/libexec/ipsec/pluto /usr/local/libexec/ipsec/pluto; do
            if [[ -x "$candidate" ]]; then
                PLUTO_PATH="$candidate"
                break
            fi
        done
    fi

    if [[ -z "$PLUTO_PATH" || ! -x "$PLUTO_PATH" ]]; then
        echo "[ERROR] Cannot find pluto binary!"
        exit 1
    fi

    echo "[*] Using pluto at: $PLUTO_PATH"

    # Start pluto with debug logging
    $PLUTO_PATH \
        --config /etc/ipsec-left/ipsec.conf \
        --nofork \
        --stderrlog \
        </dev/null >/tmp/pluto-left.log 2>&1 & disown

    # Give pluto time to initialize
    sleep 1

    # Check if pluto is running
    if pgrep -f "pluto.*ipsec-left" >/dev/null; then
        echo "[*] Pluto started successfully"
        echo "[*] PID: $(pgrep -f "pluto.*ipsec-left")"
    else
        echo "[ERROR] Pluto failed to start. Check /tmp/pluto-left.log"
        exit 1
    fi
'

echo "[*] Pluto (left) initialization complete"
echo "[*] Config: /etc/ipsec-left/ipsec.conf"
echo "[*] Log: /tmp/pluto-left.log"
echo "[*] To check status: ip netns exec left ipsec status"
