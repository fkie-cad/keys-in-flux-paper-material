#!/usr/bin/env bash
# setup_right.sh - Start libreswan pluto in right namespace
# Adapted from strongswan setup_right.sh
set -euo pipefail

RIGHT_NS=right
LEFT_IP=10.0.0.1
RIGHT_IP=10.0.0.2

# Create config directory
mkdir -p /etc/ipsec-right

# Create ipsec.conf
cat >/etc/ipsec-right/ipsec.conf <<'EOF'
# Libreswan IPsec configuration for right (responder)
config setup
    logfile=/var/log/pluto-right.log
    logtime=yes
    logappend=no
    plutodebug=all
    protostack=netkey

conn net
    left=10.0.0.2
    right=10.0.0.1
    leftid=@right
    rightid=@left
    authby=secret
    auto=add
    type=tunnel
    ike=aes128-sha2_256-modp2048
    phase2=esp
    phase2alg=aes128-sha2_256
    # Child SA traffic selectors
    leftsubnet=10.0.0.2/32
    rightsubnet=10.0.0.1/32
EOF

# Create ipsec.secrets
cat >/etc/ipsec-right/ipsec.secrets <<'EOF'
# Libreswan secrets file for right
@right @left : PSK "test123"
EOF

chmod 600 /etc/ipsec-right/ipsec.secrets

echo "[*] Starting pluto in namespace '$RIGHT_NS'..."

# Start pluto in right namespace
ip netns exec "$RIGHT_NS" bash -c '
    # Set config path
    export IPSEC_CONFS=/etc/ipsec-right

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
        --config /etc/ipsec-right/ipsec.conf \
        --nofork \
        --stderrlog \
        </dev/null >/tmp/pluto-right.log 2>&1 & disown

    # Give pluto time to initialize
    sleep 1

    # Check if pluto is running
    if pgrep -f "pluto.*ipsec-right" >/dev/null; then
        echo "[*] Pluto started successfully"
        echo "[*] PID: $(pgrep -f "pluto.*ipsec-right")"
    else
        echo "[ERROR] Pluto failed to start. Check /tmp/pluto-right.log"
        exit 1
    fi
'

echo "[*] Pluto (right) initialization complete"
echo "[*] Config: /etc/ipsec-right/ipsec.conf"
echo "[*] Log: /tmp/pluto-right.log"
echo "[*] To check status: ip netns exec right ipsec status"
