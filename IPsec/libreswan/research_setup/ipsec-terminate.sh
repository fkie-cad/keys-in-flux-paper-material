#!/usr/bin/env bash
# ipsec-terminate.sh - Terminate IPsec connection
# Adapted from strongswan ipsec-terminate.sh
set -euo pipefail

LEFT_NS="${LEFT_NS:-left}"
RIGHT_NS="${RIGHT_NS:-right}"

side="${1:-}"
conn="${2:-net}"  # Default connection name

usage() {
    echo "Usage: $0 <left|right> [connection_name]"
    echo "Example: $0 left net"
    exit 1
}

[[ "$side" == "left" || "$side" == "right" ]] || usage

ns="$([[ $side == left ]] && echo "$LEFT_NS" || echo "$RIGHT_NS")"
conf_dir="$([[ $side == left ]] && echo "/etc/ipsec-left" || echo "/etc/ipsec-right")"

echo "[*] Terminating connection in namespace '${ns}' for connection '${conn}'..."

# Libreswan: Use ipsec auto --down to terminate
ip netns exec "$ns" bash -c "
    export IPSEC_CONFS=$conf_dir
    ipsec auto --down $conn
"

if [[ $? -eq 0 ]]; then
    echo "[OK] Terminate command issued successfully"
else
    echo "[ERROR] Terminate failed"
    exit 1
fi

echo "[*] Check status with: ip netns exec $ns ipsec status"
