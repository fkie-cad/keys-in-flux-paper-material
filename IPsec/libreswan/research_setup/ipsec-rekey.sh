#!/usr/bin/env bash
# ipsec-rekey.sh - Trigger IPsec rekey
# Adapted from strongswan ipsec-rekey.sh
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

echo "[*] Triggering rekey in namespace '${ns}' for connection '${conn}'..."

# Libreswan: Use ipsec whack to trigger rekey
# Note: This may rekey IKE SA or Child SA depending on timing
ip netns exec "$ns" bash -c "
    export IPSEC_CONFS=$conf_dir

    # Try to rekey the connection
    # First, try to rekey IKE SA (parent)
    ipsec whack --rekey-ike --name $conn 2>/dev/null || \
    # If that fails, try Child SA (IPsec SA)
    ipsec whack --rekey-ipsec --name $conn 2>/dev/null || \
    # If both fail, report error
    { echo '[ERROR] Rekey failed. Check connection status.'; exit 1; }
"

if [[ $? -eq 0 ]]; then
    echo "[OK] Rekey command issued successfully"
else
    echo "[ERROR] Rekey failed"
    exit 1
fi

echo "[*] Check status with: ip netns exec $ns ipsec status"
