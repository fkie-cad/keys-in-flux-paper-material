#!/usr/bin/env bash
# status_both.sh - Show IPsec status for both namespaces
# Adapted from strongswan status_both.sh
set -euo pipefail

echo "============================================"
echo "[LEFT] IPsec Status:"
echo "============================================"
ip netns exec left bash -c '
    export IPSEC_CONFS=/etc/ipsec-left
    ipsec status || echo "[WARN] ipsec status failed"
' || true

echo ""
echo "============================================"
echo "[LEFT] XFRM State:"
echo "============================================"
ip netns exec left ip xfrm state || true

echo ""
echo "============================================"
echo "[LEFT] XFRM Policy:"
echo "============================================"
ip netns exec left ip xfrm policy || true

echo ""
echo "============================================"
echo "[RIGHT] IPsec Status:"
echo "============================================"
ip netns exec right bash -c '
    export IPSEC_CONFS=/etc/ipsec-right
    ipsec status || echo "[WARN] ipsec status failed"
' || true

echo ""
echo "============================================"
echo "[RIGHT] XFRM State:"
echo "============================================"
ip netns exec right ip xfrm state || true

echo ""
echo "============================================"
echo "[RIGHT] XFRM Policy:"
echo "============================================"
ip netns exec right ip xfrm policy || true

echo ""
