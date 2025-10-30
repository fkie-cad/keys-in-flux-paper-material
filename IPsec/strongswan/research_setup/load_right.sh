#!/usr/bin/env bash
set -euo pipefail
ip netns exec right /usr/sbin/swanctl --load-all \
  --file /etc/strongswan-right/swanctl/swanctl.conf \
  --uri  unix:///run/right.charon.vici
echo "[*] right: swanctl config loaded."