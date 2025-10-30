#!/usr/bin/env bash
set -euo pipefail
echo "[*] capturing ESP on left to /tmp/esp_left.pcap and generating ping..."
ip netns exec left bash -lc '
  ( timeout 8 tcpdump -i veth-left -s0 -w /tmp/esp_left.pcap >/dev/null 2>&1 ) &
  sleep 1
  ping -c 5 10.0.0.2 >/dev/null 2>&1 || true
  wait || true
'
ls -lh /tmp/esp_left.pcap
echo "[*] capture done."