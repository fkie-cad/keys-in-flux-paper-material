#!/usr/bin/env bash
set -euo pipefail

NUKE="${1:-}"

echo "[*] stopping/cleaning left/right namespaces..."

for NS in left right; do
  if ip netns id "$NS" &>/dev/null; then
    ip netns exec "$NS" bash -lc '
      pgrep -fa "^/usr/lib/ipsec/(starter|charon)( |$)" || true
      pgrep -fa "^/usr/lib/ipsec/(starter|charon)( |$)" | awk "{print \$1}" | xargs -r kill -9
      rm -f /var/run/charon.pid /run/charon.vici
      rm -f /run/'"$NS"'.charon.vici /run/'"$NS"'.charon.pid /var/run/'"$NS"'.charon.vici
    '
  fi
done

# Starter weltweit aus, damit nix dazwischenfunkt
systemctl disable --now strongswan-starter 2>/dev/null || true

if [[ "$NUKE" == "--nuke" ]]; then
  echo "[*] removing veth + namespaces + lab configs"
  ip -n left  link set veth-left  down 2>/dev/null || true
  ip -n right link set veth-right down 2>/dev/null || true

  ip link del veth-left 2>/dev/null || true

  ip netns del left  2>/dev/null || true
  ip netns del right 2>/dev/null || true

  rm -rf /etc/strongswan-left /etc/strongswan-right \
         /tmp/esp_left.pcap /tmp/left_keys.txt /tmp/right_keys.txt
fi

echo "[*] clear done."