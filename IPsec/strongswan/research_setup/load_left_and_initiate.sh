#!/usr/bin/env bash
set -euo pipefail

NS=left
TS=$(date +'%Y%m%d-%H%M%S')
PCAP_DIR=./dump
mkdir -p "$PCAP_DIR"
PCAP="$(readlink -f "${PCAP_DIR}/left-ike-${TS}.pcap")"

# capture IKEv2 on 500/4500 + ESP
FILTER='udp port 500 or udp port 4500 or proto 50'

echo "[*] Starting capture in netns '${NS}' -> ${PCAP}"
# Start tcpdump in the namespace, but background **on the host** so $! is the real PID we can signal.
sudo ip netns exec "${NS}" \
  tcpdump -i any -s 0 -U -nn -w "${PCAP}" ${FILTER} >/dev/null 2>&1 &
TCPDUMP_PID=$!

# small pause to ensure tcpdump is up
sleep 0.2

echo "[*] Loading config and initiating IKE..."
sudo ip netns exec left /usr/sbin/swanctl --load-all \
  --file /etc/strongswan-left/swanctl/swanctl.conf \
  --uri unix:///run/left.charon.vici

sudo ip netns exec left /usr/sbin/swanctl --initiate --ike net --child net \
  --uri unix:///run/left.charon.vici

echo "[*] left: initiated IKE/CHILD."

# give the exchange a moment to complete so packets hit disk
sleep 1.0

# stop tcpdump gracefully (SIGINT) so pcap is properly closed
if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  echo "[*] stopping capture (pid ${TCPDUMP_PID})"
  sudo kill -INT "${TCPDUMP_PID}" || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
  echo "[*] capture saved to ${PCAP}"
else
  echo "[!] tcpdump already exited; capture may be short."
fi
