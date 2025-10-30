#!/usr/bin/env bash
# load_left_and_initiate.sh - Load config and initiate IPsec connection from left
# Adapted from strongswan load_left_and_initiate.sh
set -euo pipefail

NS=left
TS=$(date +'%Y%m%d-%H%M%S')
PCAP_DIR=./dump
mkdir -p "$PCAP_DIR"
PCAP="$(readlink -f "${PCAP_DIR}/left-ike-${TS}.pcap")"

# Capture IKEv2 on 500/4500 + ESP
FILTER='udp port 500 or udp port 4500 or proto 50'

echo "[*] Starting capture in netns '${NS}' -> ${PCAP}"
# Start tcpdump in the namespace, background on host so $! is the real PID
sudo ip netns exec "${NS}" \
  tcpdump -i any -s 0 -U -nn -w "${PCAP}" ${FILTER} >/dev/null 2>&1 &
TCPDUMP_PID=$!

# Small pause to ensure tcpdump is up
sleep 0.2

echo "[*] Initiating IPsec connection..."

# Libreswan: Connection should already be auto=add from ipsec.conf
# Use ipsec auto --up to initiate
sudo ip netns exec left bash -c '
    export IPSEC_CONFS=/etc/ipsec-left
    ipsec auto --up net
'

echo "[*] Left: initiated IPsec connection 'net'"

# Give the exchange a moment to complete so packets hit disk
sleep 1.0

# Stop tcpdump gracefully (SIGINT) so pcap is properly closed
if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  echo "[*] Stopping capture (PID ${TCPDUMP_PID})"
  sudo kill -INT "${TCPDUMP_PID}" || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
  echo "[*] Capture saved to ${PCAP}"
else
  echo "[!] tcpdump already exited; capture may be short"
fi

echo "[*] Check status with: ip netns exec left ipsec status"
