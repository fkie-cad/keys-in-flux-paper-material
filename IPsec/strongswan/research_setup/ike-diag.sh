#!/usr/bin/env bash
set -euo pipefail
SIDE="${1:-}"; [[ "$SIDE" =~ ^(left|right)$ ]] || { echo "Usage: $0 <left|right>"; exit 1; }

URI="unix:///run/${SIDE}.charon.vici"

echo "[*] Checking VICI socket: ${URI}"
if [[ ! -S "${URI#unix://}" ]]; then
  echo "[ERROR] Socket not found: ${URI#unix://}"
  echo "       Enable 'vici' plugin and ensure this instance writes to this path."
  exit 2
fi
stat "${URI#unix://}" || true

echo; echo "[*] Listing connections on ${SIDE}…"
if ! sudo swanctl --list-conns --uri "${URI}"; then
  echo "[ERROR] Failed to talk to ${URI} — is vici plugin enabled in this charon?"
  exit 3
fi

echo; echo "[*] Listing SAs on ${SIDE}…"
if ! sudo swanctl --list-sas --uri "${URI}"; then
  echo "[WARN] Could not list SAs."
fi

echo; echo "[*] If connections were empty, trying --load-all…"
sudo swanctl --load-all --uri "${URI}" || true

echo; echo "[*] Listing connections (post-load)…"
sudo swanctl --list-conns --uri "${URI}" || true

echo; echo "[*] Listing SAs (post-load)…"
sudo swanctl --list-sas --uri "${URI}" || true