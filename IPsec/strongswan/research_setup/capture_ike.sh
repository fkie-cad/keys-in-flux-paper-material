#!/usr/bin/env bash
set -euo pipefail

# --- params -------------------------------------------------------------------
SIDE="${1:-left}"             # left|right
MODE="${2:-handshake}"        # handshake|rekey
CONN="${CONN:-net}"           # connection/child name if needed

# --- per-side config (override via env) ---------------------------------------
LEFT_NS="${LEFT_NS:-left}"
RIGHT_NS="${RIGHT_NS:-right}"
LEFT_URI="${LEFT_URI:-unix:///run/left.charon.vici}"
RIGHT_URI="${RIGHT_URI:-unix:///run/right.charon.vici}"
LEFT_FILE="${LEFT_FILE:-/etc/strongswan-left/swanctl/swanctl.conf}"
RIGHT_FILE="${RIGHT_FILE:-/etc/strongswan-right/swanctl/swanctl.conf}"

[[ "$SIDE" =~ ^(left|right)$ ]] || { echo "Usage: $0 <left|right> <handshake|rekey>"; exit 1; }
[[ "$MODE" =~ ^(handshake|rekey)$ ]] || { echo "Mode must be handshake|rekey"; exit 1; }

NS="$([[ $SIDE == left ]] && echo "$LEFT_NS" || echo "$RIGHT_NS")"
URI="$([[ $SIDE == left ]] && echo "$LEFT_URI" || echo "$RIGHT_URI")"
CFG="$([[ $SIDE == left ]] && echo "$LEFT_FILE" || echo "$RIGHT_FILE")"

# --- capture setup ------------------------------------------------------------
TS="$(date +'%Y%m%d-%H%M%S')"
OUTDIR="${OUTDIR:-./dump}"
mkdir -p "$OUTDIR"
PCAP="$(readlink -f "${OUTDIR}/${SIDE}-${MODE}-${TS}.pcap")"
FILTER='udp port 500 or udp port 4500 or proto 50'

echo "[*] Starting capture in netns '${NS}' -> ${PCAP}"
sudo ip netns exec "${NS}" tcpdump -i any -s 0 -U -nn -w "${PCAP}" ${FILTER} >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.2

# --- helpers ------------------------------------------------------------------
ns() { ip netns exec "$NS" bash -lc "$*"; }
vici(){ ns "/usr/sbin/swanctl --uri '${URI}' $*"; }

have_conns() { vici --list-conns | grep -q ':'; }

detect_ike_id() {
  # returns e.g. "net[3]" (the IKE_SA id)
  vici --list-sas | awk '
    /[A-Za-z0-9_.:-]+\[[0-9]+\]:/ { id=$1 }
    /local-host:/ { if (id!=""){ print id; exit } }
  '
}

# --- load config (from the correct per-side file) -----------------------------
if ! have_conns; then
  echo "[*] Loading connections from ${CFG} ..."
  vici --load-all --file "${CFG}" || true
fi

# --- action -------------------------------------------------------------------
case "$MODE" in
  handshake)
    # If an IKE_SA exists, terminate it so we get a clean full handshake
    IKE_ID="$(detect_ike_id || true)"
    if [[ -n "${IKE_ID}" ]]; then
      echo "[*] Existing IKE_SA ${IKE_ID} found → terminating to force fresh handshake…"
      vici --terminate --ike "${IKE_ID}" || true
      sleep 0.3
    fi
    echo "[*] Initiating '${CONN}' on ${SIDE}…"
    vici --initiate --child "${CONN}" || vici --initiate --ike "${CONN}" || vici --initiate --conn "${CONN}"
    ;;

  rekey)
    # If no IKE_SA yet, bring it up first; then rekey the IKE_SA
    IKE_ID="$(detect_ike_id || true)"
    if [[ -z "${IKE_ID}" ]]; then
      echo "[*] No active IKE_SA → initiating '${CONN}' first…"
      vici --initiate --child "${CONN}" || vici --initiate --ike "${CONN}" || vici --initiate --conn "${CONN}" || true
      sleep 0.8
      IKE_ID="$(detect_ike_id || true)"
    fi
    if [[ -n "${IKE_ID}" ]]; then
      echo "[*] Rekeying IKE_SA ${IKE_ID} on ${SIDE}…"
      vici --rekey --ike "${IKE_ID}"
    else
      echo "[WARN] Could not detect IKE_SA after initiate; nothing to rekey."
    fi
    ;;
esac

# Let packets flow before we stop capture
sleep 1.5

# --- stop capture cleanly -----------------------------------------------------
if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  echo "[*] stopping capture (pid ${TCPDUMP_PID})"
  sudo kill -INT "${TCPDUMP_PID}" || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
  echo "[OK] capture saved to ${PCAP}"
else
  echo "[!] tcpdump already exited; capture may be short."
fi

# --- quick status -------------------------------------------------------------
echo
echo "[*] Current SAs on ${SIDE}:"
vici --list-sas || true
