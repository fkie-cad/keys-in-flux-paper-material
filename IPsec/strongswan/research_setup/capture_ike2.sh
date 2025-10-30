#!/usr/bin/env bash
set -euo pipefail

# --- args ---------------------------------------------------------------------
SIDE="${1:-left}"             # left|right
MODE="${2:-handshake}"        # handshake|rekey
CONN="${CONN:-net}"           # CHILD/IKE config name to (re)use

[[ "$SIDE" =~ ^(left|right)$ ]] || { echo "Usage: $0 <left|right> <handshake|rekey>"; exit 1; }
[[ "$MODE" =~ ^(handshake|rekey)$ ]] || { echo "Mode must be handshake|rekey"; exit 1; }

# --- per-side config (override via env) ---------------------------------------
LEFT_NS="${LEFT_NS:-left}"
RIGHT_NS="${RIGHT_NS:-right}"
LEFT_URI="${LEFT_URI:-unix:///run/left.charon.vici}"
RIGHT_URI="${RIGHT_URI:-unix:///run/right.charon.vici}"
LEFT_FILE="${LEFT_FILE:-/etc/strongswan-left/swanctl/swanctl.conf}"
RIGHT_FILE="${RIGHT_FILE:-/etc/strongswan-right/swanctl/swanctl.conf}"

NS="$([[ $SIDE == left ]] && echo "$LEFT_NS" || echo "$RIGHT_NS")"
URI="$([[ $SIDE == left ]] && echo "$LEFT_URI" || echo "$RIGHT_URI")"
CFG="$([[ $SIDE == left ]] && echo "$LEFT_FILE" || echo "$RIGHT_FILE")"
URI_PATH="${URI#unix://}"

# --- capture setup ------------------------------------------------------------
TS="$(date +'%Y%m%d-%H%M%S')"
OUTDIR="${OUTDIR:-./dump}"
mkdir -p "$OUTDIR"
PCAP="$(readlink -f "${OUTDIR}/${SIDE}-${MODE}-${TS}.pcap")"
FILTER='udp port 500 or udp port 4500 or proto 50'

# --- helpers ------------------------------------------------------------------
ns() { ip netns exec "$NS" bash -lc "$*"; }
has_uri_flag() { ns "/usr/sbin/swanctl --help 2>&1 | grep -q -- '--uri'"; }
ensure_vici_default() {
  ns "
    set -e
    mkdir -p /var/run
    if [ ! -S '$URI_PATH' ]; then
      echo '[ERROR] VICI socket missing: $URI_PATH' >&2; exit 2
    fi
    ln -sf '$URI_PATH' /var/run/charon.vici
  "
}
vici() {
  if has_uri_flag; then
    ns "/usr/sbin/swanctl --uri '$URI' $*"
  else
    ensure_vici_default
    ns "/usr/sbin/swanctl $*"
  fi
}

have_conns() { vici --list-conns | grep -q ':'; }

# Return first IKE name and numeric id from --list-sas, e.g. "net 4"
detect_ike() {
  vici --list-sas | awk '
    # Header looks like: net: #4, ESTABLISHED, IKEv2, ...
    /^[^[:space:]]+:[[:space:]]*#[0-9]+,/ {
      name=$1; sub(":", "", name)
      if (match($0, /#[0-9]+,/)) {
        id=substr($0, RSTART+1, RLENGTH-2)  # digits after # (no comma)
        print name, id
        exit
      }
    }
  '
}

# --- terminate cleanly and wait until no SAs remain ---------------------------
sas_present() { vici --list-sas | grep -q 'ESTABLISHED'; }  # 0 if any SA present

wait_until_no_sas() {
  local __t="${1:-8}"
  local __ticks=$(( __t * 4 ))   # poll @ 4Hz
  local __i=0
  while sas_present; do
    if (( __i >= __ticks )); then
      echo "[WARN] SAs still present after ${__t}s"
      return 1
    fi
    (( __i++ ))
    sleep 0.25
  done
  return 0
}

# Terminate all matching IKE_SAs (by ike-id and by name), then wait
terminate_all_clean() {
  # 1) Try explicit IKE (id + name) if we can detect one
  local ike_line ike_name ike_id
  ike_line="$(detect_ike || true)"
  if [[ -n "$ike_line" ]]; then
    ike_name="$(awk '{print $1}' <<<"$ike_line")"
    ike_id="$(awk '{print $2}' <<<"$ike_line")"
    echo "[*] Terminating existing IKE_SA ${ike_name}[${ike_id}] on ${SIDE}…"
    vici --terminate --ike-id "${ike_id}" || vici --terminate --ike "${ike_name}" || true
    sleep 0.2
  fi

  # 2) Also try by CHILD and CONN names
  vici --terminate --child "${CONN}" 2>/dev/null || true
  vici --terminate --conn  "${CONN}" 2>/dev/null || true
  sleep 1.2

  # 3) As a last resort, terminate *all* visible IKE ids
  vici --list-sas | awk '
    /^[^[:space:]]+:[[:space:]]*#[0-9]+,/ {
      if (match($0, /#[0-9]+,/)) {
        print substr($0, RSTART+1, RLENGTH-2)
      }
    }' | while read -r id; do
      vici --terminate --ike-id "$id" || true
    done

  # 4) Wait until daemon actually removes SAs (up to 8s; VMs can be slow)
  wait_until_no_sas 10 || true
}

# --- start capture ------------------------------------------------------------
echo "[*] Starting capture in netns '${NS}' -> ${PCAP}"
sudo ip netns exec "${NS}" tcpdump -i any -s 0 -U -nn -w "${PCAP}" ${FILTER} >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.25

# --- load config if needed ----------------------------------------------------
if ! have_conns; then
  echo "[*] Loading connections from ${CFG} ..."
  if has_uri_flag; then
    ns "/usr/sbin/swanctl --load-all --file '${CFG}' --uri '${URI}'" || true
  else
    ensure_vici_default
    ns "/usr/sbin/swanctl --load-all --file '${CFG}'" || true
  fi
fi

# --- action -------------------------------------------------------------------
case "$MODE" in
  handshake)
    terminate_all_clean
    echo "[*] Initiating '${CONN}' on ${SIDE}…"
    # Your build doesn't support --conn; try CHILD then IKE
    if ! vici --initiate --child "${CONN}"; then
      vici --initiate --ike "${CONN}"
    fi
    ;;

  rekey)
    ike_line="$(detect_ike || true)"
    if [[ -z "${ike_line}" ]]; then
      echo "[*] No active IKE_SA -> initiating '${CONN}' first…"
      if ! vici --initiate --child "${CONN}"; then
        vici --initiate --ike "${CONN}" || true
      fi
      sleep 0.8
      ike_line="$(detect_ike || true)"
    fi
    if [[ -n "${ike_line}" ]]; then
      ike_id="$(awk '{print $2}' <<<"$ike_line")"
      echo "[*] Rekeying IKE_SA id ${ike_id} on ${SIDE}…"
      vici --rekey --ike-id "${ike_id}"
    else
      echo "[WARN] Could not detect IKE_SA after initiate; nothing to rekey."
    fi
    ;;
esac

# --- status snapshot (useful for debugging) -----------------------------------
echo
echo "[*] Current SAs on ${SIDE}:"
vici --list-sas || true

# --- allow packets to land, then stop capture --------------------------------
sleep 8  # generous to catch NAT-D + AUTH even on slow systems

if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
  echo "[*] stopping capture (pid ${TCPDUMP_PID})"
  sudo kill -INT "${TCPDUMP_PID}" || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
  echo "[OK] capture saved to ${PCAP}"
else
  echo "[!] tcpdump already exited; capture may be short."
fi