#!/usr/bin/env bash
set -euo pipefail

LEFT_NS="${LEFT_NS:-left}"
RIGHT_NS="${RIGHT_NS:-right}"
LEFT_IP="${LEFT_IP:-10.0.0.1}"
RIGHT_IP="${RIGHT_IP:-10.0.0.2}"
LEFT_URI="${LEFT_URI:-unix:///run/left.charon.vici}"
RIGHT_URI="${RIGHT_URI:-unix:///run/right.charon.vici}"

side="${1:-}"; ike_id_override="${2:-}"   # ike_id like con1[1]; or child/conn name
usage(){ echo "Usage: $0 <left|right> [ike_sa_id|child_or_conn_name]"; exit 1; }
[[ "$side" == "left" || "$side" == "right" ]] || usage

ns="$([[ $side == left ]] && echo "$LEFT_NS" || echo "$RIGHT_NS")"
want_ip="$([[ $side == left ]] && echo "$LEFT_IP" || echo "$RIGHT_IP")"
uri="$([[ $side == left ]] && echo "$LEFT_URI" || echo "$RIGHT_URI")"

ns_exec(){ ip netns exec "$ns" bash -lc "$*"; }
ns_exec "[ -S '${uri#unix://}' ]" || { echo "[ERROR] VICI socket not found: ${uri} in ns ${ns}" >&2; exit 2; }

detect_ike_id(){
  ns_exec "swanctl --list-sas --uri '${uri}'" | awk -v ip="$want_ip" '
    /[A-Za-z0-9_.:-]+\[[0-9]+\]:/ { id=$1 }
    /local-host:/ { if (index($0, ip)>0) { print id; exit } }
  '
}

id="${ike_id_override:-}"
if [[ -z "$id" ]]; then
  id="$(detect_ike_id || true)"
fi
[[ -n "$id" ]] || { echo "[ERROR] Could not auto-detect IKE_SA id for local-host ${want_ip}. Provide ike_id/child/conn." >&2; exit 3; }

echo "[*] Terminating in ns '${ns}' via ${uri} for '${id}' ..."
# Try terminate as IKE id, then CHILD, then conn
ns_exec "swanctl --terminate --uri '${uri}' --ike '${id}' \
      || swanctl --terminate --uri '${uri}' --child '${id}' \
      || swanctl --terminate --uri '${uri}' --conn '${id}'"
echo "[OK] Terminate command issued."