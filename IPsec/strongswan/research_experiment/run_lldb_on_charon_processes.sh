#!/usr/bin/env bash
set -euo pipefail

NS="${1:-left}"
SCRIPT="${2:-/media/psf/tls-haze/keylifespan/ipsec/strongswan/research_setup/lldb_debug/lldb_chunk_split.py}"

# Collect PIDs in the namespace
PIDS_RAW="$(sudo ip netns exec "$NS" sh -lc 'pidof charon || pgrep -x charon || true')"
if [[ -z "${PIDS_RAW// }" ]]; then
  echo "[!] No 'charon' processes found in netns '$NS'." >&2
  exit 1
fi

# Normalize into an array (handles space/newline separated lists)
mapfile -t PID_ARR < <(printf '%s\n' $PIDS_RAW | tr ' ' '\n' | sed '/^$/d')

echo "Available 'charon' processes in netns '$NS':"
i=1
for pid in "${PID_ARR[@]}"; do
  # Show a little context (pid, ppid, uptime, rss, cmd)
  LINE="$(sudo ip netns exec "$NS" sh -lc "ps -o pid=,ppid=,etime=,rss=,cmd= -p $pid | sed -E 's/^ *//'")"
  echo "  $i) $LINE"
  ((i++))
done

# Prompt user
read -rp "Select a number [1-${#PID_ARR[@]}] (or 'q' to quit): " choice
if [[ "${choice,,}" == "q" ]]; then
  echo "Aborted."
  exit 0
fi
if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#PID_ARR[@]} )); then
  echo "[!] Invalid selection." >&2
  exit 1
fi

PID="${PID_ARR[choice-1]}"
echo "[*] Attaching LLDB to PID $PID in netns '$NS'..."

# Ensure lldb exists in the netns
if ! sudo ip netns exec "$NS" sh -lc 'command -v lldb >/dev/null 2>&1'; then
  echo "[!] lldb not found inside netns '$NS'." >&2
  exit 1
fi

# Attach and prepare LLDB (stay attached & interactive; no continue/detach/quit)
sudo ip netns exec "$NS" lldb \
  -o "command script import '${SCRIPT}'" \
  -o "process attach -p ${PID}" \
  -o "install_chunk_split_bp" \
  -o "set_chunk_split_log tmp/chunk-split-${PID}.log" \
  -o "continue"
