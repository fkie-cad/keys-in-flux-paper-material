#!/usr/bin/env bash
set -euo pipefail

NS="${1:-left}"                               # netns (default: left)
OUT="${2:-/tmp}"
TS="$(date +'%Y%m%d-%H%M%S')"

mkdir -p "$OUT"

# Resolve all PIDs for charon inside the namespace (pidof first, fallback to pgrep)
PIDS="$(sudo ip netns exec "$NS" sh -lc 'pidof charon || pgrep -x charon || true')"

echo "[*] Netns: $NS"
echo "[*] Candidate PIDs for 'charon': ${PIDS:-<none>}"
echo "[*] Output dir: $OUT"

if [[ -z "${PIDS// }" ]]; then
  echo "[!] No 'charon' PIDs found inside netns '$NS'." >&2
  exit 1
fi

# Ensure lldb exists in the netns
if ! sudo ip netns exec "$NS" sh -lc 'command -v lldb >/dev/null 2>&1'; then
  echo "[!] lldb not found inside netns '$NS'." >&2
  exit 1
fi

ok=0
fail=0

for PID in $PIDS; do
  core="${OUT}/charon-${NS}-${TS}-pid${PID}.core"
  maps="${OUT}/charon-${NS}-${TS}-pid${PID}.maps"

  echo "------------------------------------------------------------"
  echo "[*] Processing PID ${PID}"
  echo "[*] Core target: ${core}"
  echo "[*] Maps target: ${maps}"

  # Attach & dump core for this PID
  if sudo ip netns exec "$NS" lldb -b -Q \
      -o "process attach -p ${PID}" \
      -o "process save-core ${core}" \
      -o "detach" -o "quit"; then

    # Optionally verify the core file exists and is non-empty
    if [[ -s "${core}" ]]; then
      echo "[+] Core saved: ${core}"
    else
      echo "[!] Core file missing or empty after LLDB for PID ${PID}" >&2
    fi

    # Save /proc/<pid>/maps for later correlation (do not fail the loop if this errors)
    if sudo ip netns exec "$NS" sh -lc "cat /proc/${PID}/maps" > "${maps}"; then
      echo "[+] Maps saved: ${maps}"
    else
      echo "[!] Failed to save maps for PID ${PID}" >&2
    fi

    ((ok++))
  else
    echo "[!] LLDB attach/dump failed for PID ${PID}" >&2
    ((fail++))
    # Continue with next PID
    continue
  fi
done

echo "============================================================"
echo "[✓] Finished. Success: ${ok}, Failed: ${fail}"
echo "[i] Files are in: ${OUT}"