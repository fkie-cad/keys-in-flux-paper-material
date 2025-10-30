#!/usr/bin/env bash
set -euo pipefail

# Usage: ./charon_dump_lib.sh [netns] [outdir] [lib_pattern]
# Example: ./charon_dump_lib.sh left /tmp 'libstrongswan'
# Pattern matches against the pathname in /proc/<pid>/maps (regex via awk ~)

NS="${1:-left}"
OUT="${2:-/tmp}"
LIBPATTERN="${3:-libstrongswan.so}"      # regex pattern to match .so path (basename or full path)
TS="$(date +'%Y%m%d-%H%M%S')"

mkdir -p "$OUT"

echo "[*] Netns: $NS"
echo "[*] Output dir: $OUT"
echo "[*] Library pattern: $LIBPATTERN"

# Collect all charon PIDs in the namespace
PIDS="$(sudo ip netns exec "$NS" sh -lc 'pidof charon || pgrep -x charon || true')"
echo "[*] Candidate PIDs for 'charon': ${PIDS:-<none>}"
if [[ -z "${PIDS// }" ]]; then
  echo "[!] No 'charon' PIDs found in netns '$NS'." >&2
  exit 1
fi

# Ensure lldb exists in the netns
if ! sudo ip netns exec "$NS" sh -lc 'command -v lldb >/dev/null 2>&1'; then
  echo "[!] lldb not found inside netns '$NS'." >&2
  exit 1
fi

ok=0; fail=0

echo "[*] Charon PIDS: ${PIDS}"

for PID in $PIDS; do
  echo "------------------------------------------------------------"
  echo "[*] PID ${PID}: scanning /proc/${PID}/maps for '$LIBPATTERN'..."

  # Pull maps for this PID from inside the netns
  MAPS_FILE="${OUT}/charon-${NS}-${TS}-pid${PID}.maps"
  sudo ip netns exec "$NS" sh -lc "cat /proc/${PID}/maps" > "${MAPS_FILE}"

  # Pick only lines that have a pathname matching LIBPATTERN and readable perms
  # /proc/<pid>/maps format: addr perms offset dev inode pathname
  # We match against the last field ($NF) and require 'r' in perms ($2).
  MATCHED_RANGES_FILE="$(mktemp)"
  awk -v pat="$LIBPATTERN" '
    NF >= 6 && $0 ~ pat {
      addr=$1; perms=$2; path=$NF;
      if (index(perms,"r")>0) {
        split(addr, a, "-");
        print a[1], a[2], perms, path
      }
    }' "${MAPS_FILE}" > "${MATCHED_RANGES_FILE}"

  if [[ ! -s "${MATCHED_RANGES_FILE}" ]]; then
    echo "[!] No readable mappings for pattern '${LIBPATTERN}' in PID ${PID}."
    ((fail++))
    rm -f "${MATCHED_RANGES_FILE}"
    continue
  fi

  # Create a manifest for traceability
  MANIFEST="${OUT}/charon-${NS}-${TS}-pid${PID}.manifest.json"
  {
    echo "{"
    echo "  \"pid\": ${PID},"
    echo "  \"timestamp\": \"${TS}\","
    echo "  \"netns\": \"${NS}\","
    echo "  \"pattern\": \"${LIBPATTERN}\","
    echo "  \"maps_file\": \"${MAPS_FILE}\","
    echo "  \"chunks\": ["
  } > "${MANIFEST}"

  # Build an LLDB command script to dump each selected range
  LLDB_CMDS="$(mktemp)"
  idx=0
  while read -r START END PERMS PATHNAME; do
    # Sanitize names for output filenames
    base="$(basename -- "$PATHNAME")"
    outbin="${OUT}/charon-${NS}-${TS}-pid${PID}-${base}-chunk${idx}-${START}-${END}.bin"
    echo "[*]  -> dump ${base} [${PERMS}] ${START}-${END} to $(basename "$outbin")"

    # LLDB memory read command (binary)
    echo "memory read --force --binary --outfile '${outbin}' 0x${START} 0x${END}" >> "${LLDB_CMDS}"

    # Append to manifest
    printf '    { "index": %d, "start": "0x%s", "end": "0x%s", "perms": "%s", "path": "%s", "outfile": "%s" },\n' \
      "$idx" "$START" "$END" "$PERMS" "$PATHNAME" "$outbin" >> "${MANIFEST}"
    ((idx++))
  done < "${MATCHED_RANGES_FILE}"

  # Finish manifest (trim trailing comma)
  # Simple sed to remove the last trailing comma before closing ]
  sed -i '$ s/},/}/' "${MANIFEST}" 2>/dev/null || true
  echo "  ]" >> "${MANIFEST}"
  echo "}" >> "${MANIFEST}"

  # Now run LLDB inside the netns against the live PID with the scripted commands
  if sudo ip netns exec "$NS" lldb -b -Q -o "process attach -p ${PID}" -s "${LLDB_CMDS}" -o "detach" -o "quit"; then
    echo "[+] PID ${PID}: dumps completed. See ${MANIFEST}"
    ((ok++))
  else
    echo "[!] PID ${PID}: LLDB attach/dump failed." >&2
    ((fail++))
  fi

  rm -f "${LLDB_CMDS}" "${MATCHED_RANGES_FILE}"
done

echo "============================================================"
echo "[✓] Finished. Success: ${ok}, Failed: ${fail}"
echo "[i] Outputs are in: ${OUT}"