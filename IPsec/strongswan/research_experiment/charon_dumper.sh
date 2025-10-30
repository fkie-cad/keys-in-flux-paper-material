NS=left
OUT=/media/psf/tls-haze/keylifespan/ipsec/hooking_experiments/charon-dumps
PATTERN='libstrongswan'   # regex or substring for the .so name/path
SCRIPT=/media/psf/tls-haze/keylifespan/ipsec/hooking_experiments/dump_module_ranges.py

mkdir -p "$OUT"

PIDS="$(sudo ip netns exec "$NS" sh -lc 'pidof charon || pgrep -x charon || true')"
echo "[*] Found the following charon PIDs: ${PIDS}"
for PID in $PIDS; do
  echo "[*] Start with dumping process memory of PID: ${PID}"
  SUB="${OUT}/pid${PID}"
  mkdir -p "$SUB"
  sudo ip netns exec "$NS" lldb -b -Q \
    -o "command script import ${SCRIPT}" \
    -o "process attach -p ${PID}" \
    -o "dumpmod --pattern '${PATTERN}' --out '${SUB}' --kind 'charon'" \
    -o "detach" -o "quit"
done