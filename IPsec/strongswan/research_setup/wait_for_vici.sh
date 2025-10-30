#!/usr/bin/env bash
# wait_for_vici.sh <socket-path> <timeout-s> [<ns-name>]
# Verifies both: the socket file exists AND a process is LISTENing on it.

set -euo pipefail
if [ $# -lt 2 ]; then
  echo "Usage: $0 <socket-path> <timeout-s> [<netns>]" >&2
  exit 2
fi

SOCK="$1"
TIMEOUT="$2"
NS="${3:-}"

run() {
  if [ -n "$1" ]; then
    ip netns exec "$1" bash -lc "$2"
  else
    bash -lc "$2"
  fi
}

i=0
while [ $i -lt "$TIMEOUT" ]; do
  if run "$NS" "[ -S '$SOCK' ]"; then
    # check listener
    if run "$NS" "ss -xpl | grep -F -- '$SOCK' >/dev/null 2>&1"; then
      echo "VICI listener ready at $SOCK"
      exit 0
    fi
  fi
  sleep 1
  i=$((i+1))
done

echo "Timeout: no active VICI listener for $SOCK after ${TIMEOUT}s" >&2
echo "Hint: run foreground to see errors, e.g.:" >&2
echo "  sudo ip netns exec ${NS:-<ns>} bash -lc 'export STRONGSWAN_CONF=<conf>; /usr/lib/ipsec/charon --nofork --use-syslog no --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 --debug-net 2'" >&2
exit 1