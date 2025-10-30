#!/usr/bin/env bash
# clear.sh - Cleanup libreswan pluto processes and namespaces
# Adapted from strongswan clear.sh
set -euo pipefail

NUKE="${1:-}"

echo "[*] Stopping/cleaning left/right namespaces..."

# Kill pluto processes in both namespaces
for NS in left right; do
  if ip netns id "$NS" &>/dev/null; then
    echo "[*] Cleaning namespace: $NS"
    ip netns exec "$NS" bash -c '
      # Find and kill pluto processes
      PLUTO_PIDS=$(pgrep -f "/usr/(local/)?libexec/ipsec/pluto" || true)
      if [[ -n "$PLUTO_PIDS" ]]; then
        echo "  Killing pluto PIDs: $PLUTO_PIDS"
        kill -9 $PLUTO_PIDS 2>/dev/null || true
      fi

      # Remove pluto control sockets
      rm -f /var/run/pluto/*.pid /var/run/pluto/*.ctl 2>/dev/null || true
    '
  fi
done

# Disable any system-wide libreswan service
systemctl stop ipsec 2>/dev/null || true
systemctl disable ipsec 2>/dev/null || true

if [[ "$NUKE" == "--nuke" ]]; then
  echo "[*] Removing veth + namespaces + lab configs (--nuke mode)"

  # Bring down interfaces
  ip -n left  link set veth-left  down 2>/dev/null || true
  ip -n right link set veth-right down 2>/dev/null || true

  # Delete veth pair
  ip link del veth-left 2>/dev/null || true

  # Delete namespaces
  ip netns del left  2>/dev/null || true
  ip netns del right 2>/dev/null || true

  # Remove config directories
  rm -rf /etc/ipsec-left /etc/ipsec-right 2>/dev/null || true

  # Remove log files
  rm -f /tmp/pluto-left.log /tmp/pluto-right.log 2>/dev/null || true
  rm -f /var/log/pluto-left.log /var/log/pluto-right.log 2>/dev/null || true
fi

echo "[*] Clear done."
echo "[*] To completely remove namespaces, run: $0 --nuke"
