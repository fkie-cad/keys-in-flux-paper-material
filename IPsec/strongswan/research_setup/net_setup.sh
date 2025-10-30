#!/usr/bin/env bash
set -euo pipefail

LEFT_NS=left
RIGHT_NS=right
LEFT_IP=10.0.0.1/24
RIGHT_IP=10.0.0.2/24

ip netns add "$LEFT_NS"  2>/dev/null || true
ip netns add "$RIGHT_NS" 2>/dev/null || true

if ! ip link show veth-left &>/dev/null; then
  ip link add veth-left type veth peer name veth-right
fi

ip link set veth-left  netns "$LEFT_NS" 2>/dev/null || true
ip link set veth-right netns "$RIGHT_NS" 2>/dev/null || true

ip -n "$LEFT_NS"  addr add "$LEFT_IP"  dev veth-left  2>/dev/null || true
ip -n "$RIGHT_NS" addr add "$RIGHT_IP" dev veth-right 2>/dev/null || true

ip -n "$LEFT_NS"  link set lo up
ip -n "$RIGHT_NS" link set lo up
ip -n "$LEFT_NS"  link set veth-left up
ip -n "$RIGHT_NS" link set veth-right up

echo "[*] ping sanity"
ip netns exec "$LEFT_NS" ping -c1 -W1 10.0.0.2 >/dev/null && echo "OK" || echo "WARN: ping failed (will still proceed)"