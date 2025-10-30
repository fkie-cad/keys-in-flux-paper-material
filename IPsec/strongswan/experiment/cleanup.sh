#!/usr/bin/env bash
#
# cleanup.sh - Aggressive cleanup of IPsec experiment leftovers
#
# Run this if experiments crash and leave processes/namespaces behind
# Usage: sudo ./cleanup.sh
#

set -e

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "[ERROR] This script must be run as root (use sudo)"
    exit 1
fi

echo "============================================"
echo "  IPsec Experiment Emergency Cleanup"
echo "============================================"
echo ""

# 1. Kill ALL charon processes
echo "[*] Killing all charon processes..."
CHARON_PIDS=$(pgrep -f '/usr/lib/ipsec/charon' || true)
if [[ -n "$CHARON_PIDS" ]]; then
    echo "    Found charon PIDs: $CHARON_PIDS"
    pkill -TERM -f '/usr/lib/ipsec/charon' 2>/dev/null || true
    sleep 1
    pkill -KILL -f '/usr/lib/ipsec/charon' 2>/dev/null || true
    echo "    [✓] All charon processes killed"
else
    echo "    [✓] No charon processes found"
fi

# 2. Kill ALL LLDB processes
echo "[*] Killing all LLDB processes..."
LLDB_PIDS=$(pgrep lldb || true)
if [[ -n "$LLDB_PIDS" ]]; then
    echo "    Found LLDB PIDs: $LLDB_PIDS"
    pkill -TERM lldb 2>/dev/null || true
    sleep 0.5
    pkill -KILL lldb 2>/dev/null || true
    echo "    [✓] All LLDB processes killed"
else
    echo "    [✓] No LLDB processes found"
fi

# 3. Kill tcpdump processes
echo "[*] Killing tcpdump processes..."
pkill -TERM tcpdump 2>/dev/null || true
sleep 0.5
pkill -KILL tcpdump 2>/dev/null || true
echo "    [✓] tcpdump processes killed"

# 4. Remove network namespaces
echo "[*] Removing network namespaces..."
for NS in left right; do
    if ip netns list | grep -q "^$NS"; then
        echo "    Deleting namespace: $NS"
        ip netns delete "$NS" 2>/dev/null || true
    fi
done
echo "    [✓] Namespaces removed"

# 5. Kill tmux sessions
echo "[*] Killing tmux session..."
tmux kill-session -t ipsec_experiment 2>/dev/null || true
echo "    [✓] tmux session killed"

# 6. Remove configuration directories
echo "[*] Removing configuration directories..."
rm -rf /etc/strongswan-left /etc/strongswan-right 2>/dev/null || true
echo "    [✓] Config directories removed"

# 7. Remove stale sockets and PIDs
echo "[*] Removing stale sockets and PID files..."
rm -f /run/left.charon.* /run/right.charon.* 2>/dev/null || true
rm -f /var/run/charon.pid 2>/dev/null || true
echo "    [✓] Sockets and PIDs removed"

# 8. Check for any remaining charon processes
echo ""
echo "[*] Verification:"
REMAINING=$(pgrep -f '/usr/lib/ipsec/charon' || true)
if [[ -n "$REMAINING" ]]; then
    echo "    [!] WARNING: Some charon processes still running: $REMAINING"
    echo "    Try: sudo kill -9 $REMAINING"
else
    echo "    [✓] No charon processes running"
fi

# Check namespaces
NS_COUNT=$(ip netns list 2>/dev/null | grep -E '^(left|right)' | wc -l)
if [[ $NS_COUNT -gt 0 ]]; then
    echo "    [!] WARNING: Some namespaces still exist"
    ip netns list | grep -E '^(left|right)' || true
else
    echo "    [✓] No experiment namespaces remaining"
fi

echo ""
echo "============================================"
echo "  Cleanup Complete!"
echo "============================================"
echo ""
echo "You can now run the experiment again:"
echo "  sudo ./run_ipsec_experiment.sh --workflow=full --traffic"
echo ""
