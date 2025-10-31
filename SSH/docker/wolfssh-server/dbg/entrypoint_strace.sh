#!/bin/bash
set -e

echo "========================================================================"
echo "  wolfSSH Debug Container - STRACE Mode"
echo "========================================================================"
echo ""
echo "This mode uses strace to trace system calls and identify KEX functions"
echo "that may not be visible in debug logs."
echo ""
echo "========================================================================"
echo ""

STRACE_LOG="/data/debug_logs/wolfssh_strace_$(date +%Y%m%d_%H%M%S).log"

echo "Starting wolfsshd under strace..."
echo "Strace output: $STRACE_LOG"
echo ""

# Run with strace to trace function calls
strace -f -o "$STRACE_LOG" \
    -e trace=open,openat,read,write,socket,connect,accept,fork,execve \
    wolfsshd -D -d -f /dev/null
