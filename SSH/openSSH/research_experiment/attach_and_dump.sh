#!/usr/bin/env bash
# attach_and_dump.sh - attach lldb to (first) sshd pid and import hook_kex.py
set -euo pipefail
PID=$(pgrep -o sshd || true)
if [ -z "$PID" ]; then
  echo "no sshd found"
  exit 1
fi
echo "[+] attaching to sshd pid $PID with lldb and importing hook_kex.py"
# run interactive lldb session - you can alternatively run the following
# and then inside lldb do: command script import /opt/ssh-debug/hook_kex.py
lldb -p "$PID" -o "command script import /opt/ssh-debug/hook_kex.py" -o "expr 0" 
# note: the -o "expr 0" keeps lldb attached - if you want a persistent lldb console omit -o expr 0