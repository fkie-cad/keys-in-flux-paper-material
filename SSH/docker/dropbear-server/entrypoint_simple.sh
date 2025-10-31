#!/bin/bash
# Simple Dropbear entrypoint - start server normally WITHOUT LLDB
# LLDB can be attached later if needed

set -e

echo "Starting Dropbear SSH server..."
echo "Port: 22 (exposed as 2223)"
echo ""

# Start Dropbear in foreground
exec /usr/sbin/dropbear -F -E -p 22
