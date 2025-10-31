#!/bin/bash
# wolfSSH entrypoint script with LLDB monitoring
# Updates ldconfig cache and starts wolfsshd under LLDB

set -e

# Update shared library cache (critical for wolfSSL/wolfSSH)
echo "Updating shared library cache..."
ldconfig

# Verify wolfSSL library is found
if ! ldconfig -p | grep -q libwolfssl; then
    echo "WARNING: libwolfssl not in library cache"
    echo "This may cause issues. Check /etc/ld.so.conf.d/"
else
    echo "✓ libwolfssl found in library cache"
fi

# Start wolfsshd with LLDB monitoring
exec /opt/lldb/run_wolfssh_lldb.sh "$@"
