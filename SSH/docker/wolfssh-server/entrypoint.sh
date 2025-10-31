#!/bin/bash
# wolfSSH entrypoint script
# Updates ldconfig cache and starts wolfsshd

set -e

# Update shared library cache
ldconfig

# Start wolfsshd with provided arguments
exec /usr/local/bin/wolfsshd "$@"
