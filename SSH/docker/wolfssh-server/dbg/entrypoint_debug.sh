#!/bin/bash
set -e

echo "========================================================================"
echo "  wolfSSH Debug Container - Verbose Logging Mode"
echo "========================================================================"
echo ""
echo "Port: 22 (exposed as 2229 on host)"
echo "Debug Log: /data/debug_logs/wolfssh_debug.log"
echo ""
echo "This container runs wolfSSH with maximum verbose output to identify"
echo "which KEX functions are actually called during key exchange."
echo ""
echo "========================================================================"
echo ""

# Set debug environment variables
export WOLFSSL_DEBUG_ON=1
export WOLFSSH_DEBUG=1

# Create debug log file
DEBUG_LOG="/data/debug_logs/wolfssh_debug_$(date +%Y%m%d_%H%M%S).log"
touch "$DEBUG_LOG"
echo "Debug output will be logged to: $DEBUG_LOG"
echo ""

# Function to log with timestamp
log_msg() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S.%N')] $1" | tee -a "$DEBUG_LOG"
}

log_msg "Creating minimal wolfsshd configuration..."
cat > /tmp/wolfsshd_config << 'CONFIG_EOF'
# wolfSSH Debug Configuration
Port 22
HostKey /etc/ssh/ssh_host_rsa_key
PasswordAuthentication yes
CONFIG_EOF

log_msg "Starting wolfSSH server with verbose debugging..."
log_msg "Command: wolfsshd -D -d -d -d -f /tmp/wolfsshd_config"
log_msg ""

# Run wolfsshd with maximum verbosity
# -D: Don't daemonize (foreground)
# -d: Debug mode (can be repeated for more verbosity)
# -f /tmp/wolfsshd_config: Config file with host keys
wolfsshd -D -d -d -d -f /tmp/wolfsshd_config 2>&1 | while IFS= read -r line; do
    log_msg "$line"
done
