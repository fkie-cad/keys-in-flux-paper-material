#!/usr/bin/env bash
#
# run_ipsec_experiment.sh
#
# Complete orchestration script for IPsec/strongSwan key lifecycle experiments
# Manages network namespaces, charon processes, LLDB monitoring, and kernel scanning
#
# Requirements:
#   - Ubuntu 24.04 (tested)
#   - strongSwan installed
#   - lldb installed
#   - Python 3 with drgn module (for kernel monitoring)
#   - tmux or gnome-terminal (for terminal spawning)
#
# Usage:
#   sudo ./run_ipsec_experiment.sh
#
# Environment Variables (optional):
#   KERNEL_SCAN_FREELISTS=true   Enable SLUB freelist scanning (finds freed keys, terminate only)
#   KERNEL_SCAN_STACKS=true      Enable kernel stack scanning (finds residual keys, terminate only)
#   KERNEL_SCAN_VMALLOC=true     Enable vmalloc region scanning (finds vmalloc keys, terminate only)
#
# Example with forensic scanning:
#   sudo KERNEL_SCAN_FREELISTS=true KERNEL_SCAN_STACKS=true KERNEL_SCAN_VMALLOC=true ./run_ipsec_experiment.sh
#

set -uo pipefail
# Note: Don't use -e to avoid silent exits - we handle errors explicitly

#=============================================================================
# Configuration
#=============================================================================

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
EXPERIMENT_DIR="$SCRIPT_DIR"

# Network configuration
LEFT_NS="left"
RIGHT_NS="right"
LEFT_IP="10.0.0.1"
RIGHT_IP="10.0.0.2"
LEFT_VETH="veth-left"
RIGHT_VETH="veth-right"

# strongSwan configuration
LEFT_CONF_DIR="/etc/strongswan-left"
RIGHT_CONF_DIR="/etc/strongswan-right"
LEFT_VICI="unix:///run/left.charon.vici"
RIGHT_VICI="unix:///run/right.charon.vici"

# Experiment output
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
OUTPUT_DIR="$EXPERIMENT_DIR/results/$TIMESTAMP"
USERSPACE_DIR="$OUTPUT_DIR/userspace"
KERNEL_DIR="$OUTPUT_DIR/kernel"
NETWORK_DIR="$OUTPUT_DIR/network"
EXPERIMENT_LOG="$OUTPUT_DIR/experiment.log"

# Process tracking
LEFT_CHARON_PID=""
RIGHT_CHARON_PID=""
LEFT_LLDB_PID=""
RIGHT_LLDB_PID=""
LEFT_TCPDUMP_PID=""
RIGHT_TCPDUMP_PID=""

# Cleanup state tracking (prevents double-cleanup from ERR trap)
export CLEANUP_IN_PROGRESS=false

# Terminal spawner (tmux or gnome-terminal)
TERM_SPAWNER=""

# Python interpreter for kernel monitoring (detected in check_dependencies)
KERNEL_PYTHON=""

# Experiment mode configuration (can be overridden by CLI arguments)
MODE="interactive"          # interactive or auto
WORKFLOW="none"             # none, initiate, rekey, terminate, full
ENABLE_TRAFFIC=false        # Generate ESP traffic after events
SKIP_LLDB=false             # Skip LLDB userspace monitoring
HTTP_PORT=8080              # Port for ESP traffic HTTP server

#=============================================================================
# Signal handling - cleanup on interruption
#=============================================================================

cleanup_on_signal() {
    local signal="$1"

    # Debug: Always log that trap was triggered
    # Use ${VAR:-} to avoid errors with set -u when variables are unset
    echo "[DEBUG] cleanup_on_signal called with signal: $signal (CLEANUP_IN_PROGRESS=${CLEANUP_IN_PROGRESS:-}, CLEANUP_COMPLETED=${CLEANUP_COMPLETED:-})" >&2

    # If cleanup already completed, skip
    if [[ "${CLEANUP_COMPLETED:-}" == "true" ]]; then
        echo "[DEBUG] Cleanup already completed successfully, skipping" >&2
        return 0
    fi

    # If cleanup is in progress and this is a new trap, wait briefly then skip
    # This handles race conditions where multiple traps fire simultaneously
    if [[ "${CLEANUP_IN_PROGRESS:-}" == "true" ]]; then
        echo "[DEBUG] Cleanup in progress from another trap, waiting..." >&2
        sleep 0.5  # Brief wait in case other cleanup is finishing
        if [[ "${CLEANUP_COMPLETED:-}" == "true" ]]; then
            echo "[DEBUG] Other cleanup completed, skipping" >&2
            return 0
        fi
        echo "[DEBUG] Cleanup still in progress after wait, skipping to avoid conflict" >&2
        return 0
    fi

    # Mark cleanup as in progress
    export CLEANUP_IN_PROGRESS=true

    echo "[DEBUG] Proceeding with cleanup for signal: $signal" >&2
    if [[ "$signal" == "EXIT" ]]; then
        log_info "Script exiting normally - running cleanup.sh..."
    else
        log_warn "Received signal $signal - running cleanup.sh..."
    fi


    # Call cleanup script
    local cleanup_script="$EXPERIMENT_DIR/cleanup.sh"
    if [[ -f "$cleanup_script" ]]; then
        echo "[DEBUG] Executing: bash $cleanup_script" >&2
        bash "$cleanup_script"
        local cleanup_exit=$?
        echo "[DEBUG] cleanup.sh completed with exit code $cleanup_exit" >&2

        # Mark as completed
        export CLEANUP_COMPLETED=true
    else
        log_error "Cleanup script not found: $cleanup_script"
    fi

    # Exit with appropriate code (skip for EXIT trap - already exiting)
    case "$signal" in
        INT)   exit 130 ;;  # 128 + 2
        TERM)  exit 143 ;;  # 128 + 15
        ERR)   exit 1   ;;
        EXIT)
            echo "[DEBUG] EXIT trap cleanup complete, returning" >&2
            return 0 ;;  # Already exiting, just return
        *)     exit 1   ;;
    esac
}

# Trap signals - INT (Ctrl+C), TERM, ERR, and EXIT (normal quit)
trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM
trap 'if [[ "${CLEANUP_IN_PROGRESS:-}" != "true" ]]; then cleanup_on_signal ERR; fi' ERR
trap 'cleanup_on_signal EXIT' EXIT

#=============================================================================
# Color output
#=============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log to both console and file
log_to_file() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')

    # Write to log file if it exists
    if [[ -n "${EXPERIMENT_LOG:-}" && -f "$EXPERIMENT_LOG" ]]; then
        echo "[$timestamp] [$level] $msg" >> "$EXPERIMENT_LOG"
    fi
}

log_info() {
    echo -e "${BLUE}[*]${NC} $*"
    log_to_file "INFO" "$*"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $*"
    log_to_file "SUCCESS" "$*"
}

log_warn() {
    echo -e "${YELLOW}[!]${NC} $*"
    log_to_file "WARN" "$*"
}

log_error() {
    echo -e "${RED}[✗]${NC} $*"
    log_to_file "ERROR" "$*"
}

log_debug() {
    local msg="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    if [[ -n "${EXPERIMENT_LOG:-}" && -f "$EXPERIMENT_LOG" ]]; then
        echo "[$timestamp] [DEBUG] $msg" >> "$EXPERIMENT_LOG"
    fi
}

log_command() {
    local cmd="$*"
    log_debug "Executing: $cmd"
}

#=============================================================================
# Helper functions
#=============================================================================

check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

IPsec/strongSwan Key Lifecycle Experiment

MODES:
  --mode=MODE           Experiment mode: interactive (default) or auto
  --workflow=WORKFLOW   Workflow to run: none, initiate, rekey, terminate, full
                        - full: initiate → rekey → terminate
                        - Implies --mode=auto

OPTIONS:
  --traffic             Generate ESP traffic (HTTP) after each event
  --skip-lldb           Skip LLDB userspace monitoring
                        NOTE: LLDB is needed to capture IKE SA secrets (SK_ai, SK_ar, etc)
                        Kernel dumps only capture ESP keys, not IKE handshake keys
                        Use --skip-lldb only if VICI issues persist
  --http-port=PORT      HTTP server port for ESP traffic (default: 8080)
  --help, -h            Show this help message

EXAMPLES:
  # Automated full workflow with LLDB (captures IKE + ESP keys):
  sudo ./run_ipsec_experiment.sh --workflow=full --traffic

  # Without LLDB (kernel ESP keys only, more reliable):
  sudo ./run_ipsec_experiment.sh --workflow=full --traffic --skip-lldb

  # Interactive mode (manual control):
  sudo ./run_ipsec_experiment.sh

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode=*)
                MODE="${1#*=}"
                if [[ "$MODE" != "interactive" && "$MODE" != "auto" ]]; then
                    log_error "Invalid mode: $MODE (must be 'interactive' or 'auto')"
                    exit 1
                fi
                ;;
            --workflow=*)
                WORKFLOW="${1#*=}"
                if [[ "$WORKFLOW" != "none" && "$WORKFLOW" != "initiate" && "$WORKFLOW" != "rekey" && "$WORKFLOW" != "terminate" && "$WORKFLOW" != "full" ]]; then
                    log_error "Invalid workflow: $WORKFLOW"
                    exit 1
                fi
                # Workflow implies auto mode
                MODE="auto"
                ;;
            --traffic)
                ENABLE_TRAFFIC=true
                ;;
            --skip-lldb)
                SKIP_LLDB=true
                ;;
            --http-port=*)
                HTTP_PORT="${1#*=}"
                ;;
            --help|-h)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
        shift
    done

    # Validate configuration
    if [[ "$WORKFLOW" != "none" && "$MODE" != "auto" ]]; then
        log_error "Workflow specified but mode is not 'auto'"
        exit 1
    fi

    # Log configuration
    log_debug "Configuration:"
    log_debug "  Mode: $MODE"
    log_debug "  Workflow: $WORKFLOW"
    log_debug "  Traffic: $ENABLE_TRAFFIC"
    log_debug "  Skip LLDB: $SKIP_LLDB"
    log_debug "  HTTP Port: $HTTP_PORT"
}

detect_terminal_spawner() {
    # For automated workflows, always use background mode (tmux can cause VICI issues)
    if [[ "$MODE" == "auto" ]]; then
        TERM_SPAWNER="background"
        log_info "Automated mode: using background LLDB (no tmux)"
        return
    fi

    # For interactive mode, prefer tmux/gnome-terminal for visibility
    if command -v tmux >/dev/null 2>&1; then
        TERM_SPAWNER="tmux"
        log_info "Using tmux for terminal spawning"
    elif command -v gnome-terminal >/dev/null 2>&1; then
        TERM_SPAWNER="gnome-terminal"
        log_info "Using gnome-terminal for terminal spawning"
    else
        log_warn "Neither tmux nor gnome-terminal found"
        log_warn "LLDB monitoring will run in background"
        TERM_SPAWNER="background"
    fi
}

detect_python_for_kernel() {
    # Detect which Python interpreter to use for kernel monitoring (drgn)
    # Checks in order:
    # 1. VIRTUAL_ENV environment variable (preserved with sudo -E)
    # 2. Common venv locations relative to script directory
    # 3. Check the original user's current directory for venv (via SUDO_USER)
    # 4. System python3

    local python_candidate=""

    # Check if VIRTUAL_ENV is set (e.g., when using sudo -E)
    if [[ -n "${VIRTUAL_ENV:-}" ]]; then
        python_candidate="$VIRTUAL_ENV/bin/python"
        if [[ -x "$python_candidate" ]]; then
            log_info "Detected virtual environment at: $VIRTUAL_ENV"
            KERNEL_PYTHON="$python_candidate"
            return 0
        fi
    fi

    # Check for common venv locations relative to script directory
    local venv_paths=(
        "$SCRIPT_DIR/env/bin/python"
        "$SCRIPT_DIR/../env/bin/python"
        "$SCRIPT_DIR/../../env/bin/python"
        "$SCRIPT_DIR/venv/bin/python"
        "$SCRIPT_DIR/../venv/bin/python"
    )

    for python_candidate in "${venv_paths[@]}"; do
        if [[ -x "$python_candidate" ]]; then
            # Verify drgn is available in this venv
            if "$python_candidate" -c "import drgn" 2>/dev/null; then
                log_info "Found virtual environment with drgn at: $python_candidate"
                KERNEL_PYTHON="$python_candidate"
                return 0
            fi
        fi
    done

    # If running under sudo, check the original user's PWD
    if [[ -n "${SUDO_USER:-}" ]]; then
        # Get the original directory before sudo
        local original_pwd="${PWD}"
        local original_env="$original_pwd/env/bin/python"
        local original_venv="$original_pwd/venv/bin/python"

        for python_candidate in "$original_env" "$original_venv"; do
            if [[ -x "$python_candidate" ]]; then
                if "$python_candidate" -c "import drgn" 2>/dev/null; then
                    log_info "Found virtual environment with drgn at: $python_candidate"
                    KERNEL_PYTHON="$python_candidate"
                    return 0
                fi
            fi
        done
    fi

    # Fall back to system python3
    if command -v python3 >/dev/null 2>&1; then
        KERNEL_PYTHON="python3"
        log_info "Using system python3"
        return 0
    fi

    log_error "No Python 3 interpreter found"
    return 1
}

check_dependencies() {
    log_info "Checking dependencies..."

    local missing=()

    command -v ip >/dev/null 2>&1 || missing+=("iproute2")
    command -v swanctl >/dev/null 2>&1 || missing+=("strongswan/swanctl")
    command -v lldb >/dev/null 2>&1 || missing+=("lldb")
    command -v python3 >/dev/null 2>&1 || missing+=("python3")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing dependencies: ${missing[*]}"
        exit 1
    fi

    # Detect Python interpreter for kernel monitoring
    if ! detect_python_for_kernel; then
        log_error "Failed to detect Python interpreter"
        exit 1
    fi

    # Check Python modules (we're already running as root)
    # Use the detected Python interpreter
    log_info "Checking drgn module availability (using: $KERNEL_PYTHON)..."
    if ! "$KERNEL_PYTHON" -c "import drgn" 2>/dev/null; then
        log_warn "drgn module not found for $KERNEL_PYTHON - kernel monitoring will be skipped"
        log_warn "Install with: sudo $KERNEL_PYTHON -m pip install drgn"
        SKIP_KERNEL_MONITORING=true
    else
        log_success "drgn module available"
        SKIP_KERNEL_MONITORING=false
    fi

    log_success "All dependencies OK"
}

#=============================================================================
# Network namespace setup
#=============================================================================

cleanup_netns() {
    local nuke_mode="${1:-}"

    # Prevent double cleanup (e.g., from ERR trap after explicit cleanup call)
    if [[ "${CLEANUP_IN_PROGRESS:-}" == "true" ]]; then
        log_debug "Cleanup already in progress, skipping duplicate call"
        return 0
    fi
    CLEANUP_IN_PROGRESS=true

    log_info "Cleaning up network namespaces..."

    # Stop packet capture if running
    if [[ -n "${LEFT_TCPDUMP_PID:-}" ]] || [[ -n "${RIGHT_TCPDUMP_PID:-}" ]]; then
        stop_packet_capture
    fi

    # Copy strongSwan logs before cleanup
    if [[ -d "/var/log/strongswan" && -n "${OUTPUT_DIR:-}" ]]; then
        log_debug "Copying strongSwan logs..."
        mkdir -p "$OUTPUT_DIR/strongswan_logs"
        cp -r /var/log/strongswan/* "$OUTPUT_DIR/strongswan_logs/" 2>/dev/null || true
    fi

    # Disable strongswan-starter globally to prevent conflicts
    systemctl disable --now strongswan-starter 2>/dev/null || true

    # Kill charon processes by netns inode (more reliable than pkill)
    for NS in "$LEFT_NS" "$RIGHT_NS"; do
        if ip netns id "$NS" &>/dev/null; then
            log_debug "Cleaning charon processes in namespace $NS..."

            # Get netns inode
            local ns_ino
            ns_ino=$(stat -c %i "/var/run/netns/$NS" 2>/dev/null || true)

            if [[ -n "$ns_ino" ]]; then
                # Find and terminate charon processes by netns inode
                for proc in /proc/[0-9]*; do
                    local pid="${proc##*/}"
                    local ns_link
                    ns_link=$(readlink "$proc/ns/net" 2>/dev/null || true)

                    if [[ "$ns_link" == "net:[$ns_ino]" ]]; then
                        local cmdline
                        cmdline=$(tr -d '\0' < "$proc/cmdline" 2>/dev/null | sed 's/\x0/ /g' || true)

                        if echo "$cmdline" | grep -q "/usr/lib/ipsec/charon"; then
                            log_debug "  Killing charon pid $pid in $NS"
                            kill -TERM "$pid" 2>/dev/null || true
                        fi
                    fi
                done

                sleep 0.5

                # Force kill if still running
                for proc in /proc/[0-9]*; do
                    local pid="${proc##*/}"
                    local ns_link
                    ns_link=$(readlink "$proc/ns/net" 2>/dev/null || true)

                    if [[ "$ns_link" == "net:[$ns_ino]" ]]; then
                        local cmdline
                        cmdline=$(tr -d '\0' < "$proc/cmdline" 2>/dev/null | sed 's/\x0/ /g' || true)

                        if echo "$cmdline" | grep -q "/usr/lib/ipsec/charon"; then
                            log_debug "  Force killing charon pid $pid"
                            kill -KILL "$pid" 2>/dev/null || true
                        fi
                    fi
                done
            fi

            # Remove stale sockets/pids inside namespace
            ip netns exec "$NS" bash -lc 'rm -f /run/*.charon.vici /run/*.charon.pid /var/run/charon.pid' 2>/dev/null || true
        fi
    done

    # Explicitly bring down and delete veth links before removing namespaces
    log_debug "Removing veth links..."
    ip -n "$LEFT_NS" link set "$LEFT_VETH" down 2>/dev/null || true
    ip -n "$RIGHT_NS" link set "$RIGHT_VETH" down 2>/dev/null || true
    ip link del "$LEFT_VETH" 2>/dev/null || true

    # Delete namespaces
    log_debug "Deleting network namespaces..."
    ip netns delete "$LEFT_NS" 2>/dev/null || true
    ip netns delete "$RIGHT_NS" 2>/dev/null || true

    # Kill tmux session if it exists
    if [[ "$TERM_SPAWNER" == "tmux" ]] && tmux has-session -t ipsec_experiment 2>/dev/null; then
        log_debug "Killing tmux session 'ipsec_experiment'"
        tmux kill-session -t ipsec_experiment 2>/dev/null || true
    fi

    # Remove config directories and temp files
    log_debug "Removing config directories and temp files..."
    rm -rf "$LEFT_CONF_DIR" "$RIGHT_CONF_DIR" 2>/dev/null || true
    rm -f /run/left.charon.* /run/right.charon.* 2>/dev/null || true
    rm -f /tmp/esp_left.pcap /tmp/left_keys.txt /tmp/right_keys.txt 2>/dev/null || true

    # CRITICAL: Kill any remaining charon processes system-wide (fallback)
    # This catches orphaned processes that escaped namespace cleanup
    log_debug "Checking for orphaned charon processes..."
    local remaining_charons
    remaining_charons=$(pgrep -f '/usr/lib/ipsec/charon' || true)
    if [[ -n "$remaining_charons" ]]; then
        log_warn "Found orphaned charon processes, killing: $remaining_charons"
        pkill -TERM -f '/usr/lib/ipsec/charon' 2>/dev/null || true
        sleep 0.5
        pkill -KILL -f '/usr/lib/ipsec/charon' 2>/dev/null || true
    fi

    log_success "Cleanup complete"

    # Reset CLEANUP_IN_PROGRESS flag so EXIT trap can run later
    # This function is called at the START of the experiment (line 1648) to clean
    # previous state, and we need EXIT trap to work at the END of the experiment
    export CLEANUP_IN_PROGRESS=false

    # NOTE: Do NOT set CLEANUP_COMPLETED here!
    # This function is called both for initial cleanup (line 1648) and error cleanup
    # Only cleanup_on_signal() should set CLEANUP_COMPLETED after calling cleanup.sh
}

setup_netns() {
    log_info "Setting up network namespaces..."

    # Create namespaces
    ip netns add "$LEFT_NS"
    ip netns add "$RIGHT_NS"

    # Create veth pair
    ip link add "$LEFT_VETH" type veth peer name "$RIGHT_VETH"

    # Assign to namespaces
    ip link set "$LEFT_VETH" netns "$LEFT_NS"
    ip link set "$RIGHT_VETH" netns "$RIGHT_NS"

    # Configure interfaces
    ip -n "$LEFT_NS" addr add "${LEFT_IP}/24" dev "$LEFT_VETH"
    ip -n "$RIGHT_NS" addr add "${RIGHT_IP}/24" dev "$RIGHT_VETH"

    # Bring up interfaces
    ip -n "$LEFT_NS" link set lo up
    ip -n "$LEFT_NS" link set "$LEFT_VETH" up
    ip -n "$RIGHT_NS" link set lo up
    ip -n "$RIGHT_NS" link set "$RIGHT_VETH" up

    log_success "Network namespaces ready"
}

#=============================================================================
# strongSwan configuration
#=============================================================================

setup_strongswan_configs() {
    log_info "Setting up strongSwan configurations..."

    # Create config directories
    mkdir -p "$LEFT_CONF_DIR/swanctl/"{conf.d,x509,x509ca,x509crl,pubkey,private}
    mkdir -p "$RIGHT_CONF_DIR/swanctl/"{conf.d,x509,x509ca,x509crl,pubkey,private}

    # Create log directory
    mkdir -p /var/log/strongswan

    # Left strongswan.conf (EXACT copy from working setup_left_debug_fg.sh)
    cat > "$LEFT_CONF_DIR/strongswan.conf" <<'EOF'
charon {
  plugins {
    include /etc/strongswan.d/charon/*.conf
    save-keys {
      esp = yes
      ike = yes
      wireshark_keys = /root/.config/wireshark
    }
    vici { socket = unix:///run/left.charon.vici }
  }
  filelog {
    /var/log/strongswan/charon_left {
      time_format = %b %e %T
      default = 2
      ike = 2
      knl = 2
      net = 2
      dmn = 2
      lib = 2
    }
  }
}
include /etc/strongswan.d/*.conf
EOF

    # Right strongswan.conf (based on working setup_right_debug_fg.sh with filelog added)
    cat > "$RIGHT_CONF_DIR/strongswan.conf" <<'EOF'
charon {
  plugins {
    include /etc/strongswan.d/charon/*.conf
    save-keys {
      esp = yes
      ike = yes
      wireshark_keys = /root/.config/wireshark
    }
    vici {
      socket = unix:///run/right.charon.vici
    }
  }
  filelog {
    /var/log/strongswan/charon_right {
      time_format = %b %e %T
      default = 2
      ike = 2
      knl = 2
      net = 2
      dmn = 2
      lib = 2
    }
  }
}
include /etc/strongswan.d/*.conf
EOF

    # Left swanctl.conf (host-to-host, aes256, with IDs)
    cat > "$LEFT_CONF_DIR/swanctl/swanctl.conf" <<EOF
connections {
    net {
        version = 2
        proposals = aes256-sha256-modp2048
        local_addrs = $LEFT_IP
        remote_addrs = $RIGHT_IP
        local {
            auth = psk
            id = left
        }
        remote {
            auth = psk
            id = right
        }
        children {
            net {
                local_ts = $LEFT_IP/32
                remote_ts = $RIGHT_IP/32
                esp_proposals = aes256-sha256
            }
        }
    }
}
secrets {
    ike-1 {
        id = left
        secret = "test123"
    }
    ike-2 {
        id = right
        secret = "test123"
    }
}
EOF

    # Right swanctl.conf (host-to-host, aes256, with IDs)
    cat > "$RIGHT_CONF_DIR/swanctl/swanctl.conf" <<EOF
connections {
    net {
        version = 2
        proposals = aes256-sha256-modp2048
        local_addrs = $RIGHT_IP
        remote_addrs = $LEFT_IP
        local {
            auth = psk
            id = right
        }
        remote {
            auth = psk
            id = left
        }
        children {
            net {
                local_ts = $RIGHT_IP/32
                remote_ts = $LEFT_IP/32
                esp_proposals = aes256-sha256
            }
        }
    }
}
secrets {
    ike-1 {
        id = left
        secret = "test123"
    }
    ike-2 {
        id = right
        secret = "test123"
    }
}
EOF

    # Initialize log files with proper permissions
    : > /var/log/strongswan/charon_left; chmod 640 /var/log/strongswan/charon_left
    : > /var/log/strongswan/charon_right; chmod 640 /var/log/strongswan/charon_right

    log_success "strongSwan configs ready"
}

setup_apparmor() {
    log_info "Configuring AppArmor..."

    if command -v aa-complain >/dev/null 2>&1; then
        aa-complain /usr/lib/ipsec/charon 2>/dev/null || true
        aa-complain /usr/sbin/swanctl 2>/dev/null || true
        # CRITICAL: tcpdump needs complain mode for netns packet capture
        aa-complain /usr/bin/tcpdump 2>/dev/null || true
        aa-complain /etc/apparmor.d/usr.bin.tcpdump 2>/dev/null || true
        log_success "AppArmor set to complain mode (charon, swanctl, tcpdump)"
    else
        log_warn "AppArmor utils not found, skipping"
    fi
}

#=============================================================================
# charon process management
#=============================================================================

wait_for_vici() {
    local vici_path="$1"
    local timeout="$2"
    local ns="$3"

    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        # Check both: socket file exists AND process is listening
        if ip netns exec "$ns" test -S "$vici_path"; then
            if ip netns exec "$ns" ss -xpl | grep -F "$vici_path" >/dev/null 2>&1; then
                log_debug "VICI listener ready at $vici_path"
                return 0
            fi
        fi
        sleep 1
        ((elapsed++))
    done

    log_error "Timeout: no active VICI listener for $vici_path after ${timeout}s"
    log_debug "Hint: check /var/log/strongswan/charon_${ns} for errors"
    return 1
}

start_charon() {
    local side="$1"  # "left" or "right"

    # Use EXACT pattern from working setup_left_debug_fg.sh and setup_right_debug_fg.sh
    if [[ "$side" == "left" ]]; then
        log_info "Starting charon (left)..."

        # Clean up any previous instance
        local left_ino
        left_ino=$(stat -c %i /var/run/netns/left 2>/dev/null || true)
        if [[ -n "$left_ino" ]]; then
            for p in /proc/[0-9]*; do
                local pid="${p##*/}"
                local ns_link
                ns_link=$(readlink "$p/ns/net" 2>/dev/null || true)
                [[ "$ns_link" == "net:[$left_ino]" ]] || continue
                local cmd
                cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g' || true)
                echo "$cmd" | grep -q "/usr/lib/ipsec/charon" && kill -TERM "$pid" 2>/dev/null || true
            done
            sleep 0.5
        fi
        ip netns exec left bash -lc 'rm -f /run/left.charon.vici /run/left.charon.pid /var/run/charon.pid' 2>/dev/null || true

        # Start charon - EXACT copy from setup_left_debug_fg.sh
        ip netns exec left bash -lc "
          export STRONGSWAN_CONF=/etc/strongswan-left/strongswan.conf
          echo 'Starting charon (left)'
          /usr/lib/ipsec/charon --use-syslog no \
            --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 --debug-net 2 \
            >> /var/log/strongswan/charon_left 2>&1 &
          echo \$! > /run/left.charon.pid
        "

        # Get PID immediately
        sleep 0.2  # Give process a moment to write PID file
        LEFT_CHARON_PID=$(cat /run/left.charon.pid 2>/dev/null || echo "")

        if [[ -z "$LEFT_CHARON_PID" ]]; then
            log_error "Failed to get charon (left) PID"
            return 1
        fi

        log_debug "charon (left) PID: $LEFT_CHARON_PID"

        # Attach LLDB immediately if not skipped - BEFORE VICI verification
        # This ensures we catch all initialization and key derivation
        if [[ "$SKIP_LLDB" != "true" ]]; then
            log_info "Attaching LLDB to left charon immediately (PID: $LEFT_CHARON_PID)..."
            attach_lldb_to_pid "left" "$LEFT_CHARON_PID"
        fi

        # Now wait for VICI - LLDB is already attached and monitoring
        if ! wait_for_vici "/run/left.charon.vici" 10 "left"; then
            log_error "charon (left) failed to start"
            return 1
        fi

        log_success "charon (left) started (PID: $LEFT_CHARON_PID)"

        # In manual/interactive mode, pause after left charon starts
        # This allows user to inspect LLDB or system state before continuing
        if [[ "$MODE" == "interactive" ]]; then
            echo ""
            log_info "Left charon is ready. LLDB monitoring is active (if enabled)."
            echo ""
            read -p "Press Enter to continue and start right charon..." _DUMMY
            echo ""
        fi

    else
        log_info "Starting charon (right)..."

        # Clean up any previous instance
        local right_ino
        right_ino=$(stat -c %i /var/run/netns/right 2>/dev/null || true)
        if [[ -n "$right_ino" ]]; then
            for p in /proc/[0-9]*; do
                local pid="${p##*/}"
                local ns_link
                ns_link=$(readlink "$p/ns/net" 2>/dev/null || true)
                [[ "$ns_link" == "net:[$right_ino]" ]] || continue
                local cmd
                cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g' || true)
                echo "$cmd" | grep -q "/usr/lib/ipsec/charon" && kill -TERM "$pid" 2>/dev/null || true
            done
            sleep 0.5
        fi
        ip netns exec right bash -lc 'rm -f /run/right.charon.vici /run/right.charon.pid /var/run/charon.pid' 2>/dev/null || true

        # Start charon - EXACT copy from setup_right_debug_fg.sh pattern
        ip netns exec right bash -lc "
          export STRONGSWAN_CONF=/etc/strongswan-right/strongswan.conf
          echo 'Starting charon (right)'
          /usr/lib/ipsec/charon --use-syslog no \
            --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 --debug-net 2 \
            >> /var/log/strongswan/charon_right 2>&1 &
          echo \$! > /run/right.charon.pid
        "

        # Use wait_for_vici from manual script pattern
        if ! wait_for_vici "/run/right.charon.vici" 10 "right"; then
            log_error "charon (right) failed to start"
            return 1
        fi

        RIGHT_CHARON_PID=$(cat /run/right.charon.pid 2>/dev/null || echo "")
        log_success "charon (right) started (PID: $RIGHT_CHARON_PID)"
    fi

    return 0
}

#=============================================================================
# LLDB monitoring
#=============================================================================

attach_lldb_to_pid() {
    local side="$1"  # "left" or "right"
    local pid="$2"   # PID to attach to

    if [[ -z "$pid" ]]; then
        log_error "No PID provided for $side charon"
        return 1
    fi

    log_debug "Attaching LLDB to $side charon (PID $pid)..."
    log_debug "Output directory: $USERSPACE_DIR/$side"

    # Export environment for monitoring script
    export IPSEC_NETNS="$side"
    export IPSEC_OUTPUT_DIR="$USERSPACE_DIR/$side"
    mkdir -p "$IPSEC_OUTPUT_DIR"

    local monitoring_script="$EXPERIMENT_DIR/monitoring_ipsec.py"
    log_debug "Monitoring script: $monitoring_script"

    case "$TERM_SPAWNER" in
        tmux)
            # Check if we're in a tmux session (use ${TMUX:-} to handle unset variable)
            if [[ -z "${TMUX:-}" ]]; then
                # Not in tmux - create a new detached session if it doesn't exist
                if ! tmux has-session -t ipsec_experiment 2>/dev/null; then
                    log_debug "Creating new tmux session 'ipsec_experiment'"
                    tmux new-session -d -s ipsec_experiment
                    log_info "Created tmux session 'ipsec_experiment'"
                    log_info "Attach with: tmux attach -t ipsec_experiment"
                else
                    log_debug "Reusing existing tmux session 'ipsec_experiment'"
                fi
                # Create window in the detached session (no sudo needed - we're already root)
                log_debug "Creating tmux window 'lldb-$side'"
                tmux new-window -t ipsec_experiment -n "lldb-$side" "IPSEC_NETNS='$side' IPSEC_OUTPUT_DIR='$IPSEC_OUTPUT_DIR' IPSEC_MODE='interactive' \
                    lldb -o 'command script import $monitoring_script' -o 'process attach -p $pid' -o 'ipsec_setup_monitoring' -o 'ipsec_auto_continue 3'; \
                    echo 'LLDB exited'; read -p 'Press enter to close...'"
                log_debug "Tmux window created for $side"
            else
                # Already in tmux - create window in current session (no sudo needed - we're already root)
                log_debug "Creating tmux window in current session"
                tmux new-window -n "lldb-$side" "IPSEC_NETNS='$side' IPSEC_OUTPUT_DIR='$IPSEC_OUTPUT_DIR' IPSEC_MODE='interactive' \
                    lldb -o 'command script import $monitoring_script' -o 'process attach -p $pid' -o 'ipsec_setup_monitoring' -o 'ipsec_auto_continue 3'; \
                    echo 'LLDB exited'; read -p 'Press enter to close...'"
            fi
            ;;
        gnome-terminal)
            log_debug "Spawning gnome-terminal for $side"
            gnome-terminal --title="LLDB $side" -- bash -c \
                "IPSEC_NETNS='$side' IPSEC_OUTPUT_DIR='$IPSEC_OUTPUT_DIR' IPSEC_MODE='interactive' \
                lldb -o 'command script import $monitoring_script' -o 'process attach -p $pid' -o 'ipsec_setup_monitoring' -o 'ipsec_auto_continue 3'; \
                echo 'LLDB exited'; read -p 'Press enter to close...'"
            ;;
        background)
            log_debug "Running LLDB in background for $side"

            # Start LLDB in background with automated mode
            # CRITICAL: Must import script BEFORE attaching, then run setup command, then auto-continue
            # The monitoring script will:
            # 1. Register custom commands on import
            # 2. Attach to process (via -o "process attach")
            # 3. Set up breakpoints (via -o "ipsec_setup_monitoring")
            # 4. Auto-continue with delay, create readiness marker, and enter keep-alive loop (via -o "ipsec_auto_continue 2")
            # 5. Keep-alive loop keeps LLDB attached until process exits (prevents charon crash)
            #
            # Logging strategy:
            # - lldb-driver.log: LLDB commands, events, process, breakpoint activity
            # - lldb-script.log: Python script output (our callbacks)
            # - lldb-stdout.log: Everything else (combined stdout/stderr)
            #
            # Use PYTHONUNBUFFERED=1 to ensure Python output is immediately written
            log_debug "  LLDB logging:"
            log_debug "    Driver:  $IPSEC_OUTPUT_DIR/lldb-driver.log"
            log_debug "    Script:  $IPSEC_OUTPUT_DIR/lldb-script.log"
            log_debug "    Stdout:  $IPSEC_OUTPUT_DIR/lldb-stdout.log"

            IPSEC_NETNS="$side" IPSEC_OUTPUT_DIR="$IPSEC_OUTPUT_DIR" IPSEC_MODE="automated" PYTHONUNBUFFERED=1 \
                nohup lldb \
                    --batch \
                    -o "settings set auto-confirm true" \
                    -o "log enable -f '$IPSEC_OUTPUT_DIR/lldb-driver.log' lldb commands event process breakpoint" \
                    -o "log enable -f '$IPSEC_OUTPUT_DIR/lldb-script.log' lldb script" \
                    -o "command script import $monitoring_script" \
                    -o "process attach -p $pid" \
                    -o "ipsec_setup_monitoring" \
                    -o "ipsec_auto_continue 2" \
                    > "$IPSEC_OUTPUT_DIR/lldb-stdout.log" 2>&1 &
            local lldb_pid=$!

            # Store PID for cleanup
            if [[ "$side" == "left" ]]; then
                LEFT_LLDB_PID=$lldb_pid
            else
                RIGHT_LLDB_PID=$lldb_pid
            fi

            log_debug "Background LLDB started (PID: $lldb_pid)"
            log_debug "  Log files: $IPSEC_OUTPUT_DIR/lldb-*.log"

            # Wait for LLDB readiness marker file
            local wait_count=0
            local max_wait=60  # 30 seconds (60 * 0.5s)
            local readiness_marker="$IPSEC_OUTPUT_DIR/.lldb_ready_$side"

            log_debug "  Waiting for LLDB readiness marker: $readiness_marker"

            while [[ $wait_count -lt $max_wait ]]; do
                # Check if readiness marker exists
                if [[ -f "$readiness_marker" ]]; then
                    log_debug "  LLDB readiness marker found"
                    log_debug "  Content: $(cat "$readiness_marker" 2>/dev/null || echo '<unreadable>')"

                    # Verify process is still alive
                    if kill -0 "$pid" 2>/dev/null; then
                        log_success "  LLDB attached and process $pid is running"
                        break
                    else
                        log_error "  Process $pid died after LLDB attachment!"
                        return 1
                    fi
                fi

                # Also check if LLDB process died
                if ! kill -0 "$lldb_pid" 2>/dev/null; then
                    log_error "LLDB process exited before becoming ready"
                    log_error "Check logs: $IPSEC_OUTPUT_DIR/lldb-*.log"

                    # Show stdout log first (most relevant)
                    if [[ -f "$IPSEC_OUTPUT_DIR/lldb-stdout.log" ]]; then
                        log_error "LLDB stdout (last 30 lines):"
                        tail -n 30 "$IPSEC_OUTPUT_DIR/lldb-stdout.log" | sed 's/^/    /' >&2
                    fi

                    # Show script log if it exists (Python errors)
                    if [[ -f "$IPSEC_OUTPUT_DIR/lldb-script.log" ]]; then
                        log_error "Python script log (last 20 lines):"
                        tail -n 20 "$IPSEC_OUTPUT_DIR/lldb-script.log" | sed 's/^/    /' >&2
                    fi

                    return 1
                fi

                sleep 0.5
                ((wait_count++))
            done

            # Check if we timed out
            if [[ $wait_count -ge $max_wait ]]; then
                log_error "Timeout waiting for LLDB readiness marker (waited 30s)"
                log_error "Expected marker: $readiness_marker"
                log_error "LLDB logs: $IPSEC_OUTPUT_DIR/lldb-*.log"

                # Show stdout log (most relevant)
                if [[ -f "$IPSEC_OUTPUT_DIR/lldb-stdout.log" ]]; then
                    log_error "LLDB stdout (last 40 lines):"
                    tail -n 40 "$IPSEC_OUTPUT_DIR/lldb-stdout.log" | sed 's/^/    /' >&2
                fi

                # Show script log (Python callbacks)
                if [[ -f "$IPSEC_OUTPUT_DIR/lldb-script.log" ]]; then
                    log_error "Python script log (last 30 lines):"
                    tail -n 30 "$IPSEC_OUTPUT_DIR/lldb-script.log" | sed 's/^/    /' >&2
                fi

                # Check if process is still alive
                if kill -0 "$pid" 2>/dev/null; then
                    log_error "Charon process $pid is still alive - LLDB may be stuck"
                else
                    log_error "Charon process $pid died - check charon logs"
                fi

                return 1
            fi
            ;;
    esac

    log_success "LLDB monitoring setup for $side"
}

#=============================================================================
# Kernel monitoring
#=============================================================================

kernel_checkpoint() {
    local checkpoint="$1"  # init, handshake, rekey, terminate

    # Skip if drgn not available
    if [[ "${SKIP_KERNEL_MONITORING:-false}" == "true" ]]; then
        log_debug "Skipping kernel checkpoint: $checkpoint (kernel debug symbols not available)"
        return 0
    fi

    log_info "Kernel checkpoint: $checkpoint"

    local kernel_monitor="$EXPERIMENT_DIR/monitor_kernel_xfrm.py"

    # Build forensic flags based on environment variables
    # Note: Forensic scans only run on 'terminate' checkpoints
    local forensic_flags=""
    if [[ "${KERNEL_SCAN_FREELISTS:-false}" == "true" ]]; then
        forensic_flags="$forensic_flags --scan-freelists"
        [[ "$checkpoint" == *"terminate"* ]] && log_debug "  Forensic mode: SLUB freelist scanning enabled"
    fi
    if [[ "${KERNEL_SCAN_STACKS:-false}" == "true" ]]; then
        forensic_flags="$forensic_flags --scan-stacks"
        [[ "$checkpoint" == *"terminate"* ]] && log_debug "  Forensic mode: Kernel stack scanning enabled"
    fi
    if [[ "${KERNEL_SCAN_VMALLOC:-false}" == "true" ]]; then
        forensic_flags="$forensic_flags --scan-vmalloc"
        [[ "$checkpoint" == *"terminate"* ]] && log_debug "  Forensic mode: vmalloc region scanning enabled"
    fi

    # Monitor both sides (we're already running as root, no sudo needed)
    for side in left right; do
        local netns_file="/var/run/netns/$side"
        local output_dir="$KERNEL_DIR/$side"

        mkdir -p "$output_dir"

        # Capture both stdout and stderr to log, but suppress scary error output to console
        local output
        output=$("$KERNEL_PYTHON" "$kernel_monitor" --checkpoint "$checkpoint" \
            --netns-file "$netns_file" --output-dir "$output_dir" $forensic_flags 2>&1 || true)

        # Log full output to file
        echo "$output" >> "$output_dir/kernel_monitor.log"

        # Check if it succeeded by looking for success markers in output
        if echo "$output" | grep -q "Checkpoint saved\|checkpoint complete"; then
            log_debug "  Scanned $side namespace"
        elif echo "$output" | grep -q "Kernel debug symbols required"; then
            # Only show this warning once
            if [[ "$checkpoint" == "init" ]]; then
                log_warn "Kernel monitoring disabled: debug symbols not available"
                log_info "  To enable: sudo apt install linux-image-\$(uname -r)-dbgsym"
                log_info "  (This is optional - userspace LLDB monitoring will still work)"
                # Disable for future checkpoints
                export SKIP_KERNEL_MONITORING=true
            fi
        else
            log_debug "  Kernel scan skipped for $side (no active SAs or symbols missing)"
        fi
    done

    log_debug "Kernel checkpoint complete (if available)"
}

trigger_manual_dump() {
    local checkpoint="$1"

    log_info "Manual dump: $checkpoint"

    # Trigger kernel checkpoints (both sides)
    kernel_checkpoint "$checkpoint"

    # Trigger userspace dumps (left side only - right has no LLDB)
    # Skip if --skip-lldb was specified
    if [[ "$SKIP_LLDB" == "true" ]]; then
        log_info "  Userspace dumps skipped (--skip-lldb mode)"
        log_success "Manual dump triggered: $checkpoint (kernel only)"
        log_info "  Kernel: Check $KERNEL_DIR/left/ and $KERNEL_DIR/right/"
        return 0
    fi

    local trigger_script="$EXPERIMENT_DIR/trigger_userspace_dump.sh"

    if [[ ! -f "$trigger_script" ]]; then
        log_error "Userspace dump trigger script not found: $trigger_script"
        return 1
    fi

    # Only trigger userspace dump for left (LLDB is only attached to left)
    local output_dir="$USERSPACE_DIR/left"

    if [[ ! -d "$output_dir" ]]; then
        log_warn "Userspace directory not found: $output_dir"
        log_warn "LLDB may not have started properly"
        log_info "  Kernel dumps completed, userspace dumps unavailable"
    else
        # Trigger dump via marker file (LLDB monitoring loop will detect it)
        log_debug "  Triggering userspace dump for left"
        "$trigger_script" "$output_dir" "$checkpoint" 2>&1 | while IFS= read -r line; do
            log_debug "    $line"
        done
        log_info "  Userspace (left only): LLDB will process dump request within 1-2 seconds"
    fi

    log_success "Manual dump triggered: $checkpoint"
    log_info "  Kernel: Check $KERNEL_DIR/left/ and $KERNEL_DIR/right/"
}

#=============================================================================
# Network packet capture
#=============================================================================

start_packet_capture() {
    log_info "Starting network packet capture..."

    # Capture filter: IKE (UDP 500/4500) + ESP (proto 50)
    local filter='udp port 500 or udp port 4500 or proto 50'

    # Start capture for left namespace
    local left_pcap="$NETWORK_DIR/left.pcap"
    log_debug "Starting tcpdump in left namespace -> $left_pcap"
    ip netns exec "$LEFT_NS" tcpdump -i any -s 0 -U -nn -w "$left_pcap" $filter >/dev/null 2>&1 &
    LEFT_TCPDUMP_PID=$!
    log_debug "Left tcpdump PID: $LEFT_TCPDUMP_PID"

    # Start capture for right namespace
    local right_pcap="$NETWORK_DIR/right.pcap"
    log_debug "Starting tcpdump in right namespace -> $right_pcap"
    ip netns exec "$RIGHT_NS" tcpdump -i any -s 0 -U -nn -w "$right_pcap" $filter >/dev/null 2>&1 &
    RIGHT_TCPDUMP_PID=$!
    log_debug "Right tcpdump PID: $RIGHT_TCPDUMP_PID"

    # Give tcpdump time to start
    sleep 0.3

    # Verify they're running
    if kill -0 "$LEFT_TCPDUMP_PID" 2>/dev/null && kill -0 "$RIGHT_TCPDUMP_PID" 2>/dev/null; then
        log_success "Packet capture started (left: $LEFT_TCPDUMP_PID, right: $RIGHT_TCPDUMP_PID)"
    else
        log_warn "Some tcpdump processes may have failed to start"
    fi
}

stop_packet_capture() {
    log_info "Stopping network packet capture..."

    # Stop left tcpdump
    if [[ -n "$LEFT_TCPDUMP_PID" ]] && kill -0 "$LEFT_TCPDUMP_PID" 2>/dev/null; then
        log_debug "Stopping left tcpdump (PID $LEFT_TCPDUMP_PID)"
        kill -INT "$LEFT_TCPDUMP_PID" 2>/dev/null || true
        wait "$LEFT_TCPDUMP_PID" 2>/dev/null || true
        log_debug "Left tcpdump stopped"
    fi

    # Stop right tcpdump
    if [[ -n "$RIGHT_TCPDUMP_PID" ]] && kill -0 "$RIGHT_TCPDUMP_PID" 2>/dev/null; then
        log_debug "Stopping right tcpdump (PID $RIGHT_TCPDUMP_PID)"
        kill -INT "$RIGHT_TCPDUMP_PID" 2>/dev/null || true
        wait "$RIGHT_TCPDUMP_PID" 2>/dev/null || true
        log_debug "Right tcpdump stopped"
    fi

    log_success "Packet capture stopped"
    log_info "Captures saved:"
    log_info "  Left:  $NETWORK_DIR/left.pcap"
    log_info "  Right: $NETWORK_DIR/right.pcap"
}

#=============================================================================
# IPsec operations
#=============================================================================

check_charon_alive() {
    local side="$1"
    local pid

    if [[ "$side" == "left" ]]; then
        pid="${LEFT_CHARON_PID:-}"
    else
        pid="${RIGHT_CHARON_PID:-}"
    fi

    if [[ -z "$pid" ]]; then
        log_error "No PID for $side charon"
        return 1
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "Charon process $pid ($side) is dead!"
        return 1
    fi

    return 0
}

check_charon_state() {
    local side="$1"
    local pid

    if [[ "$side" == "left" ]]; then
        pid="${LEFT_CHARON_PID:-}"
    else
        pid="${RIGHT_CHARON_PID:-}"
    fi

    if [[ -z "$pid" ]]; then
        log_warn "No PID for $side charon"
        return 1
    fi

    if ! kill -0 "$pid" 2>/dev/null; then
        log_error "Charon process $pid ($side) is dead!"
        return 1
    fi

    # Check process state (only works on Linux)
    if [[ -f "/proc/$pid/status" ]]; then
        local state=$(grep "^State:" "/proc/$pid/status" 2>/dev/null | awk '{print $2}')
        case "$state" in
            R|S)  # Running or Sleeping - good
                return 0
                ;;
            T)  # Stopped (by debugger or signal)
                log_error "Charon process $pid ($side) is STOPPED (likely by LLDB)"
                log_error "Process state: $state"
                return 1
                ;;
            Z)  # Zombie
                log_error "Charon process $pid ($side) is a ZOMBIE"
                return 1
                ;;
            *)
                log_warn "Charon process $pid ($side) has unusual state: $state"
                return 1
                ;;
        esac
    fi

    return 0
}

run_swanctl_with_timeout() {
    local side="$1"
    local timeout="${2:-30}"  # Default 30 second timeout
    shift 2
    local swanctl_args=("$@")

    local ns vici pid
    if [[ "$side" == "left" ]]; then
        ns="$LEFT_NS"
        vici="$LEFT_VICI"
        pid="${LEFT_CHARON_PID:-}"
    else
        ns="$RIGHT_NS"
        vici="$RIGHT_VICI"
        pid="${RIGHT_CHARON_PID:-}"
    fi

    # Check charon is alive and running BEFORE operation
    if ! check_charon_state "$side"; then
        log_error "Cannot run swanctl: charon ($side) is not in running state"
        return 1
    fi

    log_debug "Running swanctl with ${timeout}s timeout: ${swanctl_args[*]}"

    # Run swanctl with timeout
    local output
    local exit_code
    if output=$(timeout "$timeout" ip netns exec "$ns" swanctl "${swanctl_args[@]}" --uri "$vici" 2>&1); then
        exit_code=0
    else
        exit_code=$?
    fi

    # Check if timeout occurred (exit code 124)
    if [[ $exit_code -eq 124 ]]; then
        log_error "swanctl operation TIMED OUT after ${timeout}s"
        log_error "This usually means charon is stuck or not responding"

        # Check if process is still alive
        if ! check_charon_alive "$side"; then
            log_error "Charon ($side) died during swanctl operation"
        else
            log_error "Charon ($side) is alive but not responding"
            check_charon_state "$side" || true  # Show state for debugging
        fi
        return 1
    fi

    # Check charon is still alive AFTER operation
    if ! check_charon_alive "$side"; then
        log_error "Charon ($side) died during swanctl operation"
        return 1
    fi

    # Output the result
    echo "$output"

    return $exit_code
}

load_config() {
    local side="$1"
    local conf

    if [[ "$side" == "left" ]]; then
        conf="$LEFT_CONF_DIR/swanctl/swanctl.conf"
    else
        conf="$RIGHT_CONF_DIR/swanctl/swanctl.conf"
    fi

    log_info "Loading config ($side)..."
    log_command "swanctl --load-all --file $conf (with 30s timeout)"

    if run_swanctl_with_timeout "$side" 30 --load-all --file "$conf" 2>&1 | tee -a "$EXPERIMENT_LOG"; then
        log_success "Config loaded ($side)"
        return 0
    else
        log_error "Failed to load config ($side)"
        return 1
    fi
}

terminate_all_sas() {
    local side="$1"  # "left" or "right"
    local ns vici

    if [[ "$side" == "left" ]]; then
        ns="$LEFT_NS"
        vici="$LEFT_VICI"
    else
        ns="$RIGHT_NS"
        vici="$RIGHT_VICI"
    fi

    log_debug "Terminating all SAs on $side..."

    # Try to terminate all IKE SAs
    ip netns exec "$ns" swanctl --terminate --ike all --uri "$vici" 2>/dev/null || true

    # Wait for SAs to actually be removed (up to 10 seconds)
    local elapsed=0
    while [[ $elapsed -lt 10 ]]; do
        if ! ip netns exec "$ns" swanctl --list-sas --uri "$vici" 2>/dev/null | grep -q "ESTABLISHED"; then
            log_debug "All SAs terminated on $side"
            return 0
        fi
        sleep 0.25
        ((elapsed++))
    done

    log_warn "Some SAs may still be active on $side after timeout"
    return 1
}

initiate_connection() {
    log_info "Initiating IKE connection from left..."

    # CRITICAL: Terminate any existing SAs before fresh handshake
    terminate_all_sas "left"
    terminate_all_sas "right"
    sleep 0.5

    # Kernel checkpoint before handshake
    log_debug "Taking kernel checkpoint before handshake..."
    kernel_checkpoint "before_handshake"

    log_command "swanctl --initiate --child net (with 30s timeout)"

    if run_swanctl_with_timeout "left" 30 --initiate --child net 2>&1 | tee -a "$EXPERIMENT_LOG"; then
        log_success "Connection initiated successfully"

        # Kernel checkpoint after handshake
        sleep 1
        log_debug "Taking kernel checkpoint after handshake..."
        kernel_checkpoint "after_handshake"

        return 0
    else
        log_error "Failed to initiate connection (check log for details)"
        return 1
    fi
}

show_status() {
    log_info "Connection status:"

    echo ""
    echo "LEFT:"
    ip netns exec "$LEFT_NS" swanctl --list-sas --uri "$LEFT_VICI" || true

    echo ""
    echo "RIGHT:"
    ip netns exec "$RIGHT_NS" swanctl --list-sas --uri "$RIGHT_VICI" || true
}

generate_esp_traffic() {
    # Generate ESP-encrypted traffic by running HTTP server in RIGHT namespace
    # and fetching from LEFT namespace using curl.
    # This generates encrypted ESP packets that can be analyzed in pcap captures.
    # Based on capture_ipsec_http.sh from research_setup.

    if [[ "$ENABLE_TRAFFIC" != "true" ]]; then
        log_debug "Traffic generation disabled, skipping"
        return 0
    fi

    log_info "Generating ESP traffic (HTTP)..."

    local doc_root="/tmp/ipsec_traffic"
    local test_file="test_data.txt"
    local httpd_pid=""
    local traffic_duration=5

    # Create test file in RIGHT namespace
    ip netns exec "$RIGHT_NS" bash -c "
        mkdir -p '$doc_root'
        echo 'THIS IS TEST DATA FOR IPSEC ESP TRAFFIC GENERATION' > '$doc_root/$test_file'
        echo 'Timestamp: \$(date)' >> '$doc_root/$test_file'
        echo 'Generating multiple lines of data for better traffic analysis' >> '$doc_root/$test_file'
        for i in {1..20}; do echo 'Line \$i: Lorem ipsum dolor sit amet consectetur adipiscing elit' >> '$doc_root/$test_file'; done
    "

    # Kill any existing HTTP server on this port in RIGHT namespace
    ip netns exec "$RIGHT_NS" bash -c "
        if command -v ss >/dev/null 2>&1; then
            PIDS=\$(ss -ltnp 2>/dev/null | awk '\$4 ~ /:$HTTP_PORT/ { if (match(\$NF, /pid=([0-9]+)/, m)) print m[1] }' | sort -u)
            if [ -n \"\$PIDS\" ]; then
                kill -TERM \$PIDS 2>/dev/null || true
                sleep 0.3
            fi
        fi
    " 2>/dev/null || true

    # Start HTTP server in RIGHT namespace (background)
    log_debug "Starting HTTP server in RIGHT namespace on $RIGHT_IP:$HTTP_PORT"
    ip netns exec "$RIGHT_NS" bash -c "cd '$doc_root' && python3 -m http.server '$HTTP_PORT' --bind '$RIGHT_IP'" \
        > "$NETWORK_DIR/http_server.log" 2>&1 &
    httpd_pid=$!

    # Give server time to start
    sleep 1

    # Verify server is listening
    if ! ip netns exec "$RIGHT_NS" ss -ltn | grep -q ":$HTTP_PORT"; then
        log_warn "HTTP server may not be listening on $RIGHT_IP:$HTTP_PORT"
    else
        log_success "HTTP server started (PID: $httpd_pid)"
    fi

    # Generate traffic from LEFT namespace (multiple requests)
    local url="http://$RIGHT_IP:$HTTP_PORT/$test_file"
    log_info "Generating traffic: LEFT ($LEFT_IP) → RIGHT ($RIGHT_IP:$HTTP_PORT)"

    local success_count=0
    for i in {1..5}; do
        if ip netns exec "$LEFT_NS" curl -sS --fail-with-body --max-time 5 "$url" > /dev/null 2>&1; then
            log_debug "  Request $i: SUCCESS"
            ((success_count++))
        else
            log_warn "  Request $i: FAILED"
        fi
        sleep 0.5
    done

    # Keep server alive a bit longer to capture trailing packets
    sleep 2

    # Stop HTTP server
    if [[ -n "$httpd_pid" ]] && kill -0 "$httpd_pid" 2>/dev/null; then
        kill -TERM "$httpd_pid" 2>/dev/null || true
        wait "$httpd_pid" 2>/dev/null || true
        log_debug "HTTP server stopped"
    fi

    # Summary
    if [[ $success_count -gt 0 ]]; then
        log_success "ESP traffic generated: $success_count/5 requests successful"
        log_info "Traffic captured in: $NETWORK_DIR/left.pcap and $NETWORK_DIR/right.pcap"
    else
        log_error "Failed to generate ESP traffic (0/5 requests successful)"
        log_error "Check network connectivity and IPsec SA status"
        return 1
    fi

    return 0
}

rekey_connection() {
    log_info "Initiating rekey..."

    # Wait 2 seconds to let any watchpoint activity settle
    # This prevents race conditions where LLDB has stopped the process
    log_debug "Waiting 2s for LLDB watchpoints to settle..."
    sleep 2

    # Detect IKE SA ID on left
    local ike_line ike_name ike_id
    ike_line=$(run_swanctl_with_timeout "left" 10 --list-sas 2>/dev/null | \
        awk '/^[^[:space:]]+:[[:space:]]*#[0-9]+,/ {
            name=$1; sub(":", "", name)
            if (match($0, /#[0-9]+,/)) {
                id=substr($0, RSTART+1, RLENGTH-2)
                print name, id
                exit
            }
        }' || true)

    if [[ -n "$ike_line" ]]; then
        ike_name=$(echo "$ike_line" | awk '{print $1}')
        ike_id=$(echo "$ike_line" | awk '{print $2}')
        log_info "Rekeying IKE SA: $ike_name [$ike_id]"

        # Kernel checkpoint before rekey
        log_debug "Taking kernel checkpoint before rekey..."
        kernel_checkpoint "before_rekey"

        if run_swanctl_with_timeout "left" 30 --rekey --ike-id "$ike_id" 2>&1 | tee -a "$EXPERIMENT_LOG"; then
            log_success "Rekey initiated"

            # Kernel checkpoint after rekey
            sleep 1
            log_debug "Taking kernel checkpoint after rekey..."
            kernel_checkpoint "after_rekey"
        else
            log_error "Rekey failed"
            return 1
        fi
    else
        log_error "No active SA found"
        return 1
    fi
}

terminate_connection() {
    log_info "Terminating connection..."

    # Wait 2 seconds to let any watchpoint activity settle
    # This prevents race conditions where LLDB has stopped the process
    log_debug "Waiting 2s for LLDB watchpoints to settle..."
    sleep 2

    # Detect IKE SA ID on left with retry logic (in case process is temporarily stopped)
    local ike_line ike_name ike_id
    local retry_count=0
    local max_retries=3

    while [[ $retry_count -lt $max_retries ]]; do
        ike_line=$(run_swanctl_with_timeout "left" 10 --list-sas 2>/dev/null | \
            awk '/^[^[:space:]]+:[[:space:]]*#[0-9]+,/ {
                name=$1; sub(":", "", name)
                if (match($0, /#[0-9]+,/)) {
                    id=substr($0, RSTART+1, RLENGTH-2)
                    print name, id
                    exit
                }
            }' || true)

        if [[ -n "$ike_line" ]]; then
            # SA found, break out of retry loop
            break
        fi

        retry_count=$((retry_count + 1))
        if [[ $retry_count -lt $max_retries ]]; then
            log_debug "No SA found (attempt $retry_count/$max_retries), retrying in 1s..."
            sleep 1
        fi
    done

    if [[ -n "$ike_line" ]]; then
        ike_name=$(echo "$ike_line" | awk '{print $1}')
        ike_id=$(echo "$ike_line" | awk '{print $2}')
        log_info "Terminating IKE SA: $ike_name [$ike_id]"

        # Kernel checkpoint before terminate
        log_debug "Taking kernel checkpoint before terminate..."
        kernel_checkpoint "before_terminate"

        if run_swanctl_with_timeout "left" 30 --terminate --ike-id "$ike_id" 2>&1 | tee -a "$EXPERIMENT_LOG"; then
            log_success "Connection terminated"

            # Kernel checkpoint after terminate
            sleep 1
            log_debug "Taking kernel checkpoint after terminate..."
            kernel_checkpoint "after_terminate"
        else
            log_error "Terminate failed"
            return 1
        fi
    else
        log_warn "No active SA found after $max_retries attempts"
        return 1
    fi
}

#=============================================================================
# Interactive menu
#=============================================================================

show_menu() {
    echo ""
    echo "========================================"
    echo "  IPsec Experiment Control"
    echo "========================================"
    echo ""
    echo "  [H] Handshake - Load configs only"
    echo "  [I] Initiate - Establish connection"
    echo "  [R] Rekey - Trigger rekey"
    echo "  [T] Terminate - Close connection"
    echo "  [S] Status - Show SA status"
    echo "  [D] Dump - Manual memory dump"
    echo "  [K] Kernel checkpoint - Manual scan"
    echo "  [W] Windows - Show tmux windows"
    echo "  [Q] Quit - Cleanup and exit"
    echo ""
}

interactive_mode() {
    log_success "Experiment setup complete"
    log_info "Output directory: $OUTPUT_DIR"
    echo ""
    log_info "LLDB is attached and monitoring in separate windows"
    log_info "Initial kernel checkpoint taken"
    echo ""

    while true; do
        show_menu
        read -rp "Select action: " choice

        case "${choice^^}" in
            H)
                log_info "=== HANDSHAKE ==="
                kernel_checkpoint "before_handshake"
                load_config "right"
                load_config "left"
                sleep 1
                kernel_checkpoint "after_handshake"
                ;;
            I)
                log_info "=== INITIATE ==="
                # Load configs on both sides first (required for IKE to work)
                log_info "Loading configurations..."
                load_config "right"
                load_config "left"
                sleep 0.5
                # Now initiate the connection (includes kernel checkpoints)
                initiate_connection
                sleep 1
                show_status
                ;;
            R)
                log_info "=== REKEY ==="
                # rekey_connection includes kernel checkpoints
                rekey_connection
                sleep 1
                show_status
                ;;
            T)
                log_info "=== TERMINATE ==="
                # terminate_connection includes kernel checkpoints
                terminate_connection
                sleep 1
                ;;
            S)
                show_status
                ;;
            D)
                read -rp "Checkpoint name: " ckpt_name
                trigger_manual_dump "${ckpt_name:-manual}"
                ;;
            K)
                read -rp "Checkpoint name: " ckpt_name
                kernel_checkpoint "${ckpt_name:-manual}"
                ;;
            W)
                if [[ "$TERM_SPAWNER" == "tmux" ]]; then
                    if tmux has-session -t ipsec_experiment 2>/dev/null; then
                        log_info "Tmux session windows:"
                        tmux list-windows -t ipsec_experiment
                        echo ""
                        log_info "To attach: tmux attach -t ipsec_experiment"
                    else
                        log_warn "No tmux session found"
                    fi
                else
                    log_warn "Not using tmux (spawner: $TERM_SPAWNER)"
                fi
                ;;
            Q)
                log_info "Exiting..."
                break
                ;;
            *)
                log_warn "Invalid choice"
                ;;
        esac
    done
}

#=============================================================================
# Automated workflow
#=============================================================================

run_automated_workflow() {
    # Run automated workflow based on WORKFLOW variable
    # Supports: initiate, rekey, terminate, full

    log_success "Starting automated workflow: $WORKFLOW"
    log_info "Output directory: $OUTPUT_DIR"
    echo ""

    case "$WORKFLOW" in
        initiate)
            log_info "=== WORKFLOW: INITIATE ==="
            run_initiate_phase
            ;;
        rekey)
            log_info "=== WORKFLOW: REKEY ==="
            run_initiate_phase
            sleep 2
            run_rekey_phase
            ;;
        terminate)
            log_info "=== WORKFLOW: TERMINATE ==="
            run_initiate_phase
            sleep 2
            run_terminate_phase
            ;;
        full)
            log_info "=== WORKFLOW: FULL (INITIATE → REKEY → TERMINATE) ==="
            run_initiate_phase
            sleep 2
            run_rekey_phase
            sleep 2
            run_terminate_phase
            ;;
        *)
            log_error "Unknown workflow: $WORKFLOW"
            return 1
            ;;
    esac

    log_success "Automated workflow completed!"
    log_info "Results saved to: $OUTPUT_DIR"
}

run_initiate_phase() {
    log_info ">>> PHASE: INITIATE <<<"

    # Load configs on both sides
    log_info "Loading configurations..."
    load_config "right"
    load_config "left"
    sleep 0.5

    # Kernel checkpoint before handshake
    kernel_checkpoint "before_handshake"

    # Initiate connection
    log_info "Initiating IKE connection from left..."
    if ! initiate_connection; then
        log_error "Failed to initiate connection"
        return 1
    fi

    # Kernel checkpoint after handshake
    sleep 1
    kernel_checkpoint "after_handshake"

    # Show status
    show_status

    # Generate ESP traffic if enabled
    if [[ "$ENABLE_TRAFFIC" == "true" ]]; then
        log_info "Generating ESP traffic after handshake..."
        generate_esp_traffic
        kernel_checkpoint "after_handshake_traffic"
    fi

    log_success "INITIATE phase completed"
    return 0
}

run_rekey_phase() {
    log_info ">>> PHASE: REKEY <<<"

    # Kernel checkpoint before rekey
    kernel_checkpoint "before_rekey"

    # Rekey connection
    if ! rekey_connection; then
        log_error "Failed to rekey connection"
        return 1
    fi

    # Kernel checkpoint after rekey
    sleep 1
    kernel_checkpoint "after_rekey"

    # Show status
    show_status

    # Generate ESP traffic if enabled
    if [[ "$ENABLE_TRAFFIC" == "true" ]]; then
        log_info "Generating ESP traffic after rekey..."
        generate_esp_traffic
        kernel_checkpoint "after_rekey_traffic"
    fi

    log_success "REKEY phase completed"
    return 0
}

run_terminate_phase() {
    log_info ">>> PHASE: TERMINATE <<<"

    # Generate traffic before terminating (to show keys are still working)
    if [[ "$ENABLE_TRAFFIC" == "true" ]]; then
        log_info "Generating ESP traffic before terminate..."
        generate_esp_traffic
        kernel_checkpoint "before_terminate_after_traffic"
    fi

    # Kernel checkpoint before terminate
    kernel_checkpoint "before_terminate"

    # Terminate connection
    if ! terminate_connection; then
        log_error "Failed to terminate connection"
        return 1
    fi

    # Kernel checkpoint after terminate
    sleep 1
    kernel_checkpoint "after_terminate"

    log_success "TERMINATE phase completed"
    return 0
}

#=============================================================================
# Main
#=============================================================================

main() {
    # Parse command line arguments first (before any logging that might use the config)
    parse_arguments "$@"

    log_info "IPsec/strongSwan Key Lifecycle Experiment"
    log_info "==========================================="

    # Check prerequisites
    check_root
    detect_terminal_spawner
    check_dependencies

    # Setup experiment directory
    mkdir -p "$OUTPUT_DIR" "$USERSPACE_DIR" "$KERNEL_DIR" "$NETWORK_DIR"

    # Initialize log file
    touch "$EXPERIMENT_LOG"
    log_info "Output: $OUTPUT_DIR"
    log_info "Experiment log: $EXPERIMENT_LOG"
    log_debug "Experiment started at $(date)"
    log_debug "Script directory: $SCRIPT_DIR"
    log_debug "Terminal spawner: $TERM_SPAWNER"
    log_debug "Kernel Python: $KERNEL_PYTHON"

    # Clean up any previous state
    cleanup_netns

    # Setup network and configuration
    setup_netns
    setup_strongswan_configs
    setup_apparmor

    # Start charon processes
    if ! start_charon "left"; then
        log_error "Failed to start left charon - aborting"
        # EXIT trap will handle cleanup
        exit 1
    fi

    if ! start_charon "right"; then
        log_error "Failed to start right charon - aborting"
        # EXIT trap will handle cleanup
        exit 1
    fi

    # Start packet capture
    start_packet_capture

    # Initial kernel checkpoint
    sleep 1
    kernel_checkpoint "init"

    # Clean up any existing tmux session from previous runs
    if [[ "$TERM_SPAWNER" == "tmux" ]] && tmux has-session -t ipsec_experiment 2>/dev/null; then
        log_info "Cleaning up existing tmux session..."
        tmux kill-session -t ipsec_experiment 2>/dev/null || true
        sleep 0.5
    fi

    # LLDB was already attached during start_charon() if not skipped
    # Just verify everything is still running
    if [[ "$SKIP_LLDB" != "true" ]]; then
        log_info "Verifying LLDB monitoring is active..."

        # Verify that both charon and LLDB are still alive
        if ! kill -0 "$LEFT_CHARON_PID" 2>/dev/null; then
            log_error "Left charon process died after LLDB attachment!"
            log_error "Check LLDB logs: $USERSPACE_DIR/left/lldb.log"
            # EXIT trap will handle cleanup
            exit 1
        fi

        # In background mode, verify LLDB is still attached
        if [[ "$TERM_SPAWNER" == "background" ]] && [[ -n "${LEFT_LLDB_PID:-}" ]]; then
            if ! kill -0 "$LEFT_LLDB_PID" 2>/dev/null; then
                log_warn "LLDB process exited unexpectedly"
                log_debug "Check logs: $USERSPACE_DIR/left/lldb.log"
            else
                log_debug "LLDB is still monitoring (PID: $LEFT_LLDB_PID)"
            fi
        fi

        # Show tmux session status if using tmux
        if [[ "$TERM_SPAWNER" == "tmux" ]] && tmux has-session -t ipsec_experiment 2>/dev/null; then
            log_debug "Tmux session windows:"
            tmux list-windows -t ipsec_experiment | while read line; do
                log_debug "  $line"
            done
        fi

        log_success "LLDB monitoring active on left charon (PID: $LEFT_CHARON_PID)"
    fi

    # Choose mode based on configuration
    if [[ "$MODE" == "interactive" ]]; then
        # Enter interactive mode
        interactive_mode
    else
        # Run automated workflow
        run_automated_workflow
    fi

    # Cleanup is handled by EXIT trap - no need to call explicitly here
    # The EXIT trap will invoke cleanup.sh when the script exits normally

    log_success "Experiment complete!"
    log_info "Results saved to: $OUTPUT_DIR"
}

# NOTE: Traps are defined at the top of the script (after config section)
# - INT, TERM, ERR, and EXIT traps all call cleanup_on_signal()
# - cleanup_on_signal() invokes cleanup.sh
# DO NOT add additional traps here - they will override the ones at the top

# Run main
main "$@"
