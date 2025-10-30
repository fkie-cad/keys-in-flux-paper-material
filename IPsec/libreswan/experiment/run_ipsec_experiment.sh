#!/usr/bin/env bash
#
# run_ipsec_experiment.sh - IPsec/Libreswan Key Lifecycle Experiment
#
# Streamlined version adapted from strongswan run_ipsec_experiment.sh
# Focuses on --skip-lldb mode for immediate functionality
#
# Usage:
#   sudo ./run_ipsec_experiment.sh --workflow=full --skip-lldb
#

set -uo pipefail

#=============================================================================
# Configuration
#=============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXPERIMENT_DIR="$SCRIPT_DIR"

# Network configuration
LEFT_NS="left"
RIGHT_NS="right"
LEFT_IP="10.0.0.1"
RIGHT_IP="10.0.0.2"
LEFT_VETH="veth-left"
RIGHT_VETH="veth-right"
HTTP_PORT=8080              # Port for ESP traffic HTTP server

# Libreswan configuration
LEFT_CONF_DIR="/etc/ipsec-left"
RIGHT_CONF_DIR="/etc/ipsec-right"

# Pluto binary path (detect dynamically)
PLUTO_PATH=""
if [[ -x "/usr/local/libexec/ipsec/pluto" ]]; then
    PLUTO_PATH="/usr/local/libexec/ipsec/pluto"
elif [[ -x "/usr/libexec/ipsec/pluto" ]]; then
    PLUTO_PATH="/usr/libexec/ipsec/pluto"
else
    # Will fail later in check_dependencies with clear error
    PLUTO_PATH="/usr/local/libexec/ipsec/pluto"
fi

# Experiment output
TIMESTAMP=$(date +'%Y%m%d_%H%M%S')
OUTPUT_DIR="$EXPERIMENT_DIR/results/$TIMESTAMP"
KERNEL_DIR="$OUTPUT_DIR/kernel"
USERSPACE_DIR="$OUTPUT_DIR/userspace"
NETWORK_DIR="$OUTPUT_DIR/network"
EXPERIMENT_LOG="$OUTPUT_DIR/experiment.log"

# Process tracking
LEFT_PLUTO_PID=""
RIGHT_PLUTO_PID=""

# Experiment mode
MODE="interactive"
WORKFLOW="none"
SKIP_LLDB=false  # Enable LLDB monitoring by default
ENABLE_TRAFFIC_CAPTURE=false

# Python interpreter for kernel monitoring (detected later)
KERNEL_PYTHON=""

# Process tracking for packet capture
LEFT_TCPDUMP_PID=""
RIGHT_TCPDUMP_PID=""

# Cleanup tracking
export CLEANUP_IN_PROGRESS=false

#=============================================================================
# Color output and logging
#=============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_to_file() {
    local level="$1"
    shift
    local msg="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
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
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $*"
    fi
    log_to_file "DEBUG" "$*"
}

#=============================================================================
# Signal handling
#=============================================================================

cleanup_on_signal() {
    local signal="$1"
    if [[ "${CLEANUP_IN_PROGRESS:-}" == "true" ]]; then
        return 0
    fi
    export CLEANUP_IN_PROGRESS=true

    if [[ "$signal" == "EXIT" ]]; then
        log_info "Script exiting - running cleanup..."
    else
        log_warn "Received signal $signal - running cleanup..."
    fi

    # Stop packet capture before cleanup
    stop_packet_capture

    # Call cleanup script
    local cleanup_script="$EXPERIMENT_DIR/cleanup.sh"
    if [[ -f "$cleanup_script" ]]; then
        bash "$cleanup_script"
    fi

    case "$signal" in
        INT)   exit 130 ;;
        TERM)  exit 143 ;;
        ERR)   exit 1   ;;
        EXIT)  return 0 ;;
        *)     exit 1   ;;
    esac
}

trap 'cleanup_on_signal INT' INT
trap 'cleanup_on_signal TERM' TERM
trap 'cleanup_on_signal EXIT' EXIT

#=============================================================================
# Argument parsing
#=============================================================================

show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

IPsec/Libreswan Key Lifecycle Experiment

MODES:
  --mode=MODE           Experiment mode: interactive (default) or auto
  --workflow=WORKFLOW   Workflow: none, initiate, rekey, terminate, full

OPTIONS:
  --skip-lldb           Skip LLDB monitoring (default: true, LLDB TODO)
  --help, -h            Show this help

EXAMPLES:
  # Automated full workflow (kernel monitoring only):
  sudo ./run_ipsec_experiment.sh --workflow=full --skip-lldb

  # Interactive mode:
  sudo ./run_ipsec_experiment.sh

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode=*)
                MODE="${1#*=}"
                ;;
            --workflow=*)
                WORKFLOW="${1#*=}"
                MODE="auto"
                ;;
            --skip-lldb)
                SKIP_LLDB=true
                ;;
            --traffic)
                ENABLE_TRAFFIC_CAPTURE=true
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
}

#=============================================================================
# Dependency checks
#=============================================================================

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
    command -v ipsec >/dev/null 2>&1 || missing+=("libreswan")
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

    # Check Python modules using detected interpreter
    log_info "Checking drgn module availability (using: $KERNEL_PYTHON)..."
    if ! "$KERNEL_PYTHON" -c "import drgn" 2>/dev/null; then
        log_warn "drgn module not found for $KERNEL_PYTHON"
        log_warn "Kernel monitoring will be disabled"
        log_warn "Install with: $KERNEL_PYTHON -m pip install drgn"
        SKIP_KERNEL_MONITORING=true
    else
        log_success "drgn module available"
        SKIP_KERNEL_MONITORING=false
    fi

    log_success "Dependencies OK"
}

#=============================================================================
# Network namespace setup
#=============================================================================

setup_netns() {
    log_info "Setting up network namespaces..."

    ip netns add "$LEFT_NS"
    ip netns add "$RIGHT_NS"

    ip link add "$LEFT_VETH" type veth peer name "$RIGHT_VETH"

    ip link set "$LEFT_VETH" netns "$LEFT_NS"
    ip link set "$RIGHT_VETH" netns "$RIGHT_NS"

    ip -n "$LEFT_NS" addr add "${LEFT_IP}/24" dev "$LEFT_VETH"
    ip -n "$RIGHT_NS" addr add "${RIGHT_IP}/24" dev "$RIGHT_VETH"

    ip -n "$LEFT_NS" link set lo up
    ip -n "$LEFT_NS" link set "$LEFT_VETH" up
    ip -n "$RIGHT_NS" link set lo up
    ip -n "$RIGHT_NS" link set "$RIGHT_VETH" up

    log_success "Network namespaces ready"
}

#=============================================================================
# Libreswan configuration
#=============================================================================

setup_libreswan_configs() {
    log_info "Creating libreswan configurations..."

    mkdir -p "$LEFT_CONF_DIR" "$RIGHT_CONF_DIR"

    # Use simple PSK (matching strongswan experiment setup)
    # This is proven to work and simplifies debugging
    PSK="test123"
    log_info "  Using PSK: test123 (matching strongswan setup)"

    # Left config
    cat > "$LEFT_CONF_DIR/ipsec.conf" <<EOF
config setup
    logfile=/tmp/pluto-left.log
    logtime=yes
    plutodebug=all
    protostack=netkey

conn net
    left=$LEFT_IP
    right=$RIGHT_IP
    leftid=left
    rightid=right
    authby=secret
    auto=add
    type=tunnel
    ike=aes256-sha2_256-modp2048
    phase2=esp
    phase2alg=aes256-sha2_256
    leftsubnet=$LEFT_IP/32
    rightsubnet=$RIGHT_IP/32
EOF

    cat > "$LEFT_CONF_DIR/ipsec.secrets" <<EOF
# Libreswan IPsec secrets - IP-based format
# Use wildcard for maximum compatibility
: PSK "$PSK"
EOF
    chmod 600 "$LEFT_CONF_DIR/ipsec.secrets"

    # Right config
    cat > "$RIGHT_CONF_DIR/ipsec.conf" <<EOF
config setup
    logfile=/tmp/pluto-right.log
    logtime=yes
    plutodebug=all
    protostack=netkey

conn net
    left=$RIGHT_IP
    right=$LEFT_IP
    leftid=right
    rightid=left
    authby=secret
    auto=add
    type=tunnel
    ike=aes256-sha2_256-modp2048
    phase2=esp
    phase2alg=aes256-sha2_256
    leftsubnet=$RIGHT_IP/32
    rightsubnet=$LEFT_IP/32
EOF

    cat > "$RIGHT_CONF_DIR/ipsec.secrets" <<EOF
# Libreswan IPsec secrets - IP-based format
# Use wildcard for maximum compatibility
: PSK "$PSK"
EOF
    chmod 600 "$RIGHT_CONF_DIR/ipsec.secrets"

    log_success "Libreswan configs ready (AES-256, PSK: test123)"
}

#=============================================================================
# Pluto process management
#=============================================================================

start_pluto() {
    local side="$1"

    if [[ "$side" == "left" ]]; then
        log_info "Starting pluto (left)..."

        ip netns exec "$LEFT_NS" bash -c "
            export IPSEC_CONFS=$LEFT_CONF_DIR
            export PLUTO_CRYPTO_HELPER_DEBUG=1
            export NSS_DEBUG_PKCS11_MODULE=1
            $PLUTO_PATH \
                --config $LEFT_CONF_DIR/ipsec.conf \
                --secretsfile $LEFT_CONF_DIR/ipsec.secrets \
                --nofork --stderrlog \
                </dev/null >/tmp/pluto-left.log 2>&1 & disown
            echo \$! > /tmp/pluto-left.pid
        "

        sleep 1
        LEFT_PLUTO_PID=$(cat /tmp/pluto-left.pid 2>/dev/null || echo "")
        
        if [[ -z "$LEFT_PLUTO_PID" ]] || ! kill -0 "$LEFT_PLUTO_PID" 2>/dev/null; then
            log_error "Failed to start pluto (left)"
            cat /tmp/pluto-left.log 2>&1 | tail -20 >&2
            return 1
        fi

        log_success "Pluto (left) started (PID: $LEFT_PLUTO_PID)"

        # Attach LLDB if not skipped
        if [[ "$SKIP_LLDB" != "true" ]]; then
            attach_lldb_monitor "left" "$LEFT_PLUTO_PID" || {
                log_error "Failed to attach LLDB to left pluto"
                return 1
            }
        fi

        # Manual mode pause (only in interactive mode without workflow)
        if [[ "$MODE" == "interactive" && "$WORKFLOW" == "none" ]]; then
            echo ""
            if [[ "$SKIP_LLDB" == "true" ]]; then
                log_info "Left pluto is ready. LLDB monitoring is disabled (--skip-lldb)."
            else
                log_info "Left pluto is ready. LLDB monitoring is active."
            fi
            echo ""
            read -p "Press Enter to continue and start right pluto..." _DUMMY
            echo ""
        fi
    else
        log_info "Starting pluto (right)..."

        ip netns exec "$RIGHT_NS" bash -c "
            export IPSEC_CONFS=$RIGHT_CONF_DIR
            export PLUTO_CRYPTO_HELPER_DEBUG=1
            export NSS_DEBUG_PKCS11_MODULE=1
            $PLUTO_PATH \
                --config $RIGHT_CONF_DIR/ipsec.conf \
                --secretsfile $RIGHT_CONF_DIR/ipsec.secrets \
                --nofork --stderrlog \
                </dev/null >/tmp/pluto-right.log 2>&1 & disown
            echo \$! > /tmp/pluto-right.pid
        "

        sleep 1
        RIGHT_PLUTO_PID=$(cat /tmp/pluto-right.pid 2>/dev/null || echo "")

        if [[ -z "$RIGHT_PLUTO_PID" ]] || ! kill -0 "$RIGHT_PLUTO_PID" 2>/dev/null; then
            log_error "Failed to start pluto (right)"
            cat /tmp/pluto-right.log 2>&1 | tail -20 >&2
            return 1
        fi

        log_success "Pluto (right) started (PID: $RIGHT_PLUTO_PID)"

        # Attach LLDB if not skipped
        if [[ "$SKIP_LLDB" != "true" ]]; then
            attach_lldb_monitor "right" "$RIGHT_PLUTO_PID" || {
                log_error "Failed to attach LLDB to right pluto"
                return 1
            }
        fi
    fi
}

#=============================================================================
# LLDB Monitoring
#=============================================================================

attach_lldb_monitor() {
    local side="$1"
    local pid="$2"

    if [[ "$SKIP_LLDB" == "true" ]]; then
        log_warn "LLDB monitoring disabled (--skip-lldb)"
        return 0
    fi

    local IPSEC_OUTPUT_DIR="$USERSPACE_DIR/$side"
    local monitoring_script="$EXPERIMENT_DIR/monitoring_ipsec.py"

    if [[ ! -f "$monitoring_script" ]]; then
        log_error "Monitoring script not found: $monitoring_script"
        return 1
    fi

    log_info "Attaching LLDB to pluto ($side, PID: $pid)..."

    # Background mode for automated workflow
    log_debug "Running LLDB in background for $side"

    # LLDB logging
    log_debug "  LLDB logging:"
    log_debug "    Stdout:  $IPSEC_OUTPUT_DIR/lldb_callbacks.log"

    # Start LLDB in background
    # Use netns exec to attach within the namespace
    # Command sequence:
    # 1. Import script (registers commands)
    # 2. Attach to process
    # 3. Setup monitoring (sets breakpoints, creates readiness marker)
    # 4. Auto-continue with 2-second delay (enters keep-alive loop)
    ip netns exec "${side}" bash -c "
        IPSEC_NETNS='$side' \
        IPSEC_OUTPUT_DIR='$IPSEC_OUTPUT_DIR' \
        IPSEC_MODE='automated' \
        PYTHONUNBUFFERED=1 \
        nohup lldb \
            --batch \
            -o 'settings set auto-confirm true' \
            -o 'command script import $monitoring_script' \
            -o 'process attach -p $pid' \
            -o 'ipsec_setup_monitoring' \
            -o 'ipsec_auto_continue 2' \
            > '$IPSEC_OUTPUT_DIR/lldb_callbacks.log' 2>&1 &
        echo \$! > /tmp/lldb-$side.pid
    " || {
        log_error "Failed to start LLDB for $side"
        return 1
    }

    sleep 0.5
    local lldb_pid=$(cat /tmp/lldb-$side.pid 2>/dev/null || echo "")

    if [[ -z "$lldb_pid" ]] || ! kill -0 "$lldb_pid" 2>/dev/null; then
        log_error "LLDB process failed to start for $side"
        return 1
    fi

    log_debug "Background LLDB started (PID: $lldb_pid)"

    # Wait for LLDB readiness marker file
    local wait_count=0
    local max_wait=60  # 30 seconds (60 * 0.5s)
    local readiness_marker="$IPSEC_OUTPUT_DIR/.lldb_ready_$side"

    log_debug "  Waiting for LLDB readiness marker: $readiness_marker"

    while [[ $wait_count -lt $max_wait ]]; do
        # Check if readiness marker exists
        if [[ -f "$readiness_marker" ]]; then
            log_debug "  LLDB readiness marker found"

            # Verify process is still alive
            if kill -0 "$pid" 2>/dev/null; then
                log_success "  LLDB attached and process $pid is running"
                return 0
            else
                log_error "  Process $pid died after LLDB attachment!"
                return 1
            fi
        fi

        # Check if LLDB process died
        if ! kill -0 "$lldb_pid" 2>/dev/null; then
            log_error "LLDB process exited before becoming ready"
            log_error "Check logs: $IPSEC_OUTPUT_DIR/lldb_callbacks.log"

            if [[ -f "$IPSEC_OUTPUT_DIR/lldb_callbacks.log" ]]; then
                log_error "LLDB output (last 30 lines):"
                tail -n 30 "$IPSEC_OUTPUT_DIR/lldb_callbacks.log" | sed 's/^/    /' >&2
            fi

            return 1
        fi

        sleep 0.5
        ((wait_count++))
    done

    # Timeout
    log_error "Timeout waiting for LLDB readiness marker (waited 30s)"
    log_error "Expected marker: $readiness_marker"
    log_error "LLDB logs: $IPSEC_OUTPUT_DIR/lldb_callbacks.log"

    if [[ -f "$IPSEC_OUTPUT_DIR/lldb_callbacks.log" ]]; then
        log_error "LLDB output (last 40 lines):"
        tail -n 40 "$IPSEC_OUTPUT_DIR/lldb_callbacks.log" | sed 's/^/    /' >&2
    fi

    return 1
}

#=============================================================================
# Kernel monitoring
#=============================================================================

kernel_checkpoint() {
    local checkpoint="$1"

    # Skip if drgn not available or kernel monitoring disabled
    if [[ "${SKIP_KERNEL_MONITORING:-false}" == "true" ]]; then
        log_warn "Skipping kernel checkpoint: $checkpoint (drgn not available)"
        return 0
    fi

    log_info "Kernel checkpoint: $checkpoint"

    local kernel_monitor="$EXPERIMENT_DIR/monitor_kernel_xfrm.py"

    # Enable comprehensive forensic scanning for terminate checkpoints
    local forensic_flags=""
    if [[ "$checkpoint" == *"terminate"* ]]; then
        forensic_flags="--scan-freelists --scan-stacks --scan-vmalloc"
        log_info "Enabling comprehensive kernel scan (slub, slab, vmalloc, stacks)"
    fi

    for side in left right; do
        local netns_file="/var/run/netns/$side"
        local output_dir="$KERNEL_DIR/$side"
        mkdir -p "$output_dir"

        # Use detected Python interpreter (supports venv)
        "$KERNEL_PYTHON" "$kernel_monitor" --checkpoint "$checkpoint" \
            --netns-file "$netns_file" --output-dir "$output_dir" \
            $forensic_flags \
            2>&1 | tee -a "$output_dir/kernel_monitor.log" || true
    done

    log_success "Kernel checkpoint complete"
}

userspace_checkpoint() {
    local checkpoint="$1"

    # Skip if LLDB monitoring disabled
    if [[ "$SKIP_LLDB" == "true" ]]; then
        log_warn "Skipping userspace checkpoint: $checkpoint (LLDB disabled)"
        return 0
    fi

    log_info "Userspace checkpoint: $checkpoint"

    local trigger_script="$EXPERIMENT_DIR/trigger_userspace_dump.sh"

    for side in left right; do
        local output_dir="$USERSPACE_DIR/$side"

        # Check if LLDB is ready for this side
        if [[ ! -f "$output_dir/.lldb_ready_$side" ]]; then
            log_warn "Skipping userspace dump for $side (LLDB not ready)"
            continue
        fi

        # Trigger dump via marker file
        "$trigger_script" "$output_dir" "$checkpoint" 2>/dev/null || true
    done

    # Wait for LLDB to process dump requests
    sleep 2

    log_success "Userspace checkpoint complete"
}

#=============================================================================
# Network packet capture
#=============================================================================

start_packet_capture() {
    if [[ "$ENABLE_TRAFFIC_CAPTURE" != "true" ]]; then
        return 0
    fi

    log_info "Starting packet capture..."

    local filter='udp port 500 or udp port 4500 or proto 50'
    local left_pcap="$NETWORK_DIR/left.pcap"
    local right_pcap="$NETWORK_DIR/right.pcap"

    # Start tcpdump in left namespace
    ip netns exec "$LEFT_NS" tcpdump -i any -s 0 -U -nn -w "$left_pcap" $filter >/dev/null 2>&1 &
    LEFT_TCPDUMP_PID=$!

    # Start tcpdump in right namespace
    ip netns exec "$RIGHT_NS" tcpdump -i any -s 0 -U -nn -w "$right_pcap" $filter >/dev/null 2>&1 &
    RIGHT_TCPDUMP_PID=$!

    sleep 0.5  # Give tcpdump time to initialize

    log_success "Packet capture started (Left PID: $LEFT_TCPDUMP_PID, Right PID: $RIGHT_TCPDUMP_PID)"
    log_info "Captures: $left_pcap, $right_pcap"
}

stop_packet_capture() {
    if [[ "$ENABLE_TRAFFIC_CAPTURE" != "true" ]]; then
        return 0
    fi

    log_info "Stopping packet capture..."

    # Stop left tcpdump
    if [[ -n "$LEFT_TCPDUMP_PID" ]] && kill -0 "$LEFT_TCPDUMP_PID" 2>/dev/null; then
        kill -INT "$LEFT_TCPDUMP_PID" 2>/dev/null || true
        wait "$LEFT_TCPDUMP_PID" 2>/dev/null || true
        log_success "Left capture stopped (PID: $LEFT_TCPDUMP_PID)"
    fi

    # Stop right tcpdump
    if [[ -n "$RIGHT_TCPDUMP_PID" ]] && kill -0 "$RIGHT_TCPDUMP_PID" 2>/dev/null; then
        kill -INT "$RIGHT_TCPDUMP_PID" 2>/dev/null || true
        wait "$RIGHT_TCPDUMP_PID" 2>/dev/null || true
        log_success "Right capture stopped (PID: $RIGHT_TCPDUMP_PID)"
    fi

    log_success "Packet capture complete"
}

generate_esp_traffic() {
    # Generate ESP-encrypted traffic by running HTTP server in RIGHT namespace
    # and fetching from LEFT namespace using curl.
    # This generates encrypted ESP packets that can be analyzed in pcap captures.

    if [[ "$ENABLE_TRAFFIC_CAPTURE" != "true" ]]; then
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

#=============================================================================
# IPsec operations
#=============================================================================

ipsec_initiate() {
    log_info "Initiating IPsec connection..."

    # Before dumps
    userspace_checkpoint "before_initiate"
    kernel_checkpoint "before_initiate"

    # Execute operation
    ip netns exec "$LEFT_NS" bash -c "
        export IPSEC_CONFS=$LEFT_CONF_DIR
        ipsec auto --up net
    "

    sleep 2

    # After dumps
    userspace_checkpoint "after_initiate"
    kernel_checkpoint "after_initiate"

    # Generate ESP traffic if enabled
    if [[ "$ENABLE_TRAFFIC_CAPTURE" == "true" ]]; then
        log_info "Generating ESP traffic after initiate..."
        generate_esp_traffic
        kernel_checkpoint "after_initiate_traffic"
    fi

    log_success "IPsec connection established"
}

ipsec_rekey() {
    log_info "Triggering rekey..."

    # Before dumps
    userspace_checkpoint "before_rekey"
    kernel_checkpoint "before_rekey"

    # Execute operation
    ip netns exec "$LEFT_NS" bash -c "
        export IPSEC_CONFS=$LEFT_CONF_DIR
        ipsec whack --rekey-ike --name net || ipsec whack --rekey-ipsec --name net
    " || true

    sleep 2

    # After dumps
    userspace_checkpoint "after_rekey"
    kernel_checkpoint "after_rekey"

    # Generate ESP traffic if enabled
    if [[ "$ENABLE_TRAFFIC_CAPTURE" == "true" ]]; then
        log_info "Generating ESP traffic after rekey..."
        generate_esp_traffic
        kernel_checkpoint "after_rekey_traffic"
    fi

    log_success "Rekey completed"
}

ipsec_terminate() {
    log_info "Terminating IPsec connection..."

    # Generate ESP traffic BEFORE terminate if enabled
    if [[ "$ENABLE_TRAFFIC_CAPTURE" == "true" ]]; then
        log_info "Generating ESP traffic before terminate..."
        generate_esp_traffic
    fi

    # Before dumps
    userspace_checkpoint "before_terminate"
    kernel_checkpoint "before_terminate"

    # Execute operation
    ip netns exec "$LEFT_NS" bash -c "
        export IPSEC_CONFS=$LEFT_CONF_DIR
        ipsec auto --down net
    "

    sleep 2

    # After dumps (comprehensive kernel scan on terminate)
    userspace_checkpoint "after_terminate"
    kernel_checkpoint "after_terminate"

    log_success "IPsec connection terminated"
}

ipsec_status() {
    log_info "IPsec Status:"
    echo ""
    echo "=== LEFT ==="
    ip netns exec "$LEFT_NS" bash -c "
        export IPSEC_CONFS=$LEFT_CONF_DIR
        ipsec status
    " || true
    echo ""
    echo "=== RIGHT ==="
    ip netns exec "$RIGHT_NS" bash -c "
        export IPSEC_CONFS=$RIGHT_CONF_DIR
        ipsec status
    " || true
    echo ""
}

#=============================================================================
# Interactive menu
#=============================================================================

interactive_menu() {
    while true; do
        echo ""
        echo "=========================================="
        echo " IPsec/Libreswan Experiment Menu"
        echo "=========================================="
        echo "[I] Initiate - Establish IPsec connection"
        echo "[R] Rekey - Trigger rekey"
        echo "[T] Terminate - Close connection"
        echo "[S] Status - Show status"
        echo "[K] Kernel checkpoint - Manual kernel scan"
        echo "[Q] Quit - Cleanup and exit"
        echo "=========================================="
        read -p "Choose an option: " choice

        case "$choice" in
            [Ii])
                ipsec_initiate
                ;;
            [Rr])
                ipsec_rekey
                ;;
            [Tt])
                ipsec_terminate
                ;;
            [Ss])
                ipsec_status
                ;;
            [Kk])
                read -p "Checkpoint name: " checkpoint_name
                kernel_checkpoint "$checkpoint_name"
                ;;
            [Qq])
                log_info "Exiting..."
                break
                ;;
            *)
                log_error "Invalid option: $choice"
                ;;
        esac
    done
}

#=============================================================================
# Automated workflow
#=============================================================================

run_workflow() {
    case "$WORKFLOW" in
        initiate)
            ipsec_initiate
            ;;
        rekey)
            ipsec_initiate
            sleep 2
            ipsec_rekey
            ;;
        terminate)
            ipsec_initiate
            sleep 2
            ipsec_terminate
            ;;
        full)
            log_info "Running full workflow: initiate -> rekey -> terminate"
            ipsec_initiate
            sleep 3
            ipsec_rekey
            sleep 3
            ipsec_terminate
            log_success "Full workflow complete"
            ;;
        none)
            log_info "No workflow specified"
            ;;
        *)
            log_error "Unknown workflow: $WORKFLOW"
            exit 1
            ;;
    esac
}

#=============================================================================
# Main
#=============================================================================

main() {
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi

    parse_arguments "$@"

    log_info "IPsec/Libreswan Key Lifecycle Experiment"
    log_info "Mode: $MODE, Workflow: $WORKFLOW"

    check_dependencies

    # Create output directories
    mkdir -p "$OUTPUT_DIR" "$KERNEL_DIR" "$USERSPACE_DIR/left" "$USERSPACE_DIR/right" "$NETWORK_DIR"
    touch "$EXPERIMENT_LOG"

    log_info "Output directory: $OUTPUT_DIR"

    # Initial cleanup
    bash "$EXPERIMENT_DIR/cleanup.sh" 2>/dev/null || true
    export CLEANUP_IN_PROGRESS=false

    # Setup
    setup_netns
    setup_libreswan_configs
    start_pluto "left"
    start_pluto "right"

    # Start packet capture if --traffic flag is set
    start_packet_capture

    kernel_checkpoint "init"

    # Run workflow or interactive menu
    if [[ "$MODE" == "auto" ]]; then
        run_workflow
    else
        interactive_menu
    fi

    # Stop packet capture at end of experiment
    stop_packet_capture

    log_success "Experiment complete!"
    log_info "Results saved to: $OUTPUT_DIR"
}

main "$@"
