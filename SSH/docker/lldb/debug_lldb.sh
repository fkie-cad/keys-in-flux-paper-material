#!/bin/bash
# debug_lldb.sh - Interactive LLDB debugging script for OpenSSH KEX monitoring
# Usage:
#   ./debug_lldb.sh run      # Launch sshd under LLDB with manual control
#   ./debug_lldb.sh attach   # Attach to running sshd process
#   ./debug_lldb.sh symbols  # Check available KEX symbols
#   ./debug_lldb.sh test     # Test KEX breakpoint without callbacks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SSHD_BINARY="/usr/sbin/sshd"
RESULTS_DIR="${LLDB_RESULTS_DIR:-/data/lldb_results}"
DUMPS_DIR="${LLDB_DUMPS_DIR:-/data/dumps}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function print_header() {
    echo -e "${BLUE}========================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}========================================${NC}"
}

function print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

function print_error() {
    echo -e "${RED}✗ $1${NC}"
}

function print_info() {
    echo -e "${YELLOW}→ $1${NC}"
}

function check_lldb() {
    if ! command -v lldb &> /dev/null; then
        print_error "LLDB not found. Install with: apt-get install lldb python3-lldb"
        exit 1
    fi
    print_success "LLDB found: $(lldb --version | head -n1)"
}

function check_sshd() {
    if [ ! -f "$SSHD_BINARY" ]; then
        print_error "sshd not found at $SSHD_BINARY"
        exit 1
    fi

    # Check if binary has symbols
    if nm "$SSHD_BINARY" | grep -q kex_derive_keys; then
        print_success "sshd has debug symbols"
    else
        print_error "sshd is stripped (no debug symbols)"
        exit 1
    fi
}

function show_symbols() {
    print_header "Available KEX-related Symbols"

    print_info "Searching for KEX symbols in $SSHD_BINARY..."
    echo ""

    echo "=== Key Derivation Functions ==="
    nm -C "$SSHD_BINARY" | grep -i "kex.*derive" || echo "  (none found)"
    echo ""

    echo "=== KEX Functions ==="
    nm -C "$SSHD_BINARY" | grep -E "^[0-9a-f]+ T kex" || echo "  (none found)"
    echo ""

    echo "=== Memory Clearing Functions ==="
    nm -C "$SSHD_BINARY" | grep -E "(bzero|freezero)" || echo "  (none found)"
    echo ""

    echo "=== Key Management Functions ==="
    nm -C "$SSHD_BINARY" | grep -E "(sshkey|cipher|mac)" | head -20 || echo "  (none found)"
    echo ""

    # Show kex_derive_keys address specifically
    if kex_addr=$(nm "$SSHD_BINARY" | grep " T kex_derive_keys$" | awk '{print $1}'); then
        print_success "kex_derive_keys found at address: 0x$kex_addr"
    else
        print_error "kex_derive_keys not found"
    fi
}

function test_breakpoint() {
    print_header "Testing KEX Breakpoint"

    print_info "Creating LLDB command script..."

    cat > /tmp/lldb_test.py << 'EOF'
import lldb
import sys

def test_breakpoint(debugger, command, result, internal_dict):
    """Test if kex_derive_keys breakpoint can be set"""
    target = debugger.GetSelectedTarget()

    if not target.IsValid():
        print("ERROR: No valid target")
        return

    print("=== Target Info ===")
    print(f"Executable: {target.GetExecutable().GetFilename()}")
    print(f"Triple: {target.GetTriple()}")
    print(f"Byte Order: {target.GetByteOrder()}")
    print(f"Address Size: {target.GetAddressByteSize()} bytes")
    print("")

    print("=== Setting Breakpoints ===")

    # Try by name
    bp1 = target.BreakpointCreateByName("kex_derive_keys")
    print(f"Breakpoint by name: ID={bp1.GetID()}, Locations={bp1.GetNumLocations()}")

    # Try by address
    kex_addr = 0x9c028
    bp2 = target.BreakpointCreateByAddress(kex_addr)
    print(f"Breakpoint by address (0x{kex_addr:x}): ID={bp2.GetID()}, Valid={bp2.IsValid()}")

    # Try alternate functions
    alternates = ["kex_send_newkeys", "kex_input_newkeys", "kex_setup"]
    for func in alternates:
        bp = target.BreakpointCreateByName(func)
        if bp.GetNumLocations() > 0:
            print(f"Alternate breakpoint on {func}: ID={bp.GetID()}, Locations={bp.GetNumLocations()}")

    print("")
    print("=== Breakpoint Status ===")
    debugger.HandleCommand("breakpoint list")

# Register command
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_test.test_breakpoint test_bp')
    print("Command registered: test_bp")
EOF

    print_info "Starting LLDB test session..."
    echo ""

    lldb "$SSHD_BINARY" -o "command script import /tmp/lldb_test.py" -o "test_bp" -o "quit"
}

function run_with_lldb() {
    print_header "Running sshd Under LLDB"

    print_info "Directories:"
    echo "  Results: $RESULTS_DIR"
    echo "  Dumps: $DUMPS_DIR"
    echo ""

    print_info "Starting interactive LLDB session..."
    print_info "Useful commands:"
    echo "  (lldb) breakpoint set -n kex_derive_keys"
    echo "  (lldb) breakpoint set -a 0x9c028"
    echo "  (lldb) breakpoint list"
    echo "  (lldb) run -D -e"
    echo "  (lldb) process status"
    echo "  (lldb) thread backtrace"
    echo "  (lldb) frame variable"
    echo "  (lldb) quit"
    echo ""

    # Load monitoring scripts if available
    if [ -f "$SCRIPT_DIR/ssh_monitor.py" ]; then
        print_info "Monitoring scripts available - to load manually:"
        echo "  (lldb) command script import $SCRIPT_DIR/ssh_monitor.py"
        echo "  (lldb) command script import $SCRIPT_DIR/openssh_callbacks.py"
        echo ""
    fi

    lldb "$SSHD_BINARY"
}

function attach_to_sshd() {
    print_header "Attach to Running sshd"

    print_info "Looking for sshd processes..."

    # Find sshd processes
    pids=$(pgrep -f "sshd" || true)

    if [ -z "$pids" ]; then
        print_error "No sshd processes found"
        exit 1
    fi

    echo ""
    echo "Found sshd processes:"
    ps aux | grep sshd | grep -v grep
    echo ""

    # If only one sshd, attach to it
    pid_count=$(echo "$pids" | wc -w)

    if [ "$pid_count" -eq 1 ]; then
        target_pid="$pids"
        print_info "Attaching to PID $target_pid..."
    else
        print_info "Multiple sshd processes found. Enter PID to attach to:"
        read -r target_pid

        if ! echo "$pids" | grep -q "$target_pid"; then
            print_error "Invalid PID"
            exit 1
        fi
    fi

    print_info "Attaching LLDB to PID $target_pid..."
    print_info "After attach, try:"
    echo "  (lldb) breakpoint set -n kex_derive_keys"
    echo "  (lldb) continue"
    echo "  (then trigger SSH connection from another terminal)"
    echo ""

    lldb -p "$target_pid"
}

function create_lldb_commands() {
    print_header "Generate LLDB Command File"

    cat > /tmp/lldb_commands.txt << EOF
# LLDB Commands for OpenSSH KEX Debugging

# Import monitoring scripts
command script import $SCRIPT_DIR/ssh_monitor.py
command script import $SCRIPT_DIR/openssh_callbacks.py

# Set breakpoints
breakpoint set -n kex_derive_keys
breakpoint set -a 0x9c028
breakpoint set -n explicit_bzero

# List breakpoints
breakpoint list

# Run sshd
run -D -e

# Useful commands during debugging:
# - continue (c)           : Continue execution
# - breakpoint list (br l) : List all breakpoints
# - thread backtrace (bt)  : Show call stack
# - frame variable (fr v)  : Show local variables
# - process status (pro st): Show process state
# - quit (q)               : Exit LLDB
EOF

    print_success "Created /tmp/lldb_commands.txt"
    print_info "Use with: lldb -s /tmp/lldb_commands.txt $SSHD_BINARY"
    echo ""
    cat /tmp/lldb_commands.txt
}

function show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  run       - Launch sshd under LLDB with manual control"
    echo "  attach    - Attach to running sshd process"
    echo "  symbols   - Show available KEX symbols in sshd binary"
    echo "  test      - Test KEX breakpoint without callbacks"
    echo "  commands  - Generate LLDB command file"
    echo "  help      - Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  LLDB_RESULTS_DIR  - Results directory (default: /data/lldb_results)"
    echo "  LLDB_DUMPS_DIR    - Memory dumps directory (default: /data/dumps)"
    echo ""
}

# Main logic
case "${1:-help}" in
    run)
        check_lldb
        check_sshd
        run_with_lldb
        ;;
    attach)
        check_lldb
        attach_to_sshd
        ;;
    symbols)
        check_sshd
        show_symbols
        ;;
    test)
        check_lldb
        check_sshd
        test_breakpoint
        ;;
    commands)
        create_lldb_commands
        ;;
    help|--help|-h)
        show_usage
        ;;
    *)
        print_error "Unknown command: $1"
        echo ""
        show_usage
        exit 1
        ;;
esac
