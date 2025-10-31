#!/bin/bash
# debug_dropbear.sh - Interactive LLDB debugging script for Dropbear KEX monitoring
# Usage:
#   ./debug_dropbear.sh run      # Launch dropbear under LLDB with manual control
#   ./debug_dropbear.sh attach   # Attach to running dropbear process
#   ./debug_dropbear.sh symbols  # Check available KEX symbols
#   ./debug_dropbear.sh test     # Test KEX breakpoint without callbacks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DROPBEAR_BINARY="/usr/sbin/dropbear"
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

function check_dropbear() {
    if [ ! -f "$DROPBEAR_BINARY" ]; then
        print_error "dropbear not found at $DROPBEAR_BINARY"
        exit 1
    fi

    # Check if binary has symbols
    if nm "$DROPBEAR_BINARY" | grep -q gen_new_keys; then
        print_success "dropbear has debug symbols"
    else
        print_error "dropbear is stripped (no debug symbols)"
        exit 1
    fi
}

function show_symbols() {
    print_header "Available KEX-related Symbols in Dropbear"

    print_info "Searching for KEX symbols in $DROPBEAR_BINARY..."
    echo ""

    echo "=== Key Generation Functions ==="
    nm -C "$DROPBEAR_BINARY" | grep -i "gen.*key" || echo "  (none found)"
    echo ""

    echo "=== KEX Functions ==="
    nm -C "$DROPBEAR_BINARY" | grep -E "^[0-9a-f]+ T.*kex" || echo "  (none found)"
    echo ""

    echo "=== Memory Clearing Functions ==="
    nm -C "$DROPBEAR_BINARY" | grep -E "m_burn" || echo "  (none found)"
    echo ""

    echo "=== Session Management ==="
    nm -C "$DROPBEAR_BINARY" | grep -E "(session|switch_keys)" | head -20 || echo "  (none found)"
    echo ""

    # Show specific Dropbear KEX functions
    echo "=== Critical Dropbear KEX Functions ==="
    for func in gen_new_keys m_burn switch_keys recv_msg_kexdh_init send_msg_kexdh_reply; do
        if addr=$(nm "$DROPBEAR_BINARY" | grep " T $func$" | awk '{print $1}'); then
            print_success "$func found at address: 0x$addr"
        else
            print_error "$func not found"
        fi
    done
}

function test_breakpoint() {
    print_header "Testing Dropbear KEX Breakpoint"

    print_info "Creating LLDB command script..."

    cat > /tmp/lldb_dropbear_test.py << 'EOF'
import lldb
import sys

def test_breakpoint(debugger, command, result, internal_dict):
    """Test if Dropbear KEX breakpoints can be set"""
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

    print("=== Setting Dropbear Breakpoints ===")

    # Core KEX functions
    kex_functions = [
        "gen_new_keys",
        "m_burn",
        "switch_keys",
        "recv_msg_kexdh_init",
        "send_msg_kexdh_reply",
        "kexdh_gen_x",
        "gen_kexdh_reply",
    ]

    for func in kex_functions:
        bp = target.BreakpointCreateByName(func)
        locations = bp.GetNumLocations()
        if locations > 0:
            print(f"✓ {func}: ID={bp.GetID()}, Locations={locations}")
        else:
            print(f"✗ {func}: Not found")

    print("")
    print("=== Breakpoint Status ===")
    debugger.HandleCommand("breakpoint list")

# Register command
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f lldb_dropbear_test.test_breakpoint test_bp')
    print("Command registered: test_bp")
EOF

    print_info "Starting LLDB test session..."
    echo ""

    lldb "$DROPBEAR_BINARY" -o "command script import /tmp/lldb_dropbear_test.py" -o "test_bp" -o "quit"
}

function run_with_lldb() {
    print_header "Running Dropbear Under LLDB"

    print_info "Directories:"
    echo "  Results: $RESULTS_DIR"
    echo "  Dumps: $DUMPS_DIR"
    echo ""

    print_info "Starting interactive LLDB session..."
    print_info "Useful commands:"
    echo "  (lldb) breakpoint set -n gen_new_keys"
    echo "  (lldb) breakpoint set -n m_burn"
    echo "  (lldb) breakpoint set -n switch_keys"
    echo "  (lldb) breakpoint list"
    echo "  (lldb) run -F -E -p 22"
    echo "  (lldb) process status"
    echo "  (lldb) thread backtrace"
    echo "  (lldb) frame variable"
    echo "  (lldb) quit"
    echo ""

    # Load monitoring scripts if available
    if [ -f "$SCRIPT_DIR/ssh_monitor.py" ]; then
        print_info "Monitoring scripts available - to load manually:"
        echo "  (lldb) command script import $SCRIPT_DIR/ssh_monitor.py"
        echo "  (lldb) command script import $SCRIPT_DIR/dropbear_callbacks.py"
        echo ""
    fi

    print_info "Note: Dropbear uses -F (foreground) and -E (stderr logging)"
    echo ""

    lldb "$DROPBEAR_BINARY"
}

function attach_to_dropbear() {
    print_header "Attach to Running Dropbear"

    print_info "Looking for dropbear processes..."

    # Find dropbear processes
    pids=$(pgrep -f "dropbear" || true)

    if [ -z "$pids" ]; then
        print_error "No dropbear processes found"
        exit 1
    fi

    echo ""
    echo "Found dropbear processes:"
    ps aux | grep dropbear | grep -v grep
    echo ""

    # If only one dropbear, attach to it
    pid_count=$(echo "$pids" | wc -w)

    if [ "$pid_count" -eq 1 ]; then
        target_pid="$pids"
        print_info "Attaching to PID $target_pid..."
    else
        print_info "Multiple dropbear processes found. Enter PID to attach to:"
        read -r target_pid

        if ! echo "$pids" | grep -q "$target_pid"; then
            print_error "Invalid PID"
            exit 1
        fi
    fi

    print_info "Attaching LLDB to PID $target_pid..."
    print_info "After attach, try:"
    echo "  (lldb) breakpoint set -n gen_new_keys"
    echo "  (lldb) breakpoint set -n m_burn"
    echo "  (lldb) continue"
    echo "  (then trigger SSH connection from another terminal)"
    echo ""

    lldb -p "$target_pid"
}

function create_lldb_commands() {
    print_header "Generate LLDB Command File"

    cat > /tmp/lldb_dropbear_commands.txt << EOF
# LLDB Commands for Dropbear KEX Debugging

# Import monitoring scripts
command script import $SCRIPT_DIR/ssh_monitor.py
command script import $SCRIPT_DIR/dropbear_callbacks.py

# Set breakpoints on Dropbear KEX functions
breakpoint set -n gen_new_keys
breakpoint set -n m_burn
breakpoint set -n switch_keys
breakpoint set -n recv_msg_kexdh_init
breakpoint set -n send_msg_kexdh_reply

# List breakpoints
breakpoint list

# Run dropbear in foreground mode
run -F -E -p 22

# Useful commands during debugging:
# - continue (c)           : Continue execution
# - breakpoint list (br l) : List all breakpoints
# - thread backtrace (bt)  : Show call stack
# - frame variable (fr v)  : Show local variables
# - process status (pro st): Show process state
# - quit (q)               : Exit LLDB
EOF

    print_success "Created /tmp/lldb_dropbear_commands.txt"
    print_info "Use with: lldb -s /tmp/lldb_dropbear_commands.txt $DROPBEAR_BINARY"
    echo ""
    cat /tmp/lldb_dropbear_commands.txt
}

function show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  run       - Launch dropbear under LLDB with manual control"
    echo "  attach    - Attach to running dropbear process"
    echo "  symbols   - Show available KEX symbols in dropbear binary"
    echo "  test      - Test KEX breakpoint without callbacks"
    echo "  commands  - Generate LLDB command file"
    echo "  help      - Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  LLDB_RESULTS_DIR  - Results directory (default: /data/lldb_results)"
    echo "  LLDB_DUMPS_DIR    - Memory dumps directory (default: /data/dumps)"
    echo ""
    echo "Dropbear-Specific Notes:"
    echo "  - Dropbear uses -F for foreground mode (like sshd -D)"
    echo "  - Dropbear uses -E for stderr logging (like sshd -e)"
    echo "  - Key function: gen_new_keys() instead of kex_derive_keys()"
    echo "  - Memory clear: m_burn() instead of explicit_bzero()"
    echo ""
}

# Main logic
case "${1:-help}" in
    run)
        check_lldb
        check_dropbear
        run_with_lldb
        ;;
    attach)
        check_lldb
        attach_to_dropbear
        ;;
    symbols)
        check_dropbear
        show_symbols
        ;;
    test)
        check_lldb
        check_dropbear
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
