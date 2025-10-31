#!/bin/bash
# debug_wolfssh.sh - Interactive LLDB debugging script for wolfSSH KEX monitoring
# Usage:
#   ./debug_wolfssh.sh run      # Launch wolfsshd under LLDB with manual control
#   ./debug_wolfssh.sh attach   # Attach to running wolfsshd process
#   ./debug_wolfssh.sh symbols  # Check available KEX symbols
#   ./debug_wolfssh.sh test     # Test KEX breakpoint without callbacks

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSHD_BINARY="/usr/local/bin/wolfsshd"
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

function check_ldconfig() {
    # Update library cache
    print_info "Updating shared library cache..."
    ldconfig

    # Check if wolfSSL is available
    if ldconfig -p | grep -q libwolfssl; then
        print_success "libwolfssl found in library cache"
    else
        print_error "libwolfssl not found. Check /etc/ld.so.conf.d/"
    fi
}

function check_wolfsshd() {
    if [ ! -f "$WOLFSSHD_BINARY" ]; then
        print_error "wolfsshd not found at $WOLFSSHD_BINARY"
        exit 1
    fi

    # Check if binary has symbols
    if nm "$WOLFSSHD_BINARY" 2>/dev/null | grep -q GenerateKeys; then
        print_success "wolfsshd has debug symbols"
    else
        print_error "wolfsshd is stripped (no debug symbols)"
        echo ""
        print_info "Note: wolfSSH may have symbols in libwolfssh.so instead"

        # Check library
        if [ -f /usr/local/lib/libwolfssh.so ]; then
            if nm /usr/local/lib/libwolfssh.so 2>/dev/null | grep -q GenerateKeys; then
                print_success "libwolfssh.so has debug symbols"
            fi
        fi
    fi
}

function show_symbols() {
    print_header "Available KEX-related Symbols in wolfSSH"

    print_info "Searching for KEX symbols in wolfsshd and libraries..."
    echo ""

    # Check both binary and library
    for target in "$WOLFSSHD_BINARY" "/usr/local/lib/libwolfssh.so"; do
        if [ ! -f "$target" ]; then
            continue
        fi

        echo "=== Symbols in $(basename $target) ==="

        echo "-- Key Generation Functions --"
        nm -C "$target" 2>/dev/null | grep -i "generate.*key" || echo "  (none found)"
        echo ""

        echo "-- KEX Functions --"
        nm -C "$target" 2>/dev/null | grep -E "kex|Kex|KEX" | head -20 || echo "  (none found)"
        echo ""

        echo "-- Memory Clearing Functions --"
        nm -C "$target" 2>/dev/null | grep -i "forcezero\|zero" || echo "  (none found)"
        echo ""

        echo "-- Session Management --"
        nm -C "$target" 2>/dev/null | grep -i "wolfssh" | head -20 || echo "  (none found)"
        echo ""
    done

    # Show specific wolfSSH KEX functions
    echo "=== Critical wolfSSH KEX Functions ==="
    for func in GenerateKeys ForceZero DoKexDhInit SendKexDhReply SendNewKeys DoNewKeys; do
        found=0
        for target in "$WOLFSSHD_BINARY" "/usr/local/lib/libwolfssh.so"; do
            if [ -f "$target" ] && addr=$(nm "$target" 2>/dev/null | grep " T $func$" | awk '{print $1}'); then
                print_success "$func found at address: 0x$addr (in $(basename $target))"
                found=1
                break
            fi
        done
        if [ $found -eq 0 ]; then
            print_error "$func not found"
        fi
    done
}

function test_breakpoint() {
    print_header "Testing wolfSSH KEX Breakpoint"

    check_ldconfig

    print_info "Creating LLDB command script..."

    cat > /tmp/lldb_wolfssh_test.py << 'EOF'
import lldb
import sys

def test_breakpoint(debugger, command, result, internal_dict):
    """Test if wolfSSH KEX breakpoints can be set"""
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

    # List loaded modules
    print("=== Loaded Modules ===")
    for module in target.module_iter():
        print(f"  {module.GetFileSpec().GetFilename()}")
    print("")

    print("=== Setting wolfSSH Breakpoints ===")

    # Core KEX functions
    kex_functions = [
        "GenerateKeys",
        "ForceZero",
        "SendNewKeys",
        "DoNewKeys",
        "DoKexDhInit",
        "SendKexDhReply",
        "wolfSSH_accept",
        "wolfSSH_shutdown",
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
    debugger.HandleCommand('command script add -f lldb_wolfssh_test.test_breakpoint test_bp')
    print("Command registered: test_bp")
EOF

    print_info "Starting LLDB test session..."
    echo ""

    lldb "$WOLFSSHD_BINARY" -o "command script import /tmp/lldb_wolfssh_test.py" -o "test_bp" -o "quit"
}

function run_with_lldb() {
    print_header "Running wolfSSH Under LLDB"

    check_ldconfig

    print_info "Directories:"
    echo "  Results: $RESULTS_DIR"
    echo "  Dumps: $DUMPS_DIR"
    echo ""

    print_info "Starting interactive LLDB session..."
    print_info "Useful commands:"
    echo "  (lldb) breakpoint set -n GenerateKeys"
    echo "  (lldb) breakpoint set -n ForceZero"
    echo "  (lldb) breakpoint set -n SendNewKeys"
    echo "  (lldb) breakpoint list"
    echo "  (lldb) run -D -d -p 22"
    echo "  (lldb) process status"
    echo "  (lldb) thread backtrace"
    echo "  (lldb) frame variable"
    echo "  (lldb) quit"
    echo ""

    # Load monitoring scripts if available
    if [ -f "$SCRIPT_DIR/ssh_monitor.py" ]; then
        print_info "Monitoring scripts available - to load manually:"
        echo "  (lldb) command script import $SCRIPT_DIR/ssh_monitor.py"
        echo "  (lldb) command script import $SCRIPT_DIR/wolfssh_callbacks.py"
        echo ""
    fi

    print_info "Note: wolfsshd uses -D (foreground) and -d (debug logging)"
    echo ""

    lldb "$WOLFSSHD_BINARY"
}

function attach_to_wolfsshd() {
    print_header "Attach to Running wolfSSH"

    print_info "Looking for wolfsshd processes..."

    # Find wolfsshd processes
    pids=$(pgrep -f "wolfsshd" || true)

    if [ -z "$pids" ]; then
        print_error "No wolfsshd processes found"
        exit 1
    fi

    echo ""
    echo "Found wolfsshd processes:"
    ps aux | grep wolfsshd | grep -v grep
    echo ""

    # If only one wolfsshd, attach to it
    pid_count=$(echo "$pids" | wc -w)

    if [ "$pid_count" -eq 1 ]; then
        target_pid="$pids"
        print_info "Attaching to PID $target_pid..."
    else
        print_info "Multiple wolfsshd processes found. Enter PID to attach to:"
        read -r target_pid

        if ! echo "$pids" | grep -q "$target_pid"; then
            print_error "Invalid PID"
            exit 1
        fi
    fi

    print_info "Attaching LLDB to PID $target_pid..."
    print_info "After attach, try:"
    echo "  (lldb) breakpoint set -n GenerateKeys"
    echo "  (lldb) breakpoint set -n ForceZero"
    echo "  (lldb) continue"
    echo "  (then trigger SSH connection from another terminal)"
    echo ""

    lldb -p "$target_pid"
}

function create_lldb_commands() {
    print_header "Generate LLDB Command File"

    cat > /tmp/lldb_wolfssh_commands.txt << EOF
# LLDB Commands for wolfSSH KEX Debugging

# Import monitoring scripts
command script import $SCRIPT_DIR/ssh_monitor.py
command script import $SCRIPT_DIR/wolfssh_callbacks.py

# Set breakpoints on wolfSSH KEX functions
breakpoint set -n GenerateKeys
breakpoint set -n ForceZero
breakpoint set -n SendNewKeys
breakpoint set -n DoKexDhInit
breakpoint set -n SendKexDhReply

# List breakpoints
breakpoint list

# Run wolfsshd in foreground mode
run -D -d -p 22

# Useful commands during debugging:
# - continue (c)           : Continue execution
# - breakpoint list (br l) : List all breakpoints
# - thread backtrace (bt)  : Show call stack
# - frame variable (fr v)  : Show local variables
# - process status (pro st): Show process state
# - quit (q)               : Exit LLDB
EOF

    print_success "Created /tmp/lldb_wolfssh_commands.txt"
    print_info "Use with: lldb -s /tmp/lldb_wolfssh_commands.txt $WOLFSSHD_BINARY"
    echo ""
    cat /tmp/lldb_wolfssh_commands.txt
}

function show_usage() {
    echo "Usage: $0 <command>"
    echo ""
    echo "Commands:"
    echo "  run       - Launch wolfsshd under LLDB with manual control"
    echo "  attach    - Attach to running wolfsshd process"
    echo "  symbols   - Show available KEX symbols in wolfsshd binary"
    echo "  test      - Test KEX breakpoint without callbacks"
    echo "  commands  - Generate LLDB command file"
    echo "  help      - Show this help"
    echo ""
    echo "Environment Variables:"
    echo "  LLDB_RESULTS_DIR  - Results directory (default: /data/lldb_results)"
    echo "  LLDB_DUMPS_DIR    - Memory dumps directory (default: /data/dumps)"
    echo ""
    echo "wolfSSH-Specific Notes:"
    echo "  - wolfsshd uses -D for foreground mode (like sshd -D)"
    echo "  - wolfsshd uses -d for debug logging (like sshd -d)"
    echo "  - Key function: GenerateKeys() instead of kex_derive_keys()"
    echo "  - Memory clear: ForceZero() instead of explicit_bzero()"
    echo "  - wolfSSL library must be in LD_LIBRARY_PATH or ldconfig cache"
    echo ""
}

# Main logic
case "${1:-help}" in
    run)
        check_lldb
        check_wolfsshd
        run_with_lldb
        ;;
    attach)
        check_lldb
        attach_to_wolfsshd
        ;;
    symbols)
        check_wolfsshd
        show_symbols
        ;;
    test)
        check_lldb
        check_wolfsshd
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
