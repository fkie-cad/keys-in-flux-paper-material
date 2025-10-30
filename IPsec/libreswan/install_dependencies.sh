#!/usr/bin/env bash
#
# install_dependencies.sh - Install all dependencies for libreswan IPsec monitoring
#
# Usage:
#   sudo ./install_dependencies.sh [OPTIONS]
#
# Options:
#   --build-from-source   Build libreswan from source with debug symbols
#   --skip-libreswan      Skip libreswan installation (already installed)
#   --skip-kernel-debug   Skip kernel debug symbols installation
#   --venv                Create virtual environment for Python packages
#   --venv-path=PATH      Custom venv path (default: experiment/env)
#   --yes                 Assume yes to all prompts (non-interactive)
#

set -uo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[*]${NC} $*"; }
log_success() { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_error() { echo -e "${RED}[✗]${NC} $*"; }

# Options
BUILD_FROM_SOURCE=false
SKIP_LIBRESWAN=false
SKIP_KERNEL_DEBUG=false
ASSUME_YES=false
USE_VENV=false
VENV_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --build-from-source)
            BUILD_FROM_SOURCE=true
            ;;
        --skip-libreswan)
            SKIP_LIBRESWAN=true
            ;;
        --skip-kernel-debug)
            SKIP_KERNEL_DEBUG=true
            ;;
        --venv)
            USE_VENV=true
            ;;
        --venv-path=*)
            USE_VENV=true
            VENV_PATH="${1#*=}"
            ;;
        --yes|-y)
            ASSUME_YES=true
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --build-from-source   Build libreswan from source with debug symbols"
            echo "  --skip-libreswan      Skip libreswan installation"
            echo "  --skip-kernel-debug   Skip kernel debug symbols"
            echo "  --venv                Create virtual environment for Python packages"
            echo "  --venv-path=PATH      Custom venv path (default: experiment/env)"
            echo "  --yes, -y             Non-interactive mode"
            echo "  --help, -h            Show this help"
            echo ""
            echo "Auto-detection:"
            echo "  The script automatically detects existing env/ or venv/ directories"
            echo "  in the current directory or experiment/ subdirectory. If found, it"
            echo "  will use them automatically without requiring --venv flag."
            echo ""
            echo "Examples:"
            echo "  $0 --yes                           # Auto-detect venv or install system-wide"
            echo "  $0 --venv --yes                    # Force create venv in experiment/env"
            echo "  $0 --venv --build-from-source --yes  # Venv + build from source"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
    shift
done

# Set default venv path if --venv was specified
if [[ "$USE_VENV" == "true" && -z "$VENV_PATH" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    VENV_PATH="$SCRIPT_DIR/experiment/env"
fi

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo "============================================"
echo " Libreswan IPsec Monitoring - Dependencies"
echo "============================================"
echo ""

#=============================================================================
# 1. System Packages
#=============================================================================

log_info "Installing system packages..."

if [[ "$ASSUME_YES" == "true" ]]; then
    APT_FLAGS="-y"
else
    APT_FLAGS=""
fi

apt-get update

# Core tools
apt-get install $APT_FLAGS \
    build-essential \
    git \
    curl \
    wget \
    iproute2 \
    tcpdump \
    python3 \
    python3-pip \
    python3-dev \
    lldb \
    python3-lldb \
    linux-tools-common \
    linux-tools-generic

if [[ $? -eq 0 ]]; then
    log_success "System packages installed"
else
    log_error "Failed to install system packages"
    exit 1
fi

#=============================================================================
# 2. Python Packages
#=============================================================================

# Auto-detect existing virtual environments if --venv not explicitly provided
if [[ "$USE_VENV" != "true" && -z "$VENV_PATH" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    # Search for existing venv directories
    local_venv_paths=(
        "$SCRIPT_DIR/env"
        "$SCRIPT_DIR/experiment/env"
        "$SCRIPT_DIR/venv"
        "$SCRIPT_DIR/experiment/venv"
    )

    log_info "Checking for existing virtual environments..."

    for venv_candidate in "${local_venv_paths[@]}"; do
        if [[ -d "$venv_candidate" && -x "$venv_candidate/bin/python" ]]; then
            # Check if drgn is already installed in this venv
            if "$venv_candidate/bin/python" -c "import drgn" 2>/dev/null; then
                log_info "Found existing virtual environment with drgn at: $venv_candidate"
                log_info "Using this environment automatically"
                USE_VENV=true
                VENV_PATH="$venv_candidate"
                break
            else
                log_info "Found venv at $venv_candidate but drgn not installed yet"
                log_info "Will use this environment and install packages"
                USE_VENV=true
                VENV_PATH="$venv_candidate"
                break
            fi
        fi
    done

    if [[ "$USE_VENV" != "true" ]]; then
        log_info "No existing virtual environment detected"
        log_info "Will attempt system-wide installation"
        log_warn "If system-wide installation fails, use: $0 --venv --yes"
    fi
fi

if [[ "$USE_VENV" == "true" ]]; then
    # Check if venv already exists
    if [[ -d "$VENV_PATH" ]]; then
        log_info "Using existing virtual environment at: $VENV_PATH"
    else
        log_info "Creating virtual environment at: $VENV_PATH"

        # Ensure parent directory exists
        mkdir -p "$(dirname "$VENV_PATH")"

        # Create venv
        python3 -m venv "$VENV_PATH"

        if [[ $? -eq 0 ]]; then
            log_success "Virtual environment created"
        else
            log_error "Failed to create virtual environment"
            exit 1
        fi
    fi

    # Activate venv
    source "$VENV_PATH/bin/activate"
    PYTHON_CMD="$VENV_PATH/bin/python"
    PIP_CMD="$VENV_PATH/bin/pip"

    log_info "Installing Python packages in venv..."
else
    log_info "Installing Python packages system-wide..."
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
fi

# Upgrade pip
$PIP_CMD install --upgrade pip

# Core Python dependencies
$PIP_CMD install \
    drgn \
    pyyaml \
    colorama

if [[ $? -eq 0 ]]; then
    log_success "Python packages installed"
else
    log_error "Failed to install Python packages"

    if [[ "$USE_VENV" != "true" ]]; then
        echo ""
        log_error "System-wide installation failed!"
        log_info "This is likely due to PEP 668 externally-managed-environment restrictions."
        echo ""
        log_info "Solutions:"
        echo "  1. Use virtual environment (recommended):"
        echo "     sudo $0 --venv --yes"
        echo ""
        echo "  2. If you have an existing venv (env/ or venv/), ensure it's in:"
        echo "     - $SCRIPT_DIR/env/"
        echo "     - $SCRIPT_DIR/experiment/env/"
        echo "     - $SCRIPT_DIR/venv/"
        echo "     Then re-run this script."
        echo ""
        echo "  3. Override with --break-system-packages (not recommended):"
        echo "     Edit this script and add --break-system-packages to pip install"
        echo ""
    fi
    exit 1
fi

# Verify drgn installation
if $PYTHON_CMD -c "import drgn" 2>/dev/null; then
    log_success "drgn module verified"
else
    log_warn "drgn import failed - kernel monitoring may not work"
fi

# Deactivate venv if we're using one
if [[ "$USE_VENV" == "true" ]]; then
    deactivate 2>/dev/null || true
fi

#=============================================================================
# 3. Libreswan
#=============================================================================

if [[ "$SKIP_LIBRESWAN" == "true" ]]; then
    log_info "Skipping libreswan installation (--skip-libreswan)"
else
    if [[ "$BUILD_FROM_SOURCE" == "true" ]]; then
        log_info "Building libreswan from source with debug symbols..."

        # Install build dependencies
        apt-get install $APT_FLAGS \
            libnspr4-dev \
            libnss3-dev \
            libnss3-tools \
            libunbound-dev \
            libldns-dev \
            libcurl4-openssl-dev \
            libsystemd-dev \
            flex \
            bison \
            pkg-config \
            xmlto

        # Clone and build
        LIBRESWAN_DIR="/tmp/libreswan-build"
        if [[ -d "$LIBRESWAN_DIR" ]]; then
            log_info "Removing old libreswan build directory..."
            rm -rf "$LIBRESWAN_DIR"
        fi

        log_info "Cloning libreswan repository..."
        git clone https://github.com/libreswan/libreswan.git "$LIBRESWAN_DIR"

        cd "$LIBRESWAN_DIR"

        log_info "Building libreswan (this may take several minutes)..."
        # Build with debug symbols
        make CFLAGS="-g -O0" programs

        if [[ $? -eq 0 ]]; then
            log_success "Build successful"
        else
            log_error "Build failed"
            exit 1
        fi

        log_info "Installing libreswan..."
        make install

        if [[ $? -eq 0 ]]; then
            log_success "Libreswan installed from source"
            log_info "Installed to: /usr/local/sbin/ipsec, /usr/local/libexec/ipsec/"
        else
            log_error "Installation failed"
            exit 1
        fi

        cd -

        # Optionally remove build directory
        if [[ "$ASSUME_YES" == "true" ]]; then
            rm -rf "$LIBRESWAN_DIR"
        else
            read -p "Remove build directory? [y/N] " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                rm -rf "$LIBRESWAN_DIR"
                log_info "Build directory removed"
            fi
        fi

    else
        log_info "Installing libreswan from package manager..."

        apt-get install $APT_FLAGS libreswan libreswan-dbgsym libnss3-dbgsym libnss3-dev
        # libnss3-dbgsym libnss3-dev are for easy parsing chunk_t and PK11SymKey
        if [[ $? -eq 0 ]]; then
            log_success "Libreswan installed from apt"
            log_warn "Package version may not have debug symbols"
            log_info "To build with debug symbols, run: $0 --build-from-source"
        else
            log_error "Failed to install libreswan"
            exit 1
        fi
    fi
fi

#=============================================================================
# 4. Kernel Debug Symbols (Optional but Recommended)
#=============================================================================

if [[ "$SKIP_KERNEL_DEBUG" == "true" ]]; then
    log_info "Skipping kernel debug symbols (--skip-kernel-debug)"
else
    log_info "Installing kernel debug symbols (optional for kernel monitoring)..."

    # Add debug symbol repository
    if ! grep -q "ddebs.ubuntu.com" /etc/apt/sources.list.d/ddebs.list 2>/dev/null; then
        log_info "Adding Ubuntu debug symbol repository..."
        echo "deb http://ddebs.ubuntu.com $(lsb_release -cs) main restricted universe multiverse" | \
            tee -a /etc/apt/sources.list.d/ddebs.list
        echo "deb http://ddebs.ubuntu.com $(lsb_release -cs)-updates main restricted universe multiverse" | \
            tee -a /etc/apt/sources.list.d/ddebs.list

        # Import signing key
        apt-get install $APT_FLAGS ubuntu-dbgsym-keyring || {
            log_warn "Failed to install keyring, trying manual import..."
            apt-key adv --keyserver keyserver.ubuntu.com --recv-keys F2EDC64DC5AEE1F6B9C621F0C8CAB6595FDFF622 || true
        }

        apt-get update
    fi

    # Install kernel debug symbols for current kernel
    KERNEL_VERSION=$(uname -r)
    log_info "Installing debug symbols for kernel: $KERNEL_VERSION"

    apt-get install $APT_FLAGS linux-image-${KERNEL_VERSION}-dbgsym 2>&1 | tee /tmp/kernel-dbgsym-install.log

    if [[ ${PIPESTATUS[0]} -eq 0 ]]; then
        log_success "Kernel debug symbols installed"
    else
        log_warn "Kernel debug symbols installation had issues"
        log_warn "Kernel monitoring may not work optimally"
        log_info "This is optional - userspace monitoring will still work"
        log_info "Check /tmp/kernel-dbgsym-install.log for details"
    fi
fi

#=============================================================================
# 5. Configuration
#=============================================================================

log_info "Configuring system..."

# Disable system-wide libreswan service (conflicts with experiment namespaces)
systemctl stop ipsec 2>/dev/null || true
systemctl disable ipsec 2>/dev/null || true
log_info "System-wide ipsec service disabled (experiment uses network namespaces)"

# Configure AppArmor (if available)
if command -v aa-complain >/dev/null 2>&1; then
    log_info "Configuring AppArmor..."

    # Set pluto to complain mode
    aa-complain /usr/local/libexec/ipsec/pluto 2>/dev/null || true
    aa-complain /usr/libexec/ipsec/pluto 2>/dev/null || true
    aa-complain /usr/local/sbin/ipsec 2>/dev/null || true
    aa-complain /usr/sbin/ipsec 2>/dev/null || true

    # tcpdump needs complain mode for netns packet capture
    aa-complain /usr/bin/tcpdump 2>/dev/null || true

    log_success "AppArmor configured"
else
    log_info "AppArmor not found, skipping"
fi

#=============================================================================
# 6. Verification
#=============================================================================

echo ""
log_info "Verifying installation..."
echo ""

ERRORS=0

# Check binaries
echo "Checking binaries:"

if command -v ipsec >/dev/null 2>&1; then
    IPSEC_PATH=$(which ipsec)
    echo "  ✓ ipsec: $IPSEC_PATH"
    ipsec --version 2>&1 | head -n1 | sed 's/^/    /'
else
    echo "  ✗ ipsec: NOT FOUND"
    ((ERRORS++))
fi

if command -v python3 >/dev/null 2>&1; then
    PYTHON_VERSION=$(python3 --version 2>&1)
    echo "  ✓ python3: $PYTHON_VERSION"
else
    echo "  ✗ python3: NOT FOUND"
    ((ERRORS++))
fi

if command -v lldb >/dev/null 2>&1; then
    LLDB_VERSION=$(lldb --version 2>&1 | head -n1)
    echo "  ✓ lldb: $LLDB_VERSION"
else
    echo "  ✗ lldb: NOT FOUND"
    ((ERRORS++))
fi

if command -v tcpdump >/dev/null 2>&1; then
    echo "  ✓ tcpdump: $(which tcpdump)"
else
    echo "  ✗ tcpdump: NOT FOUND"
    ((ERRORS++))
fi

echo ""
echo "Checking Python modules:"

# Show which Python is being verified
if [[ "$USE_VENV" == "true" ]]; then
    echo "  (Using venv at: $VENV_PATH)"
else
    echo "  (Using system python3)"
fi

if $PYTHON_CMD -c "import drgn" 2>/dev/null; then
    DRGN_VERSION=$($PYTHON_CMD -c "import drgn; print(drgn.__version__)" 2>/dev/null || echo "unknown")
    echo "  ✓ drgn: $DRGN_VERSION"
else
    echo "  ✗ drgn: NOT FOUND"
    log_warn "Kernel monitoring will not work without drgn"
    ((ERRORS++))
fi

if $PYTHON_CMD -c "import yaml" 2>/dev/null; then
    echo "  ✓ pyyaml: installed"
else
    echo "  ✗ pyyaml: NOT FOUND"
    ((ERRORS++))
fi

echo ""
echo "Checking kernel debug symbols:"

if [[ -d /usr/lib/debug/boot/vmlinux-$(uname -r) ]] || [[ -f /usr/lib/debug/boot/vmlinux-$(uname -r) ]]; then
    echo "  ✓ Kernel debug symbols: found"
elif [[ "$SKIP_KERNEL_DEBUG" == "true" ]]; then
    echo "  - Kernel debug symbols: skipped"
else
    echo "  ! Kernel debug symbols: not found (optional)"
    log_info "Kernel monitoring may be limited without debug symbols"
fi

echo ""

#=============================================================================
# Summary
#=============================================================================

if [[ $ERRORS -eq 0 ]]; then
    log_success "Installation complete! All checks passed."
    echo ""

    if [[ "$USE_VENV" == "true" ]]; then
        echo "Python packages installed in virtual environment:"
        echo "  Location: $VENV_PATH"
        echo ""
        echo "The experiment script will auto-detect this venv."
        echo ""
        echo "To manually activate the venv:"
        echo "  source $VENV_PATH/bin/activate"
        echo ""
    else
        echo "Python packages installed system-wide."
        echo ""
    fi

    echo "Next steps:"
    echo "  cd $(dirname "$0")/experiment"
    echo "  sudo ./run_ipsec_experiment.sh --workflow=full --skip-lldb"
    echo ""
    echo "Or try manual scripts:"
    echo "  cd $(dirname "$0")/research_setup"
    echo "  sudo ./net_setup.sh"
    echo "  sudo ./setup_left.sh"
    echo "  sudo ./setup_right.sh"
    echo ""
else
    log_warn "Installation complete with $ERRORS error(s)"
    echo ""
    echo "Some components failed to install. Review the errors above."
    echo "You may still be able to use the framework with limited functionality."
    echo ""
fi

echo "For documentation, see:"
echo "  $(dirname "$0")/experiment/README.md"
echo "  $(dirname "$0")/experiment/VENV_USAGE.md"
echo "  $(dirname "$0")/research_setup/README.md"
echo ""
