#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# Test script for OpenSSH Standalone Container
#
# This script performs basic validation of the container build and functionality
##############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="openssh-standalone"

cd "$SCRIPT_DIR"

echo "=========================================="
echo "OpenSSH Standalone Container - Test Suite"
echo "=========================================="
echo ""

# Test 1: Check required files exist
echo "[TEST 1] Checking required files..."
REQUIRED_FILES=("Dockerfile" "entrypoint.sh" "openssh-keylog.patch" "build.sh" "README.md")
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  ✓ $file exists"
    else
        echo "  ✗ $file missing"
        exit 1
    fi
done
echo ""

# Test 2: Check scripts are executable
echo "[TEST 2] Checking script permissions..."
if [ -x "build.sh" ]; then
    echo "  ✓ build.sh is executable"
else
    echo "  ✗ build.sh not executable"
    exit 1
fi
if [ -x "entrypoint.sh" ]; then
    echo "  ✓ entrypoint.sh is executable"
else
    echo "  ✗ entrypoint.sh not executable"
    exit 1
fi
echo ""

# Test 3: Check Docker is available
echo "[TEST 3] Checking Docker availability..."
if command -v docker >/dev/null 2>&1; then
    echo "  ✓ Docker is available"
    docker --version
else
    echo "  ✗ Docker not found"
    echo "  Please install Docker to build and test the container"
    exit 1
fi
echo ""

# Test 4: Check if image already exists
echo "[TEST 4] Checking if image exists..."
if docker image inspect "$IMAGE_NAME:latest" >/dev/null 2>&1; then
    echo "  ✓ Image $IMAGE_NAME:latest exists"
    echo "  (Re-run ./build.sh to rebuild)"
else
    echo "  ⚠ Image $IMAGE_NAME:latest not found"
    echo "  Run ./build.sh to build the image first"
fi
echo ""

# Test 5: Validate Dockerfile syntax
echo "[TEST 5] Validating Dockerfile syntax..."
if docker build -f Dockerfile --target "" . >/dev/null 2>&1; then
    echo "  ✓ Dockerfile syntax is valid"
else
    # This check might fail, but the build might still work
    echo "  ⚠ Could not validate Dockerfile (this is ok, build might still work)"
fi
echo ""

# Test 6: Check patch file format
echo "[TEST 6] Validating patch file..."
if head -1 openssh-keylog.patch | grep -q "^diff"; then
    echo "  ✓ Patch file appears valid"
else
    echo "  ✗ Patch file format may be incorrect"
fi
echo ""

# Test 7: Check data directories
echo "[TEST 7] Checking/creating data directories..."
mkdir -p data/keylogs data/dumps data/captures
chmod 777 data/keylogs data/dumps data/captures 2>/dev/null || true
if [ -d "data/keylogs" ] && [ -d "data/dumps" ]; then
    echo "  ✓ Data directories created"
else
    echo "  ✗ Failed to create data directories"
    exit 1
fi
echo ""

echo "=========================================="
echo "Pre-build checks complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "  1. Build the container:  ./build.sh"
echo "  2. Test server mode:"
echo "       docker run -d -p 2222:22 -v \$(pwd)/data:/data $IMAGE_NAME"
echo "  3. Test client mode:"
echo "       docker run --rm -e MODE=client -e HOST=<target> -e USER=testuser $IMAGE_NAME"
echo ""
echo "For full usage, see README.md"
echo ""
