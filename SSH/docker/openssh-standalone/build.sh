#!/usr/bin/env bash
set -euo pipefail

##############################################################################
# Build script for OpenSSH Standalone Container
##############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="openssh-standalone"
IMAGE_TAG="latest"
USE_UBUNTU22="${USE_UBUNTU22:-false}"

cd "$SCRIPT_DIR"

echo "=========================================="
echo "Building $IMAGE_NAME:$IMAGE_TAG"
echo "=========================================="
echo ""

# Detect architecture
ARCH=$(uname -m)
echo "[+] Detected architecture: $ARCH"

# Auto-select Ubuntu 22.04 for ARM if not explicitly set
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    if [ "$USE_UBUNTU22" = "false" ]; then
        echo "[+] ARM architecture detected, using Ubuntu 22.04 base image"
        USE_UBUNTU22="true"
    fi
fi

# Select Dockerfile
DOCKERFILE="Dockerfile"
if [ "$USE_UBUNTU22" = "true" ]; then
    DOCKERFILE="Dockerfile.ubuntu22"
    echo "[+] Using Ubuntu 22.04 base (better ARM support)"
    IMAGE_TAG="${IMAGE_TAG}-ubuntu22"
else
    echo "[+] Using Ubuntu 20.04 base"
fi

# Check if required files exist
for file in "$DOCKERFILE" entrypoint.sh openssh-keylog.patch; do
    if [ ! -f "$file" ]; then
        echo "ERROR: Required file '$file' not found in $SCRIPT_DIR"
        exit 1
    fi
done

echo ""

# Build the image
echo "[+] Building Docker image..."
echo "[+] Dockerfile: $DOCKERFILE"
echo ""

# Check if BuildKit is available
if docker buildx version >/dev/null 2>&1 || [ "${DOCKER_BUILDKIT:-0}" = "1" ]; then
    echo "[+] Using BuildKit builder"
    DOCKER_BUILDKIT=1 docker build \
        -f "$DOCKERFILE" \
        --tag "$IMAGE_NAME:$IMAGE_TAG" \
        --tag "$IMAGE_NAME:$(date +%Y%m%d)" \
        --progress=plain \
        .
else
    echo "[+] Using legacy builder (--progress flag not supported)"
    docker build \
        -f "$DOCKERFILE" \
        --tag "$IMAGE_NAME:$IMAGE_TAG" \
        --tag "$IMAGE_NAME:$(date +%Y%m%d)" \
        .
fi

BUILD_STATUS=$?

echo ""

if [ $BUILD_STATUS -eq 0 ]; then
    echo "=========================================="
    echo "Build completed successfully!"
    echo "=========================================="
    echo ""
    echo "Image: $IMAGE_NAME:$IMAGE_TAG"
    echo "Architecture: $ARCH"
    echo "Base: $([ "$USE_UBUNTU22" = "true" ] && echo "Ubuntu 22.04" || echo "Ubuntu 20.04")"
    echo ""
    echo "Quick start examples:"
    echo ""
    echo "  # Run as SERVER:"
    echo "  docker run -d -p 2222:22 -v \$(pwd)/data:/data $IMAGE_NAME:$IMAGE_TAG"
    echo ""
    echo "  # Run as CLIENT:"
    echo "  docker run -it --rm -v \$(pwd)/data:/data \\"
    echo "    -e MODE=client \\"
    echo "    -e HOST=192.168.1.100 \\"
    echo "    -e USER=testuser \\"
    echo "    -e PASSWORD=password \\"
    echo "    $IMAGE_NAME:$IMAGE_TAG"
    echo ""
    echo "  # Verify capture:"
    echo "  ./verify_capture.sh ./data"
    echo ""
    echo "  # Check exported keys:"
    echo "  tail -f data/keylogs/ssh_keylog.log"
    echo ""
    echo "For more examples, see README.md"
    echo ""
else
    echo "=========================================="
    echo "Build failed!"
    echo "=========================================="
    echo ""
    echo "If you're on ARM (Apple Silicon, Raspberry Pi):"
    echo "  USE_UBUNTU22=true ./build.sh"
    echo ""
    echo "Or manually:"
    echo "  docker build -f Dockerfile.ubuntu22 -t $IMAGE_NAME:$IMAGE_TAG ."
    echo ""
    exit 1
fi
