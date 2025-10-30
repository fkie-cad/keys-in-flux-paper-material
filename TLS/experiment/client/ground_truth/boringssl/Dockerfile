# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    libc6-dbg \
    libunwind-dev \
    pkg-config \
    python3 \
    && apt-get clean

# Clone the BoringSSL repository
RUN git clone https://boringssl.googlesource.com/boringssl

# Set the working directory to boringssl
WORKDIR /boringssl


# Copy the test client source files into the container
COPY test_client_12_boringssl.c /boringssl/
COPY test_client_13_boringssl.c /boringssl/

# Dynamically set the pinned commit hash during the build to the latest version at build time
RUN export PINNED_COMMIT_HASH=$(git rev-parse HEAD) && \
    echo "Pinning the commit: $PINNED_COMMIT_HASH" && \
    echo "PINNED_COMMIT_HASH=$PINNED_COMMIT_HASH" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of BoringSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $PINNED_COMMIT_HASH";' >> /start.sh && \
    echo '    git checkout $PINNED_COMMIT_HASH;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build standard release version (static)
    echo 'echo "Building standard release version (static)..."' >> /start.sh && \
    echo 'mkdir -p /compiled_clients' >> /start.sh && \

    # Build shared release version
    echo 'echo "Building shared release version..."' >> /start.sh && \
    echo 'cd build && make clean && cmake -DBUILD_SHARED_LIBS=ON .. && make -j$(nproc);' >> /start.sh && \
    echo 'echo "Listing shared libraries in build directory:"' >> /start.sh && \
    echo 'find . -name "*.so*" -type f' >> /start.sh && \
    echo 'cd ..' >> /start.sh && \

    # Find actual shared library locations
    echo 'SSL_SO_LIB=$(find build -name "libssl.so*" | head -1)' >> /start.sh && \
    echo 'CRYPTO_SO_LIB=$(find build -name "libcrypto.so*" | head -1)' >> /start.sh && \
    echo 'BUILD_LIB_DIR=$(dirname $SSL_SO_LIB)' >> /start.sh && \
    echo 'echo "Using shared SSL library: $SSL_SO_LIB"' >> /start.sh && \
    echo 'echo "Using shared Crypto library: $CRYPTO_SO_LIB"' >> /start.sh && \
    echo 'echo "Library directory: $BUILD_LIB_DIR"' >> /start.sh && \

    # Compile dynamic versions of test clients
    echo 'export LD_LIBRARY_PATH=$BUILD_LIB_DIR:$LD_LIBRARY_PATH' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_boringssl_dl test_client_12_boringssl.c -L$BUILD_LIB_DIR -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_boringssl_dl test_client_13_boringssl.c -L$BUILD_LIB_DIR -lssl -lcrypto -lpthread -ldl' >> /start.sh && \

    # Copy dynamic versions of test clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_boringssl_dl test_client_13_boringssl_dl /compiled_clients/' >> /start.sh && \
    echo 'find build -name "*.so*" -exec cp {} /compiled_clients/libs/ \;' >> /start.sh && \

    # Save version information
    echo 'git log -1 --format="%H %cd" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "TLS Library: BoringSSL" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh
# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]

