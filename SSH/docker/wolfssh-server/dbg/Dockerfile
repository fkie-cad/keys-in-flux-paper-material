# wolfSSH Debug Container - Verbose Logging Edition
# Purpose: Identify actual KEX functions being called during handshake
# Port: 2229 (to avoid conflict with port 2224 for manual investigation)

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# Install dependencies + strace for function tracing + openssh-client for key generation
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    git \
    ca-certificates \
    wget \
    strace \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Use latest stable versions (as of October 2024)
ENV WOLFSSL_VERSION=5.7.6-stable
ENV WOLFSSH_VERSION=1.4.20-stable

# Build wolfSSL with MAXIMUM debug output
RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}.tar.gz && \
    tar xzf v${WOLFSSL_VERSION}.tar.gz && \
    cd wolfssl-${WOLFSSL_VERSION} && \
    ./autogen.sh && \
    CFLAGS="-DDEBUG_WOLFSSL -DWOLFSSL_DEBUG_MEMORY -g -O0 -fno-omit-frame-pointer" \
    ./configure \
        --enable-debug \
        --enable-ssh \
        --enable-keygen \
        --enable-cryptonly \
        --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Build wolfSSH with MAXIMUM debug output + wolfsshd
RUN wget https://github.com/wolfSSL/wolfssh/archive/refs/tags/v${WOLFSSH_VERSION}.tar.gz && \
    tar xzf v${WOLFSSH_VERSION}.tar.gz && \
    cd wolfssh-${WOLFSSH_VERSION} && \
    ./autogen.sh && \
    CFLAGS="-DDEBUG_WOLFSSH -DWOLFSSH_DEBUG_KEYGEN -g -O0 -fno-omit-frame-pointer" \
    ./configure \
        --enable-debug \
        --enable-sshd \
        --prefix=/usr/local && \
    make -j$(nproc) && \
    make install && \
    ldconfig

# Create testuser and sshd system user
RUN useradd -m -s /bin/bash testuser && \
    echo "testuser:password" | chpasswd && \
    useradd -r -s /usr/sbin/nologin sshd

# Generate SSH host keys in PEM format (wolfSSH requires PEM, not OpenSSH format)
RUN mkdir -p /etc/ssh && \
    ssh-keygen -t rsa -b 2048 -m PEM -f /etc/ssh/ssh_host_rsa_key -N '' && \
    ssh-keygen -t ecdsa -b 256 -m PEM -f /etc/ssh/ssh_host_ecdsa_key -N '' && \
    ssh-keygen -t ed25519 -m PEM -f /etc/ssh/ssh_host_ed25519_key -N '' && \
    chmod 600 /etc/ssh/ssh_host_*_key && \
    chmod 644 /etc/ssh/ssh_host_*_key.pub

# Create output directories
RUN mkdir -p /data/debug_logs /data/keylogs && \
    chmod 777 /data/debug_logs /data/keylogs

# Copy entrypoint scripts
COPY wolfssh-server/dbg/entrypoint_debug.sh /entrypoint_debug.sh
COPY wolfssh-server/dbg/entrypoint_strace.sh /entrypoint_strace.sh
RUN chmod +x /entrypoint_debug.sh /entrypoint_strace.sh

EXPOSE 22

# Default: Verbose logging mode
CMD ["/entrypoint_debug.sh"]
