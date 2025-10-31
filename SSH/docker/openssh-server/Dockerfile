# OpenSSH Server with LLDB Monitoring - Ubuntu 24.04
# Modernized from Ubuntu 20.04 baseline with Dropbear lessons applied
#
# Key improvements:
# - Ubuntu 24.04 (Noble)
# - LLDB 20 (matches Dropbear container)
# - OpenSSH 9.8p1 (latest stable as of Jul 2024)
# - tcpdump for PCAP capture
# - expect for automated command execution
# - Consistent directory structure with Dropbear

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# ═══════════════════════════════════════════════════════════════════════════
# BASE DEPENDENCIES
# ═══════════════════════════════════════════════════════════════════════════

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    build-essential wget curl pkg-config \
    # OpenSSH dependencies
    libssl-dev zlib1g-dev libpam0g-dev \
    # LLDB 20 + Python bindings (official Noble repos)
    lldb-20 python3-lldb-20 \
    # Python 3
    python3 python3-pip \
    # Network capture
    tcpdump \
    # Automated testing
    expect \
    # Debugging utilities
    gdb strace ltrace \
    && rm -rf /var/lib/apt/lists/*

# Link LLDB 20 as default lldb
RUN ln -sf /usr/bin/lldb-20 /usr/bin/lldb

# ═══════════════════════════════════════════════════════════════════════════
# BUILD OPENSSH FROM SOURCE WITH DEBUG SYMBOLS
# ═══════════════════════════════════════════════════════════════════════════

# Use latest stable OpenSSH (check: https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/)
# As of Oct 2025: 10.2p1 (released October 10, 2025)
ENV OPENSSH_VERSION=10.2p1

WORKDIR /tmp

# Download OpenSSH source (official mirror)
RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz && \
    wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz.asc && \
    tar xzf openssh-${OPENSSH_VERSION}.tar.gz

# Build with maximum debug symbols + symbol visibility for LD_PRELOAD
# -fvisibility=default ensures all symbols are exported (no source modification)
RUN cd openssh-${OPENSSH_VERSION} && \
    CFLAGS="-g -O0 -fno-omit-frame-pointer -fvisibility=default" \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc/ssh \
        --with-pam \
        --without-openssl-header-check && \
    make -j$(nproc) && \
    # Keep unstripped binaries for LLDB (OpenSSH 10.x has 3 binaries)
    cp sshd /usr/sbin/sshd.unstripped && \
    cp sshd-session /usr/libexec/sshd-session.unstripped && \
    cp sshd-auth /usr/libexec/sshd-auth.unstripped && \
    make install && \
    # Replace stripped versions with unstripped (debug symbols)
    mv /usr/sbin/sshd.unstripped /usr/sbin/sshd && \
    mv /usr/libexec/sshd-session.unstripped /usr/libexec/sshd-session && \
    mv /usr/libexec/sshd-auth.unstripped /usr/libexec/sshd-auth && \
    # Clean up build directory
    cd /tmp && rm -rf openssh-${OPENSSH_VERSION}*

# Create PAM configuration for sshd (standard Linux PAM config)
RUN mkdir -p /etc/pam.d && \
    echo "# PAM configuration for OpenSSH" > /etc/pam.d/sshd && \
    echo "# Standard Un*x authentication" >> /etc/pam.d/sshd && \
    echo "@include common-auth" >> /etc/pam.d/sshd && \
    echo "@include common-account" >> /etc/pam.d/sshd && \
    echo "@include common-session" >> /etc/pam.d/sshd && \
    echo "@include common-password" >> /etc/pam.d/sshd

# ═══════════════════════════════════════════════════════════════════════════
# OPENSSH CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

# Create required directories
RUN mkdir -p /var/run/sshd /var/empty /data/lldb_results /data/dumps /data/keylogs /data/captures

# Create sshd privilege separation user
RUN useradd -r -U -d /var/empty -s /bin/false -c "sshd privilege separation" sshd || true

# Generate host keys
RUN ssh-keygen -A || true

# Create test user
RUN useradd -m testuser && echo "testuser:password" | chpasswd

# Configure SSH for LLDB monitoring:
# - Enable password authentication
# - Permit root login (for testing)
# Note: UsePrivilegeSeparation removed in OpenSSH 10.2 (now mandatory)
RUN sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -ri 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo "UsePAM yes" >> /etc/ssh/sshd_config

# ═══════════════════════════════════════════════════════════════════════════
# LD_PRELOAD LIBRARY FOR KEY EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

# Create hook directory
RUN mkdir -p /opt/hooks

# Copy LD_PRELOAD library source and entrypoint
COPY hooks/libssh_kex_hook.c /opt/hooks/libssh_kex_hook.c
COPY hooks/entrypoint_preload.sh /opt/hooks/entrypoint_preload.sh

# Compile LD_PRELOAD library
RUN cd /opt/hooks && \
    gcc -shared -fPIC \
        -o libssh_kex_hook.so \
        libssh_kex_hook.c \
        -ldl -lpthread && \
    chmod 755 libssh_kex_hook.so && \
    chmod +x entrypoint_preload.sh && \
    echo "[BUILD] LD_PRELOAD library compiled: /opt/hooks/libssh_kex_hook.so"

# ═══════════════════════════════════════════════════════════════════════════
# LLDB MONITORING SCRIPTS
# ═══════════════════════════════════════════════════════════════════════════

# Create LLDB script directory
RUN mkdir -p /opt/lldb

# Copy monitoring scripts (context is docker/ directory)
# Memory dump utilities are integrated in openssh_callbacks.py
COPY lldb/openssh_callbacks.py /opt/lldb/openssh_callbacks.py
COPY lldb/attach_lldb_openssh.sh /opt/lldb/attach_lldb_openssh.sh
# PID monitoring approach (pgrep-based, Phase 1)
COPY lldb/attach_lldb_monitor.sh /opt/lldb/attach_lldb_monitor.sh
COPY lldb/monitor_and_attach_sshd_session.sh /opt/lldb/monitor_and_attach_sshd_session.sh
# Follow-fork + stop-on-exec approach (Phase 2)
COPY lldb/attach_lldb_followfork.sh /opt/lldb/attach_lldb_followfork.sh
COPY lldb/openssh_followfork_callbacks.py /opt/lldb/openssh_followfork_callbacks.py
# LLDB --waitfor loop approach (Phase 3)
COPY lldb/attach_lldb_waitfor.sh /opt/lldb/attach_lldb_waitfor.sh
# Shared KEX extraction script
COPY lldb/kex_extract.py /opt/lldb/kex_extract.py

# Make scripts executable
RUN chmod +x /opt/lldb/*.sh

# Set permissions for data directories
RUN chmod 777 /data/lldb_results /data/dumps /data/keylogs /data/captures

# ═══════════════════════════════════════════════════════════════════════════
# ENVIRONMENT & RUNTIME
# ═══════════════════════════════════════════════════════════════════════════

WORKDIR /root

# Environment variables for LLDB monitoring
ENV SSH_SERVER_TYPE=openssh \
    LLDB_RESULTS_DIR=/data/lldb_results \
    LLDB_DUMPS_DIR=/data/dumps \
    LLDB_KEYLOG=/data/keylogs/openssh_lldb.log \
    LLDB_CAPTURE_DIR=/data/captures

EXPOSE 22

# Default: Run sshd without LLDB (override in docker-compose for monitoring)
CMD ["/usr/sbin/sshd", "-D", "-e"]
