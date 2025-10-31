FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Fix GPG keys for ARM64 (Apple Silicon) builds
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/lib/apt/lists/partial

# Install dependencies
RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated \
    build-essential \
    wget \
    zlib1g-dev \
    libssl-dev \
    python3 \
    python3-pip \
    gnupg \
    software-properties-common \
    ca-certificates \
    expect \
    sshpass \
    netcat-openbsd \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Add LLVM repository for LLDB 18 (stable for Ubuntu 24.04 noble)
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && \
    apt-get install -y lldb-18 python3-lldb-18 && \
    ln -sf /usr/bin/lldb-18 /usr/bin/lldb && \
    ln -sf /usr/lib/llvm-18/lib/python3.12/dist-packages/lldb /usr/local/lib/python3.12/dist-packages/ && \
    rm -rf /var/lib/apt/lists/*

# Build OpenSSH 10.2p1 from source (CLIENT ONLY)
# Latest stable version as of October 2025
ENV OPENSSH_VERSION=10.2p1
WORKDIR /tmp

RUN wget https://ftp.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz && \
    tar xzf openssh-${OPENSSH_VERSION}.tar.gz

WORKDIR /tmp/openssh-${OPENSSH_VERSION}

# Configure: CLIENT ONLY, debug symbols, no stripping
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer" \
    ./configure \
    --prefix=/usr/local \
    --with-ssl-dir=/usr \
    --with-zlib=/usr \
    --sysconfdir=/etc/ssh \
    --without-hardening

# Build CLIENT ONLY (ssh, ssh-keygen, ssh-add, etc.)
# Do NOT build server components
RUN make -j$(nproc) ssh ssh-keygen ssh-add

# Install client binaries manually (skip server components)
RUN install -m 0755 ssh /usr/local/bin/ssh && \
    install -m 0755 ssh-keygen /usr/local/bin/ssh-keygen && \
    install -m 0755 ssh-add /usr/local/bin/ssh-add && \
    ln -sf /usr/local/bin/ssh /usr/bin/ssh && \
    ln -sf /usr/local/bin/ssh-keygen /usr/bin/ssh-keygen

# Verify symbols are present
RUN nm /usr/local/bin/ssh | grep -i kex_derive_keys && echo "✓ kex_derive_keys symbol found" || echo "⚠️ kex_derive_keys not found"

# Create directories for logs and dumps
RUN mkdir -p /data/keylogs /data/dumps /data/lldb_results && \
    chmod 777 /data/keylogs /data/dumps /data/lldb_results

# Copy LLDB monitoring scripts (client-side)
COPY lldb/openssh_client_callbacks.py /opt/lldb/openssh_client_callbacks.py
COPY lldb/ssh_state_machine.py /opt/lldb/ssh_state_machine.py
COPY lldb/ssh_memory_dump.py /opt/lldb/ssh_memory_dump.py
COPY lldb/ssh_extraction_utils.py /opt/lldb/ssh_extraction_utils.py
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py

# Copy entrypoint to separate location (not /opt/lldb which gets mounted)
COPY openssh-client-lldb/entrypoint_client.sh /usr/local/bin/entrypoint_client.sh
RUN chmod +x /usr/local/bin/entrypoint_client.sh

# Copy custom OpenSSH client with lifecycle pattern (matches wolfSSH interface)
COPY openssh-client-lldb/openssh_client_rekey.exp /usr/local/bin/openssh_client_rekey
RUN chmod +x /usr/local/bin/openssh_client_rekey

# Copy SSH lifecycle wrapper (creates local trigger file for LLDB dumps)
COPY openssh-client-lldb/ssh_lifecycle_wrapper.sh /usr/local/bin/ssh_lifecycle_wrapper
RUN chmod +x /usr/local/bin/ssh_lifecycle_wrapper

# Cleanup
WORKDIR /
RUN rm -rf /tmp/openssh-*

# Environment variables for client operation
ENV SSH_SERVER_HOST=openssh_groundtruth
ENV SSH_SERVER_PORT=22
ENV SSH_USER=testuser
ENV SSH_PASSWORD=password
ENV LLDB_KEYLOG=/data/keylogs/openssh_client_keylog.log
ENV LLDB_RESULTS_DIR=/data/lldb_results
ENV LLDB_DUMPS_DIR=/data/dumps

# Run client under LLDB monitoring
CMD ["/usr/local/bin/entrypoint_client.sh"]
