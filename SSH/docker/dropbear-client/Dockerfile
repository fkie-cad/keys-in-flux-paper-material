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

# Use latest Dropbear version (2025.88 - latest)
ENV DROPBEAR_VERSION=2025.88
WORKDIR /tmp

# Download Dropbear
RUN wget https://matt.ucc.asn.au/dropbear/dropbear-${DROPBEAR_VERSION}.tar.bz2 || \
    wget https://mirror.dropbear.nl/mirror/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2

# Extract
RUN tar xjf dropbear-${DROPBEAR_VERSION}.tar.bz2

# Build and install CLIENT ONLY (dbclient, no server)
WORKDIR /tmp/dropbear-${DROPBEAR_VERSION}
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer" ./configure --prefix=/usr
RUN make PROGRAMS="dbclient" -j$(nproc)
RUN make install

# Create directories for logs and dumps
RUN mkdir -p /data/keylogs /data/dumps /data/lldb_results && \
    chmod 777 /data/keylogs /data/dumps /data/lldb_results

# Copy LLDB monitoring scripts (client-side)
# We'll create dropbear_client_callbacks.py specifically for client-side monitoring
COPY lldb/dropbear_client_callbacks.py /opt/lldb/dropbear_client_callbacks.py
COPY lldb/ssh_state_machine.py /opt/lldb/ssh_state_machine.py
COPY lldb/ssh_memory_dump.py /opt/lldb/ssh_memory_dump.py
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/manual_dump_helper.py /opt/lldb/manual_dump_helper.py
COPY dropbear-client/entrypoint_client.sh /opt/lldb/entrypoint_client.sh
RUN chmod +x /opt/lldb/*.sh

# Copy custom Dropbear client with lifecycle pattern (matches wolfSSH interface)
COPY dropbear-client/dropbear_client_rekey.exp /usr/local/bin/dropbear_client_rekey
RUN chmod +x /usr/local/bin/dropbear_client_rekey

# Cleanup
WORKDIR /
RUN rm -rf /tmp/dropbear-*

# Environment variables for client operation
ENV SSH_SERVER_HOST=openssh_groundtruth
ENV SSH_SERVER_PORT=22
ENV SSH_USER=testuser
ENV SSH_PASSWORD=password
ENV LLDB_KEYLOG=/data/keylogs/dropbear_client_keylog.log
ENV LLDB_RESULTS_DIR=/data/lldb_results
ENV LLDB_DUMPS_DIR=/data/dumps

# Run client under LLDB monitoring
CMD ["/opt/lldb/entrypoint_client.sh"]
