FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    autoconf \
    automake \
    libtool \
    git \
    ca-certificates \
    wget \
    python3 \
    python3-pip \
    gnupg \
    software-properties-common \
    expect \
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

WORKDIR /build

# Build wolfSSL (crypto backend)
ENV WOLFSSL_VERSION=5.7.6-stable
RUN wget https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${WOLFSSL_VERSION}.tar.gz && \
    tar xzf v${WOLFSSL_VERSION}.tar.gz && \
    cd wolfssl-${WOLFSSL_VERSION} && \
    ./autogen.sh && \
    CFLAGS="-g -O0 -fno-omit-frame-pointer" \
    ./configure --enable-debug --enable-ssh --enable-keygen --enable-cryptonly --prefix=/usr/local && \
    make -j$(nproc) && make install && ldconfig

# Build wolfSSH (CLIENT ONLY - using example client)
ENV WOLFSSH_VERSION=1.4.20-stable
RUN wget https://github.com/wolfSSL/wolfssh/archive/refs/tags/v${WOLFSSH_VERSION}.tar.gz && \
    tar xzf v${WOLFSSH_VERSION}.tar.gz && \
    cd wolfssh-${WOLFSSH_VERSION} && \
    ./autogen.sh && \
    CFLAGS="-g -O0 -fno-omit-frame-pointer" \
    ./configure --enable-debug --prefix=/usr/local && \
    make -j$(nproc) && make install && ldconfig

# Build the example client from wolfSSH using make (includes all dependencies)
WORKDIR /build/wolfssh-${WOLFSSH_VERSION}

# Build examples (includes client binary)
# The actual binary is in .libs/ directory (libtool creates a wrapper script in client/)
RUN make examples && \
    cp examples/client/.libs/client /usr/local/bin/wolfssh-client && \
    chmod +x /usr/local/bin/wolfssh-client

# Verify the binary has symbols
RUN nm /usr/local/bin/wolfssh-client | grep -i "DoNewKeys\|wolfSSH" | head -5 || echo "Note: DoNewKeys is in libwolfssh.so"

# Build custom rekey clients (V1 and V2)
COPY wolfssh-client/wolfssh_client_rekey.c /build/wolfssh_client_rekey.c
COPY wolfssh-client/wolfssh_client_rekeyV2.c /build/wolfssh_client_rekeyV2.c

# Build V1 client (original implementation)
RUN gcc -g -O0 -fno-omit-frame-pointer \
    /build/wolfssh_client_rekey.c \
    -o /usr/local/bin/wolfssh-client-rekey-v1 \
    -I/usr/local/include \
    -I/usr/local/include/wolfssl \
    -L/usr/local/lib \
    -lwolfssh -lwolfssl \
    && chmod +x /usr/local/bin/wolfssh-client-rekey-v1 \
    && echo "✓ V1 client built successfully"

# Build V2 client (enhanced with drive_rekey_until_done)
RUN gcc -g -O0 -fno-omit-frame-pointer \
    /build/wolfssh_client_rekeyV2.c \
    -o /usr/local/bin/wolfssh-client-rekey-v2 \
    -I/usr/local/include \
    -I/usr/local/include/wolfssl \
    -L/usr/local/lib \
    -lwolfssh -lwolfssl \
    && chmod +x /usr/local/bin/wolfssh-client-rekey-v2 \
    && echo "✓ V2 client built successfully"

# Create symlink to V1 as default
RUN ln -sf /usr/local/bin/wolfssh-client-rekey-v1 /usr/local/bin/wolfssh-client-rekey \
    && echo "✓ Default symlink created (wolfssh-client-rekey -> v1)"

# Verify both custom client binaries
RUN echo "=== V1 Client Symbols ===" && \
    nm /usr/local/bin/wolfssh-client-rekey-v1 | grep -i "wolfSSH_TriggerKeyExchange" || echo "Note: TriggerKeyExchange is in libwolfssh.so" && \
    echo "=== V2 Client Symbols ===" && \
    nm /usr/local/bin/wolfssh-client-rekey-v2 | grep -i "wolfSSH_TriggerKeyExchange" || echo "Note: TriggerKeyExchange is in libwolfssh.so" && \
    echo "=== Available Clients ===" && \
    ls -lh /usr/local/bin/wolfssh-client-rekey* && \
    echo "✓ Both client versions verified"

# Create directories for logs and dumps
RUN mkdir -p /data/keylogs /data/dumps /data/lldb_results && \
    chmod 777 /data/keylogs /data/dumps /data/lldb_results

# Copy LLDB monitoring scripts (client-side)
COPY lldb/wolfssh_client_callbacks.py /opt/lldb/wolfssh_client_callbacks.py
COPY lldb/ssh_state_machine.py /opt/lldb/ssh_state_machine.py
COPY lldb/ssh_memory_dump.py /opt/lldb/ssh_memory_dump.py
COPY lldb/ssh_extraction_utils.py /opt/lldb/ssh_extraction_utils.py
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/manual_dump_helper.py /opt/lldb/manual_dump_helper.py
COPY wolfssh-client/entrypoint_client.sh /opt/lldb/entrypoint_client.sh
RUN chmod +x /opt/lldb/*.sh

# Don't cleanup - wolfSSH client needs the directory structure for keys
# The client example uses ChangeToWolfSshRoot() which looks for keys/ directory
WORKDIR /build/wolfssh-${WOLFSSH_VERSION}

# Environment variables for client operation
ENV SSH_SERVER_HOST=openssh_groundtruth
ENV SSH_SERVER_PORT=22
ENV SSH_USER=testuser
ENV SSH_PASSWORD=password
ENV LLDB_KEYLOG=/data/keylogs/wolfssh_client_keylog.log
ENV LLDB_RESULTS_DIR=/data/lldb_results
ENV LLDB_DUMPS_DIR=/data/dumps

# Run client under LLDB monitoring
CMD ["/opt/lldb/entrypoint_client.sh"]
