FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# Install dependencies (including git for autogen.sh and LLDB 20)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    wget \
    git \
    autoconf \
    automake \
    libtool \
    pkg-config \
    python3 \
    python3-pip \
    gnupg \
    software-properties-common \
    ca-certificates \
    lldb-20 \
    python3-lldb-20 \
    expect \
    gdb \
    && rm -rf /var/lib/apt/lists/*

# Link LLDB 20 as default lldb
RUN ln -sf /usr/bin/lldb-20 /usr/bin/lldb

# Use latest stable versions (as of October 2024)
ENV WOLFSSL_VERSION=5.7.6-stable
ENV WOLFSSH_VERSION=1.4.20-stable

# Build wolfSSL with SSH support
WORKDIR /tmp
RUN git clone --depth 1 --branch v${WOLFSSL_VERSION} https://github.com/wolfSSL/wolfssl.git

WORKDIR /tmp/wolfssl
RUN ./autogen.sh
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer -fvisibility=default" ./configure \
    --enable-ssh \
    --enable-debug \
    --prefix=/usr/local
RUN make -j$(nproc)
RUN make install
RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/local.conf && ldconfig

# Build wolfSSH with debug symbols + symbol visibility
WORKDIR /tmp
RUN git clone --depth 1 --branch v${WOLFSSH_VERSION} https://github.com/wolfSSL/wolfssh.git

WORKDIR /tmp/wolfssh
RUN ./autogen.sh
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer -fvisibility=default" ./configure \
    --with-wolfssl=/usr/local \
    --enable-sshd \
    --enable-debug \
    --prefix=/usr/local
RUN make -j$(nproc)
RUN make install

# Create directories
RUN mkdir -p /etc/ssh /etc/wolfssh /var/run/sshd

# Copy wolfSSHd configuration (build context is docker/ directory)
COPY wolfssh-server/sshd_config /etc/ssh/sshd_config

# Copy SSH host keys from wolfSSH examples
# wolfSSH includes example keys in the keys/ directory
WORKDIR /tmp/wolfssh
RUN if [ -d keys ]; then \
        cp keys/*.pem /etc/wolfssh/ 2>/dev/null || true; \
    fi
RUN ls -la /etc/wolfssh/

# Create sshd privilege separation user (required by wolfSSH)
RUN useradd -r -U -d /var/empty -s /bin/false -c "sshd privilege separation" sshd || true

# Create test user
RUN useradd -m testuser && echo "testuser:password" | chpasswd

# Create results and dumps directories (comprehensive set)
RUN mkdir -p /data/lldb_results /data/dumps /data/keylogs /data/captures && \
    chmod 777 /data/lldb_results /data/dumps /data/keylogs /data/captures

# Copy LLDB monitoring scripts (context is docker/ directory)
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/wolfssh_callbacks.py /opt/lldb/wolfssh_callbacks.py
COPY lldb/run_wolfssh_lldb.sh /opt/lldb/run_wolfssh_lldb.sh
COPY lldb/debug_wolfssh.sh /opt/lldb/debug_wolfssh.sh
RUN chmod +x /opt/lldb/run_wolfssh_lldb.sh /opt/lldb/debug_wolfssh.sh

# Copy entrypoint script (now calls LLDB wrapper)
COPY wolfssh-server/entrypoint_lldb.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Cleanup
WORKDIR /
RUN rm -rf /tmp/wolfssl /tmp/wolfssh

# Use standard SSH port
EXPOSE 22

# Environment variables for LLDB monitoring
ENV SSH_SERVER_TYPE=wolfssh \
    LLDB_RESULTS_DIR=/data/lldb_results \
    LLDB_DUMPS_DIR=/data/dumps \
    LLDB_KEYLOG=/data/keylogs/wolfssh_keylog.log \
    LLDB_ENABLE_MEMORY_DUMPS=true \
    LLDB_ENABLE_WATCHPOINTS=false

# Run wolfSSH server via entrypoint with LLDB monitoring
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["-D", "-d", "-p", "22"]
