FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Fix GPG keys for ARM64 (Apple Silicon) builds
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /var/lib/apt/lists/partial

# Install dependencies and GPG tools
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
    && rm -rf /var/lib/apt/lists/*

# Add LLVM repository for newer LLDB (Ubuntu 24.04 - noble)
# Using LLDB 18 (stable for noble) - may have ARM64 watchpoint improvements
RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm-archive-keyring.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm-archive-keyring.gpg] http://apt.llvm.org/noble/ llvm-toolchain-noble-18 main" > /etc/apt/sources.list.d/llvm.list && \
    apt-get update && \
    apt-get install -y lldb-18 python3-lldb-18 && \
    ln -sf /usr/bin/lldb-18 /usr/bin/lldb && \
    ln -sf /usr/lib/llvm-18/lib/python3.12/dist-packages/lldb /usr/local/lib/python3.12/dist-packages/ && \
    rm -rf /var/lib/apt/lists/*

# Use latest Dropbear version (2025.88 - latest)
# Includes bugfixes and improved fork/memory handling
ENV DROPBEAR_VERSION=2025.88
WORKDIR /tmp

# Download Dropbear (split steps for better error diagnosis)
RUN wget https://matt.ucc.asn.au/dropbear/dropbear-${DROPBEAR_VERSION}.tar.bz2 || \
    wget https://mirror.dropbear.nl/mirror/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2

# Extract
RUN tar xjf dropbear-${DROPBEAR_VERSION}.tar.bz2

# Build and install
WORKDIR /tmp/dropbear-${DROPBEAR_VERSION}
RUN CFLAGS="-g -O0" ./configure --prefix=/usr
RUN make PROGRAMS="dropbear dropbearkey dropbearconvert" -j$(nproc)
RUN make install

# Generate host keys
RUN mkdir -p /etc/dropbear && \
    /usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    /usr/bin/dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    /usr/bin/dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# Create test user
RUN useradd -m testuser && echo "testuser:password" | chpasswd

# Create login accounting files (required for Dropbear sessions)
RUN touch /var/run/utmp /var/log/wtmp && \
    chmod 664 /var/run/utmp /var/log/wtmp && \
    chgrp utmp /var/run/utmp /var/log/wtmp

# Create results and dumps directories
RUN mkdir -p /data/lldb_results /data/dumps && \
    chmod 777 /data/lldb_results /data/dumps

# Copy LLDB monitoring scripts (context is docker/ directory)
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/manual_dump_helper.py /opt/lldb/manual_dump_helper.py
COPY lldb/dropbear_callbacks.py /opt/lldb/dropbear_callbacks.py
COPY lldb/dropbear_server_callbacks.py /opt/lldb/dropbear_server_callbacks.py
COPY lldb/dropbear_callbacks_v2.py /opt/lldb/dropbear_callbacks_v2.py
COPY lldb/dropbear_callbacks_minimal.py /opt/lldb/dropbear_callbacks_minimal.py
COPY lldb/dropbear_callbacks_keyonly.py /opt/lldb/dropbear_callbacks_keyonly.py
COPY lldb/dropbear_callbacks_test_nosigchld.py /opt/lldb/dropbear_callbacks_test_nosigchld.py
COPY lldb/dropbear_callbacks_test_disable_wp.py /opt/lldb/dropbear_callbacks_test_disable_wp.py
COPY lldb/dropbear_callbacks_register_based.py /opt/lldb/dropbear_callbacks_register_based.py
COPY lldb/dropbear_callbacks_register_delayed.py /opt/lldb/dropbear_callbacks_register_delayed.py
COPY lldb/dropbear_callbacks_state_immediate.py /opt/lldb/dropbear_callbacks_state_immediate.py
COPY lldb/dropbear_callbacks_state_delayed.py /opt/lldb/dropbear_callbacks_state_delayed.py
COPY lldb/dropbear_dbg.py /opt/lldb/dropbear_dbg.py
COPY lldb/dropbear_callbacks_chat.py /opt/lldb/dropbear_callbacks_chat.py
COPY lldb/dropbear_test_minimal.py /opt/lldb/dropbear_test_minimal.py
COPY lldb/dropbear_test_minimal_v2.py /opt/lldb/dropbear_test_minimal_v2.py
COPY lldb/dropbear_test_option_c.py /opt/lldb/dropbear_test_option_c.py
COPY lldb/run_dropbear_lldb.sh /opt/lldb/run_dropbear_lldb.sh
COPY lldb/attach_dropbear.sh /opt/lldb/attach_dropbear.sh
COPY lldb/debug_dropbear.sh /opt/lldb/debug_dropbear.sh
COPY dropbear-server/entrypoint_auto_lldb.sh /opt/lldb/entrypoint_auto_lldb.sh
COPY dropbear-server/entrypoint_minimal.sh /opt/lldb/entrypoint_minimal.sh
COPY dropbear-server/entrypoint_simple.sh /opt/lldb/entrypoint_simple.sh
COPY dropbear-server/entrypoint_keyonly.sh /opt/lldb/entrypoint_keyonly.sh
COPY dropbear-server/entrypoint_test_nosigchld.sh /opt/lldb/entrypoint_test_nosigchld.sh
COPY dropbear-server/entrypoint_test_disable_wp.sh /opt/lldb/entrypoint_test_disable_wp.sh
COPY dropbear-server/entrypoint_test_register.sh /opt/lldb/entrypoint_test_register.sh
COPY dropbear-server/entrypoint_test_register_delayed.sh /opt/lldb/entrypoint_test_register_delayed.sh
COPY dropbear-server/entrypoint_test_state_immediate.sh /opt/lldb/entrypoint_test_state_immediate.sh
COPY dropbear-server/entrypoint_test_state_delayed.sh /opt/lldb/entrypoint_test_state_delayed.sh
COPY dropbear-server/entrypoint_lldb_launch.sh /opt/lldb/entrypoint_lldb_launch.sh
COPY dropbear-server/entrypoint_lldb_launch_v2.sh /opt/lldb/entrypoint_lldb_launch_v2.sh
COPY dropbear-server/entrypoint_lldb_launch_v3.sh /opt/lldb/entrypoint_lldb_launch_v3.sh
RUN chmod +x /opt/lldb/*.sh

# Cleanup
WORKDIR /
RUN rm -rf /tmp/dropbear-*

EXPOSE 22

# Run dropbear with auto-attach LLDB monitoring
ENV SSH_SERVER_TYPE=dropbear
ENV LLDB_RESULTS_DIR=/data/lldb_results
ENV LLDB_DUMPS_DIR=/data/dumps
CMD ["/opt/lldb/entrypoint_auto_lldb.sh"]
