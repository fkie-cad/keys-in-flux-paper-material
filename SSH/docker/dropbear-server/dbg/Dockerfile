# Ubuntu 24.04 (Noble)
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    TZ=Etc/UTC

# Base deps
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates wget build-essential pkg-config zlib1g-dev \
      python3 python3-pip \
      # LLDB 20 + Python bindings (official Noble repos)
      lldb-20 python3-lldb-20 \
    && rm -rf /var/lib/apt/lists/*

# Use the latest upstream Dropbear (check: https://matt.ucc.asn.au/dropbear/dropbear.html)
# As of Oct 2025 latest is 2025.88
ENV DROPBEAR_VERSION=2025.88
WORKDIR /tmp

# Fetch (primary + mirror)
RUN set -eux; \
    wget -O dropbear-${DROPBEAR_VERSION}.tar.bz2 \
      https://matt.ucc.asn.au/dropbear/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2 \
    || wget -O dropbear-${DROPBEAR_VERSION}.tar.bz2 \
      https://dropbear.nl/mirror/releases/dropbear-${DROPBEAR_VERSION}.tar.bz2

# Build with debug symbols
RUN tar xjf dropbear-${DROPBEAR_VERSION}.tar.bz2 && \
    cd dropbear-${DROPBEAR_VERSION} && \
    CFLAGS="-g -O0" ./configure --prefix=/usr && \
    make PROGRAMS="dropbear dropbearkey dropbearconvert scp" -j"$(nproc)" && \
    make install

# Host keys
RUN mkdir -p /etc/dropbear && \
    /usr/bin/dropbearkey -t rsa -f /etc/dropbear/dropbear_rsa_host_key && \
    /usr/bin/dropbearkey -t ecdsa -f /etc/dropbear/dropbear_ecdsa_host_key && \
    /usr/bin/dropbearkey -t ed25519 -f /etc/dropbear/dropbear_ed25519_host_key

# Test user
RUN useradd -m testuser && echo "testuser:password" | chpasswd

# Result dirs
RUN mkdir -p /data/lldb_results /data/dumps && chmod 777 /data/lldb_results /data/dumps

# LLDB helpers
RUN mkdir -p /opt/lldb
COPY lldb/dropbear_dbg.py /opt/lldb/dropbear_dbg.py
COPY dropbear-server/entrypoint_minimal.sh /opt/lldb/entrypoint_minimal.sh
COPY lldb/entrypoint_auto_lldb.sh /opt/lldb/entrypoint_auto_lldb.sh
COPY lldb/attach_dropbear.sh /opt/lldb/attach_dropbear.sh
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/dropbear_callbacks.py /opt/lldb/dropbear_callbacks.py
COPY lldb/dropbear_callbacks_v2.py /opt/lldb/dropbear_callbacks_v2.py
COPY lldb/dropbear_callbacks_minimal.py /opt/lldb/dropbear_callbacks_minimal.py
COPY lldb/dropbear_callbacks_state_immediate.py /opt/lldb/dropbear_callbacks_state_immediate.py
COPY lldb/dropbear_callbacks_state_delayed.py /opt/lldb/dropbear_callbacks_state_delayed.py
COPY lldb/entrypoint_dropbear_only.sh /opt/lldb/entrypoint_dropbear_only.sh
RUN chmod +x /opt/lldb/*.sh

# A small convenience: make lldb the default "lldb"
RUN ln -sf /usr/bin/lldb-20 /usr/bin/lldb

# Tidy up
WORKDIR /
RUN rm -rf /tmp/dropbear-*

EXPOSE 22

# Default: auto-attach LLDB (override in compose if you want plain Dropbear)
ENV LLDB_RESULTS_DIR=/data/lldb_results \
    LLDB_DUMPS_DIR=/data/dumps
CMD ["/opt/lldb/entrypoint_auto_lldb.sh"]
