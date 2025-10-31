FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies including LLDB
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    lldb \
    python3-lldb \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Build OpenSSH with debug symbols (no optimization for better debugging)
ENV OPENSSH_VERSION=8.9p1
WORKDIR /tmp
RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz && \
    tar xzf openssh-${OPENSSH_VERSION}.tar.gz

# Keep source for reference
RUN cp -r openssh-${OPENSSH_VERSION} /opt/openssh-src

WORKDIR /tmp/openssh-${OPENSSH_VERSION}
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer" ./configure \
    --prefix=/usr \
    --sysconfdir=/etc/ssh \
    --without-openssl-header-check && \
    make -j$(nproc)

# Install OpenSSH but preserve unstripped sshd with debug symbols
RUN cp sshd /usr/sbin/sshd.unstripped && \
    make install && \
    # Use unstripped version for LLDB
    mv /usr/sbin/sshd.unstripped /usr/sbin/sshd

# Create necessary directories and users
RUN mkdir -p /var/run/sshd /var/empty /data/lldb_results
RUN useradd -r -U -d /var/empty -s /bin/false -c "sshd privilege separation" sshd || true
RUN ssh-keygen -A || true
RUN useradd -m testuser && echo "testuser:password" | chpasswd

# Configure SSH for testing
RUN sed -ri 's/^#?PermitRootLogin .*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -ri 's/^#?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    sed -ri 's/^#?UsePrivilegeSeparation .*/UsePrivilegeSeparation no/' /etc/ssh/sshd_config && \
    echo "UsePrivilegeSeparation no" >> /etc/ssh/sshd_config

# Copy LLDB monitoring scripts (context is docker/ directory)
COPY lldb/ssh_monitor.py /opt/lldb/ssh_monitor.py
COPY lldb/openssh_callbacks.py /opt/lldb/openssh_callbacks.py
COPY lldb/run_ssh_lldb.sh /opt/lldb/run_ssh_lldb.sh
RUN chmod +x /opt/lldb/run_ssh_lldb.sh

# Set permissions for LLDB results
RUN chmod 777 /data/lldb_results

WORKDIR /root

EXPOSE 22

# Default: Run sshd with LLDB monitoring
ENV SSH_SERVER_TYPE=openssh
ENV LLDB_RESULTS_DIR=/data/lldb_results
CMD ["/opt/lldb/run_ssh_lldb.sh", "openssh", "-D", "-e"]
