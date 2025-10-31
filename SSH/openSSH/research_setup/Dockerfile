# Dockerfile: builds OpenSSH (portable) with debug symbols on Ubuntu 24.04
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/opt/openssh-debug/bin:${PATH}"
ENV LD_LIBRARY_PATH="/opt/openssh-debug/lib:${LD_LIBRARY_PATH}"
WORKDIR /root

# Install build deps + runtime + debug tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential autoconf automake libtool pkg-config git wget ca-certificates \
    zlib1g-dev libssl-dev libpam0g-dev libedit-dev bison flex \
    python3 python3-pip python3-dev lldb lldb-12 vim less procps \
    tcpdump iproute2 iputils-ping sudo curl sshpass \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install python helper libs (for convenience)
RUN python3 -m pip install --upgrade pip setuptools wheel && \
    python3 -m pip install pycryptodome

# Build & install OpenSSH portable with debug symbols (to /opt/openssh-debug)
# - we use conservative flags: -g -O0 -fno-omit-frame-pointer for good debugability
RUN git clone https://github.com/openssh/openssh-portable.git /root/openssh-portable && \
    cd /root/openssh-portable && \
    ./configure --prefix=/opt/openssh-debug --sysconfdir=/etc/ssh \
      CFLAGS="-g -O0 -fno-omit-frame-pointer" LDFLAGS="" \
      --with-pam=no --with-privsep-path=/var/empty || true && \
    make -j$(nproc) && make install

# Drop-in minimal sshd_config for the debug build, run on port 2222
RUN mkdir -p /etc/ssh && cat > /etc/ssh/sshd_config <<'EOF'
Port 2222
ListenAddress 0.0.0.0
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
LogLevel DEBUG3
UsePrivilegeSeparation no
PidFile /var/run/sshd.pid
Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF

# Add helper scripts and the LLDB script
COPY docker-entrypoint.sh /opt/ssh-debug/docker-entrypoint.sh
COPY attach_and_dump.sh /opt/ssh-debug/attach_and_dump.sh
COPY hook_kex.py /opt/ssh-debug/hook_kex.py
RUN chmod +x /opt/ssh-debug/docker-entrypoint.sh /opt/ssh-debug/attach_and_dump.sh

# Expose test ssh port
EXPOSE 2222

# default command: entrypoint handles host key generation + starting sshd
ENTRYPOINT ["/opt/ssh-debug/docker-entrypoint.sh"]
