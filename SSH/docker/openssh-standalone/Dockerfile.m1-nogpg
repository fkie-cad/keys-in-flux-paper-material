FROM debian:bookworm-slim

LABEL maintainer="SSH Key Lifecycle Lab"
LABEL description="OpenSSH server/client with key export - M1 workaround (no GPG verification)"

ENV DEBIAN_FRONTEND=noninteractive

##############################################################################
# Install dependencies with GPG verification disabled (for lab/research use)
##############################################################################
# Disable GPG signature verification (acceptable for isolated lab environments)
RUN echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99no-check-valid && \
    echo 'Acquire::AllowInsecureRepositories "true";' >> /etc/apt/apt.conf.d/99no-check-valid && \
    echo 'Acquire::AllowDowngradeToInsecureRepositories "true";' >> /etc/apt/apt.conf.d/99no-check-valid && \
    echo 'APT::Get::AllowUnauthenticated "true";' >> /etc/apt/apt.conf.d/99no-check-valid

RUN apt-get update --allow-insecure-repositories && \
    apt-get install -y --allow-unauthenticated \
    build-essential \
    wget \
    curl \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    libpam0g-dev \
    libselinux1-dev \
    sshpass \
    expect \
    python3 \
    python3-pip \
    socat \
    tcpdump \
    iproute2 \
    net-tools \
    vim \
    less \
    ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

##############################################################################
# Download and build OpenSSH with key export patch
##############################################################################
ENV OPENSSH_VERSION=8.9p1
WORKDIR /tmp/build

# Download OpenSSH source
RUN wget -q https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_VERSION}.tar.gz && \
    tar xzf openssh-${OPENSSH_VERSION}.tar.gz && \
    rm openssh-${OPENSSH_VERSION}.tar.gz

# Copy and apply keylog injection script
COPY inject_keylog.sh /tmp/build/
WORKDIR /tmp/build/openssh-${OPENSSH_VERSION}

# Inject keylog code directly into source
RUN chmod +x /tmp/build/inject_keylog.sh && \
    /tmp/build/inject_keylog.sh /tmp/build/openssh-${OPENSSH_VERSION}

# Configure and compile OpenSSH with debug symbols
RUN CFLAGS="-g -O0 -fno-omit-frame-pointer" \
    ./configure \
        --prefix=/usr \
        --sysconfdir=/etc/ssh \
        --with-pam \
        --with-selinux \
        --with-privsep-path=/var/empty \
        --with-privsep-user=sshd \
        --with-pid-dir=/var/run \
        --without-openssl-header-check && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /tmp/build

# Create privilege separation directory and user
RUN mkdir -p /var/empty && \
    chmod 755 /var/empty && \
    useradd -r -U -d /var/empty -s /bin/false -c "sshd privilege separation" sshd || true

##############################################################################
# Setup container environment
##############################################################################

# Create directories for data
RUN mkdir -p /data/keylogs /data/dumps /data/captures && \
    chmod 777 /data/keylogs /data/dumps /data/captures

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Set default environment variables
ENV MODE=server
ENV SSHKEYLOGFILE=/data/keylogs/ssh_keylog.log
ENV SSH_PORT=22
ENV CAPTURE_TRAFFIC=true
ENV CAPTURE_DIR=/data/captures

# Expose SSH port
EXPOSE 22

# Create /etc/ssh directory
RUN mkdir -p /etc/ssh

# Set working directory
WORKDIR /root

# Entrypoint
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]

##############################################################################
# Labels for usage info
##############################################################################
LABEL usage.server="docker run -d -p 2222:22 -v \$(pwd)/data:/data -e MODE=server openssh-standalone"
LABEL usage.client="docker run -it --rm -v \$(pwd)/data:/data -e MODE=client -e HOST=192.168.1.100 openssh-standalone"
LABEL keylog.location="/data/keylogs/ssh_keylog.log"
LABEL base.image="debian:bookworm-slim"
LABEL architecture="arm64"
LABEL security.note="GPG verification disabled - use only in isolated lab environments"
