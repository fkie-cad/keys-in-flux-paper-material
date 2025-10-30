# Use the official Ubuntu base image
FROM ubuntu:22.04

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


RUN apt-get update && apt-get install -y \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    nettle-dev \
    libgmp-dev \
    libidn2-0-dev \
    libp11-kit-dev \
    libunistring-dev \
    wget \
    git \
    ca-certificates \
    && apt-get clean

RUN apt-get install -y dash git-core gettext autopoint
RUN apt-get install -y python3 libtspi-dev
RUN apt-get install -y libtasn1-bin libtasn1-6-dev gawk gperf
RUN apt-get install -y libtss2-dev libunbound-dev dns-root-data bison gtk-doc-tools
RUN apt-get install -y texinfo texlive texlive-plain-generic texlive-extra-utils
RUN apt-get install -y valgrind nodejs softhsm2 faketime lcov libssl-dev libcmocka-dev expect libev-dev
RUN apt-get install -y dieharder openssl abigail-tools socat net-tools ppp util-linux

# Clone the gnutls repository
RUN git clone https://github.com/gnutls/gnutls.git || \
    (sleep 5 && git clone https://github.com/gnutls/gnutls.git) || \
    (sleep 10 && git clone https://github.com/gnutls/gnutls.git)

# Set the working directory to gnutls
# ...existing code...
WORKDIR /gnutls

# copy test sources out of the gnutls source tree to avoid interfering with the build
COPY test_server_12_gnutls_key_export.c /tests/
COPY test_server_13_gnutls_key_export.c /tests/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of GnuTls...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    echo './bootstrap' >> /start.sh && \
    echo './configure --enable-shared --disable-static --without-p11-kit --without-tpm' >> /start.sh && \
    echo 'make clean && make -j $(nproc) && make install' >> /start.sh && \
    # compile test programs from /tests after install (use installed headers in /usr/local/include)
    echo 'gcc /tests/test_server_12_gnutls_key_export.c -o /compiled_clients/test_server_12_gnutls_key_export_dl -I/usr/local/include -I/usr/include -L/usr/local/lib -lgnutls -lnettle -ltasn1 -lhogweed -lgmp -lidn2 -lunistring -lcrypto -lssl -lpthread -ldl' >> /start.sh && \
    echo 'gcc /tests/test_server_13_gnutls_key_export.c -o /compiled_clients/test_server_13_gnutls_key_export_dl -I/usr/local/include -I/usr/include -L/usr/local/lib -lgnutls -lnettle -ltasn1 -lhogweed -lgmp -lidn2 -lunistring -lcrypto -lssl -lpthread -ldl' >> /start.sh && \
    echo 'cp /compiled_clients/test_server_12_gnutls_key_export_dl /compiled_clients/test_server_13_gnutls_key_export_dl /compiled_clients/ 2>/dev/null || true' >> /start.sh && \
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'find . -name \*.so -exec cp {} /compiled_clients/libs/ \;' >> /start.sh && \
    echo 'echo "TLS Library: GnuTls" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]
#CMD ["/bin/bash"]


