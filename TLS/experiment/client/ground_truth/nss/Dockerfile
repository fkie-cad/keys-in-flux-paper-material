# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    python3-full \
    mercurial \
    ninja-build \
    python3-pip \
    nano \
    && apt-get clean

# Install Python packages
RUN python3 -m pip install gyp-next --break-system-packages
RUN ln -s /usr/bin/python3 /usr/bin/python

# Clone the nss repository
RUN mkdir NSS_NSPR
WORKDIR /NSS_NSPR
RUN hg clone https://hg.mozilla.org/projects/nspr
RUN hg clone https://hg.mozilla.org/projects/nss

# Set the working directory to nss
WORKDIR /NSS_NSPR/nss

# Copy the test client source files into the container
COPY test_client_12_nss.c /NSS_NSPR/nss/
COPY test_client_13_nss.c /NSS_NSPR/nss/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(hg log -r . --template "{latesttag}-{latesttagdistance}-{node|short}\n") && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
echo 'source /etc/environment' >> /start.sh && \
echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
echo '    echo "Building latest version of NSS...";' >> /start.sh && \
echo '    hg pull;' >> /start.sh && \
echo 'else' >> /start.sh && \
echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
echo '    hg update $VERSION;' >> /start.sh && \
echo 'fi' >> /start.sh && \

# Build the standard release version (shared)
echo './build.sh -c' >> /start.sh && \

# Compile dynamic version of the test clients
echo 'gcc test_client_12_nss.c -o test_client_12_nss_dl -I/NSS_NSPR/dist/Debug/include/nspr -I/NSS_NSPR/dist/public/ -L/NSS_NSPR/dist/Debug/lib -L/NSS_NSPR/nspr/Debug/dist/lib -lssl3 -lnss3 -lsoftokn3 -lfreeblpriv3 -lsqlite3 -lnssutil3 -lplds4 -lnspr4 -lplc4' >> /start.sh && \
echo 'gcc test_client_13_nss.c -o test_client_13_nss_dl -I/NSS_NSPR/dist/Debug/include/nspr -I/NSS_NSPR/dist/public/ -L/NSS_NSPR/dist/Debug/lib -L/NSS_NSPR/nspr/Debug/dist/lib -lssl3 -lnss3 -lsoftokn3 -lfreeblpriv3 -lsqlite3 -lnssutil3 -lplds4 -lnspr4 -lplc4' >> /start.sh && \

# Copy dynamic versions of test clients and shared libraries
echo 'sleep 5' >> /start.sh && \
echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
echo 'cp test_client_12_nss_dl test_client_13_nss_dl  /compiled_clients/' >> /start.sh && \
echo 'cp /NSS_NSPR/dist/Debug/lib/*.so /compiled_clients/libs' >> start.sh && \
echo 'cp /NSS_NSPR/nspr/Debug/dist/lib/*.so /compiled_clients/libs' >> start.sh && \

# Save version information
echo 'echo "TLS Library: NSS" > /compiled_clients/version.md' >> /start.sh && \
echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \

chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]
