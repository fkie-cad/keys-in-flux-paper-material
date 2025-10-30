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
    python3 \
    libssl-dev \
    nano \
    && apt-get clean

# Copy and extract the Library
COPY matrixssl-4-2-1-open.tar.gz /matrixssl-4-2-1-open.tar.gz
RUN tar -xzf matrixssl-4-2-1-open.tar.gz
RUN rm matrixssl-4-2-1-open.tar.gz
WORKDIR /matrixssl-4-2-1-open

# Copy the test client source files into the container
COPY test_client_12_matrixssl.c /matrixssl-4-2-1-open/
COPY test_client_13_matrixssl.c /matrixssl-4-2-1-open/

# Create startup script to compile the clients
# For compiling the key_export clients the Library is build with fulltest-config to enable master secret export
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'make default-config' >> /start.sh && \
    echo 'make all' >> /start.sh && \
    echo 'gcc test_client_12_matrixssl.c -o test_client_12_matrixssl_dl -I/matrixssl-4-2-1-open/configs/default/ -I/matrixssl-4-2-1-open/core/osdep/include/ -I/matrixssl-4-2-1-open/core/include/ -I/matrixssl-4-2-1-open/matrixssl/ -L/matrixssl-4-2-1-open/matrixssl/ -L/matrixssl-4-2-1-open/crypto/ -L/matrixssl-4-2-1-open/core/ -lssl_s -lcrypt_s -lcore_s' >> /start.sh && \
    echo 'gcc test_client_13_matrixssl.c -o test_client_13_matrixssl_dl -I/matrixssl-4-2-1-open/configs/default/ -I/matrixssl-4-2-1-open/core/osdep/include/ -I/matrixssl-4-2-1-open/core/include/ -I/matrixssl-4-2-1-open/matrixssl/ -L/matrixssl-4-2-1-open/matrixssl/ -L/matrixssl-4-2-1-open/crypto/ -L/matrixssl-4-2-1-open/core/ -lssl_s -lcrypt_s -lcore_s' >> /start.sh && \
    echo 'cp test_client_12_matrixssl_dl test_client_13_matrixssl_dl /compiled_clients/' >> /start.sh && \
    echo 'echo "TLS Library: matrixSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: 4.2.1" >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]


