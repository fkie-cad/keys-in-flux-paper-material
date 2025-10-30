# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

RUN apt-get update && \
    apt-get install -y strace gdb && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the server
COPY ./gnutls/ ./gnutls
COPY ./certs/ ./certs
COPY run_server.sh ./

RUN chmod +x run_server.sh

CMD ["./run_server.sh"]