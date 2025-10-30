# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

RUN apt-get update && \
    apt-get install -y python3 python3-pip lldb python3-lldb unzip nano iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app/

# Copy the clients (context is parent directory)
COPY experiment/client/ground_truth/ ./
COPY experiment/client/lldb.zip ./
COPY experiment/client/run_client.sh ./

# Unzip lldb.zip - it contains ../lldb/ paths, so we extract and handle the relative path
RUN unzip -q lldb.zip && \
    if [ -d "../lldb" ]; then mv ../lldb ./lldb; fi && \
    rm lldb.zip && \
    chmod +x run_client.sh

# Make the client binaries and the run script executable
RUN chmod +x run_client.sh && \
    find . -type f -name 'test_client_*' -exec chmod +x {} +

CMD ["./run_client.sh"]