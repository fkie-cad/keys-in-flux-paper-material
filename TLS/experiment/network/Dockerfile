# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

RUN apt-get update && \
    echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections && \
    apt-get install -y tshark && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory for the capture
WORKDIR /capture

# Copy the capture script into the container
COPY capture.sh .

# Make the script executable
RUN chmod +x capture.sh

# Set the default command to run the script
CMD ["./capture.sh"]