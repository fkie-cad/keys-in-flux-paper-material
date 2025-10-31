FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y python3 python3-pip openssh-client \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install paramiko

# Copy the Paramiko server script (server_keylogger.py)
COPY server_keylogger.py /opt/paramiko/server_keylogger.py
RUN chmod +x /opt/paramiko/server_keylogger.py

# Create shared data dir inside container (mounted by compose)
RUN mkdir -p /data/keylogs /data/dumps

WORKDIR /opt/paramiko
CMD ["python3", "/opt/paramiko/server_keylogger.py"]
