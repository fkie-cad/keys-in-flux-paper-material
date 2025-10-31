FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    openssh-client python3 python3-pip sshpass expect \
    tcpdump tshark socat tree \
    && rm -rf /var/lib/apt/lists/*

# Copy admin CLI (make sure admin_cli.py exists in ssh-client/)
COPY admin_cli.py /usr/local/bin/ssh-admin
RUN chmod +x /usr/local/bin/ssh-admin

WORKDIR /root
ENTRYPOINT ["/bin/bash"]
