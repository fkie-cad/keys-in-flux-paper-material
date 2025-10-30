#!/usr/bin/env bash
# setup_left_debug.sh  -- improved start of left charon (logs + wait)
set -euo pipefail

# Put AppArmor in complain mode for the lab (non-fatal if already set)
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y apparmor-utils >/dev/null 2>&1 || true
aa-complain /usr/lib/ipsec/charon  >/dev/null || true
aa-complain /usr/sbin/swanctl      >/dev/null || true

# Config dirs
mkdir -p /etc/strongswan-left/swanctl
mkdir -p /var/log/strongswan

# Minimal override: per-namespace VICI socket
cat >/etc/strongswan-left/strongswan.conf <<'EOF'
charon {
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici {
      socket = unix:///run/left.charon.vici
    }
  }
  include /etc/strongswan.d/charon-logging.conf
}
include /etc/strongswan.d/*.conf
EOF

# swanctl.conf for LEFT (initiator), PSK: test123
cat >/etc/strongswan-left/swanctl/swanctl.conf <<'EOF'
connections {
    net {
        version = 2
        proposals = aes256-sha256-modp2048
        local_addrs  = 10.0.0.1
        remote_addrs = 10.0.0.2

        local {
            auth = psk
            id = left
        }
        remote {
            auth = psk
            id = right
        }
        children {
            net {
                local_ts  = 10.0.0.1/32
                remote_ts = 10.0.0.2/32
                esp_proposals = aes256-sha256
            }
        }
    }
}

secrets {
    ike-1 {
        id = left
        secret = "test123"
    }
    ike-2 {
        id = right
        secret = "test123"
    }
}
EOF

LOGFILE=/var/log/strongswan/charon-left.log
touch "$LOGFILE"
chown root:root "$LOGFILE"
chmod 640 "$LOGFILE"

# Start charon in LEFT namespace, log to file
ip netns exec left bash -lc "
  export STRONGSWAN_CONF=/etc/strongswan-left/strongswan.conf
  echo 'Starting charon (left) -> logging to $LOGFILE'
  /usr/lib/ipsec/charon --use-syslog no --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 \
    >> $LOGFILE 2>&1 &
  echo \$! > /run/left.charon.pid 2>/dev/null || true
"

# Wait for left VICI socket (10s timeout)
./wait_for_vici.sh /run/left.charon.vici 10

# Status
ip netns exec left bash -lc '
  echo "---- charon processes ----"
  ps -eo pid,cmd | grep -E "[c]haron($| )" || true
  echo "---- socket ----"
  ls -l /run/left.charon.vici /run/left.charon.pid 2>/dev/null || true
  echo "---- listening sockets ----"
  ss -xpl | grep left.charon.vici || true
  echo "---- tail of log ----"
  tail -n 80 /var/log/strongswan/charon-left.log || true
'

echo "[*] setup_left_debug done."