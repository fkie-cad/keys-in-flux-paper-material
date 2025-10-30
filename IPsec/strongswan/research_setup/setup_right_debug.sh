#!/usr/bin/env bash
# setup_right_debug.sh  -- improved start of right charon (logs + wait)
set -euo pipefail

# ensure AppArmor in complain mode for the lab (non-fatal if already set)
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y apparmor-utils >/dev/null 2>&1 || true
aa-complain /usr/lib/ipsec/charon  >/dev/null || true
aa-complain /usr/sbin/swanctl      >/dev/null || true

mkdir -p /etc/strongswan-right/swanctl

cat >/etc/strongswan-right/strongswan.conf <<'EOF'
charon {
  plugins {
    include /etc/strongswan.d/charon/*.conf
    vici {
      socket = unix:///run/right.charon.vici
    }
  }
  include /etc/strongswan.d/charon-logging.conf
}
include /etc/strongswan.d/*.conf
EOF

cat >/etc/strongswan-right/swanctl/swanctl.conf <<'EOF'
connections {
    net {
        version = 2
        proposals = aes256-sha256-modp2048
        local_addrs  = 10.0.0.2
        remote_addrs = 10.0.0.1

        local {
            auth = psk
            id = right
        }
        remote {
            auth = psk
            id = left
        }
        children {
            net {
                local_ts  = 10.0.0.2/32
                remote_ts = 10.0.0.1/32
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

# Ensure log dir exists and sensible permissions
mkdir -p /var/log/strongswan
LOGFILE=/var/log/strongswan/charon-right.log
touch "$LOGFILE"
chown root:root "$LOGFILE"
chmod 640 "$LOGFILE"

# Start charon in the right netns, let it daemonize (no --nofork) and log output
ip netns exec right bash -lc "
  export STRONGSWAN_CONF=/etc/strongswan-right/strongswan.conf
  echo 'Starting charon (right) -> logging to $LOGFILE'
  # use --use-syslog no so it logs to stdout; redirect stdout/stderr to LOGFILE
  /usr/lib/ipsec/charon --use-syslog no --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 \
    >> $LOGFILE 2>&1 &
  echo \$! > /run/right.charon.pid 2>/dev/null || true
"

# Wait loop for the VICI socket (script provided below)
sudo ./wait_for_vici.sh /run/right.charon.vici 10

# Print status
ip netns exec right bash -lc '
  echo "---- charon processes ----"
  ps -eo pid,cmd | grep -E "[c]haron($| )" || true
  echo "---- socket ----"
  ls -l /run/right.charon.vici /run/right.charon.pid 2>/dev/null || true
  echo "---- listening sockets ----"
  ss -xpl | grep right.charon.vici || true
  echo "---- tail of log ----"
  tail -n 80 /var/log/strongswan/charon-right.log || true
'

echo "[*] setup_right_debug done."