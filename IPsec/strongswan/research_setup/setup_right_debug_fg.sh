#!/usr/bin/env bash
# setup right (responder) in debug mode
# is running in foreground - so ensure that you run it in a seperated terminal window

set -euo pipefail

# 0) Make sure the legacy starter isn't racing us
#systemctl disable --now strongswan-starter >/dev/null 2>&1 || true

# 1) AppArmor (lab mode)
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y apparmor-utils >/dev/null 2>&1 || true
aa-complain /usr/lib/ipsec/charon  >/dev/null || true
aa-complain /usr/sbin/swanctl      >/dev/null || true

# 2) Config dirs
mkdir -p /etc/strongswan-right/swanctl
mkdir -p /var/log/strongswan

# 3) strongswan.conf with explicit filelog + custom VICI path
cat >/etc/strongswan-right/strongswan.conf <<'EOF'
charon {
  plugins {
    # Standard-Plugin-Konfigs weiter laden
    include /etc/strongswan.d/charon/*.conf
    save-keys {
      esp = yes
      ike = yes
      wireshark_keys = /root/.config/wiresharkr
    }

    # Unser Override NACH den Includes (setzt VICI-Socket um)
    vici {
      socket = unix:///run/right.charon.vici
    }
  }

  # Optional: Logging-Defaults wieder zulassen
  include /etc/strongswan.d/charon-logging.conf
}

# Rest der systemweiten Defaults weiterhin laden
include /etc/strongswan.d/*.conf
EOF

# 4) swanctl.conf (responder / right)
cat >/etc/strongswan-right/swanctl/swanctl.conf <<'EOF'
connections {
  net {
    version = 2
    proposals = aes256-sha256-modp2048
    local_addrs  = 10.0.0.2
    remote_addrs = 10.0.0.1

    local  { 
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

LOGFILE=/var/log/strongswan/charon-right.log
: > "$LOGFILE"
chmod 640 "$LOGFILE"

# 5) SAFE cleanup: kill only charon processes in *right* netns
set +e
right_ino=$(stat -c %i /var/run/netns/right 2>/dev/null)
if [ -n "${right_ino:-}" ]; then
  # graceful
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    ns=$(readlink "$p/ns/net" 2>/dev/null || true)
    case "$ns" in
      "net[${ns:+:}[$right_ino]]"|"net:[$right_ino]")
        cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g')
        if echo "$cmd" | grep -q "/usr/lib/ipsec/charon"; then
          kill -TERM "$pid" 2>/dev/null
        fi
      ;;
    esac
  done
  sleep 0.5
  # force if needed
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    ns=$(readlink "$p/ns/net" 2>/dev/null || true)
    case "$ns" in
      "net[${ns:+:}[$right_ino]]"|"net:[$right_ino]")
        cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g')
        if echo "$cmd" | grep -q "/usr/lib/ipsec/charon"; then
          kill -KILL "$pid" 2>/dev/null
        fi
      ;;
    esac
  done
fi
# remove stale sockets/pids (in right ns)
ip netns exec right bash -lc 'rm -f /run/right.charon.vici /run/right.charon.pid /var/run/charon.pid' 2>/dev/null
set -e

# 6) Start charon in *foreground* within right netns, pipe to log
ip netns exec right bash -lc "
  export STRONGSWAN_CONF=/etc/strongswan-right/strongswan.conf
  echo 'Starting charon (right)'
  /usr/lib/ipsec/charon --use-syslog no \
    --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 --debug-net 2 \
    >> /var/log/strongswan/charon_right 2>&1 &
  echo \$! > /run/right.charon.pid
"

# 7) Wait for actual listener (not just socket file)
./wait_for_vici.sh /run/right.charon.vici 10 right

# 8) Status
ip netns exec right bash -lc '
  echo "---- charon processes ----"
  ps -eo pid,cmd | grep -E "[c]haron($| )" || true
  echo "---- socket + pid ----"
  ls -l /run/right.charon.vici /run/right.charon.pid 2>/dev/null || true
  echo "---- listeners ----"
  ss -xpl | grep right.charon.vici || true
  echo "---- log tail ----"
  tail -n 120 /var/log/strongswan/charon-right.log || true
'

echo "[*] setup_right_debug_fg done."