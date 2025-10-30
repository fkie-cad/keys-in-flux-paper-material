#!/usr/bin/env bash
# setup left (initiator) in debug mode

set -euo pipefail
systemctl disable --now strongswan-starter >/dev/null 2>&1 || true

#apt-get update -y >/dev/null 2>&1 || true
#apt-get install -y apparmor-utils >/dev/null 2>&1 || true
aa-complain /usr/lib/ipsec/charon  >/dev/null || true
aa-complain /usr/sbin/swanctl      >/dev/null || true

mkdir -p /etc/strongswan-left/swanctl
mkdir -p /var/log/strongswan

# charon config
cat >/etc/strongswan-left/strongswan.conf <<'EOF'
charon {
  plugins {
    include /etc/strongswan.d/charon/*.conf
    save-keys {
      esp = yes
      ike = yes
      wireshark_keys = /root/.config/wireshark
    }
    vici { socket = unix:///run/left.charon.vici }
  }
  filelog {
    /var/log/strongswan/charon_left {
      time_format = %b %e %T
      default = 2
      ike = 2
      knl = 2
      net = 2
      dmn = 2
      lib = 2
    }
  }
}
include /etc/strongswan.d/*.conf
EOF

cat >/etc/strongswan-left/swanctl/swanctl.conf <<'EOF'
connections {
  net {
    version = 2
    proposals = aes256-sha256-modp2048
    local_addrs  = 10.0.0.1
    remote_addrs = 10.0.0.2
    local  { 
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

LOGFILE=/var/log/strongswan/charon_left
: > "$LOGFILE"; chmod 640 "$LOGFILE"

# Safe, namespaced cleanup
set +e
left_ino=$(stat -c %i /var/run/netns/left 2>/dev/null)
if [ -n "${left_ino:-}" ]; then
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    ns=$(readlink "$p/ns/net" 2>/dev/null || true)
    [ "$ns" = "net:[$left_ino]" ] || continue
    cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g')
    echo "$cmd" | grep -q "/usr/lib/ipsec/charon" && kill -TERM "$pid" 2>/dev/null
  done
  sleep 0.5
  for p in /proc/[0-9]*; do
    pid="${p##*/}"
    ns=$(readlink "$p/ns/net" 2>/dev/null || true)
    [ "$ns" = "net:[$left_ino]" ] || continue
    cmd=$(tr -d '\0' < "$p/cmdline" 2>/dev/null | sed 's/\x0/ /g')
    echo "$cmd" | grep -q "/usr/lib/ipsec/charon" && kill -KILL "$pid" 2>/dev/null
  done
fi
ip netns exec left bash -lc 'rm -f /run/left.charon.vici /run/left.charon.pid /var/run/charon.pid' 2>/dev/null
set -e

# Foreground start, piped to file
# (charon runs foreground by default); we background via &.
ip netns exec left bash -lc "
  export STRONGSWAN_CONF=/etc/strongswan-left/strongswan.conf
  echo 'Starting charon (left)'
  /usr/lib/ipsec/charon --use-syslog no \
    --debug-dmn 2 --debug-lib 2 --debug-ike 2 --debug-knl 2 --debug-net 2 \
    >> /var/log/strongswan/charon_left 2>&1 &
  echo \$! > /run/left.charon.pid
"

./wait_for_vici.sh /run/left.charon.vici 10 left

ip netns exec left bash -lc '
  echo "---- charon processes ----"; ps -eo pid,cmd | grep -E "[c]haron($| )" || true
  echo "---- socket + pid ----";    ls -l /run/left.charon.vici /run/left.charon.pid 2>/dev/null || true
  echo "---- listeners ----";       ss -xpl | grep left.charon.vici || true
  echo "---- log tail ----";        tail -n 120 /var/log/strongswan/charon_left || true
'
echo "[*] setup_left_debug_fg done."
