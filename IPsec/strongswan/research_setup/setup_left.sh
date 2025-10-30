#!/usr/bin/env bash
# left --> client
set -euo pipefail

# AppArmor für Lab: nicht blockieren
apt-get update -y >/dev/null 2>&1 || true
apt-get install -y apparmor-utils >/dev/null 2>&1 || true
aa-complain /usr/lib/ipsec/charon  >/dev/null || true
aa-complain /usr/sbin/swanctl      >/dev/null || true

mkdir -p /etc/strongswan-left/swanctl

# Minimal-Override: eigener VICI-Socket
cat >/etc/strongswan-left/strongswan.conf <<'EOF'
charon {
  plugins {
    # Standard-Plugin-Konfigs weiter laden
    include /etc/strongswan.d/charon/*.conf

    # Unser Override NACH den Includes (setzt VICI-Socket um)
    vici {
      socket = unix:///run/left.charon.vici
    }
  }

  # Optional: Logging-Defaults wieder zulassen
  include /etc/strongswan.d/charon-logging.conf
}

# Rest der systemweiten Defaults weiterhin laden
include /etc/strongswan.d/*.conf
EOF

# swanctl.conf (PSK IKEv2, Child 'net')
cat >/etc/strongswan-left/swanctl/swanctl.conf <<'EOF'
connections {
  net {
    version = 2
    proposals = aes256-sha256-modp2048
    local_addrs  = 10.0.0.1
    remote_addrs = 10.0.0.2
    local  { auth = psk; id = left;  }
    remote { auth = psk; id = right; }
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
  ike-1 { id = left;  secret = "test123"; }
  ike-2 { id = right; secret = "test123"; }
}
EOF

# charon starten (eigene PID/Sock)
ip netns exec left bash -lc '
  export STRONGSWAN_CONF=/etc/strongswan-left/strongswan.conf
  /usr/lib/ipsec/charon --pidfile /run/left.charon.pid --nofork \
    --debug-lib 1 --debug-ike 1 --debug-knl 1 --debug-net 1 \
    </dev/null >/dev/null 2>&1 & disown
'

# pruefen
ip netns exec left bash -lc '
  ls -l /run/left.charon.pid /run/left.charon.vici || true
  ss -xpl | grep left\.charon\.vici || echo "WARN: VICI not listening"
'
echo "[*] setup_left done."
