#!/usr/bin/env bash
set -euo pipefail
exec dropbear -E -F -p 22 \
  -r /etc/dropbear/dropbear_rsa_host_key \
  -r /etc/dropbear/dropbear_ecdsa_host_key \
  -r /etc/dropbear/dropbear_ed25519_host_key \
  -w
