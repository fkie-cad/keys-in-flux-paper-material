#!/usr/bin/env bash
set -euo pipefail

# Simple entrypoint: create host keys if needed, create a test user, start sshd in foreground.

SSH_PREFIX=/opt/openssh-debug
SSHD=${SSH_PREFIX}/sbin/sshd
SSHD_CONF=/etc/ssh/sshd_config
KEYDIR=/etc/ssh
KEYS=(ssh_host_rsa_key ssh_host_ecdsa_key ssh_host_ed25519_key)

# generate host keys if absent
for k in "${KEYS[@]}"; do
  if [ ! -f "${KEYDIR}/${k}" ]; then
    echo "[+] generating host key ${k}"
    ${SSH_PREFIX}/bin/ssh-keygen -q -N "" -t ${k##*_} -f "${KEYDIR}/${k}"
  fi
done

# create a user 'testuser' with password 'test' for quick login
if ! id testuser >/dev/null 2>&1; then
  useradd -m -s /bin/bash testuser || true
  echo "testuser:test" | chpasswd
fi

# ensure /tmp/ssh-keys exists for saved keylog output
mkdir -p /tmp/ssh-keys
chmod 1777 /tmp/ssh-keys

echo "[+] starting sshd (debug build) on port 2222 ..."
exec ${SSHD} -D -e -f "${SSHD_CONF}"