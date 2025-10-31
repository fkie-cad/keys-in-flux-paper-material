#!/usr/bin/env bash
set -euo pipefail

# -- CONFIG (edit if you want) --
DDEBS_LIST="/etc/apt/sources.list.d/ddebs.list"
UBUNTU_CODENAME="$(lsb_release -cs)"   # should be 'noble' on Ubuntu 24.04
# -------------------------------

echo "[*] Preparing system (update + install prerequisites)..."
apt update
apt install -y --no-install-recommends \
  ca-certificates curl gnupg lsb-release apt-transport-https \
  software-properties-common build-essential

# 1) Enable ddebs (debug-symbol) repository for Noble
if [ ! -f "${DDEBS_LIST}" ]; then
  echo "[*] Adding ddebs (debug symbol) repository for ${UBUNTU_CODENAME}..."
  cat > ${DDEBS_LIST} <<EOF
deb http://ddebs.ubuntu.com/ ${UBUNTU_CODENAME} main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${UBUNTU_CODENAME}-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${UBUNTU_CODENAME}-security main restricted universe multiverse
EOF
fi

# Install the debug symbol keyring (makes apt trust ddebs)
echo "[*] Installing ubuntu-dbgsym-keyring..."
apt update
apt install -y ubuntu-dbgsym-keyring || {
  echo "[!] ubuntu-dbgsym-keyring install failed — continuing (you may need to enable ddebs manually)"
}

apt update

# 2) Install OpenSSH and OpenSSL + attempt to pull dbgsym packages
echo "[*] Installing OpenSSH and OpenSSL (and trying to install -dbgsym packages)..."
apt install -y --no-install-recommends openssh-server openssh-client openssl libssl-dev

# Try installing debug symbol packages if they exist
DBGSYM_PKGS=(
  "openssh-server-dbgsym"
  "openssh-client-dbgsym"
  "openssh-sftp-server-dbgsym"
  "openssl-dbgsym"        # may exist as openssl-dbgsym
  "libssl3-dbgsym"        # sometimes libssl3-dbgsym / libssl3t64-dbgsym
)

for pkg in "${DBGSYM_PKGS[@]}"; do
  if apt-cache show "$pkg" >/dev/null 2>&1; then
    echo "[*] Installing debug symbols: $pkg"
    apt install -y "$pkg" || echo "[!] apt install $pkg failed; check availability"
  else
    echo "[ ] Debug symbol package not found in apt: $pkg (skipping)"
  fi
done

# 3) Install tooling for live analysis and memory dumping
echo "[*] Installing analysis tools (gdb, binutils, elfutils, valgrind, strace, ltrace, tcpdump, etc.)..."
apt install -y --no-install-recommends \
  gdb binutils elfutils valgrind strace ltrace \
  procps lsof psmisc gettext vim less \
  tcpdump tshark # wireshark-cli may require interactive config



# 5) Python tooling: pyelftools, frida-tools, frida
echo "[*] Installing Python analysis tooling (frida-tools, pyelftools, capstone)..."
pip3 install --upgrade pip setuptools wheel
pip3 install pyelftools capstone
pip3 install frida frida-tools

# 6) Helpful extras: gcore comes from gdb, install coreutils (already present)
echo "[*] Installing helpful packages: openssh-client (already), sshpass (optional), net-tools ..."
apt install -y sshpass net-tools

echo "[*] Done. Summary of installed key packages:"
echo "  - openssh-server, openssh-client, openssl, libssl-dev"
echo "  - debug-symbol repository enabled at ${DDEBS_LIST} (if available)"
echo "  - gdb, binutils, elfutils, valgrind, strace, ltrace, tcpdump, tshark"
echo
echo "[*] Useful verification commands:"
echo "  - apt policy openssh-server && sshd -v"
echo "  - apt list --installed | grep dbgsym"
echo
echo "[*] Example: check if openssh-server-dbgsym installed:"
dpkg -l | grep openssh || true
dpkg -l | grep dbgsym || true

exit 0
