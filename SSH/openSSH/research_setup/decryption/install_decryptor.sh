#!/usr/bin/env bash
set -euo pipefail
PREFIX="$HOME/.local/share/ssh-decryptor"
mkdir -p "$PREFIX"
cp ssh_decryptor.py read_llbd_keylog.py "$PREFIX/"
chmod +x "$PREFIX"/*.py
echo "Installing python deps (scapy, pycryptodome) into user environment..."
python3 -m pip install --user scapy pycryptodome
echo "Installed into $PREFIX"
echo "Optionally copy wireshark_helper.lua into ~/.local/lib/wireshark/plugins/"
