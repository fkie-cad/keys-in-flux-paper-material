#!/usr/bin/env bash
set -euo pipefail
ip netns exec left  /usr/sbin/swanctl --export --ike net --uri unix:///run/left.charon.vici  > /tmp/left_keys.txt
ip netns exec right /usr/sbin/swanctl --export --ike net --uri unix:///run/right.charon.vici > /tmp/right_keys.txt
echo "[*] keys exported:"
ls -l /tmp/left_keys.txt /tmp/right_keys.txt
echo
echo "Open /tmp/left_keys.txt in an editor and configure Wireshark (Preferences → Protocols → ESP → Edit…) with SPI/Keys."