#!/usr/bin/env bash
set -euo pipefail
echo "[LEFT] SAs:"
ip netns exec left  /usr/sbin/swanctl --list-sas --uri  unix:///run/left.charon.vici || true
echo
echo "[RIGHT] SAs:"
ip netns exec right /usr/sbin/swanctl --list-sas --uri unix:///run/right.charon.vici || true
echo
echo "[LEFT] XFRM:"
ip netns exec left  bash -lc 'ip xfrm state; echo; ip xfrm policy' || true
echo
echo "[RIGHT] XFRM:"
ip netns exec right bash -lc 'ip xfrm state; echo; ip xfrm policy' || true
