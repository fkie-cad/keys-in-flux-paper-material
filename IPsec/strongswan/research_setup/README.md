# IPSec (strongSwan + netns) — Quick Guide

This repository provides a compact, reproducible lab to run two isolated strongSwan endpoints (`left` and `right`) inside Linux network namespaces, create an IKEv2+ESP tunnel between them, capture ESP traffic, and export keys for Wireshark decryption.

> Tested on Ubuntu 24.04 (ARM64) with strongSwan 5.9.x. Adjust paths/commands if your distro differs.

---

## What’s included

- `clear.sh` — stop/cleanup script (optional `--nuke` to remove namespaces, veth, config and pcaps)
- `net_setup.sh` — create `left` / `right` netns and veth pair (`veth-left`/`veth-right`)
- `setup_left.sh` — create minimal left configs, set AppArmor to complain, start left `charon`
- `setup_right.sh` — same for right
- `load_right.sh` — `swanctl --load-all` for right (connects to right VICI)
- `load_left_and_initiate.sh` — `swanctl --load-all` for left and initiate IKE from left
- `status_both.sh` — show `swanctl --list-sas` and `ip xfrm` for both sides
- `capture_left.sh` — generate ping traffic and capture ESP on left interface
- `export_keys_both.sh` — export key material to `/tmp/*_keys.txt` for Wireshark

---
## Quick run order
Before starting ensure that the following is executed once:
```
sudo systemctl disable --now strongswan-starter || true
sudo aa-complain /usr/lib/ipsec/charon 
sudo aa-complain /etc/apparmor.d/usr.bin.tcpdump
```
Run these commands in the following sequence:

```bash
sudo ./clear.sh --nuke
sudo ./net_setup.sh
sudo ./setup_left_debug_fg.sh
sudo ./setup_right_debug_fg.s
# in another terminal session
sudo ../research_experiment/./run_lldb_on_charon_processes.sh 
# choose there the one with the pid from the left
# now go back to the first terminal
sudo ./load_right.sh
# now our hooks are installed and we can beginn with the capture
sudo ./capture_ike2.sh left handshake 
# optional the kernel dump
sudo ../research_experiment/./scan_kernel_for_xfrm_keys.py
# altohugh the keys CHILD_SA keys already avaiable we can make a ESP protected conntection after that
 sudo ./capture_ipsec_http.sh
````

## Quick run order old way (not suggested)

Before starting ensure that the following is executed once:
```
sudo systemctl disable --now strongswan-starter || true
```

Run these commands in the following sequence:

```bash
sudo ./clear.sh                  # stop/cleanup / ensure clean start
sudo ./net_setup.sh              # create namespaces + veth pair
sudo ./setup_left.sh             # prepare & start left charon
sudo ./setup_right.sh            # prepare & start right charon
sudo ./load_right.sh             # load config on right (swanctl -> right VICI)
sudo ./load_left_and_initiate.sh # load left and initiate IKE from left
sudo ./status_both.sh            # check SAs and kernel XFRM state
# optional captures & export:
sudo ./capture_left.sh
sudo ./export_keys_both.sh
```

---

## Detailed manual steps (if you prefer to run commands yourself)

### 1. Create network namespaces + veth
```bash
sudo ip netns add left
sudo ip netns add right
sudo ip link add veth-left type veth peer name veth-right
sudo ip link set veth-left netns left
sudo ip link set veth-right netns right
sudo ip -n left addr add 10.0.0.1/24 dev veth-left
sudo ip -n right addr add 10.0.0.2/24 dev veth-right
sudo ip -n left link set lo up; sudo ip -n right link set lo up
sudo ip -n left link set veth-left up; sudo ip -n right link set veth-right up
```

### 2. Per-namespace strongSwan `strongswan.conf` override
Create `/etc/strongswan-left/strongswan.conf` with:
```
charon.plugins.vici.socket = unix:///run/left.charon.vici
```
Create `/etc/strongswan-right/strongswan.conf` with:
```
charon.plugins.vici.socket = unix:///run/right.charon.vici
```

These override lines keep all system default configs (from `/etc/strongswan.d/`) and only change which VICI socket charon listens on.

### 3. swanctl configs
Put the provided `swanctl.conf` files in:
- `/etc/strongswan-left/swanctl/swanctl.conf`
- `/etc/strongswan-right/swanctl/swanctl.conf`

They contain a small PSK-based IKEv2 connection named `net` and a CHILD called `net`. PSK used in examples: `test123`.

### 4. AppArmor (important)
By default, AppArmor can block charon/swanctl from reading nonstandard files and sockets. For the lab you can set complain mode for both:

```bash
sudo apt-get install -y apparmor-utils
sudo aa-complain /usr/lib/ipsec/charon
sudo aa-complain /usr/sbin/swanctl
```

If you need to keep enforcing mode, add explicit allow rules to the AppArmor profiles:
- `/etc/apparmor.d/usr.lib.ipsec.charon` — allow `/etc/strongswan-left/**`, `/etc/strongswan-right/**`, and `/run/*charon*.vici` etc.
- `/etc/apparmor.d/usr.sbin.swanctl` — allow access to those sockets.

(Use `apparmor_parser -r` to reload or `systemctl reload apparmor`.)

### 5. Start charon per namespace (example)
Start left charon (uses custom config):

```bash
sudo ip netns exec left bash -lc '
  export STRONGSWAN_CONF=/etc/strongswan-left/strongswan.conf
  /usr/lib/ipsec/charon --pidfile /run/left.charon.pid --nofork \
    --debug-lib 1 --debug-ike 1 --debug-knl 1 --debug-net 1 \
    </dev/null >/dev/null 2>&1 & disown
'
```

Do the same for `right` with its config and `/run/right.charon.pid`.

Confirm the socket is listening:
```bash
sudo ip netns exec left ss -xpl | grep left.charon.vici
sudo ip netns exec right ss -xpl | grep right.charon.vici
```

### 6. Load configs and initiate
Load right:
```bash
sudo ip netns exec right /usr/sbin/swanctl --load-all \
  --file /etc/strongswan-right/swanctl/swanctl.conf \
  --uri unix:///run/right.charon.vici
```

Load left and initiate (initiate from left -> right):
```bash
sudo ip netns exec left /usr/sbin/swanctl --load-all \
  --file /etc/strongswan-left/swanctl/swanctl.conf \
  --uri unix:///run/left.charon.vici

sudo ip netns exec left /usr/sbin/swanctl --initiate --ike net --child net \
  --uri unix:///run/left.charon.vici
```

Verify:
```bash
sudo ip netns exec left  /usr/sbin/swanctl --list-sas --uri unix:///run/left.charon.vici
sudo ip netns exec right /usr/sbin/swanctl --list-sas --uri unix:///run/right.charon.vici
```

---

## Capture ESP traffic and export keys for Wireshark

1. Start an ESP capture on left:
```bash
sudo ip netns exec left tcpdump -i veth-left -s0 -w /tmp/esp_left.pcap &
sleep 1
sudo ip netns exec left ping -c5 10.0.0.2
sleep 1
sudo pkill -f "tcpdump -i veth-left" || true
```

2. Export keys (for Wireshark ESP decryption):
```bash
sudo ip netns exec left  /usr/sbin/swanctl --export --ike net --uri unix:///run/left.charon.vici  > /tmp/left_keys.txt
sudo ip netns exec right /usr/sbin/swanctl --export --ike net --uri unix:///run/right.charon.vici > /tmp/right_keys.txt
```

3. In Wireshark:
- Open `/tmp/esp_left.pcap`
- Preferences → Protocols → ESP → Edit...
- Add entries using SPI and keys from `/tmp/left_keys.txt` (look for `spi_in`, `spi_out`, `enc_key`, `integ_key`, algorithm names).
- Re-open / re-decode to see decrypted payloads (ICMP, etc).

---

## Inspect kernel XFRM state (alternate view)
You can view SPIs and some parameters installed into the kernel XFRM subsystem:

```bash
sudo ip netns exec left ip xfrm state
sudo ip netns exec left ip xfrm policy
```

Keys are present in the `xfrm state` output (depending on kernel visibility and your distribution).

---

## Hooking ideas (next steps)

- **Export + compare**: use `swanctl --export` as ground truth; compare with `ip xfrm state`.
- **User-space hooks**: instrument `charon` using uprobe/`LD_PRELOAD` or Frida to intercept SA installation (where charon calls kernel netlink to create XFRM state).
- **Kernel hooks**: use Netlink monitoring (NETLINK_XFRM) or eBPF to intercept XFRM state add/delete events and log SPI + algos.
  - eBPF uprobes / tracepoints can observe charon functions or kernel xfrm tracepoints.
- If you want, I can provide a small eBPF/netlink example that logs new XFRM states as they are installed.

---

## Troubleshooting & tips

- If you see `Connection refused`: no process is listening on the VICI socket — ensure charon is running in that namespace and that the socket file was created by that process.
- If you see `Permission denied`: check AppArmor (`dmesg | grep apparmor`) — either set `aa-complain` or add explicit allow rules to the charon / swanctl profiles.
- If `charon` refuses to start with `invalid configuration` — there's often a syntax/format issue in the override file. Use the full system config as reference or use the single-line key/value form: `charon.plugins.vici.socket = unix:///run/left.charon.vici`.
- Avoid `strongswan-starter` (the `ipsec` wrapper) for this lab — it can start `charon` with different defaults and interfere. Disable it with:
  ```bash
  sudo systemctl disable --now strongswan-starter
  ```

---

## Cleanup

- Quick cleanup:
```bash
sudo ./clear.sh
```

- Full nuking (also removes netns, veth, config/pcap files):
```bash
sudo ./clear.sh --nuke
```

## Genreal Notes

- XFRM: https://codebrowser.dev/linux/linux/include/net/xfrm.h.html
- StrongSwan https://github.com/strongswan/strongswan
- IKEv2 Key Derivation Modularization: https://strongswan.org/blog/2022/04/29/strongswan-5.9.6-released.html
- https://docs.strongswan.org/docs/latest/plugins/plugins.html --> KDF --> IKEv2 key derivation wrapper using various PRFs (read also https://docs.strongswan.org/docs/latest/config/proposals.html)
- KDF Definition: https://github.com/strongswan/strongswan/blob/ac0272cad12f0b3dbe5432111d034fa7b6192f82/src/libstrongswan/crypto/kdfs/kdf.h#L26
- see also as description: https://www.strongswan.org/blog/2018/05/28/strongswan-vulnerability-(cve-2018-10811).html
