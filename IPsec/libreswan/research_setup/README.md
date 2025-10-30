# Libreswan Research Setup

Manual step-by-step scripts for IPsec experimentation with libreswan/pluto.

These scripts provide fine-grained control over the IPsec lifecycle for research and debugging purposes.

## Quick Start

### 1. Setup Network and Pluto Instances

```bash
# Create network namespaces (left/right) with veth pair
sudo ./net_setup.sh

# Start pluto in left namespace (initiator)
sudo ./setup_left.sh

# Start pluto in right namespace (responder)
sudo ./setup_right.sh
```

### 2. Establish IPsec Connection

```bash
# Initiate from left (includes packet capture)
sudo ./load_left_and_initiate.sh
```

### 3. Check Status

```bash
# Show IPsec status and XFRM state for both sides
sudo ./status_both.sh
```

### 4. Trigger Operations

```bash
# Rekey from left side
sudo ./ipsec-rekey.sh left

# Or from right side
sudo ./ipsec-rekey.sh right

# Terminate connection
sudo ./ipsec-terminate.sh left
```

### 5. Cleanup

```bash
# Stop pluto processes and remove namespaces
sudo ./clear.sh --nuke
```

---

## Script Reference

### Network Setup

**`net_setup.sh`** (symlink to strongswan)
- Creates `left` and `right` network namespaces
- Creates veth pair: `veth-left` ↔ `veth-right`
- Assigns IPs: `10.0.0.1/24` (left), `10.0.0.2/24` (right)
- Brings up interfaces
- Tests connectivity with ping

**Output:**
```
[*] ping sanity
OK
```

---

### Pluto Setup

**`setup_left.sh`**
- Creates `/etc/ipsec-left/` config directory
- Generates `ipsec.conf` for left (initiator role)
- Generates `ipsec.secrets` with PSK
- Starts pluto in left namespace
- Logs to `/tmp/pluto-left.log`

**Config:**
```
conn net
    left=10.0.0.1
    right=10.0.0.2
    leftid=@left
    rightid=@right
    authby=secret
    auto=add
    ike=aes128-sha2_256-modp2048
    phase2alg=aes128-sha2_256
```

**`setup_right.sh`**
- Creates `/etc/ipsec-right/` config directory
- Generates `ipsec.conf` for right (responder role)
- Generates `ipsec.secrets` with PSK
- Starts pluto in right namespace
- Logs to `/tmp/pluto-right.log`

**Verify:**
```bash
# Check if pluto is running
sudo ip netns exec left pgrep -fa pluto
sudo ip netns exec right pgrep -fa pluto
```

---

### Connection Management

**`load_left_and_initiate.sh`**
- Starts tcpdump packet capture in left namespace
- Captures IKEv2 (UDP 500/4500) and ESP (proto 50) traffic
- Uses `ipsec auto --up net` to initiate connection
- Saves capture to `./dump/left-ike-<timestamp>.pcap`

**Output:**
```
[*] Starting capture in netns 'left' -> ./dump/left-ike-20251013-184500.pcap
[*] Initiating IPsec connection...
[*] Left: initiated IPsec connection 'net'
[*] Capture saved to ./dump/left-ike-20251013-184500.pcap
```

---

### Operations

**`ipsec-rekey.sh <left|right> [connection_name]`**
- Triggers IKE SA or Child SA rekey
- Uses `ipsec whack --rekey-ike` or `--rekey-ipsec`
- Auto-detects which type of rekey is needed

**Usage:**
```bash
# Rekey from left side
sudo ./ipsec-rekey.sh left

# Rekey from right side
sudo ./ipsec-rekey.sh right

# Rekey specific connection
sudo ./ipsec-rekey.sh left myconn
```

**`ipsec-terminate.sh <left|right> [connection_name]`**
- Terminates IPsec connection
- Uses `ipsec auto --down`
- Tears down both IKE SA and Child SA

**Usage:**
```bash
# Terminate from left side
sudo ./ipsec-terminate.sh left

# Terminate from right side
sudo ./ipsec-terminate.sh right
```

---

### Status and Debugging

**`status_both.sh`**
- Shows IPsec status for both left and right
- Displays XFRM state (kernel SA database)
- Displays XFRM policy (kernel SP database)

**Output:**
```
============================================
[LEFT] IPsec Status:
============================================
000 #1: "net":500 STATE_V2_ESTABLISHED_IKE_SA (authenticated); EVENT_SA_REKEY in 86400s...
000 #2: "net":500 STATE_V2_ESTABLISHED_CHILD_SA (IPsec SA established); EVENT_SA_REKEY in 3600s...

============================================
[LEFT] XFRM State:
============================================
src 10.0.0.1 dst 10.0.0.2
    proto esp spi 0xc12b5678 reqid 16385 mode tunnel
    replay-window 32 flag af-unspec
    auth-trunc hmac(sha256) 0x... 128
    enc cbc(aes) 0x...
...
```

---

### Cleanup

**`clear.sh [--nuke]`**
- Kills pluto processes in both namespaces
- Stops system-wide libreswan service
- With `--nuke`: removes namespaces, veth, and configs

**Usage:**
```bash
# Stop pluto only
sudo ./clear.sh

# Full cleanup (remove everything)
sudo ./clear.sh --nuke
```

---

### Packet Capture

**`capture_ike.sh`** (symlink to strongswan)
- Can be used independently for custom captures
- Captures IKEv2 and ESP traffic
- See strongswan documentation for details

---

## Libreswan vs strongswan Command Reference

| Operation | Libreswan | strongswan |
|-----------|-----------|------------|
| Start daemon | `ipsec pluto --config <file>` | `charon` |
| Add connection | `ipsec auto --add <conn>` | `swanctl --load-conns` |
| Initiate | `ipsec auto --up <conn>` | `swanctl --initiate` |
| Status | `ipsec status` | `swanctl --list-sas` |
| Rekey IKE | `ipsec whack --rekey-ike --name <conn>` | `swanctl --rekey --ike <id>` |
| Rekey Child | `ipsec whack --rekey-ipsec --name <conn>` | `swanctl --rekey --child <id>` |
| Terminate | `ipsec auto --down <conn>` | `swanctl --terminate --ike <id>` |
| Show logs | `cat /tmp/pluto-left.log` | `cat /var/log/strongswan/charon_left` |

---

## Troubleshooting

**Pluto won't start:**
```bash
# Check if binary exists
ls -la /usr/local/libexec/ipsec/pluto
# Or
ls -la /usr/libexec/ipsec/pluto

# Check logs
tail -f /tmp/pluto-left.log
tail -f /tmp/pluto-right.log

# Ensure no system-wide pluto is running
sudo systemctl stop ipsec
sudo pkill -9 pluto
```

**Connection won't establish:**
```bash
# Check pluto is running
sudo ip netns exec left ipsec status

# Check network connectivity
sudo ip netns exec left ping 10.0.0.2

# Check IKE messages in logs
grep "initiating" /tmp/pluto-left.log
grep "STATE_" /tmp/pluto-right.log

# Check for errors
grep -i error /tmp/pluto-left.log
grep -i error /tmp/pluto-right.log
```

**Rekey fails:**
```bash
# Ensure connection is established first
sudo ./status_both.sh

# Check connection name is correct
# Default is "net" but may differ in your config

# Try from opposite side
sudo ./ipsec-rekey.sh right
```

**Namespace issues:**
```bash
# List existing namespaces
ip netns list

# If stale namespaces exist, remove them
sudo ip netns del left
sudo ip netns del right

# Then run net_setup.sh again
sudo ./net_setup.sh
```

**Can't cleanup:**
```bash
# Force cleanup
sudo pkill -9 pluto
sudo ip netns del left
sudo ip netns del right
sudo rm -rf /etc/ipsec-left /etc/ipsec-right
sudo rm -f /tmp/pluto-*.log
```

---

## Advanced Usage

### Custom Encryption Algorithms

Edit `setup_left.sh` and `setup_right.sh`, modify the `ike=` and `phase2alg=` lines:

```bash
# Example: AES-256 with SHA-512
ike=aes256-sha2_512-modp2048
phase2alg=aes256-sha2_512
```

### Debug Logging

Pluto is already configured with `plutodebug=all`. Check logs:

```bash
# Follow logs in real-time
tail -f /tmp/pluto-left.log

# Search for specific events
grep "ikev2 parent outI1" /tmp/pluto-left.log
grep "ikev2 child" /tmp/pluto-left.log
grep "rekeyed" /tmp/pluto-left.log
```

### Manual Rekey Testing

```bash
# Establish connection
sudo ./load_left_and_initiate.sh

# Wait and observe natural rekey (if configured)
# Or force immediate rekey
sudo ip netns exec left bash -c '
  export IPSEC_CONFS=/etc/ipsec-left
  ipsec whack --rekey-ike --name net
'
```

### Wireshark Analysis

```bash
# Capture during experiment
sudo ./load_left_and_initiate.sh

# Open capture in Wireshark
wireshark ./dump/left-ike-*.pcap

# Filter for IKE: udp.port == 500 or udp.port == 4500
# Filter for ESP: ip.proto == 50
```

---

## Integration with Automated Experiment

These manual scripts are the foundation for the automated experiment framework:

```
research_setup/           <-- You are here (manual control)
    ↓
../experiment/            <-- Automated orchestration
    run_ipsec_experiment.sh
    monitoring_ipsec.py (LLDB - TODO)
    monitor_kernel_xfrm.py (kernel monitoring)
```

The automated framework calls similar operations but adds:
- LLDB userspace monitoring 
- Kernel XFRM scanning (via drgn)
- Hardware watchpoints 
- Automated workflows
- Structured output

---

## Related Documentation

- **Libreswan Official Docs**: https://libreswan.org/
- **Libreswan GitHub**: https://github.com/libreswan/libreswan
