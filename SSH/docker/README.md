# SSH Key Lifecycle Experiment Framework - Complete Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Prerequisites](#prerequisites)
3. [Building Containers](#building-containers)
4. [Running Automated Experiments](#running-automated-experiments)
5. [Interactive Debugging Sessions](#interactive-debugging-sessions)
6. [Environment Variables Reference](#environment-variables-reference)
7. [Output Files & Structure](#output-files--structure)
8. [Analysis & Correlation](#analysis--correlation)
9. [Wireshark Decryption](#wireshark-decryption)
10. [Troubleshooting](#troubleshooting)
11. [Quick Reference Tables](#quick-reference-tables)

---

## Introduction

This framework provides automated and interactive SSH key lifecycle analysis for three SSH implementations:

- **OpenSSH** (client + server)
- **Dropbear** (client + server)
- **wolfSSH** (client + server)

The framework uses LLDB-based dynamic instrumentation to extract SSH session keys during key exchange (KEX), track key lifecycle with hardware watchpoints, and correlate with packet captures for traffic decryption.

**Key Features:**
- Automated lifecycle experiments (base + key update modes)
- Interactive LLDB debugging with manual inspection
- Hardware watchpoint tracking for key overwrites
- Memory dump analysis at lifecycle checkpoints
- Wireshark-compatible keylog output
- Packet capture correlation

---

## Prerequisites

### System Requirements

- **OS**: Ubuntu 24.04 x86-64, Ubuntu 24.04 ARM64, or macOS M1/M2 (ARM64)
- **Docker**: Docker Engine 20.10+ with Docker Compose
- **Disk Space**: ~5GB for all containers
- **Memory**: 4GB+ RAM recommended

### Software Dependencies

```bash
# Ubuntu
sudo apt-get update
sudo apt-get install -y docker.io docker-compose python3 python3-pip

# macOS (with Homebrew)
brew install docker docker-compose python3
```

### Permissions

Ensure Docker runs without sudo or add your user to the docker group:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

Create shared data directories with proper permissions:

```bash
cd /path/to/keylifespan/ssh/docker
mkdir -p data/keylogs data/dumps data/captures data/lldb_results
chmod -R 777 data/
```

---

## Building Containers

### Build All Containers (Recommended)

This builds all SSH implementations and their dependencies:

```bash
cd /path/to/keylifespan/ssh/docker
docker compose build
```

**Build time**: ~10-15 minutes (first run)

### Build Individual Containers

If you only need specific implementations:

```bash
# OpenSSH (client + server + ground-truth)
docker compose build openssh_client openssh_server openssh_groundtruth

# Dropbear (client + server)
docker compose build dropbear_client dropbear_server

# wolfSSH (client + server)
docker compose build wolfssh_client wolfssh_server
```

### Verify Build Success

```bash
docker compose images

# Expected output:
# REPOSITORY                    TAG       IMAGE ID       SIZE
# docker-openssh_groundtruth    latest    abc123...      250MB
# docker-openssh_client         latest    def456...      280MB
# docker-dropbear_client        latest    ghi789...      200MB
# docker-wolfssh_client         latest    jkl012...      220MB
# ...
```

### Platform-Specific Notes

**macOS M1/M2 (ARM64):**
- Uses `Dockerfile.m1-nogpg` for OpenSSH ground-truth
- Automatically detected by Docker Compose
- GPG signature verification disabled (faster builds)

**Ubuntu ARM64:**
- Fully supported with same Dockerfiles as x86-64
- LLDB >=18 provides ARM64 watchpoint support

---

## Running Automated Experiments

### Overview

Automated experiments run complete key lifecycle tests with minimal user interaction:

1. Start ground-truth server
2. Launch client with LLDB instrumentation
3. Perform KEX and extract keys
4. Optionally trigger rekey (key update mode)
5. Close session and dump memory
6. Capture packet traces
7. Generate timing CSVs and keylogs

### Run All Experiments (Recommended)

Execute the full test suite for all implementations:

```bash
./run_all_ssh_lifecycle_experiments.sh all
```

**Parameters:**
- `all` - Run OpenSSH, Dropbear, and wolfSSH (base + KU modes)
- `openssh` - Run only OpenSSH experiments
- `dropbear` - Run only Dropbear experiments
- `wolfssh` - Run only wolfSSH experiments

**Duration**: ~5-10 minutes for full suite

**Output**: Creates timestamped directory `results/ssh_lifecycle_YYYYMMDD_HHMMSS/`

### Individual Test Scripts

#### OpenSSH Client Lifecycle

**Base Mode (No Rekey):**

```bash
./test_openssh_lifecycle.sh
```

- Performs single KEX
- Extracts 6 keys (A-F: IVs, encryption, MACs)
- Tracks key lifecycle with watchpoints
- Outputs: `data/keylogs/openssh_client_keylog.log`

**Key Update Mode (With Rekey):**

```bash
./test_openssh_lifecycle_ku.sh
```

- Performs initial KEX
- Sends traffic
- Triggers rekey via Expect `~R` command
- Performs second KEX
- Tracks lifecycle of both key sets
- Outputs: `data/keylogs/openssh_client_keylog.log`, `data/lldb_results/timing_openssh.csv`

**Parameters:**
- Environment variables (see [Environment Variables Reference](#environment-variables-reference))
- No command-line parameters

**LLDB Hook Points:**
- `derive_key()` - Stable function called once per key (A-F)
- Watchpoints on keys C and D (encryption keys)

---

#### Dropbear Client Lifecycle

**Base Mode:**

```bash
./test_dropbear_lifecycle.sh
```

- Performs single KEX
- Extracts 6 keys from `gen_new_keys()` at exit breakpoint
- Tracks key lifecycle (watchpoints may be disabled if unstable)
- Outputs: `data/keylogs/dropbear_client_keylog.log`

**Key Update Mode:**

```bash
./test_dropbear_lifecycle_ku.sh
```

- Performs initial KEX
- May trigger automatic rekey after large data transfer
- **Note**: Forced rekey may be skipped due to Dropbear client limitations
- Outputs: `data/keylogs/dropbear_client_keylog.log`

**Parameters:**
- Environment variables (see [Environment Variables Reference](#environment-variables-reference))
- No command-line parameters

**LLDB Hook Points:**
- `gen_new_keys()` exit - Extract all 6 keys at once
- Watchpoints on keys C and D (if enabled)

**Known Limitations:**
- Forced rekey via expect may not work reliably
- Automatic rekey occurs after ~1GB data transfer
- Watchpoints may be disabled by default due to ARM64 fork issues

---

#### wolfSSH Client Lifecycle

**Base Mode:**

```bash
./test_wolfssh_lifecycle.sh
```

- Performs single KEX
- Extracts 4 keys (A-D: IVs and encryption for AEAD ciphers)
- Uses custom C client with programmatic API
- Outputs: `data/keylogs/wolfssh_client_keylog.log`

**Key Update Mode:**

```bash
./test_wolfssh_lifecycle_ku.sh
```

- Performs initial KEX
- Triggers rekey via wolfSSH API (`wolfSSH_SendRekeyRequest()`)
- Performs second KEX
- Tracks lifecycle of both key sets
- Outputs: `data/keylogs/wolfssh_client_keylog.log`, `data/lldb_results/timing_wolfssh.csv`

**Parameters:**
- Environment variables (see [Environment Variables Reference](#environment-variables-reference))
- No command-line parameters

**LLDB Hook Points:**
- `wolfSSH_KDF()` - Called once per key during KEX
- Watchpoints on keys C and D

**Custom Client:**
- Source: `wolfssh-client/wolfssh_client_rekey.c`
- Features: `--with-rekey`, `--keep-alive`, `--keep-alive-seconds <N>`

---

### Script Behavior

All test scripts follow this pattern:

1. **Cleanup**: Stop any running containers
2. **Start Ground-Truth Server**: `docker compose up -d openssh_groundtruth`
3. **Wait for Server**: Poll port 2226 until ready
4. **Run Client with LLDB**: Execute callbacks and extract keys
5. **Capture Output**: Save to timestamped result directory
6. **Generate Reports**: Create timing CSVs and consolidated keylogs
7. **Cleanup Containers**: Stop and remove client container

**Exit Codes:**
- `0` - Success
- `1` - Server startup failure
- `2` - Client execution failure
- `124` - Timeout (>2 minutes with LLDB hang detection)

---

## Interactive Debugging Sessions

Interactive debugging allows manual inspection of KEX, memory, and key lifecycle with full LLDB control.

### Overview

Interactive sessions drop you into an LLDB prompt where you can:
- Set custom breakpoints
- Inspect memory at arbitrary addresses
- Search for keys with `findkey` command
- Manually trigger memory dumps
- Step through code execution
- Enable/disable watchpoints dynamically

### OpenSSH Interactive Debugging

**Script:**

```bash
./debug_openssh_interactive.sh [OPTIONS]
```

**Options:**
- `--with-rekey` - Prepare environment for rekey testing
- `--keep-alive` - Keep client alive after session close (default: 10s)
- `--keep-alive-seconds <N>` - Set keep-alive duration
- `-h, --help` - Show help message

**Example Usage:**

```bash
# Basic KEX debugging
./debug_openssh_interactive.sh

# With rekey support
./debug_openssh_interactive.sh --with-rekey

# Keep alive for 30 seconds after close
./debug_openssh_interactive.sh --keep-alive-seconds 30
```

**LLDB Commands Available:**

Once in LLDB prompt:

```lldb
# Launch client (already configured)
(lldb) process launch

# Setup monitoring (breakpoints + callbacks)
(lldb) client_setup_monitoring

# Auto-continue mode (stops at KEX)
(lldb) client_auto_continue

# Step through code
(lldb) step          # Step into
(lldb) next          # Step over
(lldb) finish        # Step out
(lldb) continue      # Resume

# Inspect state
(lldb) frame variable                    # Local variables
(lldb) bt                                # Backtrace
(lldb) memory read -c 64 0x7fff12345678  # Read memory
(lldb) x/32bx 0x7fff12345678            # Examine bytes

# Search for keys
(lldb) findkey 1a2b3c4d5e6f...          # Search key in memory
(lldb) findkey --full <hex>             # Search all regions
(lldb) findkey --verbose <hex>          # Debug output

# Manual dumps
(lldb) d                                 # Quick dump
(lldb) dump post_kex                     # Named checkpoint

# Watchpoint control
(lldb) watchpoints_status                # Show state
(lldb) watchpoints_toggle                # Enable/disable
(lldb) watchpoints_list                  # Detailed list

# Exit
(lldb) quit
```

**Connection:**

From another terminal, connect to ground-truth server:

```bash
# OpenSSH client (from host)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2226 testuser@localhost
# Password: password
```

**Hook Points:**
- `derive_key()` entry and exit
- LLDB follows main process (no fork tracking needed for client)

---

### Dropbear Interactive Debugging

#### Server-Side Debugging

**Script:**

```bash
./debug_dropbear_server_interactive.sh [OPTIONS]
```

**Options:**
- `--with-rekey`, `--rekey` - Enable rekey testing (client triggers)
- `--no-auto-disable`, `--keep-breakpoints` - Keep breakpoints active after KEX
- `--auto-disable` - Auto-disable breakpoints after KEX (default)
- `-h, --help` - Show help message

**Example Usage:**

```bash
# Base debugging (auto-disable ON)
./debug_dropbear_server_interactive.sh

# Keep breakpoints for post-KEX debugging
./debug_dropbear_server_interactive.sh --no-auto-disable

# With rekey support
./debug_dropbear_server_interactive.sh --with-rekey
```

**Breakpoint Auto-Disable Behavior:**

- **Default (--auto-disable)**: Breakpoints disabled after KEX extraction
  - ✓ Allows normal interactive session (fork #2 proceeds)
  - ✓ Recommended for interactive SSH connections

- **With --no-auto-disable**: Breakpoints remain active
  - ⚠ May interfere with fork #2 (session handler)
  - ✓ Useful for debugging additional events after KEX

**LLDB Commands Available:**

```lldb
# Launch server (already configured)
(lldb) process launch --stop-at-entry -- -F -E -p 22 \
       -r /etc/dropbear/dropbear_rsa_host_key

# Setup monitoring (fork tracking + KEX breakpoints)
(lldb) server_setup_monitoring

# Auto-continue mode (stops at KEX)
(lldb) server_auto_continue

# Examine dual extraction
(lldb) frame variable                    # At gen_new_keys()
(lldb) bt                                # Backtrace

# At hashkeys() - shows KDF parameters
(lldb) frame variable keybuf keylen letter
(lldb) memory read -c 32 <keybuf_addr>   # Read derived key

# Memory address reporting
# Keys logged with address automatically:
# [HASHKEYS_EXIT] Memory location: 0xfffffffff688 (64 bytes)

# Search for keys
(lldb) findkey d77f8b958dc1fec97a70368199e04cb3
(lldb) findkey --full <hex>              # Search all regions
(lldb) findkey --verbose <hex>           # Debug output

# Manual dumps
(lldb) d                                 # Quick dump
(lldb) dump post_kex                     # Named checkpoint

# Watchpoint control
(lldb) watchpoints_toggle                # Enable/disable
(lldb) watchpoints_status                # Show state

# Exit
(lldb) quit
```

**Connection:**

From another terminal:

```bash
# Dropbear client (from host)
docker compose run --rm dropbear_client \
    /usr/local/bin/dropbear_client_rekey localhost 2223 testuser password

# Or standard dbclient
dbclient -y -p 2223 testuser@localhost
```

**Hook Points:**
- `fork()` - Track fork count (LLDB follows fork #1 only)
- `gen_new_keys()` entry and exit - Primary extraction
- `hashkeys()` entry and exit - KDF validation (called 6x per KEX)

**Fork Behavior:**
- Fork #1: Connection handler (LLDB follows this)
- Fork #2: Session process (LLDB does NOT follow)

---

#### Client-Side Debugging

**Script:**

```bash
./debug_dropbear_client_interactive.sh [OPTIONS]
```

**Options:**
- `--with-rekey`, `--rekey` - Enable rekey testing
- `--no-auto-disable`, `--keep-breakpoints` - Keep breakpoints active
- `--auto-disable` - Auto-disable breakpoints (default)
- `-h, --help` - Show help message

**Example Usage:**

```bash
./debug_dropbear_client_interactive.sh
```

**LLDB Commands:** Same as server-side, but client doesn't fork

**Target Server:** Connects to `openssh_groundtruth` on port 2226

---

### wolfSSH Interactive Debugging

**Script:**

```bash
./debug_wolfssh_interactive.sh [OPTIONS]
```

**Options:**
- `--with-rekey` - Prepare environment for rekey testing
- `--keep-alive` - Keep client alive after session close
- `--keep-alive-seconds <N>` - Set keep-alive duration
- `-h, --help` - Show help message

**Example Usage:**

```bash
# Basic KEX debugging
./debug_wolfssh_interactive.sh

# With rekey support
./debug_wolfssh_interactive.sh --with-rekey --keep-alive-seconds 20
```

**LLDB Commands Available:**

```lldb
# Launch client
(lldb) process launch

# Setup monitoring
(lldb) client_setup_monitoring
(lldb) client_auto_continue

# Examine wolfSSH_KDF() calls
(lldb) frame variable                    # Local variables at breakpoint
(lldb) bt                                # Backtrace

# Search for keys
(lldb) findkey 1a2b3c4d...
(lldb) findkey --full --verbose <hex>

# Manual dumps and watchpoints
(lldb) d
(lldb) dump post_kex
(lldb) watchpoints_status

# Exit
(lldb) quit
```

**Connection:**

wolfSSH uses custom client with programmatic API, no separate connection needed.

**Hook Points:**
- `wolfSSH_KDF()` - Called once per key (A-D for AEAD)
- Watchpoints on keys C and D

---

### Common LLDB Commands

These commands work across all implementations:

| Command | Description |
|---------|-------------|
| `process launch` | Start process with arguments |
| `client_setup_monitoring` | Setup breakpoints + callbacks |
| `server_setup_monitoring` | Setup breakpoints + callbacks (server) |
| `client_auto_continue` | Auto-continue mode (stops at KEX) |
| `server_auto_continue` | Auto-continue mode (stops at KEX) |
| `findkey <hex>` | Search for key in memory |
| `findkey --full <hex>` | Search all memory regions |
| `findkey --verbose <hex>` | Search with debug output |
| `d` | Quick memory dump |
| `dump <label>` | Named checkpoint dump |
| `watchpoints_toggle` | Enable/disable all watchpoints |
| `watchpoints_status` | Show watchpoint state |
| `watchpoints_list` | Detailed watchpoint list |
| `frame variable` | Show local variables |
| `bt` | Backtrace |
| `memory read -c <N> <addr>` | Read N bytes from address |
| `x/32bx <addr>` | Examine 32 bytes as hex |
| `step` | Step into |
| `next` | Step over |
| `finish` | Step out |
| `continue` | Resume execution |
| `quit` | Exit LLDB |

---

## Environment Variables Reference

### Global Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `LLDB_ENABLE_WATCHPOINTS` | `true` | Enable hardware watchpoints for key lifecycle tracking |
| `LLDB_ENABLE_MEMORY_DUMPS` | `false` | Enable memory dumps at lifecycle checkpoints |
| `LLDB_DUMP_TYPE` | `heap` | Dump type: `heap`, `full`, or `keys` |
| `LLDB_KEYLOG` | `data/keylogs/<impl>_client_keylog.log` | Keylog output path |
| `KEEP_ALIVE_SECONDS` | `10` | Keep process alive after close (for dumps) |

### Per-Implementation Overrides

| Variable | Default | Description |
|----------|---------|-------------|
| `LLDB_ENABLE_WATCHPOINTS_OPENSSH` | (inherits global) | OpenSSH-specific watchpoint toggle |
| `LLDB_ENABLE_WATCHPOINTS_DROPBEAR` | (inherits global) | Dropbear-specific watchpoint toggle |
| `LLDB_ENABLE_WATCHPOINTS_WOLFSSH` | (inherits global) | wolfSSH-specific watchpoint toggle |

### Dropbear Server-Specific

| Variable | Default | Description |
|----------|---------|-------------|
| `LLDB_AUTO_DISABLE_BREAKPOINTS` | `true` | Auto-disable breakpoints after KEX (interactive sessions) |
| `LLDB_AUTO_SEARCH_KEYS` | `false` | Auto-search for keys in memory (slow, for debugging) |

### Usage Examples

**Disable watchpoints for unstable runs:**

```bash
LLDB_ENABLE_WATCHPOINTS=false ./test_dropbear_lifecycle.sh
```

**Enable full memory dumps:**

```bash
LLDB_ENABLE_MEMORY_DUMPS=true LLDB_DUMP_TYPE=full ./test_openssh_lifecycle_ku.sh
```

**Keep client alive for 30 seconds:**

```bash
KEEP_ALIVE_SECONDS=30 ./test_wolfssh_lifecycle_ku.sh
```

**Dropbear server with breakpoints enabled post-KEX:**

```bash
LLDB_AUTO_DISABLE_BREAKPOINTS=false ./debug_dropbear_server_interactive.sh
```

**Enable auto-search for debugging:**

```bash
LLDB_AUTO_SEARCH_KEYS=true ./debug_dropbear_server_interactive.sh
```

---

## Output Files & Structure

### Directory Layout

After running experiments:

```
results/ssh_lifecycle_YYYYMMDD_HHMMSS/
├── openssh/
│   ├── openssh_base/
│   │   ├── openssh_client_keylog.log       # Extracted keys (Wireshark format)
│   │   ├── timing_openssh.csv              # Key lifecycle timing
│   │   ├── openssh_client_*.dump           # Memory dumps
│   │   └── openssh_lifecycle_*.pcap        # Packet capture
│   └── openssh_ku/
│       └── ... (same structure for rekey mode)
├── dropbear/
│   ├── dropbear_base/
│   │   ├── dropbear_client_keylog.log
│   │   ├── timing_dropbear.csv
│   │   ├── dropbear_client_*.dump
│   │   └── dropbear_lifecycle_*.pcap
│   └── dropbear_ku/
│       └── ...
├── wolfssh/
│   ├── wolfssh_base/
│   │   ├── wolfssh_client_keylog.log
│   │   ├── timing_wolfssh.csv
│   │   ├── wolfssh_client_*.dump
│   │   └── wolfssh_lifecycle_*.pcap
│   └── wolfssh_ku/
│       └── ...
└── experiment_summary.log                   # Aggregated results
```

### File Formats

#### Keylog Files (`*_client_keylog.log`)

SSH session keys in format suitable for Wireshark decryption:

```
# Format: cookie(hex) NEWKEYS MODE IN/OUT CIPHER cipher_name KEY key_hex IV iv_hex
abcd1234ef567890 NEWKEYS MODE IN CIPHER chacha20-poly1305@openssh.com KEY 1a2b3c... IV deadbeef...
abcd1234ef567890 NEWKEYS MODE OUT CIPHER chacha20-poly1305@openssh.com KEY 2c3d4e... IV cafebabe...
```

**Fields:**
- `cookie` - SSH exchange hash (session identifier)
- `NEWKEYS` - Marker for key activation
- `MODE` - Direction marker
- `IN` - Server→Client keys
- `OUT` - Client→Server keys
- `CIPHER` - Negotiated cipher name
- `KEY` - Encryption key (hex)
- `IV` - Initialization vector (hex)

**Ground-Truth Comparison:**

Ground-truth server also generates `data/keylogs/groundtruth.log` with same format for validation.

#### Timing CSV Files (`timing_*.csv`)

Tracks key lifecycle events with precise timestamps:

```csv
timestamp,key_id,event,details
1730125834.512,recv_cipher_key,created,Initial KEX
1730125838.109,recv_cipher_key,overwritten,Watchpoint triggered at 0x7fff12345678
1730125841.023,send_cipher_key,created,Initial KEX
1730125844.678,send_cipher_key,overwritten,Watchpoint triggered at 0x7fff87654321
```

**Events:**
- `created` - Key derived during KEX (logged at KEX exit breakpoint)
- `overwritten` - Hardware watchpoint detected key being cleared/replaced

**Key IDs:**
- `recv_cipher_key` - Key D (server→client encryption)
- `send_cipher_key` - Key C (client→server encryption)

**Lifespan Calculation:**

```python
lifespan = overwritten_timestamp - created_timestamp
```

**One-Shot Watchpoint Policy:**

Watchpoints automatically disable after first hit (return `False` in callback) to prevent excessive stops from memory clearing loops.

#### Memory Dumps (`*.dump`)

Binary snapshots at lifecycle checkpoints (if `LLDB_ENABLE_MEMORY_DUMPS=true`):

**Naming Convention:**

```
<timestamp>_<process_name>_<label>_<kex_count>_<section_name>.dump
```

Example:
```
20251028_101523_openssh_kex_exit_0_heap.dump
20251028_101525_openssh_session_closed_0_heap.dump
```

**Dump Labels:**
- `kex_entry` - Before key derivation
- `kex_exit` - After key derivation (keys in plaintext)
- `session_closed` - After session termination
- `cleanup` - After explicit cleanup

**Dump Types (controlled by `LLDB_DUMP_TYPE`):**
- `heap` - Only heap memory (default, smallest)
- `keys` - Key-containing regions only
- `full` - All readable memory (largest)

#### Packet Captures (`*.pcap`)

Network traffic captured during experiments (ground-truth mode only):

**Files:**
- `<impl>_lifecycle_*.pcap` - Client-side capture
- `groundtruth_*.pcap` - Server-side capture (openssh_groundtruth)

**Contents:**
- Encrypted SSH traffic (port 2226)
- Can be decrypted using extracted keylogs

**Capture Tool:** `tcpdump` running in ground-truth container

---

## Analysis & Correlation

### Overview

Two scripts analyze experiment results:

1. **`analyze_ssh_lifecycle.sh`** - Comprehensive per-key lifecycle analysis with base vs KU comparison
2. **`correlate_ssh_lifecycle.py`** - Detailed event correlation between keylogs, timing CSVs, and packet captures

### analyze_ssh_lifecycle.sh

**Purpose:** Automated analysis of experiment results with detailed per-key reporting

**Usage:**

```bash
# Analyze latest results (default)
./analyze_ssh_lifecycle.sh

# Analyze specific results directory
./analyze_ssh_lifecycle.sh ./results/ssh_lifecycle_20251028_143052

# Analyze archived experiments
./analyze_ssh_lifecycle.sh /path/to/old_research_working_result
```

**No parameters** - Uses environment variables or defaults

**Capabilities:**

1. **Detailed Per-Key Lifecycle Timeline:**
   - When created (timestamp from timing CSV)
   - When overwritten (watchpoint detection)
   - Lifespan duration
   - Last found in memory dump
   - Memory state (PLAINTEXT or CLEARED)

2. **Base vs KU Lifespan Comparison:**
   - Average key lifespan for base mode
   - Average key lifespan for KU mode
   - Percentage reduction in key exposure
   - Security assessment

3. **Optional Timelining Integration:**
   - Auto-detects `../../timing_analysis/timelining_events.py`
   - Provides usage instructions
   - Does NOT run automatically (user control)

4. **Custom Results Directory Support:**
   - Analyze any results directory
   - Supports archived experiments

**Example Output:**

```
=== OpenSSH Client Analysis ===

Base Mode Lifecycle:
  recv_cipher_key:
    Created: 1730125834.512
    Overwritten: 1730125838.109
    Lifespan: 3.597 seconds
    Last found: openssh_client_session_closed_0.dump
    Memory state: PLAINTEXT (found in dumps)

  send_cipher_key:
    Created: 1730125834.523
    Overwritten: 1730125838.145
    Lifespan: 3.622 seconds
    Last found: openssh_client_session_closed_0.dump
    Memory state: PLAINTEXT (found in dumps)

  Average lifespan (base): 3.610 seconds

KU Mode Lifecycle:
  recv_cipher_key:
    Created: 1730125901.234
    Overwritten: 1730125903.456
    Lifespan: 2.222 seconds
    ...

  Average lifespan (KU): 2.156 seconds

Comparison:
  Base mode average lifespan: 3.610 seconds
  KU mode average lifespan: 2.156 seconds
  Reduction: 40.3% (1.454 seconds shorter)

  Security Assessment: KU mode reduces key exposure time by 40.3%
```

**Exit Codes:**
- `0` - Success
- `1` - Results directory not found
- `2` - No timing CSVs found

---

### correlate_ssh_lifecycle.py

**Purpose:** Detailed event correlation for research analysis

**Usage:**

```bash
python3 ./correlate_ssh_lifecycle.py \
    --keylog <path_to_keylog> \
    --timing <path_to_timing_csv> \
    --pcap <path_to_pcap> \
    --dumps <path_to_dumps_dir> \
    --output <output_json>
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--keylog` | Yes | Path to keylog file (`*_client_keylog.log`) |
| `--timing` | Yes | Path to timing CSV (`timing_*.csv`) |
| `--pcap` | No | Path to packet capture (`*.pcap`) |
| `--dumps` | No | Path to directory containing memory dumps |
| `--output` | No | Output JSON file path (default: `correlation_results.json`) |
| `--verbose`, `-v` | No | Enable verbose output |
| `--debug` | No | Enable debug output |

**Example:**

```bash
cd results/ssh_lifecycle_20251028_143052/openssh/openssh_base

python3 ../../../../correlate_ssh_lifecycle.py \
    --keylog openssh_client_keylog.log \
    --timing ../../../lldb_results/timing_openssh.csv \
    --pcap openssh_lifecycle_20251028_143052.pcap \
    --dumps . \
    --output correlation_analysis.json \
    --verbose
```

**Output Format (JSON):**

```json
{
  "keylog_entries": [
    {
      "cookie": "abcd1234ef567890",
      "direction": "IN",
      "cipher": "chacha20-poly1305@openssh.com",
      "key": "1a2b3c4d...",
      "iv": "deadbeef..."
    }
  ],
  "timing_events": [
    {
      "timestamp": 1730125834.512,
      "key_id": "recv_cipher_key",
      "event": "created",
      "details": "Initial KEX"
    }
  ],
  "pcap_stats": {
    "total_packets": 1234,
    "ssh_packets": 567,
    "encrypted_bytes": 123456
  },
  "dump_analysis": {
    "kex_exit": {
      "keys_found": ["recv_cipher_key", "send_cipher_key"],
      "memory_state": "PLAINTEXT"
    },
    "session_closed": {
      "keys_found": ["recv_cipher_key", "send_cipher_key"],
      "memory_state": "PLAINTEXT"
    }
  },
  "lifecycle_summary": {
    "recv_cipher_key": {
      "created": 1730125834.512,
      "overwritten": 1730125838.109,
      "lifespan": 3.597,
      "found_in_dumps": ["kex_exit", "session_closed"]
    }
  }
}
```

**Capabilities:**
- Parse keylog and timing CSV formats
- Correlate events by timestamp
- Analyze packet captures for traffic patterns
- Search for keys in memory dumps
- Generate comprehensive JSON report

---

## Wireshark Decryption

### Overview

Three methods to decrypt captured SSH traffic:

1. **Direct keylog import** (easiest, recommended)
2. **Manual key entry** (for individual sessions)
3. **Custom decryptor script** (batch processing)

### Method 1: Direct Keylog Import (Recommended)

**Steps:**

1. Open Wireshark
2. Go to `Edit → Preferences → Protocols → SSH`
3. Set "SSH keylog file" to path of keylog:
   ```
   /path/to/data/keylogs/openssh_client_keylog.log
   ```
4. Click OK
5. Open PCAP file:
   ```
   /path/to/results/ssh_lifecycle_*/openssh/openssh_base/openssh_lifecycle_*.pcap
   ```
6. Traffic should now be decrypted (check protocol column)

**Verification:**

- SSH packets should show decrypted payloads in packet details
- Filter by `ssh.packet_length_decrypted` to see only decrypted traffic
- Right-click packet → "Protocol Preferences" → verify keylog is loaded

**Troubleshooting:**

- Ensure keylog format matches Wireshark expectations (see [Output Files](#output-files--structure))
- Check cookie values match between keylog and PCAP (first 16 bytes of KEX)
- Verify cipher names are recognized by Wireshark

---

### Method 2: Manual Key Entry

**Steps:**

1. Open PCAP in Wireshark
2. Go to `Edit → Preferences → Protocols → SSH`
3. Click "Edit" next to "SSH keys"
4. Add keys manually from keylog:
   - **Cookie**: `abcd1234ef567890` (from keylog)
   - **Direction**: IN or OUT
   - **Cipher**: `chacha20-poly1305@openssh.com`
   - **Key**: `1a2b3c4d5e6f...` (hex)
   - **IV**: `deadbeef...` (hex)
5. Click OK and reload PCAP

**Use Case:** Single session analysis or validation

---

### Method 3: Custom Decryptor Script

**Purpose:** Batch decryption with detailed debugging and JSON key format support

**Script Location:**

```bash
../openSSH/research_setup/decryption/ssh_decryptor.py
```

**Usage:**

```bash
python3 ../openSSH/research_setup/decryption/ssh_decryptor.py \
    --pcap <input_pcap> \
    --keys <keys_json_or_keylog> \
    --out <output_json> \
    --decrypted-pcap <output_pcap> \
    [--debug] \
    [--debug-max <N>]
```

**Parameters:**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `--pcap` | Yes | Input PCAP file path |
| `--keys` | Yes | Keys file (JSON or keylog format) |
| `--out` | Yes | Output JSON file (decrypted analysis) |
| `--decrypted-pcap` | No | Output decrypted PCAP file |
| `--debug` | No | Enable debug output |
| `--debug-max <N>` | No | Limit debug output to first N packets |

**Example:**

```bash
python3 ../openSSH/research_setup/decryption/ssh_decryptor.py \
    --pcap data/captures/server_20251018_155646_port22.pcap \
    --keys analysis/groundtruth/keys.json \
    --out analysis/groundtruth/dec2.pcap \
    --decrypted-pcap decrypted.pcap \
    --debug \
    --debug-max 5
```

**Keys File Format (JSON):**

```json
{
  "sessions": [
    {
      "cookie": "abcd1234ef567890",
      "keys": {
        "IN": {
          "cipher": "chacha20-poly1305@openssh.com",
          "key": "1a2b3c4d5e6f...",
          "iv": "deadbeef..."
        },
        "OUT": {
          "cipher": "chacha20-poly1305@openssh.com",
          "key": "2c3d4e5f...",
          "iv": "cafebabe..."
        }
      }
    }
  ]
}
```

**Keys File Format (Keylog):**

Standard SSH keylog format (same as Wireshark):

```
abcd1234ef567890 NEWKEYS MODE IN CIPHER chacha20-poly1305@openssh.com KEY 1a2b3c... IV deadbeef...
```

**Output (JSON):**

```json
{
  "pcap_file": "data/captures/server_20251018_155646_port22.pcap",
  "total_packets": 1234,
  "decrypted_packets": 567,
  "decryption_rate": 0.459,
  "sessions": [
    {
      "cookie": "abcd1234ef567890",
      "packets_decrypted": 567,
      "cipher": "chacha20-poly1305@openssh.com"
    }
  ]
}
```

**Output (PCAP):**

Decrypted PCAP file with SSH payload in cleartext (if `--decrypted-pcap` specified).

**Use Case:**
- Batch processing of multiple captures
- Automated decryption pipeline
- Custom analysis workflows
- Debugging decryption issues with `--debug`

---

### Comparison Matrix

| Method | Ease of Use | Batch Support | Debugging | Use Case |
|--------|-------------|---------------|-----------|----------|
| Direct Keylog | ★★★★★ | No | Limited | Interactive analysis |
| Manual Entry | ★★☆☆☆ | No | Good | Single session validation |
| Decryptor Script | ★★★☆☆ | Yes | Excellent | Automation, research |

---

## Troubleshooting

### Common Issues

#### 1. No Keys Extracted

**Symptoms:**
- Empty keylog files
- No timing CSV generated
- LLDB breakpoints not hitting

**Causes:**
- Ground-truth server not running
- LLDB callbacks not loaded
- Incorrect hook points (symbol not found)

**Fixes:**

```bash
# Check server status
docker compose ps | grep openssh_groundtruth

# Restart server
docker compose up -d openssh_groundtruth

# Rebuild container if symbols missing
docker compose build <impl>_client

# Check write permissions
chmod -R 777 data/

# Verify LLDB breakpoint in logs
docker compose logs <impl>_client | grep "Breakpoint"
```

---

#### 2. No Timing CSV Generated

**Symptoms:**
- Keylog exists but no `timing_*.csv`
- Watchpoints not triggering

**Causes:**
- Watchpoints disabled
- Keys not overwritten (session too short)
- ARM64 watchpoint issues

**Fixes:**

```bash
# Enable watchpoints explicitly
LLDB_ENABLE_WATCHPOINTS=true ./test_openssh_lifecycle_ku.sh

# Use KU script for longer sessions
./test_openssh_lifecycle_ku.sh  # Instead of base

# Check watchpoint status in logs
docker compose logs openssh_client | grep "WATCHPOINT"

# For Dropbear on ARM64, may need to disable
LLDB_ENABLE_WATCHPOINTS_DROPBEAR=false ./test_dropbear_lifecycle.sh
```

---

#### 3. Rekey Not Triggering

**Symptoms:**
- KU script runs but only one KEX in keylog
- No second key set extracted

**Causes:**
- Expect script timeout
- Client doesn't support forced rekey
- Server-side rekey disabled

**Fixes:**

**OpenSSH:**
```bash
# Ensure using KU script
./test_openssh_lifecycle_ku.sh

# Check expect script
cat expect/openssh_client_rekey.exp

# Verify `~R` command sent in logs
```

**Dropbear:**
```bash
# Use KU script (but may skip forced rekey)
./test_dropbear_lifecycle_ku.sh

# Note: Dropbear client may not support forced rekey
# Automatic rekey occurs after ~1GB data transfer
```

**wolfSSH:**
```bash
# Ensure using KU script with custom client
./test_wolfssh_lifecycle_ku.sh

# Check custom client source
cat wolfssh-client/wolfssh_client_rekey.c

# Verify `--with-rekey` flag used
```

---

#### 4. Large Memory Dumps

**Symptoms:**
- Dumps >1GB each
- Disk space exhaustion
- Slow experiment runs

**Fixes:**

```bash
# Use heap dumps only (default)
LLDB_DUMP_TYPE=heap ./test_openssh_lifecycle.sh

# Use key-only dumps (smallest)
LLDB_DUMP_TYPE=keys ./test_openssh_lifecycle.sh

# Disable dumps entirely
LLDB_ENABLE_MEMORY_DUMPS=false ./test_openssh_lifecycle.sh
```

---

#### 5. LLDB Exits with Hang

**Symptoms:**
- Test script hangs for >2 minutes
- No output in terminal
- Container doesn't stop

**Fixes:**

```bash
# Monitor log file during test
tail -f /tmp/<test_name>.log

# Manual cleanup if hung
docker compose stop <impl>_client
docker compose rm -f <impl>_client

# Kill orphaned LLDB processes
docker exec <impl>_client pkill -9 lldb

# Rebuild if persistent
docker compose build <impl>_client
```

**Automatic Detection:**

`run_all_ssh_lifecycle_experiments.sh` includes hang detection:
- Monitors log file for activity
- Forces cleanup after 2-minute timeout
- Continues to next test

---

#### 6. findkey Not Finding Keys (Interactive)

**Symptoms:**
- `findkey <hex>` reports "not found"
- But `memory read <addr>` shows key is present

**Fixes:**

```bash
# Rebuild container (LLDB API compatibility)
docker compose build dropbear_server

# Use verbose mode to debug
(lldb) findkey --verbose d77f8b958dc1fec97a70368199e04cb3

# Try full search (all regions)
(lldb) findkey --full d77f8b958dc1fec97a70368199e04cb3

# Check hex string format (even length)
(lldb) findkey 1a2b3c4d  # ✓ Correct
(lldb) findkey 1a2b3c4   # ✗ Wrong (odd length)
```

---

#### 7. Watchpoint Crashes on ARM64

**Symptoms:**
- LLDB crashes when watchpoint hits
- Container exits unexpectedly
- Only on ARM64 (M1/M2 or ARM64 Ubuntu)

**Fixes:**

```bash
# Disable watchpoints for affected implementation
LLDB_ENABLE_WATCHPOINTS_DROPBEAR=false ./test_dropbear_lifecycle.sh

# Or disable globally
LLDB_ENABLE_WATCHPOINTS=false ./run_all_ssh_lifecycle_experiments.sh all

# Still get keylogs, just no timing CSV
```

**Note:** OpenSSH and wolfSSH watchpoints typically stable on ARM64.

---

#### 8. Permission Denied on data/

**Symptoms:**
- Cannot write keylogs or dumps
- "Permission denied" errors in logs

**Fixes:**

```bash
# Fix permissions
chmod -R 777 data/

# Or recreate with correct permissions
rm -rf data/
mkdir -p data/keylogs data/dumps data/captures data/lldb_results
chmod -R 777 data/
```

---

#### 9. analyze_ssh_lifecycle.sh: syntax error

**Symptoms:**
- `syntax error near unexpected token 'done'`
- Script exits immediately

**Fix:**

```bash
# Update to latest version (fixed 2025-10-28)
git pull origin main

# Or check bash syntax
bash -n ./analyze_ssh_lifecycle.sh
```

---

#### 10. Monitoring Output Missing

**Symptoms:**
- No terminal output during test run
- Can't see progress

**Fix:**

```bash
# Update to latest version (fixed 2025-10-28)
git pull origin main

# Or manually monitor log file
tail -f /tmp/<test_name>.log
```

---

### Platform-Specific Issues

#### macOS M1/M2

**Issue:** GPG signature verification fails during build

**Fix:**
```bash
# Uses Dockerfile.m1-nogpg automatically
docker compose build openssh_groundtruth
```

**Issue:** Watchpoints unstable on some implementations

**Fix:**
```bash
# Disable for Dropbear
LLDB_ENABLE_WATCHPOINTS_DROPBEAR=false ./test_dropbear_lifecycle.sh
```

---

#### Ubuntu ARM64

**Issue:** LLDB 18 required for ARM64 watchpoint support

**Fix:**
```bash
# Verify LLDB version in container
docker compose run --rm openssh_client lldb --version
# Should be: lldb version 18.x.x

# Rebuild if old version
docker compose build openssh_client
```

---

## Quick Reference Tables

### Test Scripts Summary

| Script | Implementation | Mode | Rekey | Duration | Output |
|--------|----------------|------|-------|----------|--------|
| `run_all_ssh_lifecycle_experiments.sh all` | All | Base + KU | Yes | 5-10 min | Timestamped results/ |
| `test_openssh_lifecycle.sh` | OpenSSH | Base | No | ~1 min | Keylog + PCAP |
| `test_openssh_lifecycle_ku.sh` | OpenSSH | KU | Yes | ~2 min | Keylog + Timing CSV + PCAP |
| `test_dropbear_lifecycle.sh` | Dropbear | Base | No | ~1 min | Keylog + PCAP |
| `test_dropbear_lifecycle_ku.sh` | Dropbear | KU | Maybe | ~2 min | Keylog + (Timing CSV) + PCAP |
| `test_wolfssh_lifecycle.sh` | wolfSSH | Base | No | ~1 min | Keylog + PCAP |
| `test_wolfssh_lifecycle_ku.sh` | wolfSSH | KU | Yes | ~2 min | Keylog + Timing CSV + PCAP |

---

### Debug Scripts Summary

| Script | Implementation | Side | Fork Tracking | Auto-Disable BP | Target Server |
|--------|----------------|------|---------------|-----------------|---------------|
| `debug_openssh_interactive.sh` | OpenSSH | Client | No | N/A | openssh_groundtruth:2226 |
| `debug_dropbear_server_interactive.sh` | Dropbear | Server | Yes (fork #1) | Yes (default) | Listens on :2223 |
| `debug_dropbear_client_interactive.sh` | Dropbear | Client | No | Yes (default) | openssh_groundtruth:2226 |
| `debug_wolfssh_interactive.sh` | wolfSSH | Client | No | N/A | openssh_groundtruth:2226 |

---

### LLDB Commands Quick Reference

| Command | Purpose | Availability |
|---------|---------|--------------|
| `client_setup_monitoring` | Setup breakpoints + callbacks | Client scripts |
| `server_setup_monitoring` | Setup breakpoints + callbacks | Server scripts |
| `client_auto_continue` | Auto-continue to KEX | Client scripts |
| `server_auto_continue` | Auto-continue to KEX | Server scripts |
| `findkey <hex>` | Search key in memory | All scripts |
| `findkey --full <hex>` | Search all memory regions | All scripts |
| `findkey --verbose <hex>` | Search with debug output | All scripts |
| `d` | Quick dump | All scripts |
| `dump <label>` | Named checkpoint dump | All scripts |
| `watchpoints_toggle` | Enable/disable watchpoints | All scripts |
| `watchpoints_status` | Show watchpoint state | All scripts |
| `watchpoints_list` | Detailed watchpoint list | All scripts |

---

### Environment Variables Quick Reference

| Variable | Default | Scope | Impact |
|----------|---------|-------|--------|
| `LLDB_ENABLE_WATCHPOINTS` | `true` | Global | Enable/disable all watchpoints |
| `LLDB_ENABLE_WATCHPOINTS_OPENSSH` | (inherits) | OpenSSH | Override for OpenSSH |
| `LLDB_ENABLE_WATCHPOINTS_DROPBEAR` | (inherits) | Dropbear | Override for Dropbear |
| `LLDB_ENABLE_WATCHPOINTS_WOLFSSH` | (inherits) | wolfSSH | Override for wolfSSH |
| `LLDB_ENABLE_MEMORY_DUMPS` | `false` | Global | Enable/disable dumps |
| `LLDB_DUMP_TYPE` | `heap` | Global | `heap`, `full`, or `keys` |
| `LLDB_AUTO_DISABLE_BREAKPOINTS` | `true` | Dropbear Server | Auto-disable after KEX |
| `LLDB_AUTO_SEARCH_KEYS` | `false` | Dropbear Server | Auto-search in memory |
| `KEEP_ALIVE_SECONDS` | `10` | Global | Keep-alive duration |

---

### Output Files Quick Reference

| File Type | Naming Pattern | Purpose | Tools |
|-----------|----------------|---------|-------|
| Keylog | `<impl>_client_keylog.log` | Wireshark-compatible keys | Wireshark, ssh_decryptor.py |
| Timing CSV | `timing_<impl>.csv` | Watchpoint events | analyze_ssh_lifecycle.sh, Excel |
| Memory Dumps | `<timestamp>_<label>_*.dump` | Binary memory snapshots | correlate_ssh_lifecycle.py |
| Packet Captures | `<impl>_lifecycle_*.pcap` | Network traffic | Wireshark, ssh_decryptor.py |
| Ground-Truth Keylog | `groundtruth.log` | Validation reference | Compare with LLDB keylogs |

---

### Analysis Scripts Quick Reference

| Script | Purpose | Input | Output |
|--------|---------|-------|--------|
| `analyze_ssh_lifecycle.sh` | Comprehensive lifecycle analysis | Results directory | Terminal report + summary.txt |
| `correlate_ssh_lifecycle.py` | Event correlation | Keylog, timing CSV, PCAP, dumps | JSON report |
| `ssh_decryptor.py` | Batch PCAP decryption | PCAP, keys JSON/keylog | Decrypted PCAP, JSON analysis |

---

### Wireshark Decryption Quick Reference

| Method | Difficulty | Batch | Debugging | Command |
|--------|-----------|-------|-----------|---------|
| Direct Keylog Import | Easy | No | Limited | Edit → Preferences → Protocols → SSH → SSH keylog file |
| Manual Key Entry | Medium | No | Good | Edit → Preferences → Protocols → SSH → Edit keys |
| ssh_decryptor.py | Medium | Yes | Excellent | `python3 ssh_decryptor.py --pcap <file> --keys <file>` |

---

## Conclusion

This framework provides comprehensive SSH key lifecycle analysis across three implementations with both automated experiments and interactive debugging capabilities.

**Key Takeaways:**
- Use `run_all_ssh_lifecycle_experiments.sh all` for automated comparative analysis
- Use debug scripts for manual investigation and validation
- Watchpoints provide precise key lifecycle timing
- Ground-truth validation ensures extraction accuracy
- Wireshark integration enables traffic decryption and correlation

**For Questions or Issues:**
- Check [Troubleshooting](#troubleshooting) section
- Examine container logs: `docker compose logs <service>`
