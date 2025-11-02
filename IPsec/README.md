# IPsec Key Lifecycle Analysis Framework

This directory contains IPsec IKEv2/ESP key lifecycle monitoring frameworks for analyzing cryptographic key derivation and memory persistence across multiple IPsec implementations.

## Supported Implementations

| Implementation | Version                 | Experiment Location         |
|----------------|-------------------------|-----------------------------|
| **strongSwan** | Linux strongSwan 5.9.13 | `strongswan/experiment/`    |
| **Libreswan**  | 4.14-1ubuntu2           | `libreswan/experiment/`     |


We evaluated our results on a Ubuntu 24.04 with Kernel version 6.8.0-85-generic.

---

## Prerequisites and Installation

### System Requirements

- **OS**: Ubuntu 24.04 (x86-64 or ARM64) or similar Linux distribution
- **RAM**: 4GB+ recommended
- **Disk Space**: 2GB for tools and results
- **Root Access**: Required for network namespace operations and kernel monitoring

### Required Software

Both strongSwan and Libreswan experiments require the following dependencies:

#### 1. Core Dependencies

```bash
# Update system packages
sudo apt-get update

# Install strongSwan/Libreswan
sudo apt-get install -y strongswan strongswan-pki libcharon-extra-plugins
# OR for Libreswan
sudo apt-get install -y libreswan

# Install LLDB (version 18 recommended)
sudo apt-get install -y lldb-18 python3-lldb-18
sudo ln -sf /usr/bin/lldb-18 /usr/bin/lldb

# Install Python dependencies
sudo apt-get install -y python3 python3-pip python3-dev python3-venv
```

#### 2. Python Modules

```bash
# Install drgn for kernel memory scanning
pip3 install drgn

# Install analysis dependencies
pip3 install pyyaml tabulate pandas matplotlib
```

#### 3. Network Tools

```bash
# Install packet capture and analysis tools
sudo apt-get install -y tcpdump tshark iproute2 iputils-ping

# Install tmux or gnome-terminal for multi-window display
sudo apt-get install -y tmux
# OR
sudo apt-get install -y gnome-terminal
```

#### 4. AppArmor Configuration (Required)

strongSwan and Libreswan require AppArmor to be in complain mode:

```bash
# Set AppArmor to complain mode for IPsec daemons
sudo aa-complain /usr/lib/ipsec/charon
sudo aa-complain /usr/sbin/swanctl
sudo aa-complain /usr/libexec/ipsec/pluto

# Verify configuration
sudo aa-status | grep ipsec
```

### Automated Installation

Both implementations provide automated installation scripts:

**strongSwan:**
```bash
cd strongswan/experiment
# Follow installation prompts in README.md
```

**Libreswan:**
```bash
cd libreswan
./install_dependencies.sh
```

---

## Running Experiments

### strongSwan Experiment

The strongSwan experiment provides comprehensive IKEv2/ESP key lifecycle monitoring with hardware watchpoints and kernel XFRM scanning.

#### Quick Start

```bash
cd strongswan/experiment
sudo ./run_ipsec_experiment.sh
```

#### Features

- **LLDB Userspace Monitoring**: Extracts IKE keys (SK_ai, SK_ar, SK_ei, SK_er) and ESP keys (ENCR_*, INTEG_*)
- **Hardware Watchpoints**: Tracks key overwrites with precise timing (4 concurrent watchpoints)
- **Kernel XFRM Scanning**: Monitors kernel-level ESP key states using drgn
- **Network Namespaces**: Isolated left/right strongSwan instances
- **Interactive Menu**: Control handshake, initiate, rekey, terminate operations
- **Packet Captures**: Automatic PCAP generation for both endpoints

#### Interactive Menu

Once started, you'll see an interactive prompt:

```
[H] Handshake - Load configs only
[I] Initiate - Establish connection
[R] Rekey - Trigger rekey
[T] Terminate - Close connection
[S] Status - Show SA status
[K] Kernel checkpoint - Manual XFRM scan
[Q] Quit - Cleanup and exit
```

#### Output Structure

```
results/YYYYmmdd_HHMMSS/
├── userspace/
│   ├── left/
│   │   ├── events.log              # Human-readable events
│   │   ├── events.jsonl            # Machine-readable events
│   │   ├── keys.json               # Extracted IKE/ESP keys
│   │   ├── timing_strongswan.csv   # Watchpoint timing data
│   │   ├── ikev2_decryption_table  # Wireshark decryption keys
│   │   └── dump_*.bin              # Memory dumps
│   └── right/
│       └── ...
├── kernel/
│   ├── left/
│   │   └── xfrm_*.json             # Kernel XFRM state dumps
│   └── right/
│       └── ...
└── network/
    ├── left_capture.pcap
    └── right_capture.pcap
```

#### Platform Support

- **x86-64**: Fully supported
- **ARM64** (aarch64): Fully supported with auto-detection

#### Documentation

See `strongswan/experiment/README.md` for detailed documentation.

---

### Libreswan Experiment

The Libreswan experiment provides IKEv2/ESP key lifecycle monitoring with Pluto daemon instrumentation.

#### Quick Start

```bash
cd libreswan/experiment
sudo ./run_ipsec_experiment.sh
```

#### Features

- **LLDB Pluto Monitoring**: Extracts IKE and ESP keys from Libreswan's Pluto daemon
- **Kernel XFRM Scanning**: Monitors kernel-level ESP key states
- **Network Namespaces**: Isolated left/right Libreswan instances
- **Interactive Menu**: Similar control interface to strongSwan
- **Packet Captures**: Automatic PCAP generation

#### Output Structure

Similar to strongSwan with implementation-specific adaptations:

```
results/YYYYmmdd_HHMMSS/
├── userspace/
│   ├── left/
│   │   ├── events.log
│   │   ├── keys.json
│   │   ├── timing_libreswan.csv
│   │   └── dump_*.bin
│   └── right/
│       └── ...
├── kernel/
│   └── ...
└── network/
    └── ...
```

---

## Analyzing Results

### Available Analysis Tools

The ipsec directory provides several analysis scripts for post-experiment correlation and comparison:

#### 1. compare_key_lifespan.py

Compares key lifecycle timing across implementations or experiments.

**Usage:**

```bash
cd ipsec
python3 compare_key_lifespan.py \
    --strongswan strongswan/experiment/results/20251009_233529 \
    --libreswan libreswan/experiment/results/20251010_102345 \
    --output comparison_report.txt
```

**Features:**
- Per-key lifespan comparison
- Statistical analysis (mean, median, std dev)
- Implementation behavior comparison

#### 2. analyze_protocol_state_correlation.py

Correlates protocol state transitions with key lifecycle events.

**Usage:**

```bash
python3 analyze_protocol_state_correlation.py \
    --results strongswan/experiment/results/20251009_233529 \
    --output correlation_analysis.json
```

**Features:**
- Correlates IKE_SA_INIT, IKE_AUTH, CREATE_CHILD_SA events
- Maps key derivation to protocol states
- Identifies timing anomalies

#### 3. find_ipsec_secrets.py (strongSwan)

Searches for extracted keys in memory dumps to validate persistence.

**Usage:**

```bash
cd strongswan/experiment
./find_ipsec_secrets.py results/20251009_233529/userspace/left
```

**Features:**
- ASCII table output showing dump filenames and key presence
- Validates key extraction accuracy
- Identifies key lifecycle boundaries

**Example Output:**

```
Key 'SK_ei' Presence Across Dumps:
+---------------------+-----------+--------+
| Dump                | Present   | Offset |
+---------------------+-----------+--------+
| dump_0_handshake    | ✗         | -      |
| dump_1_kex_exit     | ✓         | 0x1234 |
| dump_2_established  | ✓         | 0x1234 |
| dump_3_rekey        | ✓         | 0x5678 |
| dump_4_terminated   | ✗         | -      |
+---------------------+-----------+--------+
```

#### 4. convert_ipsec_to_tls_format.py (strongSwan)

Converts IPsec experiment results to TLS-compatible format for unified analysis.

**Usage:**

```bash
cd strongswan/experiment
./convert_ipsec_to_tls_format.py \
    results/20251009_233529/userspace/left \
    tls_compat/strongswan_left
```

**Features:**
- Converts timing CSV to TLS format
- Enables use of TLS analysis tools
- Maintains compatibility with timelining scripts

**Integration:**

```bash
cd ../../../timing_analysis
python3 timelining_events.py ../ipsec/strongswan/experiment/tls_compat/strongswan_left
```

#### 5. correlate_pcap_keys.py (Libreswan)

Correlates extracted keys with packet captures for traffic decryption.

**Usage:**

```bash
cd libreswan/experiment
./correlate_pcap_keys.py \
    --keys results/20251010_102345/userspace/left/keys.json \
    --pcap results/20251010_102345/network/left_capture.pcap \
    --output correlation_results.json
```

#### 6. extract_spis_from_pcap.py (strongSwan)

Extracts Security Parameter Indexes (SPIs) from packet captures for manual correlation.

**Usage:**

```bash
cd strongswan/experiment
./extract_spis_from_pcap.py \
    results/20251009_233529/network/left_capture.pcap \
    --output spis.json
```

---

## Typical Analysis Workflow

### 1. Run Experiment

```bash
# strongSwan
cd strongswan/experiment
sudo ./run_ipsec_experiment.sh

# Libreswan
cd libreswan/experiment
sudo ./run_ipsec_experiment.sh
```

### 2. Find Results Directory

```bash
# strongSwan
ls -lt strongswan/experiment/results/ | head -2

# Libreswan
ls -lt libreswan/experiment/results/ | head -2
```

### 3. Search for Keys in Memory Dumps (strongSwan)

```bash
cd strongswan/experiment
./find_ipsec_secrets.py results/20251009_233529/userspace/left
```

### 4. Convert to TLS Format (strongSwan)

```bash
./convert_ipsec_to_tls_format.py \
    results/20251009_233529/userspace/left \
    tls_compat/strongswan_left
```

### 5. Run Unified Analysis

```bash
cd ../../../timing_analysis
python3 timelining_events.py ../ipsec/strongswan/experiment/tls_compat/strongswan_left
```

### 6. Compare Implementations

```bash
cd ../ipsec
python3 compare_key_lifespan.py \
    --strongswan strongswan/experiment/results/20251009_233529 \
    --libreswan libreswan/experiment/results/20251010_102345
```

---

## Troubleshooting

### Common Issues

#### 1. Permission Denied

**Symptoms:**
- "Permission denied" when accessing `/dev/crash`, `/proc/kcore`, or network namespaces

**Fixes:**

```bash
# Run with sudo
sudo ./run_ipsec_experiment.sh

# Verify kernel symbols are accessible
sudo ls -l /proc/kcore /dev/crash
```

#### 2. AppArmor Blocking

**Symptoms:**
- "Permission denied" in audit logs
- strongSwan/Libreswan fails to start

**Fixes:**

```bash
# Set AppArmor to complain mode
sudo aa-complain /usr/lib/ipsec/charon
sudo aa-complain /usr/sbin/swanctl
sudo aa-complain /usr/libexec/ipsec/pluto

# Verify
sudo aa-status | grep ipsec
```

#### 3. drgn Module Not Found

**Symptoms:**
- "ModuleNotFoundError: No module named 'drgn'"

**Fixes:**

```bash
# Install drgn
pip3 install drgn

# For system-wide installation
sudo pip3 install drgn
```

#### 4. Network Namespace Conflicts

**Symptoms:**
- "Namespace already exists"
- Cannot create veth pairs

**Fixes:**

```bash
# Cleanup network namespaces (strongSwan)
cd strongswan/experiment
sudo ./cleanup.sh

# Cleanup network namespaces (Libreswan)
cd libreswan/research_setup
sudo ./clear.sh

# Manual cleanup
sudo ip netns delete left 2>/dev/null || true
sudo ip netns delete right 2>/dev/null || true
```

