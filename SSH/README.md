# SSH Key Lifecycle Analysis Framework

This directory contains the SSH implementation monitoring framework for analyzing cryptographic key lifecycle across multiple SSH implementations.


## Supported Implementations

| Implementation | Version | Client | Server | Rekey Support |
|----------------|---------|--------|--------|---------------|
| OpenSSH | 10.2p1 | ✓  | ✗  | ✓  (via `~R`) |
| Dropbear | 2025.88 | ✓  | ✓  |  ✗ (automatic) is implemented but not working |
| wolfSSH | 1.4.12 | ✓  | ✗   | ✓  (programmatic) |

We evaluated our results on a Ubuntu 24.04 with Kernel version 6.8.0-85-generic.

---


## Directory Structure

### `docker/`

Contains the **dockerized SSH key lifecycle analysis framework**, a comprehensive environment for automated and interactive debugging of SSH key exchange and key lifecycle tracking.

**Key Features:**
- Multi-container Docker Compose setup with OpenSSH, Dropbear, and wolfSSH implementations
- LLDB-based dynamic instrumentation for key extraction
- Hardware watchpoint tracking for key lifecycle timing
- Automated test scripts and interactive debugging sessions
- Wireshark-compatible keylog output for traffic decryption

**Quick Start:**
```bash
cd docker
docker compose build
./run_all_ssh_lifecycle_experiments.sh all
```


---

### `openSSH/`

Contains **utility scripts and research tools** for OpenSSH-specific key extraction and decryption workflows.

**Contents:**
- `research_setup/` - Manual OpenSSH debugging and LLDB scripts
- `research_experiment/` - Advanced KEX extraction experiments
- `decryption/` - SSH packet decryption tools (`ssh_decryptor.py`)

**Use Cases:**
- Manual LLDB debugging of OpenSSH sshd/ssh processes
- Custom key extraction workflows
- Batch PCAP decryption with extracted keys
- Research and validation of extraction techniques

---

## Getting Started

For automated experiments with all implementations:

```bash
cd docker
./run_all_ssh_lifecycle_experiments.sh all
./analyze_ssh_lifecycle.sh
```

For interactive debugging:

```bash
cd docker
./debug_openssh_interactive.sh
./debug_dropbear_server_interactive.sh
./debug_wolfssh_interactive.sh
```


## Requirements

- Docker Engine 20.10+ with Docker Compose
- Python 3.8+
- 4GB+ RAM, 5GB disk space for containers
- Platform: Ubuntu 24.04 (x86-64/ARM64) or macOS M1/M2
