#!/usr/bin/env python3
"""
convert_ssh_to_wireshark.py

Converts SSH keylogs from LLDB-extracted formats to Wireshark-compatible format.

Supports multiple SSH implementations:
- wolfSSH: NEWKEYS MODE <dir> TYPE <type> VALUE <hex>
- Dropbear: [timestamp] CLIENT <key_label>: <hex>
- OpenSSH: <timestamp> NEWKEYS MODE <dir> CIPHER <cipher> KEY <hex> IV <hex>

Usage:
  ./convert_ssh_to_wireshark.py \\
    --ssh-keylog data/keylogs/wolfssh_client_keylog.log \\
    --pcap data/captures/wolfssh_lifecycle_*.pcap \\
    --out wireshark_keylog.txt \\
    [--implementation wolfssh|dropbear|openssh]

Output format (Wireshark SSH keylog):
  <cookie_hex> SHARED_SECRET <shared_secret_hex>

The cookie is extracted from the SSH_MSG_KEXINIT packet (message ID 0x14).
Multiple NEWKEYS exchanges (base + rekey) are supported.
"""

import argparse
import re
import sys
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import glob


def detect_implementation(keylog_path: str) -> Optional[str]:
    """
    Auto-detect SSH implementation from keylog format.

    Returns: 'wolfssh', 'dropbear', 'openssh', or None
    """
    try:
        with open(keylog_path, 'r', errors='ignore') as f:
            content = f.read(2000)  # Read first 2000 chars

        # wolfSSH: "NEWKEYS MODE IN TYPE KEY VALUE"
        if 'NEWKEYS' in content and 'TYPE' in content and 'VALUE' in content:
            return 'wolfssh'

        # Dropbear: "[timestamp] CLIENT C_ENCRYPTION_KEY"
        if 'CLIENT' in content and ('C_ENCRYPTION_KEY' in content or 'D_ENCRYPTION_KEY' in content):
            return 'dropbear'

        # OpenSSH: "NEWKEYS MODE IN CIPHER"
        if 'NEWKEYS' in content and 'CIPHER' in content:
            return 'openssh'

        return None
    except Exception as e:
        print(f"ERROR: Could not detect implementation: {e}", file=sys.stderr)
        return None


def parse_wolfssh_keylog(keylog_path: str) -> List[Dict[str, str]]:
    """
    Parse wolfSSH keylog format.

    Format: 2025-10-27 22:02:06.434 NEWKEYS MODE IN TYPE KEY VALUE <hex>

    Returns list of key dictionaries with fields:
    - timestamp, direction, type, key_hex
    """
    keys = []

    with open(keylog_path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or 'NEWKEYS' not in line:
                continue

            # Extract components
            match = re.search(r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+NEWKEYS\s+MODE\s+(\w+)\s+TYPE\s+(\w+)\s+VALUE\s+([0-9a-fA-F]+)', line)
            if match:
                keys.append({
                    'timestamp': match.group(1),
                    'direction': match.group(2),  # IN or OUT
                    'type': match.group(3),  # KEY or IV
                    'key_hex': match.group(4)
                })

    return keys


def parse_dropbear_keylog(keylog_path: str) -> List[Dict[str, str]]:
    """
    Parse Dropbear keylog format.

    Format: [2025-10-27 18:23:24.012185] CLIENT C_ENCRYPTION_KEY_CLIENT_TO_SERVER: <hex>

    Returns list of key dictionaries with fields:
    - timestamp, key_label, key_hex
    """
    keys = []

    with open(keylog_path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or 'CLIENT' not in line:
                continue

            # Extract components
            match = re.search(r'\[([^\]]+)\]\s+CLIENT\s+([A-Z_]+):\s+([0-9a-fA-F]+)', line)
            if match:
                keys.append({
                    'timestamp': match.group(1),
                    'key_label': match.group(2),  # C_ENCRYPTION_KEY_*, D_ENCRYPTION_KEY_*, etc.
                    'key_hex': match.group(3)
                })

    return keys


def parse_openssh_keylog(keylog_path: str) -> List[Dict[str, str]]:
    """
    Parse OpenSSH keylog format.

    Format: <timestamp> NEWKEYS MODE IN CIPHER <cipher> KEY <hex> IV <hex>

    Returns list of key dictionaries with fields:
    - timestamp, direction, cipher, key_hex, iv_hex
    """
    keys = []

    with open(keylog_path, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or 'NEWKEYS' not in line:
                continue

            # Extract components
            parts = line.split()
            if len(parts) < 8:
                continue

            # Parse: timestamp NEWKEYS MODE <dir> CIPHER <cipher> KEY <hex> [IV <hex>]
            try:
                timestamp = ' '.join(parts[:2])
                direction = parts[3]
                cipher = parts[5]
                key_hex = parts[7]
                iv_hex = parts[9] if len(parts) >= 10 else None

                keys.append({
                    'timestamp': timestamp,
                    'direction': direction,
                    'cipher': cipher,
                    'key_hex': key_hex,
                    'iv_hex': iv_hex
                })
            except (IndexError, ValueError):
                continue

    return keys


def extract_cookie_from_pcap(pcap_path: str) -> Optional[str]:
    """
    Extract SSH KEX cookie from PCAP file.

    Scans for SSH_MSG_KEXINIT (0x14) packet and extracts the 16-byte cookie
    that immediately follows the message type.

    Returns: cookie as hex string, or None if not found
    """
    try:
        # Try scapy first (if available)
        try:
            from scapy.all import rdpcap, Raw, TCP

            pkts = rdpcap(pcap_path)
            for pkt in pkts:
                if Raw in pkt and TCP in pkt:
                    payload = bytes(pkt[Raw].load)

                    # Scan for SSH_MSG_KEXINIT (0x14) followed by 16-byte cookie
                    for i in range(len(payload) - 17):
                        if payload[i] == 0x14:
                            cookie = payload[i+1:i+1+16]
                            if len(cookie) == 16:
                                return cookie.hex()

            return None

        except ImportError:
            # Fallback: raw binary search
            with open(pcap_path, 'rb') as f:
                content = f.read()

            # Search for 0x14 byte followed by 16 bytes
            for i in range(len(content) - 17):
                if content[i] == 0x14:
                    # Heuristic: cookie should not be all zeros or all 0xff
                    cookie = content[i+1:i+1+16]
                    if len(cookie) == 16 and cookie != b'\x00' * 16 and cookie != b'\xff' * 16:
                        return cookie.hex()

            return None

    except Exception as e:
        print(f"WARNING: Could not extract cookie from PCAP: {e}", file=sys.stderr)
        return None


def select_encryption_key(keys: List[Dict[str, str]], implementation: str) -> Optional[str]:
    """
    Select the primary encryption key from parsed keys.

    For wolfSSH: Prefer OUT direction KEY type
    For Dropbear: Prefer C_ENCRYPTION_KEY_CLIENT_TO_SERVER
    For OpenSSH: Prefer OUT direction with ChaCha20-Poly1305

    Returns: key hex string, or None
    """
    if not keys:
        return None

    if implementation == 'wolfssh':
        # Prefer OUT direction, KEY type
        for key in keys:
            if key.get('direction') == 'OUT' and key.get('type') == 'KEY':
                return key['key_hex']
        # Fallback: any KEY
        for key in keys:
            if key.get('type') == 'KEY':
                return key['key_hex']

    elif implementation == 'dropbear':
        # Prefer client-to-server encryption key
        for key in keys:
            if key.get('key_label') == 'C_ENCRYPTION_KEY_CLIENT_TO_SERVER':
                return key['key_hex']
        # Fallback: any encryption key
        for key in keys:
            if 'ENCRYPTION' in key.get('key_label', ''):
                return key['key_hex']

    elif implementation == 'openssh':
        # Prefer OUT direction
        for key in keys:
            if key.get('direction') == 'OUT':
                return key['key_hex']
        # Fallback: first key
        return keys[0]['key_hex']

    # Ultimate fallback: first key with key_hex field
    for key in keys:
        if 'key_hex' in key:
            return key['key_hex']

    return None


def convert_to_wireshark_format(
    ssh_keylog: str,
    pcap_path: str,
    output_path: str,
    implementation: Optional[str] = None
) -> bool:
    """
    Convert SSH keylog to Wireshark-compatible format.

    Args:
        ssh_keylog: Path to SSH keylog file
        pcap_path: Path to PCAP file (for cookie extraction)
        output_path: Path to output Wireshark keylog file
        implementation: SSH implementation name ('wolfssh', 'dropbear', 'openssh'), or None for auto-detect

    Returns: True if successful, False otherwise
    """
    # Auto-detect implementation if not specified
    if implementation is None:
        implementation = detect_implementation(ssh_keylog)
        if implementation is None:
            print("ERROR: Could not auto-detect implementation. Please specify --implementation", file=sys.stderr)
            return False
        print(f"Detected implementation: {implementation}")

    # Parse keylog based on implementation
    if implementation == 'wolfssh':
        keys = parse_wolfssh_keylog(ssh_keylog)
    elif implementation == 'dropbear':
        keys = parse_dropbear_keylog(ssh_keylog)
    elif implementation == 'openssh':
        keys = parse_openssh_keylog(ssh_keylog)
    else:
        print(f"ERROR: Unknown implementation: {implementation}", file=sys.stderr)
        return False

    if not keys:
        print("ERROR: No keys found in keylog file", file=sys.stderr)
        return False

    print(f"Parsed {len(keys)} key entries from keylog")

    # Select primary encryption key
    shared_secret = select_encryption_key(keys, implementation)
    if not shared_secret:
        print("ERROR: Could not select encryption key from keylog", file=sys.stderr)
        return False

    print(f"Selected shared secret (length={len(shared_secret)//2} bytes)")

    # Extract cookie from PCAP
    # Support glob pattern for multiple PCAP files
    pcap_files = glob.glob(pcap_path)
    if not pcap_files:
        print(f"WARNING: No PCAP files found matching pattern: {pcap_path}", file=sys.stderr)
        print("Generating keylog with placeholder cookie (00000000000000000000000000000000)", file=sys.stderr)
        cookie_hex = "00" * 16
    else:
        # Try first PCAP file
        cookie_hex = extract_cookie_from_pcap(pcap_files[0])
        if not cookie_hex:
            # Try remaining PCAP files
            for pcap_file in pcap_files[1:]:
                cookie_hex = extract_cookie_from_pcap(pcap_file)
                if cookie_hex:
                    break

        if not cookie_hex:
            print("WARNING: Could not extract cookie from any PCAP file", file=sys.stderr)
            print("Generating keylog with placeholder cookie (00000000000000000000000000000000)", file=sys.stderr)
            cookie_hex = "00" * 16
        else:
            print(f"Extracted cookie from PCAP: {cookie_hex}")

    # Generate Wireshark keylog format
    wireshark_line = f"{cookie_hex} SHARED_SECRET {shared_secret}\n"

    # Write output
    with open(output_path, 'w') as f:
        f.write(wireshark_line)

    print(f"Wrote Wireshark keylog to: {output_path}")
    print("\nUsage:")
    print(f"  wireshark {pcap_files[0] if pcap_files else '<capture.pcap>'} -o 'ssh.keylog_file:{output_path}'")
    print(f"  OR: Set in Wireshark Preferences → Protocols → SSH → Keylog file")

    return True


def main():
    parser = argparse.ArgumentParser(
        description='Convert SSH keylogs to Wireshark-compatible format',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect implementation
  ./convert_ssh_to_wireshark.py \\
    --ssh-keylog data/keylogs/wolfssh_client_keylog.log \\
    --pcap data/captures/wolfssh_lifecycle_*.pcap \\
    --out wireshark_keylog.txt

  # Explicit implementation
  ./convert_ssh_to_wireshark.py \\
    --ssh-keylog data/keylogs/dropbear_client_keylog.log \\
    --pcap data/captures/dropbear_lifecycle_*.pcap \\
    --out wireshark_keylog.txt \\
    --implementation dropbear
"""
    )

    parser.add_argument('--ssh-keylog', required=True,
                        help='Path to SSH keylog file (LLDB-extracted format)')
    parser.add_argument('--pcap', required=True,
                        help='Path to PCAP file(s) - supports wildcards')
    parser.add_argument('--out', required=True,
                        help='Path to output Wireshark keylog file')
    parser.add_argument('--implementation', choices=['wolfssh', 'dropbear', 'openssh'],
                        help='SSH implementation (auto-detect if not specified)')

    args = parser.parse_args()

    # Validate input files
    if not os.path.exists(args.ssh_keylog):
        print(f"ERROR: SSH keylog file not found: {args.ssh_keylog}", file=sys.stderr)
        sys.exit(1)

    # Convert to Wireshark format
    success = convert_to_wireshark_format(
        ssh_keylog=args.ssh_keylog,
        pcap_path=args.pcap,
        output_path=args.out,
        implementation=args.implementation
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
