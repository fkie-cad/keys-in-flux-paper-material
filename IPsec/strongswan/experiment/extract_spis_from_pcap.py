#!/usr/bin/env python3
"""
extract_spis_from_pcap.py

Extract IKE SPIs from packet capture and update keylog files.
This script updates ikev2_decryption_table with correct SPIs extracted from IKE_SA_INIT packets.

Usage:
    python3 extract_spis_from_pcap.py --pcap results/*/network/left.pcap --keylog results/*/userspace/left/ikev2_decryption_table
    python3 extract_spis_from_pcap.py --result-dir results/20251009_120721
"""
import argparse
import json
import os
import re
import subprocess
import sys

def extract_spis_from_pcap(pcap_file):
    """Extract initiator and responder SPIs from IKE_SA_INIT packets using tshark

    Returns:
        list of tuples: [(initiator_spi, responder_spi), ...]
    """
    try:
        # Extract IKE SPIs from IKE_SA_INIT messages
        cmd = [
            'tshark', '-r', pcap_file,
            '-Y', 'isakmp.messageid == 0 && isakmp.exchangetype == 34',  # IKE_SA_INIT
            '-T', 'fields',
            '-e', 'isakmp.initiator_spi',
            '-e', 'isakmp.responder_spi'
        ]

        output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)

        spis = []
        for line in output.strip().split('\n'):
            if line:
                parts = line.split('\t')
                if len(parts) >= 2:
                    init_spi = parts[0].replace(':', '').lower()
                    resp_spi = parts[1].replace(':', '').lower()
                    if init_spi and resp_spi and init_spi != '0' * 16:
                        spis.append((init_spi, resp_spi))

        return spis
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"[WARNING] Could not extract SPIs from {pcap_file}: {e}", file=sys.stderr)
        return []

def update_ikev2_keylog(keylog_file, spis):
    """Update ikev2_decryption_table file with correct SPIs

    Args:
        keylog_file: Path to ikev2_decryption_table
        spis: List of (initiator_spi, responder_spi) tuples
    """
    if not os.path.exists(keylog_file):
        print(f"[WARNING] Keylog file not found: {keylog_file}", file=sys.stderr)
        return

    # Read existing keylog
    with open(keylog_file, 'r') as f:
        lines = f.readlines()

    if not lines or not spis:
        print("[INFO] No keys or SPIs to update")
        return

    # Update SPIs in keylog (assumes 1-to-1 correspondence)
    updated_lines = []
    for i, line in enumerate(lines):
        if i < len(spis):
            init_spi, resp_spi = spis[i]
            # Replace first two fields (initiator_spi, responder_spi)
            parts = line.strip().split(',', 2)
            if len(parts) >= 3:
                updated_line = f"{init_spi},{resp_spi},{parts[2]}\n"
                updated_lines.append(updated_line)
                print(f"[UPDATE] SA {i}: {init_spi[:8]}..._{resp_spi[:8]}...")
            else:
                updated_lines.append(line)
        else:
            updated_lines.append(line)

    # Write updated keylog
    with open(keylog_file, 'w') as f:
        f.writelines(updated_lines)

    print(f"[SUCCESS] Updated {len(updated_lines)} entries in {keylog_file}")

def main():
    parser = argparse.ArgumentParser(description='Extract SPIs from pcap and update keylog')
    parser.add_argument('--pcap', help='Path to pcap file')
    parser.add_argument('--keylog', help='Path to ikev2_decryption_table file')
    parser.add_argument('--result-dir', help='Path to experiment result directory (auto-detects files)')
    args = parser.parse_args()

    if args.result_dir:
        # Auto-detect files in result directory
        pcap_file = None
        keylog_file = None

        # Look for pcap in network/
        for pcap in ['network/left.pcap', 'network/right.pcap']:
            pcap_path = os.path.join(args.result_dir, pcap)
            if os.path.exists(pcap_path):
                pcap_file = pcap_path
                break

        # Look for keylog in userspace/left/
        keylog_path = os.path.join(args.result_dir, 'userspace/left/ikev2_decryption_table')
        if os.path.exists(keylog_path):
            keylog_file = keylog_path
    else:
        pcap_file = args.pcap
        keylog_file = args.keylog

    if not pcap_file or not os.path.exists(pcap_file):
        print(f"[ERROR] PCAP file not found: {pcap_file}", file=sys.stderr)
        sys.exit(1)

    if not keylog_file:
        print(f"[ERROR] Keylog file not specified", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Extracting SPIs from: {pcap_file}")
    spis = extract_spis_from_pcap(pcap_file)

    if not spis:
        print("[WARNING] No SPIs found in pcap", file=sys.stderr)
        sys.exit(1)

    print(f"[INFO] Found {len(spis)} IKE SA(s)")
    for i, (init_spi, resp_spi) in enumerate(spis):
        print(f"  SA {i}: I={init_spi[:16]}... R={resp_spi[:16]}...")

    print(f"[INFO] Updating keylog: {keylog_file}")
    update_ikev2_keylog(keylog_file, spis)

if __name__ == '__main__':
    main()
