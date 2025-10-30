#!/usr/bin/env python3
"""
convert_ipsec_to_tls_format.py

Convert IPsec experiment results from hierarchical structure to flat TLS-compatible structure.
This enables using the same analysis tools for both TLS and IPsec experiments.

IPsec Structure:
    results/YYYYmmdd_HHMMSS/
    ├── userspace/
    │   ├── left/
    │   │   ├── dump_init_TIMESTAMP.bin
    │   │   ├── dump_before_handshake_TIMESTAMP.bin
    │   │   ├── dump_after_handshake_TIMESTAMP.bin
    │   │   ├── events.log
    │   │   ├── events.jsonl
    │   │   ├── keys.json
    │   │   └── timing_*.csv (watchpoint lifecycle - strongswan or libreswan)
    │   └── right/
    ├── kernel/
    │   ├── left/
    │   │   ├── xfrm_*.json
    │   │   └── xfrm_memory_*.bin
    │   └── right/
    └── network/
        ├── left.pcap
        └── right.pcap

TLS Structure:
    library/
    ├── TIMESTAMP_pre_handshake.dump
    ├── TIMESTAMP_post_handshake.dump
    ├── timing_13.csv (with lifecycle info)
    ├── keylog_shutdown_1.log
    ├── capture.pcap (from network/left.pcap or right.pcap)
    └── lifecycle_summary.json (NEW: watchpoint and kernel tracking)

Usage:
    ./convert_ipsec_to_tls_format.py <ipsec_results_dir> <output_dir>

    Example:
    ./convert_ipsec_to_tls_format.py results/20251009_233529/userspace/left tls_compat_results/strongswan
"""

import json
import os
import sys
import shutil
from pathlib import Path
from datetime import datetime
import argparse
import re
import csv


def extract_timestamp_from_filename(filename: str) -> str:
    """
    Extract timestamp from IPsec dump filename.

    Example:
        dump_before_handshake_20251009_233559_372910.bin -> 20251009_233559_372910
    """
    basename = os.path.basename(filename)
    # Find timestamp pattern: YYYYmmdd_HHMMSS_microseconds
    match = re.search(r'(\d{8}_\d{6}_\d{6})', basename)
    if match:
        return match.group(1)
    return "unknown"


def extract_event_from_filename(filename: str) -> tuple:
    """
    Extract event name and timing (before/after) from IPsec dump filename.

    Returns:
        (timing, event) tuple, e.g., ("pre", "handshake") or ("post", "child_sa")
    """
    basename = os.path.basename(filename)
    if "before_" in basename:
        timing = "pre"
        event = basename.split("before_")[1].split("_")[0]
    elif "after_" in basename:
        timing = "post"
        event = basename.split("after_")[1].split("_")[0]
    elif "init" in basename:
        timing = "init"
        event = "init"
    else:
        timing = "unknown"
        event = "unknown"

    return (timing, event)


def parse_watchpoint_lifecycle(csv_file: str) -> dict:
    """
    Parse timing CSV (timing_libreswan.csv or timing_strongswan.csv) to extract watchpoint lifecycle information.

    Returns dict with key lifecycle data:
    {
        'SK_ei': {
            'created': '2025-10-13T13:56:14.425837',
            'created_address': '0xf1239803eb80',
            'overwritten': '2025-10-13T13:56:56.160154',
            'overwrite_count': 3
        },
        ...
    }
    """
    lifecycle = {}

    if not os.path.exists(csv_file):
        return lifecycle

    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Handle CSV headers with or without leading spaces
                event = (row.get('event') or row.get(' event', '')).strip()
                key_name = (row.get('key_name') or row.get(' key_name', '')).strip()
                timestamp = (row.get('timestamp') or row.get(' timestamp', '')).strip()
                address = (row.get('address') or row.get(' address', '')).strip()

                if not key_name:
                    continue

                if key_name not in lifecycle:
                    lifecycle[key_name] = {
                        'overwrite_count': 0,
                        'overwrite_events': []
                    }

                # Parse _set events (key creation)
                if event.endswith('_set'):
                    lifecycle[key_name]['created'] = timestamp
                    lifecycle[key_name]['created_address'] = address

                # Parse _overwritten events (key overwrites)
                elif event.endswith('_overwritten'):
                    lifecycle[key_name]['overwrite_count'] += 1
                    lifecycle[key_name]['overwrite_events'].append({
                        'timestamp': timestamp,
                        'address': address
                    })
                    # Store the last overwrite
                    lifecycle[key_name]['overwritten'] = timestamp
                    lifecycle[key_name]['overwritten_address'] = address

    except Exception as e:
        print(f"[WARNING] Failed to parse watchpoint lifecycle: {e}", file=sys.stderr)

    return lifecycle


def convert_timing_csv(ipsec_timing_file: str, output_file: str, keys_file: str):
    """
    Convert IPsec timing CSV (timing_libreswan.csv or timing_strongswan.csv) to TLS timing_13.csv format.

    IPsec format:
        ID, timestamp, event, key_name, address, value

    TLS format:
        ID, timestamp, label, secret
    """
    try:
        # Load keys to get full key values
        keys = {}
        if os.path.exists(keys_file):
            with open(keys_file, 'r') as f:
                keys_data = json.load(f)

                # IKE SA keys
                for i, ike_sa in enumerate(keys_data.get('ike_sa', [])):
                    for key_name, key_hex in ike_sa.items():
                        if key_name not in ['encryption_alg', 'integrity_alg']:
                            keys[key_name] = key_hex

                # ESP keys (handle both direct format and keylog format)
                for i, esp_sa in enumerate(keys_data.get('esp', [])):
                    # Direct format: ENCR_i, ENCR_r, etc.
                    if 'ENCR_i' in esp_sa or 'ENCR_r' in esp_sa:
                        for key_name in ['ENCR_i', 'ENCR_r', 'INTEG_i', 'INTEG_r']:
                            if key_name in esp_sa:
                                keys[key_name] = esp_sa[key_name]
                    # Keylog format: enc_key, auth_key
                    elif 'enc_key' in esp_sa or 'auth_key' in esp_sa:
                        spi = esp_sa.get('spi', '')
                        if 'OUT' in spi or i % 2 == 0:
                            keys['ENCR_i'] = esp_sa.get('enc_key', '')
                            keys['INTEG_i'] = esp_sa.get('auth_key', '')
                        else:
                            keys['ENCR_r'] = esp_sa.get('enc_key', '')
                            keys['INTEG_r'] = esp_sa.get('auth_key', '')

        # Read IPsec timing CSV
        with open(ipsec_timing_file, 'r') as f_in, open(output_file, 'w') as f_out:
            # Write TLS header
            f_out.write("ID, timestamp, label, secret\n")

            # Skip IPsec header
            header = f_in.readline()

            # Convert each line
            for line in f_in:
                parts = [p.strip() for p in line.strip().split(',')]
                if len(parts) < 4:
                    continue

                run_id = parts[0]
                timestamp = parts[1]
                event = parts[2]
                key_name = parts[3]

                # Convert timestamp format from ISO to TLS format
                # ISO: 2025-10-09T23:35:59.372910
                # TLS: 2025-09-25 14:18:31.882759
                timestamp_cleaned = timestamp.replace('T', ' ')

                # Get full key value from keys.json
                secret = keys.get(key_name, "")
                if secret:
                    # Convert hex string to space-separated bytes
                    secret_bytes = ' '.join(secret[i:i+2] for i in range(0, len(secret), 2))
                else:
                    # Use value from timing CSV if available
                    if len(parts) >= 6:
                        value_hex = parts[5].replace('0x', '')
                        secret_bytes = ' '.join(value_hex[i:i+2] for i in range(0, len(value_hex), 2))
                    else:
                        secret_bytes = ""

                # Map IPsec event names to TLS labels
                label_map = {
                    'SK_ei_set': 'IKE SK_ei',
                    'SK_er_set': 'IKE SK_er',
                    'SK_ai_set': 'IKE SK_ai',
                    'SK_ar_set': 'IKE SK_ar',
                    'ENCR_i_set': 'ESP ENCR_i',
                    'ENCR_r_set': 'ESP ENCR_r',
                    'SK_ei_overwritten': 'IKE SK_ei cleared',
                    'SK_er_overwritten': 'IKE SK_er cleared',
                    'ENCR_i_overwritten': 'ESP ENCR_i cleared',
                    'ENCR_r_overwritten': 'ESP ENCR_r cleared',
                }
                label = label_map.get(event, event)

                f_out.write(f"{run_id}, {timestamp_cleaned}, {label}, {secret_bytes}\n")

        print(f"[*] Converted timing CSV: {output_file}")

    except FileNotFoundError:
        print(f"[WARNING] Timing file not found: {ipsec_timing_file}", file=sys.stderr)
        print(f"[INFO] Skipping timing conversion (watchpoints may not have been enabled)", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Failed to convert timing CSV: {e}", file=sys.stderr)


def create_lifecycle_summary(lifecycle_data: dict, kernel_dir: Path, output_file: str):
    """
    Create a comprehensive lifecycle summary JSON combining watchpoint and kernel data.
    """
    try:
        summary = {
            'watchpoint_lifecycle': lifecycle_data,
            'kernel_tracking': {
                'available': kernel_dir.exists() if kernel_dir else False,
                'xfrm_checkpoints': [],
                'forensic_checkpoints': []
            }
        }

        # Add kernel checkpoint information if available
        if kernel_dir and kernel_dir.exists():
            # List XFRM checkpoints
            xfrm_files = sorted(kernel_dir.glob("xfrm_*.json"))
            for xf in xfrm_files:
                if 'forensic' not in xf.name:
                    summary['kernel_tracking']['xfrm_checkpoints'].append(xf.name)

            # List forensic checkpoints
            forensic_files = sorted(kernel_dir.glob("xfrm_forensic_*.json"))
            for ff in forensic_files:
                summary['kernel_tracking']['forensic_checkpoints'].append(ff.name)

        with open(output_file, 'w') as f:
            json.dump(summary, f, indent=2)

        print(f"[*] Created lifecycle summary: {output_file}")

    except Exception as e:
        print(f"[WARNING] Failed to create lifecycle summary: {e}", file=sys.stderr)


def find_network_pcap(ipsec_dir: Path) -> Path:
    """
    Find the corresponding network pcap file for the given userspace directory.

    If ipsec_dir is: results/20251013_135547/userspace/left
    Look for: results/20251013_135547/network/left.pcap
    """
    # Determine which side (left or right)
    side = ipsec_dir.name  # 'left' or 'right'

    # Navigate to network directory
    if 'userspace' in ipsec_dir.parts:
        # Go up two levels (from userspace/left to results/timestamp/)
        root_dir = ipsec_dir.parent.parent
        network_dir = root_dir / 'network'
        pcap_file = network_dir / f"{side}.pcap"

        if pcap_file.exists():
            return pcap_file

    return None


def convert_keylog(keys_file: str, output_file: str):
    """
    Convert IPsec keys.json to TLS-compatible keylog format.

    TLS keylog format (NSS format):
        CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
        SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <secret>
        CLIENT_TRAFFIC_SECRET_0 <client_random> <secret>
        SERVER_TRAFFIC_SECRET_0 <client_random> <secret>

    IPsec equivalent:
        IKE_SK_EI <initiator_spi> <secret>
        IKE_SK_ER <initiator_spi> <secret>
        IKE_SK_AI <initiator_spi> <secret>
        IKE_SK_AR <initiator_spi> <secret>
        ESP_ENCR_I <child_spi> <secret>
        ESP_ENCR_R <child_spi> <secret>
    """
    try:
        with open(keys_file, 'r') as f:
            keys_data = json.load(f)

        with open(output_file, 'w') as f:
            # Write IKE SA keys
            for i, ike_sa in enumerate(keys_data.get('ike_sa', [])):
                # Use index as pseudo-SPI
                spi = f"{'00'*8}"  # Placeholder SPI

                for key_name in ['sk_ei', 'sk_er', 'sk_ai', 'sk_ar', 'sk_pi', 'sk_pr']:
                    if key_name in ike_sa:
                        label = f"IKE_{key_name.upper()}"
                        secret = ike_sa[key_name]
                        f.write(f"{label} {spi} {secret}\n")

            # Write ESP keys (handle both formats)
            for i, esp_sa in enumerate(keys_data.get('esp', [])):
                spi = esp_sa.get('spi', f"{'00'*8}")

                # Direct format
                if 'ENCR_i' in esp_sa or 'ENCR_r' in esp_sa:
                    for key_name in ['ENCR_i', 'INTEG_i', 'ENCR_r', 'INTEG_r']:
                        if key_name in esp_sa:
                            label = f"ESP_{key_name.upper()}"
                            secret = esp_sa[key_name]
                            f.write(f"{label} {spi} {secret}\n")
                # Keylog format
                elif 'enc_key' in esp_sa or 'auth_key' in esp_sa:
                    if 'OUT' in spi or i % 2 == 0:
                        if 'enc_key' in esp_sa:
                            f.write(f"ESP_ENCR_I {spi} {esp_sa['enc_key']}\n")
                        if 'auth_key' in esp_sa:
                            f.write(f"ESP_INTEG_I {spi} {esp_sa['auth_key']}\n")
                    else:
                        if 'enc_key' in esp_sa:
                            f.write(f"ESP_ENCR_R {spi} {esp_sa['enc_key']}\n")
                        if 'auth_key' in esp_sa:
                            f.write(f"ESP_INTEG_R {spi} {esp_sa['auth_key']}\n")

        print(f"[*] Created keylog: {output_file}")

    except FileNotFoundError:
        print(f"[ERROR] Keys file not found: {keys_file}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] Failed to create keylog: {e}", file=sys.stderr)


def find_kernel_directory(ipsec_dir: Path) -> Path:
    """
    Find the corresponding kernel directory for a userspace directory.

    If ipsec_dir is: results/20251013_135547/userspace/left
    Return: results/20251013_135547/kernel/left
    """
    if 'userspace' in ipsec_dir.parts:
        parts = list(ipsec_dir.parts)
        try:
            idx = parts.index('userspace')
            parts[idx] = 'kernel'
            kernel_dir = Path(*parts)
            if kernel_dir.exists():
                return kernel_dir
        except ValueError:
            pass
    return None


def convert_ipsec_to_tls_format(ipsec_dir: str, output_dir: str):
    """
    Main conversion function.
    """
    ipsec_path = Path(ipsec_dir)
    output_path = Path(output_dir)

    # Check input directory
    if not ipsec_path.exists():
        print(f"[ERROR] IPsec directory not found: {ipsec_dir}", file=sys.stderr)
        sys.exit(1)

    # Create output directory
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"\n{'='*70}")
    print(f"IPsec to TLS Format Conversion")
    print(f"{'='*70}")
    print(f"Input:  {ipsec_dir}")
    print(f"Output: {output_dir}")
    print()

    # Find kernel and network directories
    kernel_dir = find_kernel_directory(ipsec_path)
    pcap_file = find_network_pcap(ipsec_path)

    if kernel_dir:
        print(f"[*] Kernel directory found: {kernel_dir}")
    else:
        print(f"[INFO] No kernel directory found")

    if pcap_file:
        print(f"[*] Network pcap found: {pcap_file}")
    else:
        print(f"[INFO] No network pcap found")
    print()

    # Find all dump files
    dump_files = sorted(ipsec_path.glob("dump_*.bin"))
    if not dump_files:
        print(f"[ERROR] No dump files found in {ipsec_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Found {len(dump_files)} dump files")

    # Convert each dump file
    for dump_file in dump_files:
        timestamp = extract_timestamp_from_filename(str(dump_file))
        timing, event = extract_event_from_filename(str(dump_file))

        # Generate TLS-compatible filename
        if timing == "init":
            tls_filename = f"{timestamp}_init.dump"
        else:
            tls_filename = f"{timestamp}_{timing}_{event}.dump"

        output_file = output_path / tls_filename

        # Copy dump file
        shutil.copy2(str(dump_file), str(output_file))
        print(f"    {dump_file.name} -> {tls_filename}")

    print()

    # Parse watchpoint lifecycle data
    # Auto-detect timing CSV file (supports both strongSwan and LibreSwan)
    timing_file = None
    for csv_name in ["timing_libreswan.csv", "timing_strongswan.csv"]:
        candidate = ipsec_path / csv_name
        if candidate.exists():
            timing_file = candidate
            break

    lifecycle_data = {}
    if timing_file:
        lifecycle_data = parse_watchpoint_lifecycle(str(timing_file))
        print(f"[*] Parsed watchpoint lifecycle: {len(lifecycle_data)} keys tracked from {timing_file.name}")

    # Convert timing CSV if it exists
    keys_file = ipsec_path / "keys.json"
    if timing_file:
        output_timing = output_path / "timing_13.csv"
        convert_timing_csv(str(timing_file), str(output_timing), str(keys_file))
    else:
        print(f"[INFO] No timing file found (timing_libreswan.csv or timing_strongswan.csv)")
        print(f"       This is expected if watchpoints were not enabled")

    # Create lifecycle summary JSON
    if lifecycle_data or kernel_dir:
        output_lifecycle = output_path / "lifecycle_summary.json"
        create_lifecycle_summary(lifecycle_data, kernel_dir, str(output_lifecycle))

    # Convert keys.json to keylog
    if keys_file.exists():
        output_keylog = output_path / "keylog_ipsec.log"
        convert_keylog(str(keys_file), str(output_keylog))
    else:
        print(f"[WARNING] No keys.json found")

    # Copy network pcap file
    if pcap_file:
        output_pcap = output_path / "capture.pcap"
        shutil.copy2(str(pcap_file), str(output_pcap))
        print(f"[*] Copied network pcap: {pcap_file.name} -> capture.pcap")

    # Copy other useful files
    for filename in ['events.log', 'events.jsonl', 'keys.json', 'ikev2_decryption_table']:
        src = ipsec_path / filename
        if src.exists():
            dst = output_path / filename
            shutil.copy2(str(src), str(dst))
            print(f"[*] Copied: {filename}")

    # Copy kernel dumps if available
    if kernel_dir:
        kernel_output = output_path / "kernel"
        kernel_output.mkdir(exist_ok=True)

        # Copy XFRM JSON files
        for xfrm_file in kernel_dir.glob("xfrm_*.json"):
            dst = kernel_output / xfrm_file.name
            shutil.copy2(str(xfrm_file), str(dst))

        # Copy kernel memory dumps
        for dump_file in kernel_dir.glob("xfrm_memory_*.bin"):
            dst = kernel_output / dump_file.name
            shutil.copy2(str(dump_file), str(dst))

        print(f"[*] Copied kernel data to: {kernel_output.relative_to(output_path)}/")

    print()
    print(f"{'='*70}")
    print(f"Conversion complete!")
    print(f"{'='*70}")
    print()
    print(f"TLS-compatible results are in: {output_dir}")
    print()
    print(f"Output files:")
    print(f"  - dump files: {len(dump_files)} userspace memory dumps")
    if timing_file.exists():
        print(f"  - timing_13.csv: Watchpoint lifecycle timing")
    if lifecycle_data:
        print(f"  - lifecycle_summary.json: Complete lifecycle tracking")
    if keys_file.exists():
        print(f"  - keylog_ipsec.log: IKE and ESP keys")
    if pcap_file:
        print(f"  - capture.pcap: Network traffic capture")
    if kernel_dir:
        print(f"  - kernel/: Kernel XFRM states and memory dumps")
    print()
    print(f"You can now use TLS analysis tools on this directory:")
    print(f"  - timelining_events.py")
    print(f"  - find_secrets_in_dumps.py (TLS version)")
    print(f"  - timing.ipynb")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Convert IPsec results to TLS-compatible format",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Convert single results directory
    ./convert_ipsec_to_tls_format.py results/20251009_233529/userspace/left tls_compat/strongswan

    # Convert latest results
    ./convert_ipsec_to_tls_format.py $(ls -td results/*/userspace/left | head -1) tls_compat/strongswan_latest

    # Convert both left and right
    ./convert_ipsec_to_tls_format.py results/20251009_233529/userspace/left tls_compat/strongswan_left
    ./convert_ipsec_to_tls_format.py results/20251009_233529/userspace/right tls_compat/strongswan_right
"""
    )

    parser.add_argument(
        'ipsec_dir',
        help='Path to IPsec results directory (e.g., results/YYYYmmdd_HHMMSS/userspace/left)'
    )

    parser.add_argument(
        'output_dir',
        help='Path to output directory for TLS-compatible format'
    )

    args = parser.parse_args()

    convert_ipsec_to_tls_format(args.ipsec_dir, args.output_dir)


if __name__ == "__main__":
    main()
