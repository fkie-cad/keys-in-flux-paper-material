#!/usr/bin/env python3
"""
find_ipsec_secrets.py

Search for IPsec secrets (IKE SA and ESP keys) in memory dumps and generate
an ASCII table showing secret presence/absence at each lifecycle stage.

Usage:
    ./find_ipsec_secrets.py <results_directory> [--full-details]

    Example:
    ./find_ipsec_secrets.py results/20251009_233529/userspace/left

Output:
    - ASCII table showing which secrets were found in which dumps (key secrets only by default)
    - Summary statistics
    - Last found location for key secrets (SKEYSEED, sk_d, sk_ei, sk_er, ENCR_i, ENCR_r)
    - Watchpoint lifecycle information (created, overwritten)
    - Kernel space tracking (XFRM state dumps and forensic scans)

Flags:
    --full-details: Show all keys (sk_ai, sk_ar, sk_pi, sk_pr, INTEG_i, INTEG_r) in addition to key secrets
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple
from datetime import datetime
import argparse


def search_secret_in_dump(dump_file: str, secret_hex: str) -> bool:
    """
    Search for a hex-encoded secret in a binary dump file.

    Args:
        dump_file: Path to the binary dump file
        secret_hex: Hex-encoded secret (e.g., "9de846d8dd510084...")

    Returns:
        True if secret found, False otherwise
    """
    try:
        # Convert hex string to bytes
        secret_bytes = bytes.fromhex(secret_hex)

        # Read dump file in chunks to handle large files
        chunk_size = 1024 * 1024  # 1MB chunks
        with open(dump_file, 'rb') as f:
            # Use a sliding window approach to handle secrets that span chunks
            overlap = len(secret_bytes) - 1
            previous_chunk_tail = b''

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Search in previous tail + current chunk
                search_data = previous_chunk_tail + chunk
                if secret_bytes in search_data:
                    return True

                # Save tail for next iteration
                previous_chunk_tail = chunk[-overlap:] if len(chunk) >= overlap else chunk

        return False

    except FileNotFoundError:
        print(f"[WARNING] Dump file not found: {dump_file}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"[ERROR] Failed to search in {dump_file}: {e}", file=sys.stderr)
        return False


def extract_stage_from_filename(filename: str) -> str:
    """
    Extract lifecycle stage from dump filename.

    Examples:
        dump_init_20251009_233547_815012.bin -> init
        dump_before_handshake_20251009_233559_372910.bin -> before_handshake
        dump_after_handshake_20251009_233601_353314.bin -> after_handshake
    """
    basename = os.path.basename(filename)
    if basename.startswith("dump_"):
        # Remove "dump_" prefix and timestamp suffix
        parts = basename[5:].split("_")
        # Find where timestamp starts (YYYYMMDD format)
        for i, part in enumerate(parts):
            if part.isdigit() and len(part) == 8:
                # Join everything before the timestamp
                return "_".join(parts[:i])

        # Fallback: just remove .bin extension
        return basename[5:].replace(".bin", "")

    return basename


def load_keys(keys_file: str) -> Dict[str, List[Dict]]:
    """
    Load keys from keys.json file.

    Returns:
        Dictionary with 'ike_sa' and 'esp' lists
    """
    try:
        with open(keys_file, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] Keys file not found: {keys_file}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"[ERROR] Invalid JSON in {keys_file}: {e}", file=sys.stderr)
        sys.exit(1)


def parse_watchpoint_lifecycle(csv_file: str) -> Dict[str, Dict]:
    """
    Parse timing CSV (timing_libreswan.csv or timing_strongswan.csv) to extract watchpoint lifecycle information.

    Returns:
        Dictionary mapping key names to lifecycle info:
        {
            'sk_ei': {
                'created': '2025-10-13T13:56:14.425837',
                'created_address': '0xf1239803eb80',
                'overwritten': '2025-10-13T13:56:16.895367',
                'overwritten_address': '0xf1239803eb80',
                'overwrite_count': 5
            },
            ...
        }
    """
    lifecycle = {}

    if not os.path.exists(csv_file):
        return lifecycle

    try:
        import csv
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Handle both "event" and " event" (with leading space)
                event = (row.get('event') or row.get(' event', '')).strip()
                key_name = (row.get('key_name') or row.get(' key_name', '')).strip()
                timestamp = (row.get('timestamp') or row.get(' timestamp', '')).strip()
                address = (row.get('address') or row.get(' address', '')).strip()

                if not key_name:
                    continue

                # Normalize key name (SK_ei -> sk_ei, ENCR_i -> ENCR_i)
                normalized_key = key_name

                if normalized_key not in lifecycle:
                    lifecycle[normalized_key] = {
                        'overwrite_count': 0,
                        'overwrite_events': []
                    }

                # Parse _set events (key creation)
                if event.endswith('_set'):
                    lifecycle[normalized_key]['created'] = timestamp
                    lifecycle[normalized_key]['created_address'] = address

                # Parse _overwritten events (key overwrites)
                elif event.endswith('_overwritten'):
                    lifecycle[normalized_key]['overwrite_count'] += 1
                    lifecycle[normalized_key]['overwrite_events'].append({
                        'timestamp': timestamp,
                        'address': address
                    })
                    # Store the last overwrite
                    lifecycle[normalized_key]['overwritten'] = timestamp
                    lifecycle[normalized_key]['overwritten_address'] = address

    except Exception as e:
        print(f"[WARNING] Failed to parse {csv_file}: {e}", file=sys.stderr)

    return lifecycle


def parse_kernel_xfrm_files(kernel_dir: Path) -> Dict[str, List[Dict]]:
    """
    Parse kernel XFRM JSON files to extract ESP key information.

    Returns:
        Dictionary with checkpoint names mapping to list of XFRM states:
        {
            'after_handshake': [
                {'spi_out': 0x12345678, 'spi_in': 0x87654321,
                 'encr_key_out': '...', 'encr_key_in': '...', ...}
            ],
            ...
        }
    """
    xfrm_data = {}

    if not kernel_dir.exists():
        return xfrm_data

    # Find all xfrm_*.json files (not forensic files)
    xfrm_files = sorted(kernel_dir.glob("xfrm_*.json"))

    for xfrm_file in xfrm_files:
        # Skip forensic files
        if 'forensic' in xfrm_file.name:
            continue

        try:
            with open(xfrm_file, 'r') as f:
                data = json.load(f)

            # Extract checkpoint name from filename
            # Format: xfrm_after_handshake_20251009_233601.json
            filename = xfrm_file.stem  # Remove .json
            parts = filename.split('_')
            # Find where timestamp starts
            checkpoint_parts = []
            for part in parts[1:]:  # Skip 'xfrm' prefix
                if part.isdigit() and len(part) == 8:
                    break
                checkpoint_parts.append(part)
            checkpoint = '_'.join(checkpoint_parts) if checkpoint_parts else 'unknown'

            xfrm_data[checkpoint] = data.get('xfrm_states', [])

        except Exception as e:
            print(f"[WARNING] Failed to parse {xfrm_file}: {e}", file=sys.stderr)

    return xfrm_data


def parse_kernel_forensic_files(kernel_dir: Path) -> Dict[str, Dict]:
    """
    Parse kernel forensic JSON files to extract freed key residues.

    Returns:
        Dictionary with checkpoint names mapping to forensic findings:
        {
            'after_terminate': {
                'freelist_residues': [...],
                'stack_residues': [...],
                'vmalloc_residues': [...]
            }
        }
    """
    forensic_data = {}

    if not kernel_dir.exists():
        return forensic_data

    forensic_files = sorted(kernel_dir.glob("xfrm_forensic_*.json"))

    for forensic_file in forensic_files:
        try:
            with open(forensic_file, 'r') as f:
                data = json.load(f)

            checkpoint = data.get('checkpoint', 'unknown')
            forensic_data[checkpoint] = {
                'freelist_residues': data.get('findings', {}).get('freelist', []),
                'stack_residues': data.get('findings', {}).get('stack', []),
                'vmalloc_residues': data.get('findings', {}).get('vmalloc', [])
            }

        except Exception as e:
            print(f"[WARNING] Failed to parse {forensic_file}: {e}", file=sys.stderr)

    return forensic_data


def search_in_kernel_dumps(kernel_dir: Path, secret_hex: str) -> List[Tuple[str, str]]:
    """
    Search for a secret in kernel memory dumps.

    Returns:
        List of (checkpoint, dump_file) tuples where secret was found
    """
    found_locations = []

    if not kernel_dir.exists():
        return found_locations

    # Search xfrm_memory_*.bin files
    dump_files = sorted(kernel_dir.glob("xfrm_memory_*.bin"))

    for dump_file in dump_files:
        if search_secret_in_dump(str(dump_file), secret_hex):
            # Extract checkpoint from filename
            filename = dump_file.stem
            # Format: xfrm_memory_after_handshake_20251009_233601
            parts = filename.split('_')
            checkpoint_parts = []
            for part in parts[2:]:  # Skip 'xfrm' and 'memory'
                if part.isdigit() and len(part) == 8:
                    break
                checkpoint_parts.append(part)
            checkpoint = '_'.join(checkpoint_parts) if checkpoint_parts else 'unknown'

            found_locations.append((checkpoint, str(dump_file)))

    return found_locations


def find_kernel_directory(results_dir: Path) -> Optional[Path]:
    """
    Find the corresponding kernel directory for a userspace results directory.

    If results_dir is: results/20251009_233529/userspace/left
    Return: results/20251009_233529/kernel/left
    """
    # Check if we're in a userspace directory
    if 'userspace' in results_dir.parts:
        # Replace 'userspace' with 'kernel'
        parts = list(results_dir.parts)
        try:
            idx = parts.index('userspace')
            parts[idx] = 'kernel'
            kernel_dir = Path(*parts)
            if kernel_dir.exists():
                return kernel_dir
        except ValueError:
            pass

    # Alternative: Look for sibling kernel directory
    parent = results_dir.parent
    if parent.name in ['left', 'right']:
        # We're in userspace/left or userspace/right
        kernel_dir = parent.parent / 'kernel' / parent.name
        if kernel_dir.exists():
            return kernel_dir

    return None


def find_secrets_in_dumps(results_dir: str, full_details: bool = False):
    """
    Main function to search for secrets in dumps and generate ASCII table.

    Args:
        results_dir: Path to results directory (userspace)
        full_details: If True, show all keys; if False, only show key secrets
    """
    results_path = Path(results_dir)

    # Check if results directory exists
    if not results_path.exists():
        print(f"[ERROR] Results directory not found: {results_dir}", file=sys.stderr)
        sys.exit(1)

    # Load keys
    keys_file = results_path / "keys.json"
    if not keys_file.exists():
        print(f"[ERROR] keys.json not found in {results_dir}", file=sys.stderr)
        sys.exit(1)

    keys = load_keys(str(keys_file))

    # Find kernel directory
    kernel_dir = find_kernel_directory(results_path)
    has_kernel = kernel_dir is not None

    # Parse watchpoint lifecycle data from timing CSV
    # Auto-detect timing CSV file (supports both strongSwan and LibreSwan)
    timing_csv = None
    for csv_name in ["timing_libreswan.csv", "timing_strongswan.csv"]:
        candidate = results_path / csv_name
        if candidate.exists():
            timing_csv = candidate
            break

    if timing_csv:
        watchpoint_lifecycle = parse_watchpoint_lifecycle(str(timing_csv))
        print(f"[*] Using timing file: {timing_csv.name}")
    else:
        watchpoint_lifecycle = {}
        print(f"[INFO] No timing CSV found (watchpoints may not have been enabled)")

    # Parse kernel XFRM data
    kernel_xfrm_data = {}
    kernel_forensic_data = {}
    if has_kernel:
        kernel_xfrm_data = parse_kernel_xfrm_files(kernel_dir)
        kernel_forensic_data = parse_kernel_forensic_files(kernel_dir)

    # Find all userspace dump files
    dump_files = sorted(results_path.glob("dump_*.bin"))
    if not dump_files:
        print(f"[ERROR] No dump files found in {results_dir}", file=sys.stderr)
        sys.exit(1)

    # Extract stages from filenames
    stages = [extract_stage_from_filename(str(f)) for f in dump_files]

    # Build search matrix
    # Format: {key_name: {stage: found (bool)}}
    search_results = {}

    # Track last dump where each key secret was found (for summary)
    # Format: {key_name: {'userspace': (stage, dump_path), 'kernelspace': [(checkpoint, dump_path), ...]}}
    last_found = {}

    # Track kernel findings
    # Format: {key_name: {checkpoint: [found_in_xfrm, found_in_dump, found_in_forensic]}}
    kernel_findings = {}

    print(f"\n{'='*70}")
    print(f"IPsec Secret Search in Memory Dumps")
    print(f"{'='*70}")
    print(f"Results directory: {results_dir}")
    print(f"Number of userspace dumps: {len(dump_files)}")
    if has_kernel:
        print(f"Kernel directory: {kernel_dir}")
    else:
        print(f"Kernel directory: Not found (kernel dumps not available)")
    print(f"Lifecycle stages: {', '.join(stages)}")
    print()

    # Process IKE SA keys
    print("[*] Searching for IKE SA keys in userspace dumps...")
    for i, ike_sa in enumerate(keys.get('ike_sa', [])):
        print(f"    IKE SA #{i+1}:")
        for key_name in ['SKEYSEED', 'SKEYSEED_rekey', 'sk_d', 'sk_ei', 'sk_er', 'sk_ai', 'sk_ar', 'sk_pi', 'sk_pr']:
            if key_name in ike_sa:
                secret_hex = ike_sa[key_name]
                full_key_name = f"IKE_{i+1}_{key_name}" if len(keys.get('ike_sa', [])) > 1 else key_name

                if full_key_name not in search_results:
                    search_results[full_key_name] = {}

                if full_key_name not in last_found:
                    last_found[full_key_name] = {}

                print(f"      - {key_name}: {secret_hex[:16]}...")

                # Search userspace dumps
                for stage, dump_file in zip(stages, dump_files):
                    found = search_secret_in_dump(str(dump_file), secret_hex)
                    search_results[full_key_name][stage] = found

                    # Track last occurrence for IKE key secrets
                    if found and key_name in ['SKEYSEED', 'SKEYSEED_rekey', 'sk_d', 'sk_ei', 'sk_er', 'sk_ai', 'sk_ar', 'sk_pi', 'sk_pr']:
                        last_found[full_key_name]['userspace'] = (stage, str(dump_file))

                # Search kernel dumps (IKE keys typically not in kernel, but check anyway)
                if has_kernel:
                    kernel_locations = search_in_kernel_dumps(kernel_dir, secret_hex)
                    if kernel_locations:
                        last_found[full_key_name]['kernelspace'] = kernel_locations

    # Search kernel dumps for ESP keys
    if has_kernel and keys.get('esp'):
        print("\n[*] Searching for ESP keys in kernel dumps and XFRM data...")
        print(f"    Kernel directory: {kernel_dir}")
        print(f"    XFRM checkpoints: {len(kernel_xfrm_data)}")
        print(f"    Forensic checkpoints: {len(kernel_forensic_data)}")

    # Process ESP keys
    if keys.get('esp'):
        print("\n[*] Searching for ESP keys in userspace dumps...")
        for i, esp_sa in enumerate(keys.get('esp', [])):
            print(f"    ESP SA #{i+1} (SPI: {esp_sa.get('spi', 'unknown')}):")

            # Handle both formats:
            # 1. Direct format: ENCR_i, ENCR_r, INTEG_i, INTEG_r
            # 2. Keylog format: enc_key, auth_key
            key_mappings = []

            # Check for direct format
            if 'ENCR_i' in esp_sa or 'ENCR_r' in esp_sa:
                key_mappings = [
                    ('ENCR_i', 'ENCR_i'),
                    ('INTEG_i', 'INTEG_i'),
                    ('ENCR_r', 'ENCR_r'),
                    ('INTEG_r', 'INTEG_r')
                ]
            # Check for keylog format
            elif 'enc_key' in esp_sa or 'auth_key' in esp_sa:
                # Determine direction from SPI
                spi = esp_sa.get('spi', '')
                if 'OUT' in spi or i % 2 == 0:  # First in pair is typically outbound
                    key_mappings = [
                        ('enc_key', 'ENCR_i'),
                        ('auth_key', 'INTEG_i')
                    ]
                else:  # Second is inbound
                    key_mappings = [
                        ('enc_key', 'ENCR_r'),
                        ('auth_key', 'INTEG_r')
                    ]

            for json_key, display_key in key_mappings:
                if json_key in esp_sa:
                    secret_hex = esp_sa[json_key]
                    full_key_name = f"ESP_{i+1}_{display_key}" if len(keys.get('esp', [])) > 1 else display_key

                    if full_key_name not in search_results:
                        search_results[full_key_name] = {}

                    if full_key_name not in last_found:
                        last_found[full_key_name] = {}

                    print(f"      - {display_key}: {secret_hex[:16]}...")

                    # Search userspace dumps
                    for stage, dump_file in zip(stages, dump_files):
                        found = search_secret_in_dump(str(dump_file), secret_hex)
                        search_results[full_key_name][stage] = found

                        # Track last occurrence for ESP key secrets
                        if found and key_name in ['ENCR_i', 'ENCR_r', 'INTEG_i', 'INTEG_r']:
                            last_found[full_key_name]['userspace'] = (stage, str(dump_file))

                    # Search kernel dumps (ESP keys ARE in kernel - this is critical!)
                    if has_kernel:
                        kernel_locations = search_in_kernel_dumps(kernel_dir, secret_hex)
                        if kernel_locations:
                            last_found[full_key_name]['kernelspace'] = kernel_locations
                            if full_key_name not in kernel_findings:
                                kernel_findings[full_key_name] = {}
                            for checkpoint, dump_path in kernel_locations:
                                if checkpoint not in kernel_findings[full_key_name]:
                                    kernel_findings[full_key_name][checkpoint] = {
                                        'found_in_dump': True,
                                        'dump_path': dump_path
                                    }

                        # Check XFRM JSON files for ESP keys
                        for checkpoint, xfrm_states in kernel_xfrm_data.items():
                            for state in xfrm_states:
                                # Check encryption keys
                                for xfrm_key_field in ['encr_key_out', 'encr_key_in', 'auth_key_out', 'auth_key_in']:
                                    if xfrm_key_field in state:
                                        xfrm_key_hex = state[xfrm_key_field].replace(' ', '')
                                        if xfrm_key_hex == secret_hex:
                                            if full_key_name not in kernel_findings:
                                                kernel_findings[full_key_name] = {}
                                            if checkpoint not in kernel_findings[full_key_name]:
                                                kernel_findings[full_key_name][checkpoint] = {}
                                            kernel_findings[full_key_name][checkpoint]['found_in_xfrm'] = True
                                            kernel_findings[full_key_name][checkpoint]['xfrm_field'] = xfrm_key_field

                        # Check forensic files
                        for checkpoint, forensic in kernel_forensic_data.items():
                            for residue_type in ['freelist_residues', 'stack_residues', 'vmalloc_residues']:
                                for residue in forensic.get(residue_type, []):
                                    if residue.get('key_hex', '').replace(' ', '') == secret_hex:
                                        if full_key_name not in kernel_findings:
                                            kernel_findings[full_key_name] = {}
                                        if checkpoint not in kernel_findings[full_key_name]:
                                            kernel_findings[full_key_name][checkpoint] = {}
                                        if 'forensic' not in kernel_findings[full_key_name][checkpoint]:
                                            kernel_findings[full_key_name][checkpoint]['forensic'] = []
                                        kernel_findings[full_key_name][checkpoint]['forensic'].append(residue_type.replace('_residues', ''))

    # Filter keys to display based on full_details flag
    # Key secrets: SKEYSEED, sk_d, sk_ei, sk_er, ENCR_i, ENCR_r
    key_secrets = ['SKEYSEED', 'SKEYSEED_rekey', 'sk_d', 'sk_ei', 'sk_er', 'ENCR_i', 'ENCR_r']
    if full_details:
        keys_to_display = sorted(search_results.keys())
    else:
        # Only show key secrets (filter out IKE_*_ prefix if present)
        keys_to_display = []
        for key_name in sorted(search_results.keys()):
            # Extract base name (e.g., "IKE_1_sk_ei" -> "sk_ei", "ENCR_i" -> "ENCR_i")
            base_name = key_name.split('_')[-2] + '_' + key_name.split('_')[-1] if '_' in key_name and key_name.count('_') >= 2 else key_name
            if any(ks in key_name for ks in key_secrets):
                keys_to_display.append(key_name)

    # Generate ASCII table
    print(f"\n{'='*70}")
    print("Secret Presence Matrix")
    if not full_details:
        print("(Showing key secrets only - use --full-details for all keys)")
    print(f"{'='*70}")
    print()

    if not keys_to_display:
        print("[WARNING] No keys to display")
    else:
        # Calculate column widths
        key_col_width = max(len(k) for k in keys_to_display) + 2
        stage_col_width = max(max(len(s) for s in stages), 5) + 2

        # Print header
        header = f"{'Key Name':<{key_col_width}}"
        for stage in stages:
            header += f"{stage:^{stage_col_width}}"
        print(header)
        print("-" * len(header))

        # Print rows
        for key_name in keys_to_display:
            row = f"{key_name:<{key_col_width}}"
            for stage in stages:
                found = search_results[key_name].get(stage, False)
                symbol = "✓" if found else "✗"
                row += f"{symbol:^{stage_col_width}}"
            print(row)

    print()

    # Generate statistics
    print(f"{'='*70}")
    print("Summary Statistics")
    print(f"{'='*70}")
    print()

    total_keys = len(search_results)
    total_searches = total_keys * len(stages)
    total_found = sum(1 for key_results in search_results.values()
                     for found in key_results.values() if found)

    print(f"Total keys tracked: {total_keys}")
    print(f"Total dumps analyzed: {len(dump_files)}")
    print(f"Total searches performed: {total_searches}")
    print(f"Secrets found: {total_found} ({total_found/total_searches*100:.1f}%)")
    print()

    # Per-key statistics
    print("Per-key statistics:")
    for key_name in sorted(search_results.keys()):
        found_count = sum(1 for found in search_results[key_name].values() if found)
        total_dumps = len(search_results[key_name])
        print(f"  {key_name}: {found_count}/{total_dumps} dumps ({found_count/total_dumps*100:.0f}%)")

    print()

    # Per-stage statistics
    print("Per-stage statistics:")
    for stage in stages:
        found_count = sum(1 for key_results in search_results.values()
                         if key_results.get(stage, False))
        print(f"  {stage}: {found_count}/{total_keys} keys ({found_count/total_keys*100:.0f}%)")

    print()

    # Last Found Summary (for key secrets) with Lifecycle Information
    print(f"{'='*70}")
    print("Key Secrets - Lifecycle Tracking")
    print(f"{'='*70}")
    print()

    key_secrets = ['SKEYSEED', 'SKEYSEED_rekey', 'sk_d', 'sk_ei', 'sk_er', 'ENCR_i', 'ENCR_r']
    for secret in key_secrets:
        # Handle both simple key names and IKE_1_/ESP_1_ prefixed names
        full_key_name = None
        for key in last_found.keys():
            if key == secret or key.endswith(f"_{secret}"):
                full_key_name = key
                break

        print(f"{'─' * 70}")
        print(f"{secret}")
        print(f"{'─' * 70}")

        # Show watchpoint lifecycle
        # Map display name to CSV key name (sk_ei -> SK_ei, ENCR_i -> ENCR_i)
        watchpoint_key_variants = [
            secret,  # Direct match (ENCR_i)
            secret.upper().replace('SK_', 'SK_'),  # SK_ei -> SK_ei
            'SK_' + secret.split('_')[1] if secret.startswith('sk_') else None  # sk_ei -> SK_ei
        ]

        wpl = None
        for variant in watchpoint_key_variants:
            if variant and variant in watchpoint_lifecycle:
                wpl = watchpoint_lifecycle[variant]
                break

        if wpl:
            print("  Watchpoint Tracking:")
            if 'created' in wpl:
                print(f"    Created:     {wpl['created']}")
                if 'created_address' in wpl:
                    print(f"                 Address: {wpl['created_address']}")
            if 'overwritten' in wpl:
                overwrite_count = wpl.get('overwrite_count', 0)
                print(f"    Overwritten: {wpl['overwritten']} ({overwrite_count} times total)")
                if 'overwritten_address' in wpl:
                    print(f"                 Address: {wpl['overwritten_address']}")
            if 'created' not in wpl and 'overwritten' not in wpl:
                print("    No watchpoint data available")
            print()
        else:
            print("  Watchpoint Tracking: No data available")
            print()

        # Show userspace findings
        if full_key_name and full_key_name in last_found and 'userspace' in last_found[full_key_name]:
            stage, dump_path = last_found[full_key_name]['userspace']
            print("  Userspace:")
            print(f"    Last found:  {stage}")
            print(f"    Dump file:   {Path(dump_path).name}")
        else:
            print("  Userspace:")
            print(f"    NOT FOUND in any userspace dump")
        print()

        # Show kernelspace findings
        if has_kernel:
            print("  Kernelspace:")
            if full_key_name and full_key_name in last_found and 'kernelspace' in last_found[full_key_name]:
                kernel_locs = last_found[full_key_name]['kernelspace']
                if kernel_locs:
                    last_checkpoint, last_dump = kernel_locs[-1]  # Last one
                    print(f"    Last found in kernel dump: {last_checkpoint}")
                    print(f"    Dump file:   {Path(last_dump).name}")

                    # Show XFRM and forensic details
                    if full_key_name in kernel_findings:
                        for checkpoint, findings in kernel_findings[full_key_name].items():
                            if findings.get('found_in_xfrm'):
                                print(f"    XFRM state:  Found in checkpoint '{checkpoint}' as {findings.get('xfrm_field', 'unknown')}")
                            if findings.get('forensic'):
                                forensic_types = ', '.join(findings['forensic'])
                                print(f"    Forensic:    Found in checkpoint '{checkpoint}' ({forensic_types})")
                else:
                    print("    NOT FOUND in kernel dumps")
            else:
                print("    NOT FOUND in kernel dumps")

                # But check if found in XFRM or forensic
                if full_key_name and full_key_name in kernel_findings:
                    for checkpoint, findings in kernel_findings[full_key_name].items():
                        if findings.get('found_in_xfrm'):
                            print(f"    XFRM state:  Found in checkpoint '{checkpoint}' as {findings.get('xfrm_field', 'unknown')}")
                        if findings.get('forensic'):
                            forensic_types = ', '.join(findings['forensic'])
                            print(f"    Forensic:    Found in checkpoint '{checkpoint}' ({forensic_types})")
        else:
            print("  Kernelspace: Not available (no kernel directory)")

        print()

    print(f"{'='*70}")


def main():
    parser = argparse.ArgumentParser(
        description="Search for IPsec secrets in memory dumps",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Search in a specific results directory (key secrets only)
    ./find_ipsec_secrets.py results/20251009_233529/userspace/left

    # Show all keys including integrity and auth keys
    ./find_ipsec_secrets.py results/20251009_233529/userspace/left --full-details

    # Search in latest results
    ./find_ipsec_secrets.py $(ls -td results/*/userspace/left | head -1)
"""
    )

    parser.add_argument(
        'results_dir',
        help='Path to results directory containing keys.json and dump files'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--full-details',
        action='store_true',
        help='Show all keys (default: only show key secrets SKEYSEED, sk_d, sk_ei, sk_er, ENCR_i, ENCR_r)'
    )

    args = parser.parse_args()

    find_secrets_in_dumps(args.results_dir, full_details=args.full_details)


if __name__ == "__main__":
    main()
