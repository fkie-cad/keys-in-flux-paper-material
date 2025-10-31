#!/usr/bin/env python3
"""
SSH Secret Finder - Search for SSH secrets in memory dumps

This tool searches memory dumps for SSH secrets (shared secrets, session keys)
extracted from groundtruth keylogs. It generates an ASCII table showing which
secrets are present in which lifecycle stages.

Usage:
    ./find_ssh_secrets_in_dumps.py <results_dir>

Example:
    ./find_ssh_secrets_in_dumps.py ../data/dumps

Input:
    - Groundtruth keylog files: groundtruth_*.log (SHARED_SECRET, NEWKEYS format)
    - Memory dumps: dump_*.bin or *.dump files with lifecycle stage in filename

Output:
    - ASCII table showing secret presence across lifecycle stages
    - Summary statistics

Keylog Format:
    <timestamp> SHARED_SECRET <hex>
    <timestamp> NEWKEYS MODE IN CIPHER <name> KEY <hex> IV <hex>
    <timestamp> NEWKEYS MODE OUT CIPHER <name> KEY <hex> IV <hex>
    <timestamp> COOKIE <hex> CIPHER_IN <name> CIPHER_OUT <name> SESSION_ID <hex>
"""

import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Set, Tuple
from collections import defaultdict


def parse_keylog(keylog_file: Path) -> Dict[str, str]:
    """
    Parse groundtruth keylog file and extract secrets.

    Returns:
        Dictionary mapping secret_name -> hex_value
    """
    secrets = {}

    if not keylog_file.exists():
        print(f"Warning: Keylog file not found: {keylog_file}")
        return secrets

    with open(keylog_file, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 3:
                continue

            timestamp = parts[0]

            # Parse SHARED_SECRET
            if 'SHARED_SECRET' in line:
                # Format: <timestamp> SHARED_SECRET <hex>
                if len(parts) >= 3:
                    secret_hex = parts[2]
                    secrets['shared_secret_k'] = secret_hex
                    print(f"  [+] Loaded SHARED_SECRET ({len(secret_hex)//2} bytes)")

            # Parse NEWKEYS
            elif 'NEWKEYS' in line:
                # Format: <timestamp> NEWKEYS MODE IN/OUT CIPHER <name> KEY <hex> IV <hex>
                try:
                    mode_idx = parts.index('MODE')
                    direction = parts[mode_idx + 1]  # IN or OUT
                    key_idx = parts.index('KEY')
                    iv_idx = parts.index('IV')

                    key_hex = parts[key_idx + 1]
                    iv_hex = parts[iv_idx + 1]

                    secrets[f'cipher_key_{direction.lower()}'] = key_hex
                    secrets[f'cipher_iv_{direction.lower()}'] = iv_hex

                    print(f"  [+] Loaded NEWKEYS {direction}: KEY ({len(key_hex)//2} bytes), IV ({len(iv_hex)//2} bytes)")
                except (ValueError, IndexError) as e:
                    print(f"  [!] Warning: Failed to parse NEWKEYS line {line_num}: {e}")
                    continue

            # Parse COOKIE and SESSION_ID
            elif 'COOKIE' in line:
                # Format: <timestamp> COOKIE <hex> CIPHER_IN <name> CIPHER_OUT <name> SESSION_ID <hex>
                try:
                    cookie_idx = parts.index('COOKIE')
                    session_id_idx = parts.index('SESSION_ID')

                    cookie_hex = parts[cookie_idx + 1]
                    session_id_hex = parts[session_id_idx + 1]

                    secrets['cookie'] = cookie_hex
                    secrets['session_id'] = session_id_hex

                    print(f"  [+] Loaded COOKIE ({len(cookie_hex)//2} bytes), SESSION_ID ({len(session_id_hex)//2} bytes)")
                except (ValueError, IndexError) as e:
                    print(f"  [!] Warning: Failed to parse COOKIE line {line_num}: {e}")
                    continue

    return secrets


def extract_stage_from_filename(filename: str) -> str:
    """
    Extract lifecycle stage from dump filename.

    Examples:
        dump_init_20251018_184203.bin -> init
        dump_rekey_after_20251018.bin -> rekey_after
        post_kex_region_0.dump -> post_kex
        pre_kex_0x7f1234.dump -> pre_kex
    """
    # Common stage patterns
    stage_patterns = [
        r'dump_(\w+?)_\d{8}',         # dump_init_20251018
        r'dump_(\w+?)_',              # dump_rekey_
        r'(pre|post)_kex',            # pre_kex, post_kex
        r'dump_(\w+)\.bin',           # dump_init.bin
        r'(\w+?)_region',             # init_region
    ]

    for pattern in stage_patterns:
        match = re.search(pattern, filename)
        if match:
            return match.group(1)

    # Fallback: extract word before extension
    base = os.path.basename(filename)
    name_parts = base.replace('.bin', '').replace('.dump', '').split('_')
    if len(name_parts) >= 2:
        return name_parts[1]

    return 'unknown'


def search_secret_in_dump(dump_file: Path, secret_hex: str) -> bool:
    """
    Search for secret in dump file using sliding window approach.

    Args:
        dump_file: Path to memory dump
        secret_hex: Hex string of secret to search for

    Returns:
        True if secret found, False otherwise
    """
    try:
        secret_bytes = bytes.fromhex(secret_hex)
        chunk_size = 1024 * 1024  # 1MB chunks for large files

        with open(dump_file, 'rb') as f:
            # Overlap to handle secrets spanning chunk boundaries
            overlap = len(secret_bytes) - 1
            previous_chunk_tail = b''

            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Search in combined data
                search_data = previous_chunk_tail + chunk
                if secret_bytes in search_data:
                    return True

                # Keep tail for next iteration
                if len(chunk) == chunk_size:
                    previous_chunk_tail = chunk[-overlap:] if overlap > 0 else b''
                else:
                    break

        return False

    except Exception as e:
        print(f"  [!] Error searching {dump_file.name}: {e}")
        return False


def find_secrets_in_directory(results_dir: Path, secrets: Dict[str, str]) -> Dict[str, Dict[str, bool]]:
    """
    Search all dump files in directory for secrets.

    Returns:
        Dictionary: {stage_name: {secret_name: found_bool}}
    """
    results = defaultdict(lambda: defaultdict(bool))

    # Find all dump files
    dump_files = list(results_dir.glob('**/*.bin')) + list(results_dir.glob('**/*.dump'))

    if not dump_files:
        print(f"Warning: No dump files found in {results_dir}")
        return results

    print(f"\n[*] Searching {len(dump_files)} memory dumps for {len(secrets)} secrets...")

    for dump_file in sorted(dump_files):
        stage = extract_stage_from_filename(dump_file.name)

        print(f"\n  Analyzing: {dump_file.name} (stage: {stage})")

        for secret_name, secret_hex in secrets.items():
            if not secret_hex or secret_hex == 'unknown':
                continue

            found = search_secret_in_dump(dump_file, secret_hex)
            results[stage][secret_name] = results[stage][secret_name] or found

            if found:
                print(f"    ✓ Found {secret_name}")

    return results


def print_ascii_table(secrets: Dict[str, str], results: Dict[str, Dict[str, bool]]):
    """
    Print ASCII table showing secret presence across stages.
    """
    if not results:
        print("\n[!] No results to display")
        return

    # Get ordered stages
    stages = sorted(results.keys())
    secret_names = sorted(secrets.keys())

    print("\n" + "=" * 100)
    print("SSH Secret Presence Matrix")
    print("=" * 100)

    # Header
    header = f"{'Secret':<25}"
    for stage in stages:
        header += f" | {stage:^15}"
    print(header)
    print("-" * len(header))

    # Rows
    for secret_name in secret_names:
        row = f"{secret_name:<25}"
        for stage in stages:
            found = results[stage].get(secret_name, False)
            symbol = "✓" if found else "✗"
            row += f" | {symbol:^15}"
        print(row)

    print("=" * 100)
    print()


def print_summary(secrets: Dict[str, str], results: Dict[str, Dict[str, bool]]):
    """
    Print summary statistics.
    """
    total_secrets = len(secrets)
    total_stages = len(results)

    print("\n" + "=" * 60)
    print("Summary Statistics")
    print("=" * 60)

    print(f"Total secrets loaded:     {total_secrets}")
    print(f"Total lifecycle stages:   {total_stages}")

    # Count secrets found per stage
    print("\nSecrets found per stage:")
    for stage in sorted(results.keys()):
        found_count = sum(1 for found in results[stage].values() if found)
        percentage = (found_count / total_secrets * 100) if total_secrets > 0 else 0
        print(f"  {stage:20s}: {found_count}/{total_secrets} ({percentage:.1f}%)")

    # Count stages where each secret appears
    print("\nSecret persistence across stages:")
    for secret_name in sorted(secrets.keys()):
        stage_count = sum(1 for stage in results.keys() if results[stage].get(secret_name, False))
        percentage = (stage_count / total_stages * 100) if total_stages > 0 else 0
        print(f"  {secret_name:25s}: {stage_count}/{total_stages} stages ({percentage:.1f}%)")

    print("=" * 60)
    print()


def main():
    if len(sys.argv) < 2:
        print("Usage: ./find_ssh_secrets_in_dumps.py <results_dir>")
        print("\nExample: ./find_ssh_secrets_in_dumps.py ../data/dumps")
        sys.exit(1)

    results_dir = Path(sys.argv[1])
    if not results_dir.exists():
        print(f"Error: Results directory does not exist: {results_dir}")
        sys.exit(1)

    print("=" * 60)
    print("SSH Secret Finder - Memory Dump Analysis")
    print("=" * 60)

    # Find keylog files (support both groundtruth and ssh_keylog formats)
    keylog_patterns = ["groundtruth_*.log", "ssh_keylog_*.log", "*keylog*.log"]
    keylog_files = []

    for pattern in keylog_patterns:
        files = list(results_dir.glob(pattern))
        if files:
            keylog_files.extend(files)
            break  # Found files with this pattern, no need to try others

    if not keylog_files:
        # Try parent directory
        for pattern in keylog_patterns:
            files = list(results_dir.parent.glob("keylogs/" + pattern))
            if files:
                keylog_files.extend(files)
                break

    if not keylog_files:
        print(f"\nError: No keylog files found")
        print(f"  Searched patterns: {', '.join(keylog_patterns)}")
        print(f"  Searched: {results_dir}/")
        print(f"  Searched: {results_dir.parent}/keylogs/")
        print(f"\nExpected format: groundtruth_*.log or ssh_keylog_*.log")
        sys.exit(1)

    # Load secrets from all keylog files
    all_secrets = {}
    for keylog_file in keylog_files:
        print(f"\n[*] Loading secrets from: {keylog_file.name}")
        secrets = parse_keylog(keylog_file)
        all_secrets.update(secrets)

    if not all_secrets:
        print("\n[!] No secrets loaded from keylog files")
        sys.exit(1)

    print(f"\n[*] Total secrets loaded: {len(all_secrets)}")

    # Search dumps
    results = find_secrets_in_directory(results_dir, all_secrets)

    # Display results
    print_ascii_table(all_secrets, results)
    print_summary(all_secrets, results)


if __name__ == "__main__":
    main()
