#!/usr/bin/env python3
"""
SSH Keylog Parser

Parses openssh_groundtruth keylog format and creates KeyLifespanEntry objects.

Supported Formats:
1. NEWKEYS format: <timestamp> NEWKEYS MODE <IN|OUT> CIPHER <cipher> KEY <hex> IV <hex>
2. COOKIE format: <timestamp> COOKIE <cookie> CIPHER_IN <c> CIPHER_OUT <c> SESSION_ID <sid>

Author: SSH Key Lifecycle Lab
"""

import re
import sys
from pathlib import Path
from typing import List, Optional
from key_lifespan import KeyLifespanEntry, SessionLifespan, create_key_id


def extract_server_from_filename(filepath: Path) -> str:
    """
    Extract server name from keylog filename
    E.g., groundtruth_openssh.log → openssh
    """
    filename = filepath.stem  # Remove .log extension
    parts = filename.split('_')
    if len(parts) >= 2:
        return parts[-1]  # Last part is server name
    return "unknown"


def parse_newkeys_line(line: str) -> Optional[dict]:
    """
    Parse NEWKEYS format line
    Format: <timestamp> NEWKEYS MODE <IN|OUT> CIPHER <cipher> KEY <hex> IV <hex>

    Example:
    1760378380 NEWKEYS MODE IN CIPHER chacha20-poly1305@openssh.com KEY a76d2323... IV unknown
    """
    parts = line.strip().split()

    if len(parts) < 10 or 'NEWKEYS' not in line:
        return None

    try:
        # Find indices of keywords
        mode_idx = parts.index('MODE') + 1 if 'MODE' in parts else None
        cipher_idx = parts.index('CIPHER') + 1 if 'CIPHER' in parts else None
        key_idx = parts.index('KEY') + 1 if 'KEY' in parts else None
        iv_idx = parts.index('IV') + 1 if 'IV' in parts else None

        if not all([mode_idx, cipher_idx, key_idx]):
            return None

        return {
            'timestamp': float(parts[0]),
            'mode': parts[mode_idx],
            'cipher': parts[cipher_idx],
            'key_hex': parts[key_idx],
            'iv_hex': parts[iv_idx] if iv_idx else "unknown"
        }

    except (ValueError, IndexError):
        return None


def parse_cookie_line(line: str) -> Optional[dict]:
    """
    Parse COOKIE format line
    Format: <timestamp> COOKIE <cookie> CIPHER_IN <c> CIPHER_OUT <c> SESSION_ID <sid>

    This format is less common but included for completeness
    """
    parts = line.strip().split()

    if len(parts) < 8 or 'COOKIE' not in line:
        return None

    try:
        cookie_idx = parts.index('COOKIE') + 1
        cipher_in_idx = parts.index('CIPHER_IN') + 1
        cipher_out_idx = parts.index('CIPHER_OUT') + 1
        session_id_idx = parts.index('SESSION_ID') + 1

        return {
            'timestamp': float(parts[0]),
            'cookie': parts[cookie_idx],
            'cipher_in': parts[cipher_in_idx],
            'cipher_out': parts[cipher_out_idx],
            'session_id': parts[session_id_idx]
        }

    except (ValueError, IndexError):
        return None


def parse_keylog_file(keylog_path: Path) -> List[KeyLifespanEntry]:
    """
    Parse complete keylog file and return list of KeyLifespanEntry objects
    """
    if not keylog_path.exists():
        raise FileNotFoundError(f"Keylog file not found: {keylog_path}")

    server = extract_server_from_filename(keylog_path)
    entries = []
    key_sequence = {}  # Track sequence numbers per session+mode

    with open(keylog_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue

            # Try parsing as NEWKEYS format
            newkeys_data = parse_newkeys_line(line)
            if newkeys_data:
                timestamp = newkeys_data['timestamp']
                mode = newkeys_data['mode']
                session_id = str(int(timestamp))  # Use timestamp as session ID

                # Track sequence number for this session+mode
                key = f"{session_id}_{mode}"
                seq = key_sequence.get(key, 0)
                key_sequence[key] = seq + 1

                # Determine if this is a rekey (sequence > 0)
                is_rekey = seq > 0

                entry = KeyLifespanEntry(
                    key_id=create_key_id(session_id, mode, seq),
                    server=server,
                    session_id=session_id,
                    derived_at=timestamp,
                    mode=mode,
                    cipher=newkeys_data['cipher'],
                    key_hex=newkeys_data['key_hex'],
                    key_length=len(newkeys_data['key_hex']) // 2,  # Hex is 2 chars per byte
                    iv_hex=newkeys_data['iv_hex'],
                    is_rekey=is_rekey,
                    rekey_trigger='client' if is_rekey else 'initial'
                )

                entries.append(entry)

    return entries


def parse_experiment_keylogs(data_dir: Path) -> dict:
    """
    Parse all experiment keylogs in a directory

    Returns: dict mapping server_name -> List[KeyLifespanEntry]
    """
    keylog_dir = data_dir / 'keylogs'
    if not keylog_dir.exists():
        raise FileNotFoundError(f"Keylog directory not found: {keylog_dir}")

    results = {}

    # Find all groundtruth_*.log files
    for keylog_file in keylog_dir.glob('groundtruth_*.log'):
        server = extract_server_from_filename(keylog_file)
        try:
            entries = parse_keylog_file(keylog_file)
            results[server] = entries
            print(f"Parsed {len(entries)} keys from {keylog_file.name}")
        except Exception as e:
            print(f"Error parsing {keylog_file.name}: {e}")

    return results


def create_session_from_keys(keys: List[KeyLifespanEntry]) -> SessionLifespan:
    """
    Create a SessionLifespan object from a list of keys
    """
    if not keys:
        raise ValueError("Cannot create session from empty key list")

    session = SessionLifespan(
        session_id=keys[0].session_id,
        server=keys[0].server,
        started_at=min(k.derived_at for k in keys)
    )

    for key in keys:
        session.add_key(key)

    # Set end time to last key derivation (or last packet if available)
    last_times = [k.last_packet_at or k.derived_at for k in keys]
    session.ended_at = max(last_times)

    return session


def print_key_summary(keys: List[KeyLifespanEntry]):
    """Print human-readable summary of parsed keys"""
    if not keys:
        print("No keys found")
        return

    print(f"\n{'='*70}")
    print(f"KEY EXTRACTION SUMMARY - {keys[0].server.upper()}")
    print(f"{'='*70}")

    for i, key in enumerate(keys, 1):
        rekey_marker = " [REKEY]" if key.is_rekey else ""
        print(f"\n[{i}] {key.key_id}{rekey_marker}")
        print(f"    Mode:      {key.mode}")
        print(f"    Cipher:    {key.cipher}")
        print(f"    Derived:   {key.derived_at}")
        print(f"    Key:       {key.key_hex[:64]}...")
        print(f"    Key Len:   {key.key_length} bytes")


def main():
    """CLI for testing keylog parser"""
    import argparse

    parser = argparse.ArgumentParser(description='Parse SSH keylogs')
    parser.add_argument('keylog', type=Path,
                       help='Path to keylog file or data directory')
    parser.add_argument('--summary', action='store_true',
                       help='Print human-readable summary')
    parser.add_argument('--json', action='store_true',
                       help='Output as JSON')

    args = parser.parse_args()

    try:
        if args.keylog.is_file():
            # Parse single file
            keys = parse_keylog_file(args.keylog)

            if args.summary:
                print_key_summary(keys)
            elif args.json:
                import json
                session = create_session_from_keys(keys)
                print(json.dumps(session.to_dict(), indent=2))
            else:
                print(f"Parsed {len(keys)} keys from {args.keylog}")
                for key in keys:
                    print(f"  {key.key_id}: {key.mode} {key.cipher}")

        elif args.keylog.is_dir():
            # Parse all keylogs in directory
            results = parse_experiment_keylogs(args.keylog)

            print(f"\n{'='*70}")
            print("EXPERIMENT KEY EXTRACTION SUMMARY")
            print(f"{'='*70}")
            for server, keys in results.items():
                rekey_count = sum(1 for k in keys if k.is_rekey)
                print(f"{server:12s}: {len(keys):3d} keys ({rekey_count} rekeys)")

        else:
            print(f"Error: {args.keylog} is neither a file nor directory")
            return 1

        return 0

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
