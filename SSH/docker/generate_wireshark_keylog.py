#!/usr/bin/env python3
"""
Generate Wireshark SSH keylog from OpenSSH groundtruth keylog.

Wireshark SSH keylog format:
    <cookie_hex> SHARED_SECRET <K_hex>

Where:
- cookie_hex: 32-character hex string (16 bytes) from SSH_MSG_KEXINIT
- K_hex: Shared secret from Diffie-Hellman key exchange

Usage:
    python3 generate_wireshark_keylog.py --keylog data/keylogs/groundtruth.log \
        --out analysis/groundtruth/ssh_wireshark.keylog

    Optional: --pcap <file> to extract cookie if not in keylog
"""

import argparse
import re
import subprocess
import sys
import os
from pathlib import Path


def find_tshark():
    """
    Find tshark executable.
    Check PATH first, then macOS Wireshark.app location.
    """
    # Try PATH
    try:
        result = subprocess.run(['which', 'tshark'],
                              capture_output=True, text=True, check=False)
        if result.returncode == 0 and result.stdout.strip():
            tshark_path = result.stdout.strip()
            # Verify it's executable
            if os.path.isfile(tshark_path) and os.access(tshark_path, os.X_OK):
                print(f"✓ Found tshark in PATH: {tshark_path}")
                return tshark_path
    except Exception:
        pass

    # Try macOS Wireshark.app location
    macos_tshark = '/Applications/Wireshark.app/Contents/MacOS/tshark'
    if os.path.isfile(macos_tshark) and os.access(macos_tshark, os.X_OK):
        print(f"✓ Found tshark in Wireshark.app: {macos_tshark}")
        return macos_tshark

    # Not found
    print("ERROR: tshark not found!")
    print()
    print("tshark is required to extract SSH cookies from PCAP files.")
    print()
    print("Installation options:")
    print("  - macOS: brew install wireshark")
    print("  - Ubuntu: sudo apt-get install tshark")
    print("  - Manual: Download from https://www.wireshark.org/download.html")
    print()
    print("Expected locations checked:")
    print("  - System PATH (via 'which tshark')")
    print("  - /Applications/Wireshark.app/Contents/MacOS/tshark (macOS)")
    sys.exit(1)


def parse_groundtruth_keylog(keylog_path):
    """
    Parse OpenSSH groundtruth keylog.

    Returns list of sessions, each with:
        {
            'shared_secret': '<K_hex>',
            'cookie': '<cookie_hex>' or None,
            'session_id': '<session_id_hex>',
            'timestamp': <unix_timestamp>
        }
    """
    sessions = []
    current_session = {}

    with open(keylog_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # SHARED_SECRET line
            m = re.match(r'(\d+)\s+SHARED_SECRET\s+([0-9a-fA-F]+)', line)
            if m:
                timestamp = int(m.group(1))
                shared_secret = m.group(2).lower()

                # Start new session if we already have one
                if current_session:
                    sessions.append(current_session)

                current_session = {
                    'timestamp': timestamp,
                    'shared_secret': shared_secret,
                    'cookie': None,
                    'session_id': None
                }
                continue

            # COOKIE line
            m = re.search(r'COOKIE\s+([0-9a-fA-F]{32})', line)
            if m and current_session:
                current_session['cookie'] = m.group(1).lower()
                continue

            # SESSION_ID
            m = re.search(r'SESSION_ID\s+([0-9a-fA-F]+)', line)
            if m and current_session:
                current_session['session_id'] = m.group(1).lower()
                continue

    # Don't forget last session
    if current_session:
        sessions.append(current_session)

    return sessions


def extract_cookie_from_pcap(pcap_path, tshark_path):
    """
    Extract SSH cookie from PCAP using tshark.
    Returns first cookie found (as 32-character hex string).
    """
    try:
        # Extract SSH_MSG_KEXINIT packets
        # The cookie is in the ssh.cookie field
        cmd = [
            tshark_path,
            '-r', pcap_path,
            '-Y', 'ssh.cookie',  # Filter for SSH packets
            '-T', 'fields',
            '-e', 'ssh.cookie'
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Parse output - cookies are colon-separated hex
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Convert "aa:bb:cc:dd..." to "aabbccdd..."
            cookie_hex = line.replace(':', '').lower()

            # Validate it's 16 bytes (32 hex chars)
            if len(cookie_hex) == 32 and all(c in '0123456789abcdef' for c in cookie_hex):
                return cookie_hex

        return None

    except subprocess.CalledProcessError as e:
        print(f"Warning: tshark failed to extract cookie: {e}")
        return None
    except Exception as e:
        print(f"Warning: Error extracting cookie from PCAP: {e}")
        return None


def generate_wireshark_keylog(sessions, output_path):
    """
    Generate Wireshark SSH keylog file.

    Format: <cookie_hex> SHARED_SECRET <K_hex>
    """
    with open(output_path, 'w') as f:
        for session in sessions:
            cookie = session.get('cookie')
            K = session.get('shared_secret')

            if not K:
                print(f"Warning: Session at timestamp {session.get('timestamp')} has no shared secret")
                continue

            if not cookie:
                print(f"Warning: Session at timestamp {session.get('timestamp')} has no cookie")
                print(f"  You can extract it from PCAP with --pcap option")
                continue

            # Write Wireshark format
            f.write(f"{cookie} SHARED_SECRET {K}\n")

    print(f"\n✓ Wireshark keylog written to: {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Generate Wireshark SSH keylog from OpenSSH groundtruth keylog',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage (cookie in keylog):
  python3 generate_wireshark_keylog.py \\
      --keylog data/keylogs/groundtruth.log \\
      --out analysis/groundtruth/ssh_wireshark.keylog

  # Extract cookie from PCAP if missing:
  python3 generate_wireshark_keylog.py \\
      --keylog data/keylogs/groundtruth.log \\
      --pcap data/captures/groundtruth_server.pcap \\
      --out analysis/groundtruth/ssh_wireshark.keylog

Wireshark usage:
  1. Open Wireshark
  2. Edit → Preferences → Protocols → SSH
  3. Set "SSH key log file" to the generated .keylog file
  4. Open your PCAP and SSH traffic should be decrypted
        """
    )

    parser.add_argument('--keylog', required=True, help='Input groundtruth keylog file')
    parser.add_argument('--out', required=True, help='Output Wireshark keylog file')
    parser.add_argument('--pcap', help='Optional: PCAP file to extract cookie if not in keylog')

    args = parser.parse_args()

    # Validate input file
    if not os.path.isfile(args.keylog):
        print(f"ERROR: Keylog file not found: {args.keylog}")
        sys.exit(1)

    # Check for tshark (only if PCAP extraction might be needed)
    tshark_path = None
    if args.pcap:
        if not os.path.isfile(args.pcap):
            print(f"ERROR: PCAP file not found: {args.pcap}")
            sys.exit(1)
        tshark_path = find_tshark()

    # Parse groundtruth keylog
    print(f"Parsing keylog: {args.keylog}")
    sessions = parse_groundtruth_keylog(args.keylog)
    print(f"✓ Found {len(sessions)} session(s)")

    # Extract cookies from PCAP if needed and available
    if args.pcap and tshark_path:
        print(f"\nExtracting cookies from PCAP: {args.pcap}")
        pcap_cookie = extract_cookie_from_pcap(args.pcap, tshark_path)

        if pcap_cookie:
            print(f"✓ Extracted cookie from PCAP: {pcap_cookie}")
            # Apply to sessions that don't have a cookie
            for session in sessions:
                if not session.get('cookie'):
                    session['cookie'] = pcap_cookie
                    print(f"  → Applied to session at timestamp {session['timestamp']}")
        else:
            print("⚠ Could not extract cookie from PCAP")

    # Show session details
    print("\nSession details:")
    for i, session in enumerate(sessions, 1):
        print(f"  Session {i}:")
        print(f"    Timestamp:     {session['timestamp']}")
        print(f"    Shared Secret: {session['shared_secret'][:32]}... ({len(session['shared_secret'])} chars)")
        print(f"    Cookie:        {session.get('cookie', 'MISSING')}")
        sid = session.get('session_id')
        print(f"    Session ID:    {sid[:32] + '...' if sid else 'N/A'}")

    # Create output directory if needed
    out_dir = os.path.dirname(args.out)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir)
        print(f"\n✓ Created output directory: {out_dir}")

    # Generate Wireshark keylog
    print("\nGenerating Wireshark keylog...")
    generate_wireshark_keylog(sessions, args.out)

    print("\n" + "="*60)
    print("SUCCESS!")
    print("="*60)
    print(f"\nWireshark SSH keylog file: {args.out}")
    print("\nTo use in Wireshark:")
    print("  1. Open Wireshark")
    print("  2. Edit → Preferences → Protocols → SSH")
    print("  3. Set 'SSH key log file' to the path above")
    print("  4. Open your PCAP - SSH traffic should be decrypted")
    print()


if __name__ == '__main__':
    main()
