#!/usr/bin/env python3
# read_llbd_keylog.py
"""
Read LLDB-style keylog and write a JSON file mapping flows/cipher-roles to raw key/iv.

Usage:
  python3 read_llbd_keylog.py /tmp/ssh-keys/ssh_keylog.txt keys.json
"""

import sys, json, re
from pathlib import Path

def parse_line(line):
    # Example flexible formats:
    # 2025-10-08T12:34:56 KEX-A 0a1b2c... cipher=aes128-ctr dir=client2server iv=0011...
    parts = line.strip().split()
    if len(parts) < 2:
        return None
    # label may be second token
    label = parts[1]
    # the rest may contain a hex blob or key=... + metadata
    rest = " ".join(parts[2:])
    # if a direct hex blob (no key=), accept that as 'key'
    m_hex = re.search(r'\b([0-9a-fA-F]{32,})\b', rest)
    key = None
    if m_hex:
        key = m_hex.group(1)
    # optional key=... iv=... cipher=... dir=
    kvs = {}
    for m in re.finditer(r'(\w+)=([^\s]+)', rest):
        kvs[m.group(1)] = m.group(2)
    if 'key' in kvs:
        key = kvs['key']
    iv = kvs.get('iv', None)
    cipher = kvs.get('cipher', None)
    direction = kvs.get('dir', None)
    return {
        "label": label,
        "key_hex": key,
        "iv_hex": iv,
        "cipher": cipher,
        "direction": direction,
        "raw": rest
    }

def main():
    if len(sys.argv) != 3:
        print("Usage: read_llbd_keylog.py <in_keylog> <out_json>")
        sys.exit(1)
    inpath = Path(sys.argv[1])
    outpath = Path(sys.argv[2])
    if not inpath.exists():
        print("input not found:", inpath)
        sys.exit(1)
    rows = []
    for line in inpath.read_text().splitlines():
        p = parse_line(line)
        if p and p['key_hex']:
            rows.append(p)
    outpath.write_text(json.dumps(rows, indent=2))
    print("wrote", outpath, "with", len(rows), "entries")

if __name__ == "__main__":
    main()
