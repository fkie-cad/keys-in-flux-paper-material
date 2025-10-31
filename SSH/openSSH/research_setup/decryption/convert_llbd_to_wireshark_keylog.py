#!/usr/bin/env python3
"""
convert_llbd_to_wireshark_keylog.py

Usage:
  python3 convert_llbd_to_wireshark_keylog.py --lldb-keylog lldblog.txt --pcap capture.pcap --out wireshark_ssh_keys.txt

This will:
- extract the first big hex blob from the lldb keylog (assumed to be the shared secret)
- scan the pcap for an SSH_MSG_KEXINIT (message id 0x14) and extract the 16-byte cookie (heuristic)
- emit a Wireshark-compatible keylog line:
    <cookie_hex> SHARED_SECRET <shared_secret_hex>
"""
import argparse, re, sys
from scapy.all import rdpcap, TCP, Raw

def extract_hex_from_lldblog(path):
    txt = open(path,'r',errors='ignore').read()
    # find the largest hex blob (>=32 hex chars)
    blobs = re.findall(r'([0-9a-fA-F]{32,})', txt)
    if not blobs:
        return None
    # choose the longest blob (heuristic assuming shared secret is long)
    blobs.sort(key=len, reverse=True)
    return blobs[0]

def find_kexinit_cookie_in_pcap(pcap_path):
    pkts = rdpcap(pcap_path)
    for p in pkts:
        if Raw in p and TCP in p:
            b = bytes(p[Raw].load)
            # scan for byte 0x14 followed by at least 16 bytes
            for i in range(len(b)-17):
                if b[i] == 0x14:
                    cookie = b[i+1:i+1+16]
                    # sanity: cookie should be non printable mostly
                    if len(cookie) == 16:
                        return cookie.hex()
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--lldb-keylog', required=True)
    ap.add_argument('--pcap', required=True)
    ap.add_argument('--out', required=True)
    args = ap.parse_args()

    secret_hex = extract_hex_from_lldblog(args.lldb_keylog)
    if not secret_hex:
        print("ERROR: no hex blob found in LLDB keylog", file=sys.stderr)
        sys.exit(2)
    print("Using secret (len=%d hex chars)" % len(secret_hex))

    cookie_hex = find_kexinit_cookie_in_pcap(args.pcap)
    if not cookie_hex:
        print("WARNING: couldn't locate KEXINIT cookie in pcap; you may supply cookie manually.")
        # fallback: write with an all-zero cookie (not ideal)
        cookie_hex = "00"*16

    with open(args.out, 'w') as fh:
        fh.write(f"{cookie_hex} SHARED_SECRET {secret_hex}\n")
    print("Wrote keylog file:", args.out)
    print("Put this file in Wireshark Prefs (Protocols -> SSH -> (Key file)) or embed it in pcapng DSB.")

if __name__ == "__main__":
    main()
