#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Parse XFRM SAs/policies from either:
  (A) live namespace:   ip netns exec <ns> bash -lc 'ip xfrm state; echo; ip xfrm policy'
  (B) a mixed text file that may contain sections like:
        [LEFT] SAs:
        [RIGHT] SAs:
        [LEFT] XFRM:
        [RIGHT] XFRM:
…and scan a directory of *.bin memory dumps for the keys.

Usage examples:
  # Basic (namespace 'left', dump dir given)
  ./scan_xfrm_keys.py -n left -d /tmp/xfrm-dump-4026532323-20250925-163637

  # If you already captured text to a file:
  ./scan_xfrm_keys.py -n left -d /tmp/xfrm-dump-... --xfrm-text /path/to/xfrm.txt

  # Show up to 50 matches per key and include ASCII-hex search (default on)
  ./scan_xfrm_keys.py -n left -d /tmp/xfrm-dump-... --max-hits 50

Notes:
- We decide initiator/responder by whether SA.src is an IPv4 in the selected netns.
- We scan for raw bytes first, then ASCII-hex; results are de-duplicated per file/offset.
"""

import argparse, subprocess, sys, re, os, mmap, ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple

# ---------- shell helpers ----------

def run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(e.output.decode("utf-8", "replace"), file=sys.stderr)
        return ""

def get_ipv4_in_netns(ns: str) -> List[str]:
    txt = run(["ip", "-n", ns, "-o", "-4", "addr", "show"])
    ips = []
    for line in txt.splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+\b", line)
        if m:
            ips.append(m.group(1))
    return ips

# ---------- text extraction for mixed files ----------

SECTION_HDR_RE = re.compile(r"(?mi)^\[(?P<label>[A-Za-z0-9_ -]+)\]\s*(?::|\s)\s*$")

def extract_block(text: str, wanted_label: str) -> Optional[str]:
    """
    Extract the block that starts at a line exactly like:  [WANTED_LABEL] XFRM:
    and ends before the next line that begins with '[' (next section) or EOF.
    """
    # Accept "XFRM:" header lines for the chosen side.
    pat = re.compile(rf"(?mi)^\[{re.escape(wanted_label)}\]\s*XFRM:\s*$")
    m = pat.search(text)
    if not m:
        return None
    start = m.end()
    # next section or EOF
    m2 = re.search(r"(?m)^\[[^\]\n]+\][^\n]*$", text[start:])
    end = start + (m2.start() if m2 else len(text) - start)
    block = text[start:end].strip()
    return block if block else None

def extract_left_ips_from_sas(text: str, side_label: str = "LEFT") -> List[str]:
    """
    Try to infer local IPv4(s) from the '[LEFT] SAs:' block:
      local  'left' @ 10.0.0.1[4500]
    """
    # Find the [LEFT] SAs: block, then scan a reasonable window after it.
    pat = re.compile(rf"(?mi)^\[{re.escape(side_label)}\]\s*SAs:\s*$")
    m = pat.search(text)
    if not m:
        return []
    tail = text[m.end():]
    # Stop at next section header
    m2 = re.search(r"(?m)^\[[^\]\n]+\][^\n]*$", tail)
    if m2:
        tail = tail[:m2.start()]
    ips = []
    for line in tail.splitlines():
        # 'local  'left' @ 10.0.0.1[4500]'
        mm = re.search(r"\blocal\b.*?@[\s]*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
        if mm:
            ips.append(mm.group(1))
    return ips

# ---------- tiny utils ----------

def normalize_hex_key(s: str) -> str:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return re.sub(r"[^0-9a-fA-F]", "", s).lower()

def hex_to_bytes(s: str) -> bytes:
    s = normalize_hex_key(s)
    if len(s) % 2 == 1:
        s = "0" + s
    return bytes.fromhex(s)

def find_all(b: bytes, sub: bytes, max_hits: int = 1000) -> List[int]:
    if not sub:
        return []
    hits, start = [], 0
    while True:
        idx = b.find(sub, start)
        if idx == -1:
            break
        hits.append(idx)
        if len(hits) >= max_hits:
            break
        start = idx + 1
    return hits

# ---------- XFRM parsing ----------

@dataclass
class SA:
    src: str
    dst: str
    spi: str
    mode: str
    enc_algo: Optional[str] = None
    enc_key_hex: Optional[str] = None
    auth_algo: Optional[str] = None
    auth_key_hex: Optional[str] = None
    dir_hint: Optional[str] = None  # 'initiator' or 'responder'

@dataclass
class ParseResult:
    states: List[SA] = field(default_factory=list)
    policies_raw: str = ""

STATE_HDR_RE = re.compile(r"^\s*src\s+(\S+)\s+dst\s+(\S+)\s*$")
PROTO_RE     = re.compile(r"^\s*proto\s+(\S+)\s+spi\s+(\S+)\s+reqid\s+\S+\s+mode\s+(\S+)\s*$")
ENC_RE       = re.compile(r"^\s*enc\s+(\S+)\s+(0x)?([0-9A-Fa-f]+)\s*$")
AUTH_RE      = re.compile(r"^\s*auth(?:-trunc)?\s+(\S+)\s+(0x)?([0-9A-Fa-f]+)\b")

def parse_xfrm_text(text: str) -> ParseResult:
    parts = text.splitlines()
    # split into states vs policies at first blank line
    blank_idx = next((i for i,l in enumerate(parts) if l.strip() == ""), len(parts))
    state_lines = parts[:blank_idx]
    policy_lines = parts[blank_idx+1:]

    states: List[SA] = []
    cur: Optional[SA] = None
    for line in state_lines:
        m = STATE_HDR_RE.match(line)
        if m:
            if cur:
                states.append(cur)
            cur = SA(src=m.group(1), dst=m.group(2), spi="", mode="")
            continue
        if not cur:
            continue
        m = PROTO_RE.match(line)
        if m:
            cur.spi  = m.group(2).lower()
            cur.mode = m.group(3)
            continue
        m = ENC_RE.match(line)
        if m:
            cur.enc_algo = m.group(1)
            cur.enc_key_hex = (m.group(2) or "") + m.group(3)
            continue
        m = AUTH_RE.match(line)
        if m:
            cur.auth_algo = m.group(1)
            cur.auth_key_hex = (m.group(2) or "") + m.group(3)
            continue
    if cur:
        states.append(cur)

    return ParseResult(states=states, policies_raw="\n".join(policy_lines))

def classify_dirs(states: List[SA], left_ips: List[str]) -> None:
    left_set = set(left_ips)
    for sa in states:
        s = sa.src.split("/")[0]
        try:
            src_ip = ipaddress.ip_address(s)
            sa.dir_hint = "initiator" if str(src_ip) in left_set else "responder"
        except ValueError:
            sa.dir_hint = None

# ---------- key scanning ----------

@dataclass
class KeySpec:
    label: str
    raw: bytes
    hexstr: str
    owner: str   # initiator/responder/unknown
    kind: str    # enc/auth

@dataclass
class Hit:
    path: str
    offset: int

def build_keys(states: List[SA]) -> Tuple[List[KeySpec], List[KeySpec]]:
    enc, auth = [], []
    for sa in states:
        role = sa.dir_hint or "unknown"
        route = f"{sa.src}->{sa.dst}"
        if sa.enc_key_hex:
            hx = normalize_hex_key(sa.enc_key_hex)
            enc.append(KeySpec(
                label=f"enc ({role}) spi={sa.spi} {route}",
                raw=hex_to_bytes(hx), hexstr=hx, owner=role, kind="enc"
            ))
        if sa.auth_key_hex:
            hx = normalize_hex_key(sa.auth_key_hex)
            auth.append(KeySpec(
                label=f"auth ({role}) spi={sa.spi} {route}",
                raw=hex_to_bytes(hx), hexstr=hx, owner=role, kind="auth"
            ))
    return enc, auth

def scan_file_for_key(path: str, key: KeySpec, max_hits: int, scan_ascii: bool) -> List[Hit]:
    hits = []
    try:
        with open(path, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            # raw
            for off in find_all(mm, key.raw, max_hits=max_hits):
                hits.append(Hit(path, off))
            if scan_ascii:
                h = key.hexstr.encode("ascii")
                for off in find_all(mm, h, max_hits=max_hits): hits.append(Hit(path, off))
                h0 = b"0x" + h
                for off in find_all(mm, h0, max_hits=max_hits): hits.append(Hit(path, off))
    except (FileNotFoundError, PermissionError):
        pass
    # dedup
    uniq = {(h.path, h.offset): h for h in hits}
    return list(uniq.values())

def scan_dir_for_keys(dump_dir: str, keys: List[KeySpec], max_hits: int, scan_ascii: bool) -> Dict[str, List[Hit]]:
    files = [os.path.join(dump_dir, p) for p in os.listdir(dump_dir) if p.endswith(".bin")]
    files.sort()
    out: Dict[str, List[Hit]] = {k.label: [] for k in keys}
    for k in keys:
        for p in files:
            out[k.label].extend(scan_file_for_key(p, k, max_hits, scan_ascii))
    return out

# ---------- CLI ----------

def main():
    ap = argparse.ArgumentParser(description="Parse XFRM keys (from netns or mixed file) and scan dumps.")
    ap.add_argument("-n", "--netns", default="left", help="network namespace name (default: left)")
    ap.add_argument("-d", "--dump-dir", required=True, help="directory with *.bin memory dumps")
    ap.add_argument("--from-file", help="path to mixed file containing [LEFT]/[RIGHT] SAs/XFRM sections")
    ap.add_argument("--side", choices=["LEFT","RIGHT"], default="LEFT", help="which [SIDE] XFRM section to parse (default: LEFT)")
    ap.add_argument("--left-ip", action="append", default=[], help="explicit local IP(s) to mark initiator; can be given multiple times")
    ap.add_argument("--no-ascii", action="store_true", help="do not search for ASCII-hex copies of keys")
    ap.add_argument("--max-hits", type=int, default=200, help="max matches per key per file (default: 200)")
    args = ap.parse_args()

    # 1) Obtain the XFRM text (either from file's [SIDE] XFRM block or live netns)
    if args.from_file:
        with open(args.from_file, "r", encoding="utf-8", errors="replace") as fh:
            whole = fh.read()
        block = extract_block(whole, args.side)
        if not block:
            print(f"[!] No '[{args.side}] XFRM:' block found. Falling back to parsing entire file.", file=sys.stderr)
            xfrm_txt = whole
        else:
            xfrm_txt = block
        # For initiator inference, try: --left-ip > netns lookup > [LEFT] SAs inference
        left_ips = list(args.left_ip)
        if not left_ips:
            # try live netns (optional)
            ips_ns = get_ipv4_in_netns(args.netns)
            left_ips = ips_ns if ips_ns else extract_left_ips_from_sas(whole, side_label=args.side)
            if not left_ips:
                print("[!] Could not infer local IPs (no --left-ip, netns empty, and no IPs in SAs). Direction may be 'unknown'.", file=sys.stderr)
    else:
        # Live mode
        xfrm_txt = run(["ip", "netns", "exec", args.netns, "bash", "-lc", "ip xfrm state; echo; ip xfrm policy"])
        left_ips = list(args.left_ip) or get_ipv4_in_netns(args.netns)

    if not xfrm_txt.strip():
        print("[!] No XFRM text to parse. Abort.", file=sys.stderr)
        sys.exit(2)

    # 2) Parse and classify
    parsed = parse_xfrm_text(xfrm_txt)
    if not parsed.states:
        print("[!] No XFRM states parsed. Abort.", file=sys.stderr)
        sys.exit(2)
    if left_ips:
        classify_dirs(parsed.states, left_ips)
    else:
        for s in parsed.states: s.dir_hint = "unknown"

    # 3) Build keys; enc first
    enc_keys, auth_keys = build_keys(parsed.states)

    # 4) Scan
    if not os.path.isdir(args.dump_dir):
        print(f"[!] Dump dir not found: {args.dump_dir}", file=sys.stderr)
        sys.exit(2)
    res_enc  = scan_dir_for_keys(args.dump_dir, enc_keys,  args.max_hits, scan_ascii=(not args.no_ascii))
    res_auth = scan_dir_for_keys(args.dump_dir, auth_keys, args.max_hits, scan_ascii=(not args.no_ascii))

    # 5) Report: ENC first, then AUTH; show initiator/responder split
    def report(title: str, results: Dict[str, List]):
        print(f"\n=== {title} ===")
        printed_any = False
        labels = list(results.keys())
        # keep original order of enc/auth construction
        for ks in (enc_keys if title.startswith("ENC") else auth_keys):
            label = ks.label
            hits = results.get(label, [])
            role = "INITIATOR" if ks.owner == "initiator" else ("RESPONDER" if ks.owner == "responder" else "UNKNOWN")
            print(f"\n- {label}  [{role}]")
            if not hits:
                print("  (no occurrences)")
            else:
                printed_any = True
                for h in sorted(hits, key=lambda x: (x.path, x.offset)):
                    print(f"  {h.path}: offset 0x{h.offset:x} ({h.offset} bytes)")
        return printed_any

    any1 = report("ENC KEY OCCURRENCES",  res_enc)
    any2 = report("AUTH KEY OCCURRENCES", res_auth)
    if not (any1 or any2):
        print("\n[!] No key occurrences found in the dumps.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()