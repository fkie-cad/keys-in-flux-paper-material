#!/usr/bin/env python3
"""
make_ikev2_table.py

Create a Wireshark ikev2_decryption_table entry from SK_* keys + a capture (pcap).
Optionally also emit an esp_sa entry if child/ESP keys are provided.

Requires: tshark (for extracting SPIs and optional esp info)
Usage examples:
  # Minimal (provide SK_* on CLI; PCAP must contain IKE_SA_INIT)
  ./make_ikev2_table.py -p left-handshake.pcap \
    --sk-ei a8fc7ec3...d4aae195 \
    --sk-er dc4e2a91...5fb4265a \
    --sk-ai 1094469b...0d34c \
    --sk-ar eabdefc7...0ff9ce \
    -o ikev2_decryption_table.txt

  # Provide keys from a JSON or key=value file
  ./make_ikev2_table.py -p left-handshake.pcap --keys-file keys.json

  # Also generate esp_sa (pass child keys or include in keys-file)
  ./make_ikev2_table.py -p left-handshake.pcap --keys-file keys.txt --emit-esp \
    --esp-out esp_sa.txt

Key names accepted (case-insensitive) in file or CLI:
  sk_ei, sk_er, sk_ai, sk_ar
  enc_algo (IKE encryption name), integ_algo (IKE integrity name)
  child_enc_key, child_auth_key, child_enc_algo, child_auth_algo
  child_spi, child_src, child_dst


Further Examples:
  ./make_ikev2_table.py -p left-handshake.pcap --keys-file keys.json -o ikev2_decryption_table.txt
  ./make_ikev2_table.py -p left-handshake.pcap --keys-file keys.json --emit-esp --esp-out esp_sa.txt
"""
import argparse
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from typing import Dict, Optional, Tuple, List

HEX32_RE = re.compile(r'^[0-9a-f]{64}$', re.IGNORECASE)   # 32 bytes -> 64 hex chars
SPI_RE   = re.compile(r'^[0-9a-f]{16}$', re.IGNORECASE)   #  8 bytes -> 16 hex chars

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

def norm_hex(s: str) -> str:
    s = s.strip()
    if s.startswith(('0x','0X')):
        s = s[2:]
    s = re.sub(r'[^0-9a-fA-F]', '', s)
    return s.lower()

def _maybe_add_macos_wireshark_to_path():
    if sys.platform != "darwin":
        return
    candidates = [
        "/Applications/Wireshark.app/Contents/MacOS",
        os.path.expanduser("~/Applications/Wireshark.app/Contents/MacOS"),
    ]
    cur = os.environ.get("PATH", "")
    parts = cur.split(os.pathsep) if cur else []
    changed = False
    for d in candidates:
        if os.path.isdir(d) and d not in parts:
            parts.append(d)
            changed = True
    if changed:
        os.environ["PATH"] = os.pathsep.join(parts)

def check_tshark():
    if shutil.which('tshark') is not None:
        return
    _maybe_add_macos_wireshark_to_path()
    if shutil.which('tshark') is None:
        eprint("ERROR: tshark not found. Install Wireshark or add it to PATH "
               "(e.g., /Applications/Wireshark.app/Contents/MacOS on macOS).")
        sys.exit(2)

def run_tshark_fields(pcap: str, display_filter: str, fields: List[str], count: Optional[int]=None) -> List[tuple]:
    """
    Run tshark and return fields as tuples. Any tshark error returns [].
    """
    cmd = ['tshark', '-r', pcap, '-Y', display_filter, '-T', 'fields']
    for f in fields:
        cmd += ['-e', f]
    if count:
        cmd += ['-c', str(count)]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return []
    lines = [ln for ln in out.splitlines() if ln.strip()]
    results = []
    for ln in lines:
        parts = ln.split('\t')
        while len(parts) < len(fields):
            parts.append('')
        results.append(tuple(parts))
    return results

def _pick_valid_spi_pair(rows: List[tuple]) -> Optional[Tuple[str,str]]:
    """
    From rows of (init,resp), return first pair with valid lengths and non-zero responder SPI.
    """
    for init, resp in rows:
        spi_i = norm_hex(init or '')
        spi_r = norm_hex(resp or '')
        if not (SPI_RE.match(spi_i) and SPI_RE.match(spi_r)):
            continue
        if spi_r == '0000000000000000':
            continue
        return spi_i, spi_r
    return None

def extract_ike_spis(pcap: str) -> Tuple[str,str]:
    """
    Extract IKE SPIs (initiator/responder) from PCAP.

    Order of attempts (failures are swallowed):
      1) isakmp.exchange_type==35 (IKE_AUTH), fields isakmp.ispi/rspi  [BEST]
      2) isakmp (any),             fields isakmp.ispi/rspi
      3) ikev2.msg.type==35,       fields ikev2.init_spi/resp_spi
      4) ikev2 (any),              fields ikev2.init_spi/resp_spi
      5) isakmp.exchange_type==35, fields isakmp.init_cookie/resp_cookie
      6) isakmp (any),             fields isakmp.init_cookie/resp_cookie
      7) isakmp (any),             fields isakmp.initiator_cookie/responder_cookie
    """
    attempts = [
        ('isakmp && isakmp.exchange_type==35', ['isakmp.ispi','isakmp.rspi']),
        ('isakmp',                              ['isakmp.ispi','isakmp.rspi']),
        ('ikev2 && ikev2.msg.type==35',        ['ikev2.init_spi','ikev2.resp_spi']),
        ('ikev2',                              ['ikev2.init_spi','ikev2.resp_spi']),
        ('isakmp && isakmp.exchange_type==35', ['isakmp.init_cookie','isakmp.resp_cookie']),
        ('isakmp',                              ['isakmp.init_cookie','isakmp.resp_cookie']),
        ('isakmp',                              ['isakmp.initiator_cookie','isakmp.responder_cookie']),
    ]

    for flt, flds in attempts:
        rows = run_tshark_fields(pcap, flt, flds, count=10)
        pair = _pick_valid_spi_pair(rows)
        if pair:
            return pair

    # Only now show a helpful error once.
    sample = subprocess.getoutput(
        f'tshark -r {shlex.quote(pcap)} -Y "isakmp || ikev2" '
        '-T fields -e frame.number -e ip.src -e ip.dst '
        '-e isakmp.ispi -e isakmp.rspi -e isakmp.init_cookie -e isakmp.resp_cookie '
        '-e ikev2.init_spi -e ikev2.resp_spi -c 6'
    )
    raise RuntimeError(
        "Could not find IKE SPIs in the pcap using common fields.\n"
        "Tips:\n"
        " - Ensure the pcap contains IKE_AUTH (both SPIs present).\n"
        " - Or pass --ike-spi-init <hex16> --ike-spi-resp <hex16> manually.\n"
        f"Sample field dump:\n{sample}"
    )

def extract_esp_info(pcap: str) -> Optional[Tuple[str,str,str]]:
    rows = run_tshark_fields(pcap, 'esp', ['ip.src','ip.dst','esp.spi'], count=10)
    for src,dst,spi in rows:
        if src and dst and spi:
            return (src.strip(), dst.strip(), norm_hex(spi))
    return None

def read_keys_file(path: str) -> Dict[str,str]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path,'r') as f:
        txt = f.read().strip()
    # JSON?
    try:
        data = json.loads(txt)
        if isinstance(data, dict):
            return {k.lower(): str(v) for k,v in data.items()}
    except Exception:
        pass
    # key=value lines
    data = {}
    for ln in txt.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith('#'):
            continue
        if '=' in ln:
            k,v = ln.split('=',1)
            data[k.strip().lower()] = v.strip()
    return data

def build_ikev2_line(spi_i: str, spi_r: str, sk_ei: str, sk_er: str, enc_algo: str, sk_ai: str, sk_ar: str, integ_algo: str) -> str:
    return ','.join([
        spi_i,
        spi_r,
        sk_ei,
        sk_er,
        f'"{enc_algo}"',
        sk_ai,
        sk_ar,
        f'"{integ_algo}"'
    ])

def build_esp_sa_line(src: str, dst: str, spi: str, enc_algo: str, enc_key: str, auth_algo: str, auth_key: str) -> str:
    spi_pref  = '0x' + spi
    enc_pref  = '0x' + enc_key
    auth_pref = '0x' + auth_key if auth_key else ''
    return ','.join([
        '"ESP"',
        f'"{src}"',
        f'"{dst}"',
        f'"{spi_pref}"',
        f'"{enc_algo}"',
        f'"{enc_pref}"',
        f'"{auth_algo}"' if auth_algo else '""',
        f'"{auth_pref}"' if auth_pref else '""'
    ])

def validate_sk(name: str, value: str) -> str:
    v = norm_hex(value)
    if not HEX32_RE.match(v):
        raise ValueError(f"{name} must be 32 bytes (64 hex chars). Got length {len(v)}: {value}")
    return v

def validate_spi(val: str) -> str:
    v = norm_hex(val)
    if not SPI_RE.match(v):
        raise ValueError(f"SPI must be 8 bytes (16 hex chars). Got '{val}' -> '{v}'")
    return v

def main():
    parser = argparse.ArgumentParser(description="Create Wireshark ikev2_decryption_table entry (and optional esp_sa)")
    parser.add_argument('-p','--pcap', required=True, help='PCAP with IKE handshake')
    parser.add_argument('--sk-ei', help='SK_ei hex')
    parser.add_argument('--sk-er', help='SK_er hex')
    parser.add_argument('--sk-ai', help='SK_ai hex')
    parser.add_argument('--sk-ar', help='SK_ar hex')
    parser.add_argument('--enc-algo', default='AES-CBC-256 [RFC3602]', help='IKE encryption algorithm string for Wireshark')
    parser.add_argument('--integ-algo', default='HMAC_SHA2_256_128 [RFC4868]', help='IKE integrity algorithm string for Wireshark')
    parser.add_argument('--keys-file', help='JSON or key=value file with keys')
    parser.add_argument('--ike-spi-init', help='Override: IKE initiator SPI (16 hex chars)')
    parser.add_argument('--ike-spi-resp', help='Override: IKE responder  SPI (16 hex chars)')
    parser.add_argument('-o','--out', default='ikev2_decryption_table.txt', help='Output file for ikev2_decryption_table')
    parser.add_argument('--emit-esp', action='store_true', help='Also emit an esp_sa line if child keys provided')
    parser.add_argument('--esp-out', default='esp_sa.txt', help='Output file for esp_sa')
    parser.add_argument('--child-enc-key', help='Child (ESP) encryption key hex')
    parser.add_argument('--child-auth-key', help='Child (ESP) auth key hex (if separate)')
    parser.add_argument('--child-enc-algo', help='Child enc algo string (e.g. cbc(aes) or gcm(aes))')
    parser.add_argument('--child-auth-algo', help='Child auth algo string (e.g. hmac(sha256) 128)')
    parser.add_argument('--child-spi', help='Child SPI (hex, 16 chars) for esp_sa')
    parser.add_argument('--child-src', help='Child SA src IP (for esp_sa)')
    parser.add_argument('--child-dst', help='Child SA dst IP (for esp_sa)')
    args = parser.parse_args()

    check_tshark()

    values: Dict[str,str] = {}
    if args.keys_file:
        try:
            values = read_keys_file(args.keys_file)
        except Exception as e:
            eprint("Failed to read keys file:", e)
            sys.exit(1)

    def pick(*names):
        for k in names:
            v = values.get(k)
            if v:
                return v
        return None

    sk_ei = args.sk_ei or pick('sk_ei','sk-ei','skey_ei','skeyei')
    sk_er = args.sk_er or pick('sk_er','sk-er','skey_er','skeyer')
    sk_ai = args.sk_ai or pick('sk_ai','sk-ai','skey_ai','skeyai')
    sk_ar = args.sk_ar or pick('sk_ar','sk-ar','skey_ar','skeyar')

    if not all([sk_ei, sk_er, sk_ai, sk_ar]):
        eprint("Missing SK_* values. Provide --sk-ei/--sk-er/--sk-ai/--sk-ar or a keys-file with those entries.")
        sys.exit(1)

    try:
        sk_ei = validate_sk('SK_ei', sk_ei)
        sk_er = validate_sk('SK_er', sk_er)
        sk_ai = validate_sk('SK_ai', sk_ai)
        sk_ar = validate_sk('SK_ar', sk_ar)
    except ValueError as e:
        eprint("Key validation error:", e)
        sys.exit(1)

    enc_algo   = args.enc_algo   or values.get('enc_algo')   or 'AES-CBC-256 [RFC3602]'
    integ_algo = args.integ_algo or values.get('integ_algo') or 'HMAC_SHA2_256_128 [RFC4868]'

    # IKE SPIs: override or extract
    if args.ike_spi_init and args.ike_spi_resp:
        try:
            ike_spi_i = validate_spi(args.ike_spi_init)
            ike_spi_r = validate_spi(args.ike_spi_resp)
        except ValueError as e:
            eprint("Provided IKE SPI validation failed:", e)
            sys.exit(1)
    else:
        try:
            ike_spi_i, ike_spi_r = extract_ike_spis(args.pcap)
        except Exception as e:
            eprint("Failed extracting IKE SPIs from pcap:", e)
            eprint("Hint: supply them manually with --ike-spi-init <hex16> --ike-spi-resp <hex16>")
            sys.exit(1)

    ike_line = build_ikev2_line(ike_spi_i, ike_spi_r, sk_ei, sk_er, enc_algo, sk_ai, sk_ar, integ_algo)
    try:
        with open(args.out, 'w') as f:
            f.write(ike_line + '\n')
    except Exception as e:
        eprint("Failed writing ikev2 output file:", e)
        sys.exit(1)

    print("\nIKEv2 decryption table entry (Wireshark) -- saved to:", args.out)
    print(ike_line)

    # Optional ESP entry
    if args.emit_esp:
        child_enc_key  = args.child_enc_key  or pick('child_enc_key','enc_key','esp_enc_key')
        child_auth_key = args.child_auth_key or pick('child_auth_key','auth_key','esp_auth_key','')
        child_enc_algo = args.child_enc_algo or pick('child_enc_algo','child_enc','enc_algo_child')
        child_auth_algo= args.child_auth_algo or pick('child_auth_algo','child_auth','auth_algo_child','')
        child_spi      = args.child_spi      or pick('child_spi','')
        child_src      = args.child_src      or pick('child_src','')
        child_dst      = args.child_dst      or pick('child_dst','')

        if not child_enc_key:
            eprint("emit-esp requested but no child_enc_key provided (CLI or keys-file). Cannot create esp_sa.")
            sys.exit(1)

        child_enc_key = norm_hex(child_enc_key)
        if child_auth_key:
            child_auth_key = norm_hex(child_auth_key)

        if not (child_spi and child_src and child_dst):
            info = extract_esp_info(args.pcap)
            if info:
                src_ip, dst_ip, esp_spi = info
                child_src = child_src or src_ip
                child_dst = child_dst or dst_ip
                child_spi = child_spi or esp_spi
            else:
                eprint("Could not auto-extract ESP info from pcap. Provide --child-spi/--child-src/--child-dst.")
                sys.exit(1)

        try:
            child_spi = validate_spi(child_spi)
        except ValueError as e:
            eprint("child SPI validation failed:", e)
            sys.exit(1)

        if not child_enc_algo:
            child_enc_algo = 'cbc(aes)'
        if not child_auth_algo:
            child_auth_algo = 'hmac(sha256) 128' if child_auth_key else ''

        esp_line = build_esp_sa_line(child_src, child_dst, child_spi, child_enc_algo, child_enc_key, child_auth_algo, child_auth_key or '')
        try:
            with open(args.esp_out, 'w') as fe:
                fe.write(esp_line + '\n')
        except Exception as e:
            eprint("Failed writing esp output file:", e)
            sys.exit(1)

        print("\nESP SA entry (Wireshark) -- saved to:", args.esp_out)
        print(esp_line)

    print("\nDone.")
    return 0

if __name__ == '__main__':
    sys.exit(main())