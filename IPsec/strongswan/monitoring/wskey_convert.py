#!/usr/bin/env python3
"""
wskey_convert.py

Convert JSON describing ESP and IKEv2 keys into Wireshark-compatible
esp_sa and ikev2_decryption_table files.

Usage:
  python3 wskey_convert.py --input keys.json --outdir /root/.config/wireshark --print

Output:
  <outdir>/esp_sa
  <outdir>/ikev2_decryption_table

Notes:
  - JSON accepts hex strings with or without "0x".
  - esp entries must include spi (hex), enc_key (hex), cipher string (Wireshark name),
    and optionally auth and auth_key.
  - ikev2 entries must include initiator_spi, responder_spi, sk_ei, sk_er,
    encryption_alg, sk_ai, sk_ar, integrity_alg (see Wireshark docs).
"""
import argparse
import json
import os
import re
import sys

HEX_RE = re.compile(r'^(?:0x)?([0-9a-fA-F]+)$')

def norm_hex(s):
    """Normalize hex string: remove 0x and lower-case. Return None if not hex."""
    if s is None:
        return None
    m = HEX_RE.match(str(s).strip())
    return m.group(1).lower() if m else None

def write_esp_sa_line(entry):
    """
    Produce a Wireshark esp_sa line:
    "IPv4","SRC","DST","0xSPI","CIPHER","0xENCKEY","AUTHALG","0xAUTHKEY"
    Note: SPI in strongSwan example is with 0x prefix and 8 hex chars (4 bytes).
    We'll preserve the user's spi length.
    """
    ip_ver = entry.get('ip_version', 4)
    if ip_ver == 4:
        ip_tag = "IPv4"
    elif ip_ver == 6:
        ip_tag = "IPv6"
    else:
        ip_tag = "IPv4"

    src = entry.get('src') or ''
    dst = entry.get('dst') or ''
    spi_raw = norm_hex(entry.get('spi') or '')
    spi_field = "0x" + spi_raw if spi_raw else "0x0"

    cipher = entry.get('cipher') or ''
    enc_key = norm_hex(entry.get('enc_key') or '')
    enc_key_field = "0x" + enc_key if enc_key else ''

    auth_alg = entry.get('auth') or ''
    auth_key = norm_hex(entry.get('auth_key') or '')
    auth_key_field = "0x" + auth_key if auth_key else ''

    # If auth is empty, Wireshark allows empty field; produce 8 fields anyway
    # Escape double quotes in fields
    def q(s): return '"' + str(s).replace('"','""') + '"'

    fields = [
        q(ip_tag),
        q(src),
        q(dst),
        q(spi_field),
        q(cipher),
        q(enc_key_field),
        q(auth_alg),
        q(auth_key_field)
    ]
    return ",".join(fields)

def write_ikev2_line(entry):
    """
    Produce a Wireshark ikev2_decryption_table line.
    Fields (order): Initiator SPI, Responder SPI, SK_ei, SK_er, Encryption Algorithm,
                    SK_ai, SK_ar, Integrity Algorithm
    All hex fields should be without 0x prefix in Wireshark examples, but strongSwan example shows raw hex (no 0x for ike table).
    We'll write raw hex (no 0x) for those fields and leave alg strings quoted if containing commas.
    """
    initiator_spi = norm_hex(entry.get('initiator_spi') or '')
    responder_spi = norm_hex(entry.get('responder_spi') or '')
    sk_ei = norm_hex(entry.get('sk_ei') or '')
    sk_er = norm_hex(entry.get('sk_er') or '')
    encryption_alg = entry.get('encryption_alg') or ''
    sk_ai = norm_hex(entry.get('sk_ai') or '')
    sk_ar = norm_hex(entry.get('sk_ar') or '')
    integrity_alg = entry.get('integrity_alg') or ''

    # Build CSV-like line; if alg fields contain commas we will quote them
    def maybe_quote(s):
        if ',' in s or '"' in s or ' ' in s:
            return '"' + s.replace('"','""') + '"'
        return s

    fields = [
        initiator_spi,
        responder_spi,
        sk_ei,
        sk_er,
        maybe_quote(encryption_alg),
        sk_ai,
        sk_ar,
        maybe_quote(integrity_alg)
    ]
    return ",".join(fields)

def main():
    p = argparse.ArgumentParser(description="Convert JSON keys -> Wireshark esp_sa & ikev2_decryption_table")
    p.add_argument("--input", "-i", required=True, help="JSON input file")
    p.add_argument("--outdir", "-o", required=True, help="Output directory for esp_sa and ikev2_decryption_table")
    p.add_argument("--print", action="store_true", help="Print generated lines to stdout")
    args = p.parse_args()

    with open(args.input, "r") as fh:
        data = json.load(fh)

    esp_entries = data.get("esp", []) or []
    ike_entries = data.get("ikev2", []) or []

    outdir = args.outdir
    os.makedirs(outdir, exist_ok=True)
    esp_path = os.path.join(outdir, "esp_sa")
    ikev2_path = os.path.join(outdir, "ikev2_decryption_table")

    generated_esp = []
    generated_ike = []

    # Validate and create lines
    for e in esp_entries:
        # minimal validation
        if not e.get('src') or not e.get('dst') or not e.get('spi') or not e.get('enc_key'):
            print("Skipping ESP entry missing required fields (src/dst/spi/enc_key):", e, file=sys.stderr)
            continue
        line = write_esp_sa_line(e)
        generated_esp.append(line)

    for k in ike_entries:
        # minimal validation
        required = ['initiator_spi','responder_spi','sk_ei','sk_er','encryption_alg','sk_ai','sk_ar','integrity_alg']
        if not all(k.get(r) for r in required):
            print("Skipping IKEv2 entry missing required fields:", k, file=sys.stderr)
            continue
        line = write_ikev2_line(k)
        generated_ike.append(line)

    # Write files (overwrite)
    if generated_esp:
        with open(esp_path, "w") as fh:
            for L in generated_esp:
                fh.write(L + "\n")
        print(f"[+] Wrote {len(generated_esp)} ESP SA lines to: {esp_path}")
    else:
        print("[*] No ESP entries generated.")

    if generated_ike:
        with open(ikev2_path, "w") as fh:
            for L in generated_ike:
                fh.write(L + "\n")
        print(f"[+] Wrote {len(generated_ike)} IKEv2 decryption lines to: {ikev2_path}")
    else:
        print("[*] No IKEv2 entries generated.")

    if args.print:
        if generated_esp:
            print("\n=== esp_sa lines ===")
            for L in generated_esp:
                print(L)
        if generated_ike:
            print("\n=== ikev2_decryption_table lines ===")
            for L in generated_ike:
                print(L)

if __name__ == "__main__":
    main()