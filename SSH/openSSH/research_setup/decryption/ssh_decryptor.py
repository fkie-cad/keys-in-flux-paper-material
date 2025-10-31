#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SSH decryptor for OpenSSH chacha20-poly1305@openssh.com with robust heuristics

Features
- Correct OpenSSH key layout (64B per direction = K2||K1).
- Nonce uses SSH per-direction sequence number (does NOT reset at NEWKEYS).
- Heuristics try both key orders and both direction keys + several starting seqnos.
- TCP reassembly drops overlaps/retransmissions (first-seen policy).
- Optional plaintext PCAP writer (--decrypted-pcap): emits UDP frames with decrypted payloads
  (Wireshark will show plaintext as raw data).
- Debug hexdumps (--debug, --debug-max N): show encrypted payload and decrypted payload per packet.

Usage
  python3 ssh_decryptor.py --pcap in.pcap --keys keys.json \
      --decrypted-pcap decrypted.pcap --debug --debug-max 5
"""

import argparse, json, struct
from collections import defaultdict, namedtuple

from scapy.all import rdpcap, wrpcap, TCP, IP, UDP, Raw

from Crypto.Cipher import ChaCha20
from Crypto.Hash import Poly1305

SSH_MSG_NEWKEYS = 21
SSH_MAX_PACKET = 35000

# ---------------------- small helpers ----------------------

def u32(b: bytes) -> int:
    return struct.unpack('>I', b)[0]

def tobytes(hexstr):
    return bytes.fromhex(hexstr) if hexstr else None

def hexdump(buf: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(buf), width):
        chunk = buf[i:i+width]
        hexpart = ' '.join(f'{x:02x}' for x in chunk)
        asciip = ''.join(chr(x) if 32 <= x < 127 else '.' for x in chunk)
        lines.append(f'{i:04x}  {hexpart:<{width*3}}  {asciip}')
    return '\n'.join(lines)

# ---------------------- reassembly -------------------------

def flow_key(pkt):
    ip = pkt[IP]; t = pkt[TCP]
    return (ip.src, t.sport, ip.dst, t.dport)

def reassemble_streams(packets, ssh_ports=(22,)):
    """
    Assemble per-direction TCP byte streams for SSH ports with overlap removal.
    Policy: keep first-seen bytes for any overlapping seq range (drop retransmits).
    """
    segs = defaultdict(list)
    for p in packets:
        if IP in p and TCP in p:
            t = p[TCP]
            if t.sport in ssh_ports or t.dport in ssh_ports:
                payload = bytes(t.payload)
                if not payload:
                    continue
                segs[flow_key(p)].append((int(t.seq), payload))

    streams = {}
    for k, chunks in segs.items():
        chunks.sort(key=lambda x: x[0])
        assembled = bytearray()
        base_seq = None
        next_seq = None
        for s, data in chunks:
            if base_seq is None:
                base_seq = s
                next_seq = s
            if s >= next_seq:
                overlap = 0
            else:
                overlap = next_seq - s
                if overlap >= len(data):
                    continue
            assembled.extend(data[overlap:])
            next_seq = s + len(data)
            # keep next_seq aligned to assembled length
            next_seq = max(next_seq, base_seq + len(assembled))
        streams[k] = bytes(assembled)
    return streams

# -------------------- crypto (OpenSSH) ---------------------

def chacha_openssh_decrypt(key1_len: bytes, key2_pay: bytes, seq_no: int,
                           enc_len_bytes: bytes, ct: bytes, tag: bytes):
    """
    OpenSSH chacha20-poly1305@openssh.com

    key1_len: 32B K1 (length key)
    key2_pay: 32B K2 (payload key)
    seq_no: per-direction SSH packet sequence number (int)
    enc_len_bytes: 4B *encrypted* packet length
    ct: ciphertext (packet_length bytes)
    tag: 16B Poly1305 tag
    """
    nonce = b'\x00\x00\x00\x00' + seq_no.to_bytes(8, 'big')

    # (1) Decrypt length with K1 @ counter=0
    c_len = ChaCha20.new(key=key1_len, nonce=nonce)
    dec_len = c_len.encrypt(enc_len_bytes)
    packet_length = u32(dec_len)
    if packet_length == 0 or packet_length > SSH_MAX_PACKET:
        raise ValueError(f"Invalid packet length {packet_length}")
    if len(ct) != packet_length:
        raise ValueError(f"Ciphertext length {len(ct)} != packet_length {packet_length}")

    # (2) Verify Poly1305 over ENC(length) || ENC(payload) (derived form)
    poly = Poly1305.new(key=key2_pay, nonce=nonce, cipher=ChaCha20)
    poly.update(enc_len_bytes)
    poly.update(ct)
    calc_tag = poly.digest()
    if calc_tag != tag:
        raise ValueError(f"Poly1305 tag mismatch (expected {tag.hex()}, got {calc_tag.hex()})")

    # (3) Decrypt payload with K2 @ counter=1 (skip first 64 bytes)
    c_pay = ChaCha20.new(key=key2_pay, nonce=nonce)
    _ = c_pay.encrypt(b'\x00' * 64)
    plaintext = c_pay.encrypt(ct)

    return packet_length, plaintext

# ---------------------- sessions & keys --------------------

SessionInfo = namedtuple("SessionInfo",
    ["client_ip","client_port","server_ip","server_port","cipher","variant","c2s_key","s2c_key"])

def extract_ips_from_pcap(pcap_file, ssh_ports=(22,)):
    pkts = rdpcap(pcap_file)
    for p in pkts:
        if IP in p and TCP in p:
            t = p[TCP]
            if t.dport in ssh_ports:
                return p[IP].src, t.sport, p[IP].dst, t.dport
            elif t.sport in ssh_ports:
                return p[IP].dst, t.dport, p[IP].src, t.sport
    return None, None, None, None

def guess_variant_from_cipher(cipher: str):
    c = (cipher or "").lower()
    if 'chacha20-poly1305' in c:
        return 'chacha-openssh'
    return 'unknown'

def load_sessions(keys_json, pcap_file=None, ssh_ports=(22,)):
    with open(keys_json, 'r') as f:
        data = json.load(f)

    if isinstance(data, dict):
        entries = data.get('sessions', [data])
    elif isinstance(data, list):
        entries = data
    else:
        raise ValueError("Invalid JSON format for sessions")

    sessions = []
    for e in entries:
        if 'keys' in e:
            cipher = e.get('cipher', '')
            keys_obj = e['keys']
            if 'client_to_server' in keys_obj:
                c2s_hex = keys_obj['client_to_server'].get('encryption_key', '')
                s2c_hex = keys_obj.get('server_to_client', {}).get('encryption_key', '')
            elif 'out' in keys_obj:
                c2s_hex = keys_obj['out'].get('encryption_key', '')
                s2c_hex = keys_obj.get('in', {}).get('encryption_key', '')
            else:
                c2s_hex = ''
                s2c_hex = ''

            c2s = tobytes(c2s_hex)
            s2c = tobytes(s2c_hex)
            if not c2s and not s2c:
                print("Warning: no encryption keys present in entry")
                continue

            variant = guess_variant_from_cipher(cipher)

            client_ip = e.get('client_ip'); client_port = e.get('client_port')
            server_ip = e.get('server_ip'); server_port = e.get('server_port')

            if (not client_ip or not server_ip) and pcap_file:
                print("IPs not in JSON, extracting from PCAP...")
                c_ip, c_port, s_ip, s_port = extract_ips_from_pcap(pcap_file, ssh_ports)
                client_ip = client_ip or c_ip; client_port = client_port or c_port
                server_ip = server_ip or s_ip; server_port = server_port or s_port

            sessions.append(SessionInfo(client_ip, client_port, server_ip, server_port,
                                        cipher, variant, c2s, s2c))
        elif 'client' in e or 'enc_key_hex' in e:
            client = e.get('client', {}); server = e.get('server', {})
            cipher = e.get('cipher', '')
            variant = e.get('variant') or guess_variant_from_cipher(cipher)
            enc = tobytes(e.get('enc_key_hex'))
            sessions.append(SessionInfo(client.get('ip'), client.get('port'),
                                        server.get('ip'), server.get('port'),
                                        cipher, variant, enc, enc))
        else:
            print(f"Warning: unrecognized entry keys: {list(e.keys())}")
    return sessions

# --------------------- matching & handshake ----------------

def find_matching_session(sessions, ip_src, sport, ip_dst, dport):
    for s in sessions:
        if (str(s.client_ip) == str(ip_src) and s.client_port == sport and
            str(s.server_ip) == str(ip_dst) and s.server_port == dport):
            return s, "c2s"
        if (str(s.client_ip) == str(ip_dst) and s.client_port == dport and
            str(s.server_ip) == str(ip_src) and s.server_port == sport):
            return s, "s2c"
    for s in sessions:
        if s.client_ip is None or s.server_ip is None:
            return s, "c2s"
    return None, None

def skip_ssh_handshake_and_count(data: bytes):
    """
    Skip banner + cleartext handshake packets in THIS direction.
    Returns (pos_after_newkeys, handshake_packet_count).
    """
    pos = 0; count = 0
    rn = data.find(b'\r\n'); n = data.find(b'\n')
    banner_end = rn if rn != -1 else n
    if banner_end != -1:
        pos = banner_end + (2 if rn != -1 else 1)

    while pos + 4 <= len(data):
        packet_len = u32(data[pos:pos+4])
        if packet_len == 0 or packet_len > SSH_MAX_PACKET:
            break
        end = pos + 4 + packet_len
        if end > len(data):
            break
        msg_type = data[pos + 5] if packet_len > 1 else None
        count += 1
        if msg_type == SSH_MSG_NEWKEYS:
            return end, count
        pos = end
    return pos, count

# ---------------------- heuristics & decrypt ----------------

def split_keys(enc_key_bytes: bytes, order: str):
    """
    Split 64B key into (K1_len, K2_pay).
    'k2k1' => enc_key = K2||K1 (OpenSSH spec) -> returns (K1, K2)
    'k1k2' => enc_key = K1||K2 -> returns (K1, K2)
    """
    if not enc_key_bytes or len(enc_key_bytes) != 64:
        return None, None
    first = enc_key_bytes[:32]; second = enc_key_bytes[32:]
    return (second, first) if order == 'k2k1' else (first, second)

def try_decrypt_first_packet(data: bytes, pos0: int, key1_len: bytes, key2_pay: bytes, seq0: int):
    if pos0 + 4 > len(data):
        return False, 0, b'', b'', "Truncated: need 4B encrypted length"
    enc_len = data[pos0:pos0+4]
    try:
        c_len = ChaCha20.new(key=key1_len, nonce=b'\x00\x00\x00\x00' + seq0.to_bytes(8, 'big'))
        dec_len = c_len.encrypt(enc_len)
        packet_length = u32(dec_len)
    except Exception as e:
        return False, 0, b'', b'', f"Length decrypt error: {e}"

    if packet_length == 0 or packet_length > SSH_MAX_PACKET:
        return False, 0, b'', b'', f"Invalid packet length {packet_length}"

    total = 4 + packet_length + 16
    if pos0 + total > len(data):
        return False, 0, b'', b'', f"Truncated packet: need {total} bytes"

    ct = data[pos0+4 : pos0+4+packet_length]
    tag = data[pos0+4+packet_length : pos0+4+packet_length+16]

    try:
        verified_len, pt = chacha_openssh_decrypt(key1_len, key2_pay, seq0, enc_len, ct, tag)
        if verified_len != packet_length:
            return False, 0, b'', b'', f"Packet length mismatch {packet_length} vs {verified_len}"
    except Exception as e:
        return False, 0, b'', b'', f"Decrypt/verify error: {e}"

    if len(pt) < 2:
        return False, 0, b'', b'', "Plaintext too short"

    padding_len = pt[0]
    payload_len = packet_length - 1 - padding_len
    if payload_len < 1 or payload_len > len(pt) - 1:
        return False, 0, b'', b'', f"Unreasonable payload length {payload_len}"

    payload0 = pt[1:1+payload_len]
    return True, total, ct, payload0, ""

def parse_and_decrypt_stream(data, session, direction_tag, out_packets,
                             debug=False, debug_max=10, debug_label="",
                             max_seq_probe=10):
    """
    Decrypt a reassembled stream.
    Appends (payload_bytes, seq_no) to out_packets for plaintext PCAP emission.
    Returns (parsed_packets_count, errors_list, debug_items)
    debug_items: list of dicts {'seq': int, 'ct': bytes, 'pt': bytes}
    """
    pos, handshake_count = skip_ssh_handshake_and_count(data)

    # candidate key sources (direction and opposite)
    key_choices = []
    if direction_tag == "c2s":
        if session.c2s_key: key_choices.append(("dir=C2S", session.c2s_key))
        if session.s2c_key: key_choices.append(("dir=S2C(opposite)", session.s2c_key))
    else:
        if session.s2c_key: key_choices.append(("dir=S2C", session.s2c_key))
        if session.c2s_key: key_choices.append(("dir=C2S(opposite)", session.c2s_key))

    key_orders = [('k2k1', 'OpenSSH(K2||K1)'), ('k1k2', 'Swapped(K1||K2)')]

    seq_candidates = []
    primary = [handshake_count, handshake_count + 1, max(handshake_count - 1, 0)]
    fallback = list(range(0, max_seq_probe))
    for s in primary + fallback:
        if s not in seq_candidates:
            seq_candidates.append(s)

    errors = []
    debug_items = []
    chosen = None  # (key_src_label, order_label, seq_start, K1, K2)

    # Heuristic: validate first encrypted packet
    for key_src_label, enc_key in key_choices:
        for order, order_label in key_orders:
            k1, k2 = split_keys(enc_key, order)
            if not k1 or not k2:
                errors.append(f"{key_src_label} {order_label}: key length mismatch (need 64B)")
                continue
            for seq0 in seq_candidates:
                ok, consumed, ct0, pt0, err = try_decrypt_first_packet(data, pos, k1, k2, seq0)
                if ok:
                    print(f"    Heuristic success: {key_src_label}, order={order_label}, seq_start={seq0}, first_packet_len={consumed}")
                    chosen = (key_src_label, order_label, seq0, k1, k2)
                    # seed debug first packet
                    if debug and len(debug_items) < debug_max:
                        debug_items.append({'seq': seq0, 'ct': ct0, 'pt': pt0})
                    break
                else:
                    errors.append(f"{key_src_label} {order_label} seq={seq0}: {err}")
            if chosen:
                break
        if chosen:
            break

    if not chosen:
        return 0, ["Heuristics failed on first packet"] + errors[:10], debug_items

    key_src_label, order_label, seq_no, key1, key2 = chosen

    # Full parse
    parsed = 0
    p = pos
    while p < len(data):
        if p + 4 > len(data):
            errors.append(f"Truncated at pos {p}: need 4B encrypted length")
            break

        enc_len = data[p:p+4]
        try:
            c_len = ChaCha20.new(key=key1, nonce=b'\x00\x00\x00\x00' + seq_no.to_bytes(8, 'big'))
            dec_len = c_len.encrypt(enc_len)
            packet_length = u32(dec_len)
        except Exception as e:
            errors.append(f"Length decrypt error at pos {p}, seq {seq_no}: {e}")
            break

        if packet_length == 0 or packet_length > SSH_MAX_PACKET:
            errors.append(f"Invalid packet length {packet_length} at pos {p}, seq {seq_no}")
            break

        total = 4 + packet_length + 16
        if p + total > len(data):
            errors.append(f"Truncated packet at pos {p}: need {total} bytes, have {len(data)-p}")
            break

        ct = data[p+4 : p+4+packet_length]
        tag = data[p+4+packet_length : p+4+packet_length+16]

        try:
            verified_len, pt_full = chacha_openssh_decrypt(key1, key2, seq_no, enc_len, ct, tag)
            if verified_len != packet_length:
                errors.append(f"Packet length mismatch at pos {p}: {packet_length} vs {verified_len}")
                break
        except Exception as e:
            errors.append(f"Decrypt/verify error at pos {p}, seq {seq_no}: {e}")
            break

        if not pt_full:
            errors.append(f"Empty plaintext at pos {p}")
            break

        padding_len = pt_full[0]
        payload_len = packet_length - 1 - padding_len
        if payload_len < 0 or payload_len > len(pt_full) - 1:
            errors.append(f"Unreasonable payload length {payload_len} at pos {p}")
            break

        pt = pt_full[1:1+payload_len]
        out_packets.append((pt, seq_no))
        if debug and len(debug_items) < debug_max:
            debug_items.append({'seq': seq_no, 'ct': ct, 'pt': pt})

        parsed += 1
        p += total
        seq_no += 1

    if parsed > 0:
        print(f"    Using {key_src_label}, order={order_label}, seq_start={chosen[2]} -> parsed {parsed} pkt(s)")
    return parsed, errors, debug_items

# --------------------------- main --------------------------

def main():
    ap = argparse.ArgumentParser(description="Decrypt SSH (OpenSSH chacha20-poly1305@openssh.com) with robust heuristics")
    ap.add_argument('--pcap', required=True, help="Input PCAP file")
    ap.add_argument('--keys', required=True, help="Keys JSON file")
    ap.add_argument('--out', help='Optional: write original packets unchanged (original packets; decryption is validated)')
    ap.add_argument('--decrypted-pcap', help="Write plaintext as UDP frames to this PCAP (for Wireshark viewing)")
    ap.add_argument('--ssh-ports', default='22', help='Comma-separated SSH ports (default: 22)')
    ap.add_argument('--max-seq-try', type=int, default=10, help='Max low sequence numbers to probe if needed (default: 10)')
    ap.add_argument('--debug', action='store_true', help='Print hexdumps of encrypted & decrypted payloads')
    ap.add_argument('--debug-max', type=int, default=10, help='Max packets per flow to dump (default: 10)')
    args = ap.parse_args()

    ssh_ports = tuple(int(p) for p in args.ssh_ports.split(','))

    print(f"Loading sessions from {args.keys}")
    sessions = load_sessions(args.keys, args.pcap, ssh_ports)
    print(f"Loaded {len(sessions)} session(s)")
    for s in sessions:
        print(f"  Session: {s.client_ip}:{s.client_port} -> {s.server_ip}:{s.server_port}")
        c2s_len = len(s.c2s_key) if s.c2s_key else 0
        s2c_len = len(s.s2c_key) if s.s2c_key else 0
        print(f"    Cipher: {s.cipher}, Variant: {s.variant}")
        print(f"    C2S key: {c2s_len} bytes, S2C key: {s2c_len} bytes")

    print(f"\nReading PCAP: {args.pcap}")
    pkts = rdpcap(args.pcap)
    streams = reassemble_streams(pkts, ssh_ports=ssh_ports)
    print(f"Found {len(streams)} TCP flow(s) on SSH ports")

    decrypted_flows = 0
    dec_pkts = []  # plaintext UDP frames (if --decrypted-pcap)

    for flow, data in streams.items():
        ip_src, sport, ip_dst, dport = flow
        print(f"\nFlow: {ip_src}:{sport} -> {ip_dst}:{dport} ({len(data)} bytes)")
        session, direction = find_matching_session(sessions, ip_src, sport, ip_dst, dport)
        if not session:
            print("  No matching session found, skipping")
            continue

        print(f"  Matched session, direction: {direction}")
        start_pos, handshake_count = skip_ssh_handshake_and_count(data)
        print(f"  Handshake packets (this direction): {handshake_count}, encrypted starts at pos {start_pos}")

        out_packets = []
        parsed, errors, dbg_items = parse_and_decrypt_stream(
            data, session, direction, out_packets,
            debug=args.debug, debug_max=args.debug_max,
            debug_label=f"{ip_src}:{sport}->{ip_dst}:{dport}",
            max_seq_probe=args.max_seq_try
        )

        print(f"  Parsed: {parsed} packets")
        if errors:
            print(f"  Errors: {len(errors)}")
            for err in errors[:10]:
                print(f"    - {err}")
            if len(errors) > 10:
                print(f"    ... and {len(errors)-10} more")

        # Debug hexdumps:
        if args.debug and dbg_items:
            print(f"  Debug hexdumps (up to {args.debug_max} packets):")
            for item in dbg_items:
                seq = item['seq']; ct = item['ct']; pt = item['pt']
                print(f"    [seq {seq}] Encrypted payload ({len(ct)} bytes):")
                print(hexdump(ct))
                print(f"    [seq {seq}] Decrypted payload ({len(pt)} bytes):")
                print(hexdump(pt))
                print()

        if parsed > 0:
            decrypted_flows += 1
            total_plaintext = sum(len(pl) for pl, _ in out_packets)
            print(f"  Decrypted plaintext bytes: {total_plaintext}")

            # Build synthetic UDP frames with plaintext for Wireshark viewing
            if args.decrypted_pcap:
                # choose ports: 2222 for c2s, 2223 for s2c
                dport_plain = 2222 if direction == "c2s" else 2223
                sport_plain = sport if isinstance(sport, int) else 40000
                for pt, seqno in out_packets:
                    pkt = IP(src=ip_src, dst=ip_dst)/UDP(sport=sport_plain, dport=dport_plain)/Raw(load=pt)
                    dec_pkts.append(pkt)

    print(f"\n{'='*60}")
    if decrypted_flows == 0:
        print("WARNING: No flows were successfully decrypted!")
        print("\nTroubleshooting tips:")
        print("  1) Keys might belong to a different session (timestamps/hosts).")
        print("  2) Extractor may have swapped directions (this script tries both).")
        print("  3) If capture has gaps, reassembly may still miss data.")
        print("  4) Increase --max-seq-try for exotic handshakes.")
    else:
        print(f"Successfully decrypted {decrypted_flows} flow(s)")

    # Write original PCAP (unchanged)
    print(f"\nWriting original packets: {args.out}")
    wrpcap(args.out, pkts)

    # Write plaintext PCAP, if requested
    if args.decrypted_pcap and dec_pkts:
        print(f"Writing decrypted plaintext pcap: {args.decrypted_pcap}")
        wrpcap(args.decrypted_pcap, dec_pkts)

    print("Done.\nNote:")
    print(" - The original PCAP remains encrypted (SSH payloads).")
    print(" - Open the decrypted plaintext PCAP to view application data as raw UDP.")
    print(" - Use --debug to see per-packet ciphertext/plaintext hexdumps in the terminal.")

if __name__ == "__main__":
    main()
