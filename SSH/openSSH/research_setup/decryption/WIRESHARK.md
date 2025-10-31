# Wireshark integration for SSH key-based decryption (SSHKex-based, easy + native paths)

This document describes two ways to decrypt SSH traffic using session keys extracted from a running OpenSSH process (for example with the LLDB hook we built earlier that calls `derive_key()` and writes key blobs).

**Paths:**
- **Easy path (recommended):** use the Python decryptor (`decrypt_ssh_pcap.py`) + `read_llbd_keylog.py` to convert LLDB output → JSON → decrypted PCAP. Optionally a Lua menu launches the decryptor from Wireshark.
- **Native path:** compile `packet-ssh.c` (from SSHKex) and install it as a Wireshark plugin/dissector (best UX but requires building against Wireshark).

---

## Quick TL;DR (easy path)
1. Ensure LLDB hook writes structured key lines, e.g.:
`2025-10-08T12:34:56 KEX-C key=0123... iv=0011... cipher=aes128-ctr dir=client2server``. See also the expected Keylog-Format.
2. Convert to JSON:
`python3 read_llbd_keylog.py /tmp/ssh-keys/ssh_keylog.txt /tmp/ssh-keys/keys.json`
3. Decrypt the PCAP:
`python3 decrypt_ssh_pcap.py --pcap /tmp/ssh-capture.pcap --keys /tmp/ssh-keys/keys.json --out /tmp/ssh-decrypted.pcap`
4. Open `/tmp/ssh-decrypted.pcap` in Wireshark.

The decryption script requires the following python packages:
```bash
python3 -m pip install --user scapy pycryptodome
```
---

## Files included
- `read_llbd_keylog.py` — convert LLDB keylog to structured JSON usable by decryptor.
- `decrypt_ssh_pcap.py` — PoC decryptor adapted from SSHKex (supports AES-CTR in PoC).
- `wireshark_helper.lua` — optional Lua menu helper for Wireshark to call the decryptor.
- `install_decryptor.sh` — installs python deps & copies the helper scripts to `~/.local/share/ssh-decryptor/`.

---

## How it works (overview)
- LLDB script hooks `kex_derive_keys()` and calls `derive_key()` to obtain derived symmetric key material (the exact same code the server uses). The LLDB script must also write which direction the blob belongs to (`client2server` / `server2client`) and the negotiated cipher name. With that precise info the Python PoC can decrypt the SSH TCP payload using the symmetric key + IV and write a decrypted PCAP.

---

## Expected Keylog Format
 
Place, per SSH session, a JSON file (one file per session or one array) with entries like the example below. The decryptor reads this JSON and uses the keys/IVs and metadata to decrypt packets for flows matching the 4-tuple:
```json
[
  {
    "session_id": "sess-2025-10-09-001",
    "client": {"ip":"10.0.2.15","port":51234},
    "server": {"ip":"10.0.2.2","port":22},
    "cipher": "aes128-gcm@openssh.com",
    "kex_session_id": "abcd...",              # optional diagnostic
    "initial_iv_hex": "00112233445566778899aabb",   # 12 bytes for AES-GCM
    "enc_key_hex": "0123456789abcdef0123456789abcdef", # encryption key (16/32 bytes)
    "mac_key_hex": null,
    "variant": "aes-gcm"   # one of: "aes-gcm", "chacha-ietf", "chacha-openssh", "aes-ctr" etc.
  },
  {
    "session_id": "sess-2025-10-09-002",
    "client": {"ip":"192.168.1.20","port":54321},
    "server": {"ip":"192.168.1.2","port":22},
    "cipher": "chacha20-poly1305@openssh.com",
    "enc_key_hex": "..." ,
    "poly_key_material_hex": "..." ,   # optional: if you capture both K1/K2 or two keys
    "variant": "chacha-openssh"
  }
]

```

- For AES-GCM you must provide initial_iv_hex (12 bytes) and the enc_key_hex (16 or 32 bytes). The decryptor treats the 12-byte IV as RFC 5647’s IV (4-octet fixed + 8-octet invocation counter, with counter starting at 0 for the first packet unless you put a different invocation_counter_start field).
- For ChaCha/OpenSSH you should provide the derived keys produced by kex_derive_keys() (or whatever your LLDB hook can expose). For the OpenSSH variant we expect either (a) the full pair of 32-byte keys used by OpenSSH (K1/K2), or (b) a derived poly_key_material (makes life easier). The script accepts both.
- For AES-CTR + HMAC you should provide enc_key_hex, iv_hex (counter/nonce) and mac_key_hex plus mac_algo (e.g. hmac-sha2-256) — the script supports HMAC-SHA2 families for MAC verification.
- The script attempts to automatically map sessions to flows by 4-tuple (client ip/port + server ip/port). If you create a single JSON with many sessions, the tool will attempt to match them to flows in the pcap.