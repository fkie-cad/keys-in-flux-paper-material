#!/usr/bin/env python3
"""
shared_ipsec.py

Shared utilities for IPsec/StrongSwan LLDB monitoring
Supports both x86_64 and aarch64 architectures
"""
import lldb
import os
import sys
import struct
from datetime import datetime
from typing import Optional, Tuple, Dict, List
import json


class ArchitectureHelper:
    """Helper class for architecture-specific operations"""

    def __init__(self, frame: lldb.SBFrame):
        self.frame = frame
        self.triple = frame.GetThread().GetProcess().GetTarget().GetTriple()
        self.is_aarch64 = "aarch64" in self.triple or "arm64" in self.triple
        self.is_x86_64 = "x86_64" in self.triple or "x86-64" in self.triple
        self.ptr_size = 8  # Both architectures are 64-bit

    def get_register_names(self) -> Dict[str, List[str]]:
        """Get register names for current architecture"""
        if self.is_aarch64:
            return {
                "args": ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"],
                "sp": "sp",
                "pc": "pc",
                "fp": "x29",
                "lr": "x30"
            }
        else:  # x86_64
            return {
                "args": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
                "sp": "rsp",
                "pc": "rip",
                "fp": "rbp",
                "lr": None  # x86_64 uses stack for return address
            }

    def get_arg_register(self, index: int) -> Optional[str]:
        """Get argument register name by index (0-based)"""
        regs = self.get_register_names()["args"]
        if index < len(regs):
            return regs[index]
        return None

    def read_register(self, reg_name: str) -> Optional[int]:
        """Read register value as unsigned integer"""
        reg = self.frame.FindRegister(reg_name)
        if not reg.IsValid():
            return None
        try:
            val = reg.GetValue()
            if val is None:
                return None
            return int(val, 0)
        except Exception:
            return None

    def read_arg_register(self, index: int) -> Optional[int]:
        """Read argument register by index"""
        reg_name = self.get_arg_register(index)
        if reg_name:
            return self.read_register(reg_name)
        return None

    def get_return_address(self) -> Optional[int]:
        """Get the return address for current function

        On x86_64: return address is at *($rsp)
        On aarch64: return address is in $lr (x30)

        Returns:
            Return address or None if unable to read
        """
        if self.is_aarch64:
            # ARM64: return address is in link register (x30)
            return self.read_register("x30")
        else:
            # x86_64: return address is at top of stack
            sp = self.read_register("rsp")
            if sp is None:
                return None

            # Read pointer from stack
            process = self.frame.GetThread().GetProcess()
            error = lldb.SBError()
            data = process.ReadMemory(sp, 8, error)
            if not error.Success():
                return None

            import struct
            return struct.unpack('<Q', data)[0]


class ChunkReader:
    """Helper class for reading strongSwan chunk_t structures

    chunk_t is defined as: { uint8_t* ptr; size_t len; }
    Total size: 16 bytes on 64-bit systems
    """

    def __init__(self, frame: lldb.SBFrame):
        self.frame = frame
        self.process = frame.GetThread().GetProcess()
        self.arch = ArchitectureHelper(frame)

    def read_chunk_from_args(self, ptr_arg_idx: int, len_arg_idx: int) -> Tuple[int, int, bytes]:
        """Read chunk_t passed by value (exploded into ptr, len registers)

        Args:
            ptr_arg_idx: Register index for chunk.ptr
            len_arg_idx: Register index for chunk.len

        Returns:
            Tuple of (ptr, length, data)
        """
        ptr = self.arch.read_arg_register(ptr_arg_idx)
        length = self.arch.read_arg_register(len_arg_idx)

        if not ptr or not length:
            return 0, 0, b""

        data = self._read_memory(ptr, length)
        return ptr, length, data

    def read_chunk_from_memory(self, addr: int) -> Tuple[int, int, bytes]:
        """Read chunk_t from memory address (chunk_t* parameter)

        Args:
            addr: Address of chunk_t structure in memory

        Returns:
            Tuple of (ptr, length, data)
        """
        # Read chunk_t structure (16 bytes: 8-byte ptr + 8-byte len)
        chunk_buf = self._read_memory(addr, 16)
        if not chunk_buf or len(chunk_buf) < 16:
            return 0, 0, b""

        ptr, length = struct.unpack("<QQ", chunk_buf)
        data = self._read_memory(ptr, length) if ptr and length else b""
        return ptr, length, data

    def _read_memory(self, addr: int, size: int, max_size: int = 65536) -> bytes:
        """Safe memory read with size limit"""
        if not addr or addr == 0 or size <= 0:
            return b""

        # Limit read size to prevent excessive memory consumption
        size = min(size, max_size)

        error = lldb.SBError()
        data = self.process.ReadMemory(addr, size, error)

        if not error.Success():
            return b""

        # Ensure bytes type
        if isinstance(data, str):
            try:
                data = data.encode('latin-1')
            except Exception:
                pass

        return bytes(data) if data else b""


class MemoryDumper:
    """Helper class for dumping process memory at checkpoints"""

    def __init__(self, process: lldb.SBProcess, output_dir: str):
        self.process = process
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def dump_full_memory(self, checkpoint_name: str) -> str:
        """Dump all readable memory regions to file using /proc/[pid]/maps

        Args:
            checkpoint_name: Name for this checkpoint (e.g., "init", "handshake")

        Returns:
            Path to dump file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dump_path = os.path.join(self.output_dir, f"dump_{checkpoint_name}_{timestamp}.bin")

        regions_dumped = 0
        total_bytes = 0

        try:
            # Get PID
            pid = self.process.GetProcessID()

            # Read /proc/[pid]/maps to get memory regions
            maps_file = f"/proc/{pid}/maps"
            if not os.path.exists(maps_file):
                print(f"[MemDump] Warning: {maps_file} not found")
                return ""

            with open(dump_path, "wb") as f:
                with open(maps_file, "r") as maps:
                    for line in maps:
                        try:
                            # Parse maps line format: address perms offset dev inode pathname
                            # Example: 7ffff7dd0000-7ffff7e00000 r-xp 00000000 08:01 12345 /lib/x86_64-linux-gnu/ld-2.31.so
                            parts = line.split()
                            if len(parts) < 2:
                                continue

                            addr_range = parts[0]
                            perms = parts[1]

                            # Only dump readable regions
                            if 'r' not in perms:
                                continue

                            # Parse address range
                            start_str, end_str = addr_range.split('-')
                            start_addr = int(start_str, 16)
                            end_addr = int(end_str, 16)
                            size = end_addr - start_addr

                            if size <= 0 or size > 100 * 1024 * 1024:  # Skip empty or > 100MB regions
                                continue

                            # Try to read memory
                            error = lldb.SBError()
                            data = self.process.ReadMemory(start_addr, size, error)

                            if error.Success() and data:
                                # Write region header: address (8 bytes) + size (8 bytes)
                                f.write(struct.pack("<QQ", start_addr, size))
                                # Write data
                                if isinstance(data, str):
                                    data = data.encode('latin-1')
                                f.write(data)
                                regions_dumped += 1
                                total_bytes += size

                        except Exception as e:
                            # Skip regions that can't be read
                            continue

            print(f"[MemDump] {checkpoint_name}: {regions_dumped} regions, {total_bytes} bytes -> {dump_path}")
            return dump_path

        except Exception as e:
            print(f"[MemDump] Error during dump: {e}")
            import traceback
            traceback.print_exc()
            return ""

    def dump_specific_range(self, checkpoint_name: str, addr: int, size: int) -> str:
        """Dump a specific memory range

        Args:
            checkpoint_name: Name for this checkpoint
            addr: Start address
            size: Size in bytes

        Returns:
            Path to dump file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dump_path = os.path.join(self.output_dir, f"dump_{checkpoint_name}_{timestamp}.bin")

        try:
            error = lldb.SBError()
            data = self.process.ReadMemory(addr, size, error)

            if error.Success() and data:
                with open(dump_path, "wb") as f:
                    f.write(struct.pack("<QQ", addr, size))
                    if isinstance(data, str):
                        data = data.encode('latin-1')
                    f.write(data)

                print(f"[MemDump] {checkpoint_name}: 0x{addr:x} ({size} bytes) -> {dump_path}")
                return dump_path
        except Exception as e:
            print(f"[MemDump] Error: {e}")

        return ""


class EventLogger:
    """Helper class for logging events to structured files"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        self.events_log = os.path.join(output_dir, "events.log")
        self.json_log = os.path.join(output_dir, "events.jsonl")

    def log_event(self, event_type: str, details: Dict):
        """Log an event with timestamp

        Args:
            event_type: Type of event (e.g., "ike_keys", "esp_keys")
            details: Dictionary of event details
        """
        timestamp = datetime.now().isoformat()

        # Human-readable log
        with open(self.events_log, "a") as f:
            f.write(f"[{timestamp}] {event_type}:\n")
            for key, value in details.items():
                f.write(f"  {key}: {value}\n")
            f.write("\n")

        # JSON log for parsing
        event_obj = {
            "timestamp": timestamp,
            "event_type": event_type,
            "details": details
        }
        with open(self.json_log, "a") as f:
            f.write(json.dumps(event_obj) + "\n")

    def log_key_derivation(self, key_type: str, length: int, sample_hex: str, metadata: Dict = None):
        """Log a key derivation event

        Args:
            key_type: Type of key (e.g., "SK_ei", "ENCR_i")
            length: Key length in bytes
            sample_hex: Hex string of first few bytes
            metadata: Additional metadata
        """
        details = {
            "key_type": key_type,
            "length": length,
            "sample": sample_hex
        }
        if metadata:
            details.update(metadata)

        self.log_event("key_derivation", details)


def format_hex(data: bytes, limit: int = 64) -> str:
    """Format bytes as hex string with optional limit"""
    if not data:
        return "<empty>"

    sample = data[:limit]
    hex_str = " ".join(f"{b:02x}" for b in sample)

    if len(data) > limit:
        hex_str += f" ... ({len(data)} bytes total)"

    return hex_str


def get_process_info(process: lldb.SBProcess) -> Dict[str, any]:
    """Get process information"""
    return {
        "pid": process.GetProcessID(),
        "name": process.GetTarget().GetExecutable().GetFilename(),
        "architecture": process.GetTarget().GetTriple(),
        "num_threads": process.GetNumThreads()
    }


class KeylogWriter:
    """Writes Wireshark-compatible keylog files for IKEv2 and ESP"""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        self.ikev2_log = os.path.join(output_dir, "ikev2_decryption_table")
        self.esp_log = os.path.join(output_dir, "esp_sa")
        self.keys_json = os.path.join(output_dir, "keys.json")

        # Storage for extracted keys
        self.ike_sa_keys = {}  # { 'sa_id': {...}, ... }
        self.esp_keys = {}     # { 'spi': {...}, ... }

        # Current IKE SA being built
        self.current_ike_sa = None

    def add_ike_key(self, key_name: str, key_data: bytes, context: Dict = None):
        """Add an IKE SA key (SK_ei, SK_er, SK_ai, SK_ar, SK_pi, SK_pr)

        Args:
            key_name: Key name (sk_ei, sk_er, sk_ai, sk_ar, etc.)
            key_data: Full key bytes
            context: Additional context (SPIs, algorithms, etc.)
        """
        if self.current_ike_sa is None:
            self.current_ike_sa = {}

        self.current_ike_sa[key_name.lower()] = key_data.hex()

        # Merge context if provided
        if context:
            for k, v in context.items():
                if k not in self.current_ike_sa:
                    self.current_ike_sa[k] = v

    def finalize_ike_sa(self, initiator_spi: str = None, responder_spi: str = None,
                        encryption_alg: str = None, integrity_alg: str = None):
        """Finalize current IKE SA and prepare for writing

        Args:
            initiator_spi: Initiator SPI (16 hex chars)
            responder_spi: Responder SPI (16 hex chars)
            encryption_alg: Encryption algorithm name (e.g., "AES-CBC [RFC3602]")
            integrity_alg: Integrity algorithm name (e.g., "HMAC_SHA2_256_128 [RFC4868]")
        """
        if self.current_ike_sa is None:
            return

        # Fill in SPIs if provided
        if initiator_spi:
            self.current_ike_sa['initiator_spi'] = initiator_spi
        if responder_spi:
            self.current_ike_sa['responder_spi'] = responder_spi
        if encryption_alg:
            self.current_ike_sa['encryption_alg'] = encryption_alg
        if integrity_alg:
            self.current_ike_sa['integrity_alg'] = integrity_alg

        # Store by SPIs (or timestamp if SPIs not available)
        sa_id = f"{initiator_spi or 'unknown'}_{responder_spi or 'unknown'}"
        if sa_id == "unknown_unknown":
            sa_id = f"ike_sa_{len(self.ike_sa_keys)}"

        self.ike_sa_keys[sa_id] = dict(self.current_ike_sa)
        self.current_ike_sa = None

    def add_esp_key(self, spi: str, src: str, dst: str, enc_key: bytes, auth_key: bytes = None,
                    cipher: str = None, auth_alg: str = None):
        """Add an ESP SA key

        Args:
            spi: ESP SPI (8 hex chars)
            src: Source IP
            dst: Destination IP
            enc_key: Encryption key bytes
            auth_key: Authentication key bytes (optional)
            cipher: Cipher name (e.g., "AES-CBC [RFC3602]")
            auth_alg: Auth algorithm (e.g., "HMAC-SHA-2-256 [RFC4868]")
        """
        self.esp_keys[spi] = {
            'spi': spi,
            'src': src,
            'dst': dst,
            'enc_key': enc_key.hex(),
            'auth_key': auth_key.hex() if auth_key else '',
            'cipher': cipher or 'AES-CBC [RFC3602]',
            'auth': auth_alg or 'HMAC-SHA-2-256 [RFC4868]'
        }

    def write_keylogs(self):
        """Write all accumulated keys to Wireshark-compatible files"""

        # Write IKEv2 decryption table
        if self.ike_sa_keys:
            with open(self.ikev2_log, 'w') as f:
                for sa_id, keys in self.ike_sa_keys.items():
                    # Check if we have required keys
                    required = ['sk_ei', 'sk_er', 'sk_ai', 'sk_ar']
                    if not all(k in keys for k in required):
                        print(f"[KeylogWriter] Skipping incomplete IKE SA: {sa_id}", file=sys.stderr)
                        continue

                    # Format: initiator_spi,responder_spi,sk_ei,sk_er,encryption_alg,sk_ai,sk_ar,integrity_alg
                    initiator_spi = keys.get('initiator_spi', '0' * 16)
                    responder_spi = keys.get('responder_spi', '0' * 16)
                    encryption_alg = keys.get('encryption_alg', 'AES-CBC [RFC3602]')
                    integrity_alg = keys.get('integrity_alg', 'HMAC_SHA2_256_128 [RFC4868]')

                    # Quote algorithm names if they contain commas or spaces
                    def maybe_quote(s):
                        if ',' in s or ' ' in s:
                            return f'"{s}"'
                        return s

                    line = f"{initiator_spi},{responder_spi},{keys['sk_ei']},{keys['sk_er']}," \
                           f"{maybe_quote(encryption_alg)},{keys['sk_ai']},{keys['sk_ar']},{maybe_quote(integrity_alg)}\n"
                    f.write(line)

            print(f"[KeylogWriter] Wrote {len(self.ike_sa_keys)} IKEv2 SA(s) to {self.ikev2_log}")

        # Write ESP SA table
        if self.esp_keys:
            with open(self.esp_log, 'w') as f:
                for spi, keys in self.esp_keys.items():
                    # Format: "IPv4","SRC","DST","0xSPI","CIPHER","0xENCKEY","AUTHALG","0xAUTHKEY"
                    def q(s): return f'"{s}"'

                    line = f"{q('IPv4')},{q(keys['src'])},{q(keys['dst'])},{q('0x' + keys['spi'])}," \
                           f"{q(keys['cipher'])},{q('0x' + keys['enc_key'])}," \
                           f"{q(keys['auth'])},{q('0x' + keys['auth_key'])}\n"
                    f.write(line)

            print(f"[KeylogWriter] Wrote {len(self.esp_keys)} ESP SA(s) to {self.esp_log}")

        # Write JSON backup with all keys
        json_data = {
            'ike_sa': list(self.ike_sa_keys.values()),
            'esp': list(self.esp_keys.values())
        }
        with open(self.keys_json, 'w') as f:
            json.dump(json_data, f, indent=2)

        print(f"[KeylogWriter] Wrote JSON backup to {self.keys_json}")


class TimingLogger:
    """Logs key lifecycle timing events to CSV file (compatible with TLS timing format)"""

    def __init__(self, output_dir: str, run_id: int = 1):
        self.output_dir = output_dir
        self.run_id = run_id
        self.timing_csv = os.path.join(output_dir, "timing_libreswan.csv")
        self.events = []

        # Write CSV header
        self._write_header()

    def _write_header(self):
        """Write CSV header if file doesn't exist"""
        if not os.path.exists(self.timing_csv):
            with open(self.timing_csv, 'w') as f:
                f.write("ID, timestamp, event, key_name, address, value\n")

    def log_event(self, event: str, key_name: str, address: int = 0, value: bytes = None):
        """Log a timing event

        Args:
            event: Event type (e.g., 'sk_ei_set', 'sk_ei_overwritten')
            key_name: Name of the key (e.g., 'sk_ei', 'ENCR_i')
            address: Memory address (hex)
            value: First 16 bytes of key material (optional)
        """
        import datetime

        timestamp = datetime.datetime.now().isoformat()
        addr_hex = f"0x{address:x}" if address else "0x0"

        # Format value as hex (first 16 bytes)
        if value:
            value_hex = value[:16].hex() if len(value) >= 16 else value.hex()
        else:
            value_hex = ""

        # Append to CSV
        with open(self.timing_csv, 'a') as f:
            f.write(f"{self.run_id}, {timestamp}, {event}, {key_name}, {addr_hex}, {value_hex}\n")

        print(f"[TimingLogger] {event}: {key_name} @ {addr_hex}")

    def log_watchpoint_set(self, key_name: str, address: int, value: bytes):
        """Log when a watchpoint is set on a key"""
        self.log_event(f"{key_name}_set", key_name, address, value)

    def log_watchpoint_hit(self, key_name: str, address: int, old_value: bytes = None, new_value: bytes = None):
        """Log when a watchpoint is triggered (key overwritten)"""
        # Log with new value if available, otherwise use old
        value = new_value if new_value else old_value
        self.log_event(f"{key_name}_overwritten", key_name, address, value)

    def log_key_cleared(self, key_name: str, address: int):
        """Log when a key is explicitly cleared/zeroed"""
        self.log_event(f"{key_name}_cleared", key_name, address, b'\x00' * 16)
