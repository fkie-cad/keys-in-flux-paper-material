#!/usr/bin/env python3
"""
monitor_kernel_xfrm.py

Kernel space XFRM state monitoring using drgn
Scans kernel memory for IPsec ESP keys without invoking ip xfrm commands

Usage:
    sudo NETNS_FILE=/var/run/netns/left python3 monitor_kernel_xfrm.py --checkpoint init
    sudo NETNS_FILE=/var/run/netns/left python3 monitor_kernel_xfrm.py --checkpoint handshake

Supports: x86_64, aarch64 (kernel is architecture-agnostic at this level)
"""
import os
import sys
import argparse
import struct
import json
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass

# Elevate to root if needed
if os.geteuid() != 0:
    print("[*] Re-executing with sudo...")
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

# Import drgn
try:
    from drgn import program_from_kernel, set_default_prog, FaultError, KmodSearchMethod
    from drgn.helpers.linux.pid import find_task
    from drgn.helpers.linux.list import list_for_each_entry
except ImportError:
    print("[ERROR] drgn module not found. Install with: pip install drgn")
    sys.exit(1)


def tsize(t):
    """Compatibility helper for drgn type size (handles old and new API)"""
    try:
        return t.size
    except AttributeError:
        return t.sizeof


@dataclass
class XFRMKey:
    """Represents an XFRM key found in kernel"""
    kind: str  # "enc" or "auth"
    spi: str
    src: str
    dst: str
    key_hex: str
    key_bytes: bytes
    addr: int  # Kernel address where found


class KernelXFRMMonitor:
    """Monitor XFRM state in kernel memory using drgn"""

    def __init__(self, netns_file: str, output_dir: str, scan_freelists: bool = False,
                 scan_stacks: bool = False, scan_vmalloc: bool = False):
        self.netns_file = netns_file
        self.output_dir = output_dir
        self.scan_freelists = scan_freelists
        self.scan_stacks = scan_stacks
        self.scan_vmalloc = scan_vmalloc
        os.makedirs(output_dir, exist_ok=True)

        # Initialize drgn
        print("[*] Attaching to kernel...")
        self.prog = program_from_kernel()
        self.prog.debug_info_options.try_kmod = KmodSearchMethod.NONE

        # Suppress "missing debugging symbols" stderr output (non-fatal warnings)
        import warnings
        import contextlib

        try:
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore")
                # Redirect stderr to filter out "missing debugging symbols" messages
                with contextlib.redirect_stderr(open(os.devnull, 'w')):
                    self.prog.load_debug_info(main=True)
        except Exception as e:
            # Only show actual errors, not missing symbol warnings
            if "missing debugging symbols" not in str(e).lower():
                print(f"[WARN] Debug info: {e}")

        set_default_prog(self.prog)

        self.ptr_size = self.prog.type("void *").size

        # Resolve network namespace
        self.net = self._resolve_netns()

        # Track known keys for pattern matching
        self.known_key_patterns = set()

    def _resolve_netns(self):
        """Resolve struct net from netns file"""
        print(f"[*] Resolving netns: {self.netns_file}")
        st = os.stat(self.netns_file)
        target_inum = st.st_ino
        self.netns_inum = target_inum  # Store for later use

        # Try to access net_namespace_list (requires debug symbols)
        try:
            head = self.prog["net_namespace_list"]
        except KeyError:
            print("[ERROR] Kernel debug symbols not available")
            print("[INFO] Install debug symbols: sudo apt install linux-image-$(uname -r)-dbgsym")
            print("[INFO] Or enable ddebs repository: https://wiki.ubuntu.com/Debug%20Symbol%20Packages")
            raise RuntimeError("Kernel debug symbols required for XFRM scanning")

        for net in list_for_each_entry("struct net", head.address_of_(), "list"):
            if int(net.ns.inum) == target_inum:
                print(f"[✓] Found netns inum={target_inum}")
                return net

        raise RuntimeError(f"Could not find netns with inum={target_inum}")

    def _safe_read(self, addr: int, size: int) -> Optional[bytes]:
        """Safely read kernel memory"""
        try:
            return self.prog.read(addr, size)
        except FaultError:
            return None

    def _iter_xfrm_states(self):
        """Iterate xfrm_state structures in the network namespace

        Uses raw pointer walking to handle stripped kernels
        """
        xfrm = self.net.xfrm
        st_t = self.prog.type("struct xfrm_state")
        st_size = tsize(st_t)

        def validate_state(base_addr: int):
            """Validate if address contains a valid xfrm_state"""
            try:
                from drgn import Object
                s = Object(self.prog, "struct xfrm_state", address=base_addr)
                proto = int(s.id.proto)
                family = int(s.props.family)
                spi = int(s.id.spi)
                # ESP=50, AH=51; AF_INET=2, AF_INET6=10
                if proto in (50, 51) and family in (2, 10) and spi != 0:
                    return s
            except Exception:
                pass
            return None

        # Try state_all list if available
        if hasattr(xfrm, "state_all"):
            try:
                head_addr = int(xfrm.state_all.address_of_())
                # Walk list_head via raw pointers
                next_ptr = self._safe_read(head_addr, self.ptr_size)
                if next_ptr:
                    next_addr = struct.unpack("<Q" if self.ptr_size == 8 else "<I", next_ptr)[0]
                    visited = set()

                    while next_addr and next_addr != head_addr and next_addr not in visited:
                        visited.add(next_addr)
                        # Try different offsets to find container
                        for offset in range(0, min(st_size, 2048), 8):
                            s = validate_state(next_addr - offset)
                            if s is not None:
                                yield s
                                break

                        # Read next pointer
                        next_ptr = self._safe_read(next_addr, self.ptr_size)
                        if not next_ptr:
                            break
                        next_addr = struct.unpack("<Q" if self.ptr_size == 8 else "<I", next_ptr)[0]
            except Exception as e:
                print(f"[WARN] state_all walk failed: {e}")

    def _extract_key_from_algo(self, algo_addr: int, algo_type: str) -> Optional[Tuple[bytes, int]]:
        """Extract key from xfrm_algo* structure

        Returns (key_bytes, key_length_bits)
        """
        if not algo_addr:
            return None

        try:
            from drgn import Object

            if algo_type == "ealg":
                algo = Object(self.prog, "struct xfrm_algo", address=algo_addr).read_()
                key_len_bits = int(algo.alg_key_len)
            elif algo_type == "aalg":
                algo = Object(self.prog, "struct xfrm_algo_auth", address=algo_addr).read_()
                key_len_bits = int(algo.alg_key_len)
            elif algo_type == "aead":
                algo = Object(self.prog, "struct xfrm_algo_aead", address=algo_addr).read_()
                key_len_bits = int(algo.alg_key_len)
            else:
                return None

            key_len_bytes = (key_len_bits + 7) // 8
            if key_len_bytes <= 0 or key_len_bytes > 4096:
                return None

            # Key starts after the header
            # Approximate header size based on type
            if algo_type == "ealg":
                hdr_size = 68  # sizeof(struct xfrm_algo) up to alg_key
            elif algo_type == "aalg":
                hdr_size = 72  # sizeof(struct xfrm_algo_auth) up to alg_key
            else:  # aead
                hdr_size = 72  # sizeof(struct xfrm_algo_aead) up to alg_key

            key_bytes = self._safe_read(algo_addr + hdr_size, key_len_bytes)
            if key_bytes:
                return bytes(key_bytes), key_len_bits

        except Exception as e:
            print(f"[WARN] Key extraction failed: {e}")

        return None

    def scan_xfrm_keys(self) -> List[XFRMKey]:
        """Scan kernel for XFRM keys"""
        keys = []

        print("[*] Scanning XFRM states...")
        print(f"[DEBUG] Netns inum: {self.netns_inum}")
        print(f"[DEBUG] Net namespace address: {hex(int(self.net))}")

        count = 0
        for state in self._iter_xfrm_states():
            count += 1
            try:
                # Extract SPI and addresses
                spi = int(state.id.spi)
                spi_hex = f"0x{spi:08x}"

                print(f"[DEBUG] State #{count}: SPI={spi_hex}")

                family = int(state.props.family)
                if family == 2:  # AF_INET
                    # IPv4 addresses are stored as __be32 (big-endian 32-bit integers)
                    # Convert to dotted decimal notation
                    try:
                        # Read as big-endian 32-bit integer, then extract bytes
                        src_be32 = int(state.props.saddr.a4)
                        dst_be32 = int(state.id.daddr.a4)

                        # Extract bytes in network byte order (big-endian)
                        src_bytes = [
                            (src_be32 >> 0) & 0xff,
                            (src_be32 >> 8) & 0xff,
                            (src_be32 >> 16) & 0xff,
                            (src_be32 >> 24) & 0xff
                        ]
                        dst_bytes = [
                            (dst_be32 >> 0) & 0xff,
                            (dst_be32 >> 8) & 0xff,
                            (dst_be32 >> 16) & 0xff,
                            (dst_be32 >> 24) & 0xff
                        ]

                        src = ".".join(str(b) for b in src_bytes)
                        dst = ".".join(str(b) for b in dst_bytes)
                    except Exception as e:
                        print(f"[DEBUG]   Failed to parse IPv4 addresses: {e}")
                        src = dst = "unknown"
                elif family == 10:  # AF_INET6
                    src = "ipv6"
                    dst = "ipv6"
                else:
                    src = dst = "unknown"

                print(f"[DEBUG]   Family={family}, src={src}, dst={dst}")

                # Extract encryption key (ealg)
                ealg_ptr = int(state.ealg) if hasattr(state, "ealg") else 0
                print(f"[DEBUG]   ealg_ptr={hex(ealg_ptr) if ealg_ptr else 'NULL'}")
                if ealg_ptr:
                    result = self._extract_key_from_algo(ealg_ptr, "ealg")
                    if result:
                        key_bytes, key_len = result
                        print(f"[DEBUG]   Extracted enc key: {len(key_bytes)} bytes")
                        keys.append(XFRMKey(
                            kind="enc",
                            spi=spi_hex,
                            src=src,
                            dst=dst,
                            key_hex=key_bytes.hex(),
                            key_bytes=key_bytes,
                            addr=ealg_ptr
                        ))
                    else:
                        print(f"[DEBUG]   Failed to extract enc key")

                # Extract authentication key (aalg)
                aalg_ptr = int(state.aalg) if hasattr(state, "aalg") else 0
                print(f"[DEBUG]   aalg_ptr={hex(aalg_ptr) if aalg_ptr else 'NULL'}")
                if aalg_ptr:
                    result = self._extract_key_from_algo(aalg_ptr, "aalg")
                    if result:
                        key_bytes, key_len = result
                        print(f"[DEBUG]   Extracted auth key: {len(key_bytes)} bytes")
                        keys.append(XFRMKey(
                            kind="auth",
                            spi=spi_hex,
                            src=src,
                            dst=dst,
                            key_hex=key_bytes.hex(),
                            key_bytes=key_bytes,
                            addr=aalg_ptr
                        ))
                    else:
                        print(f"[DEBUG]   Failed to extract auth key")

                # Extract AEAD key if present
                aead_ptr = int(state.aead) if hasattr(state, "aead") else 0
                print(f"[DEBUG]   aead_ptr={hex(aead_ptr) if aead_ptr else 'NULL'}")
                if aead_ptr:
                    result = self._extract_key_from_algo(aead_ptr, "aead")
                    if result:
                        key_bytes, key_len = result
                        print(f"[DEBUG]   Extracted aead key: {len(key_bytes)} bytes")
                        keys.append(XFRMKey(
                            kind="aead",
                            spi=spi_hex,
                            src=src,
                            dst=dst,
                            key_hex=key_bytes.hex(),
                            key_bytes=key_bytes,
                            addr=aead_ptr
                        ))
                    else:
                        print(f"[DEBUG]   Failed to extract aead key")

            except Exception as e:
                print(f"[WARN] Error processing state: {e}")
                continue

        print(f"[✓] Found {count} XFRM states, extracted {len(keys)} keys")

        # Store known keys for pattern matching in freelist/stack scans
        for key in keys:
            if len(key.key_bytes) >= 16:  # Only track substantial keys
                self.known_key_patterns.add(key.key_bytes[:16])  # First 16 bytes as pattern

        return keys

    def _search_memory_for_keys(self, memory: bytes, base_addr: int,
                                context: str) -> List[XFRMKey]:
        """Search a memory buffer for known key patterns

        Args:
            memory: Memory buffer to search
            base_addr: Base kernel address of this memory
            context: Description (e.g., "freelist", "stack")

        Returns:
            List of found keys
        """
        found_keys = []

        if not self.known_key_patterns:
            return found_keys

        # Search for each known key pattern
        for pattern in self.known_key_patterns:
            offset = 0
            while True:
                offset = memory.find(pattern, offset)
                if offset == -1:
                    break

                # Found a match - try to extract full key
                addr = base_addr + offset

                # Try to read more context (up to 128 bytes for full key + metadata)
                if offset + 128 <= len(memory):
                    key_region = memory[offset:offset+128]

                    # Look for key-like structures (32-byte aligned, reasonable length)
                    for key_len in [16, 20, 24, 32, 48, 64]:
                        if offset + key_len <= len(memory):
                            candidate = memory[offset:offset+key_len]

                            # Check if this looks like a complete key
                            # (not all zeros, not all 0xff, has some entropy)
                            if (candidate != b'\x00' * key_len and
                                candidate != b'\xff' * key_len and
                                len(set(candidate)) > 4):  # At least 4 different bytes

                                found_keys.append(XFRMKey(
                                    kind=f"residue_{context}",
                                    spi="unknown",
                                    src="forensic",
                                    dst="forensic",
                                    key_hex=candidate.hex(),
                                    key_bytes=candidate,
                                    addr=addr
                                ))
                                break  # Found key at this offset, move on

                offset += 1  # Continue searching

        return found_keys

    def scan_slub_freelists(self) -> List[XFRMKey]:
        """Scan SLUB/slab cache freelists for freed key material

        This catches keys that were recently freed but not yet overwritten.
        Focuses on kmalloc caches commonly used by XFRM.
        """
        print("\n[*] Scanning SLUB freelists for freed keys...")
        found_keys = []

        if not self.known_key_patterns:
            print("[*] No known key patterns, skipping freelist scan")
            return found_keys

        # Target caches where XFRM allocates
        target_caches = [
            'kmalloc-256', 'kmalloc-512', 'kmalloc-1k', 'kmalloc-2k',
            'xfrm_state'  # If it exists as dedicated cache
        ]

        try:
            # Get slab_caches list
            try:
                slab_caches = self.prog['slab_caches']
            except KeyError:
                print("[WARN] slab_caches not found (stripped kernel?)")
                return found_keys

            scanned_caches = 0
            scanned_objects = 0

            # Walk all slab caches
            for cache in list_for_each_entry("struct kmem_cache",
                                            slab_caches.address_of_(), "list"):
                try:
                    cache_name = cache.name.string_().decode('utf-8')

                    # Only scan target caches
                    if not any(target in cache_name for target in target_caches):
                        continue

                    scanned_caches += 1
                    print(f"  [*] Scanning cache: {cache_name}")

                    # Get object size
                    object_size = int(cache.object_size) if hasattr(cache, 'object_size') else int(cache.size)

                    # Walk per-CPU freelists
                    if hasattr(cache, 'cpu_slab'):
                        for cpu in range(self.prog['nr_cpu_ids'].value_()):
                            try:
                                # Get per-CPU slab
                                cpu_slab_ptr = int(cache.cpu_slab) + (cpu * self.ptr_size)
                                cpu_slab_data = self._safe_read(cpu_slab_ptr, self.ptr_size)

                                if not cpu_slab_data:
                                    continue

                                cpu_slab_addr = struct.unpack("<Q", cpu_slab_data)[0]
                                if not cpu_slab_addr:
                                    continue

                                # Read freelist pointer
                                freelist_data = self._safe_read(cpu_slab_addr, self.ptr_size)
                                if not freelist_data:
                                    continue

                                freelist_ptr = struct.unpack("<Q", freelist_data)[0]

                                # Walk freelist
                                visited = set()
                                while freelist_ptr and freelist_ptr not in visited:
                                    visited.add(freelist_ptr)
                                    scanned_objects += 1

                                    # Read freed object
                                    obj_data = self._safe_read(freelist_ptr, object_size)
                                    if obj_data:
                                        # Search for key patterns in this freed object
                                        matches = self._search_memory_for_keys(
                                            obj_data, freelist_ptr, f"freelist_{cache_name}")
                                        found_keys.extend(matches)

                                    # Get next freelist pointer (stored at offset 0 of freed object)
                                    next_data = self._safe_read(freelist_ptr, self.ptr_size)
                                    if not next_data:
                                        break
                                    freelist_ptr = struct.unpack("<Q", next_data)[0]

                            except Exception as e:
                                continue  # Skip this CPU

                except Exception as e:
                    print(f"  [WARN] Cache scan error: {e}")
                    continue

            print(f"[✓] Scanned {scanned_caches} caches, {scanned_objects} freed objects")
            print(f"[✓] Found {len(found_keys)} key residues in freelists")

        except Exception as e:
            print(f"[ERROR] Freelist scan failed: {e}")

        return found_keys

    def scan_kernel_stacks(self) -> List[XFRMKey]:
        """Scan kernel thread stacks for key residue

        This catches temporary copies of keys during crypto operations.
        """
        print("\n[*] Scanning kernel stacks for key residue...")
        found_keys = []

        if not self.known_key_patterns:
            print("[*] No known key patterns, skipping stack scan")
            return found_keys

        try:
            # Get init_task (PID 0)
            init_task = self.prog['init_task']

            scanned_threads = 0
            max_threads = 200  # Limit to avoid excessive scanning

            # Walk task list
            for task in list_for_each_entry("struct task_struct",
                                           init_task.tasks.address_of_(), "tasks"):
                if scanned_threads >= max_threads:
                    break

                try:
                    pid = int(task.pid)
                    comm = task.comm.string_().decode('utf-8', errors='replace')

                    # Focus on kernel threads and network-related threads
                    # Skip user processes (mm != NULL means userspace process)
                    if hasattr(task, 'mm') and int(task.mm) != 0:
                        continue

                    # Only scan relevant kernel threads
                    relevant = any(name in comm.lower() for name in
                                 ['ksoftirq', 'network', 'crypto', 'kworker', 'xfrm'])

                    if not relevant and scanned_threads > 50:
                        continue  # After first 50, be selective

                    scanned_threads += 1

                    # Get stack pointer
                    if hasattr(task, 'stack'):
                        stack_addr = int(task.stack)

                        # Kernel stacks are typically 8KB or 16KB
                        # Try 16KB to be safe
                        stack_size = 16384

                        stack_data = self._safe_read(stack_addr, stack_size)
                        if stack_data:
                            # Search for key patterns
                            matches = self._search_memory_for_keys(
                                stack_data, stack_addr, f"stack_{comm}_{pid}")

                            if matches:
                                print(f"  [!] Found key residue in {comm} (PID {pid})")
                                found_keys.extend(matches)

                except Exception as e:
                    continue  # Skip this task

            print(f"[✓] Scanned {scanned_threads} kernel threads")
            print(f"[✓] Found {len(found_keys)} key residues in stacks")

        except Exception as e:
            print(f"[ERROR] Stack scan failed: {e}")

        return found_keys

    def scan_vmalloc_regions(self, max_bytes: int = 256 * 1024 * 1024) -> List[XFRMKey]:
        """Scan vmalloc areas for key residue

        This catches keys allocated via vmalloc (less common for XFRM, but possible).
        Based on scan_kernel_for_xfrm_keys.py implementation.

        Args:
            max_bytes: Maximum bytes to scan (default: 256MB)
        """
        print(f"\n[*] Scanning vmalloc regions (max {max_bytes // (1024*1024)}MB)...")
        found_keys = []

        if not self.known_key_patterns:
            print("[*] No known key patterns, skipping vmalloc scan")
            return found_keys

        try:
            # Get vmap_area_list
            try:
                vmap_head = self.prog['vmap_area_list']
            except KeyError:
                print("[WARN] vmap_area_list not found (stripped kernel?)")
                return found_keys

            scanned_regions = 0
            scanned_bytes = 0

            # Walk vmalloc areas
            for vmap_area in list_for_each_entry("struct vmap_area",
                                                 vmap_head.address_of_(), "list"):
                try:
                    start = int(vmap_area.va_start)
                    end = int(vmap_area.va_end)

                    if end <= start:
                        continue

                    size = end - start

                    # Check if we've hit the limit
                    if scanned_bytes >= max_bytes:
                        break

                    # Cap this region if needed
                    if scanned_bytes + size > max_bytes:
                        size = max_bytes - scanned_bytes

                    if size <= 0:
                        break

                    scanned_regions += 1

                    # Read vmalloc region
                    region_data = self._safe_read(start, size)
                    if region_data:
                        # Search for key patterns
                        matches = self._search_memory_for_keys(
                            region_data, start, f"vmalloc_0x{start:x}")

                        if matches:
                            print(f"  [!] Found keys in vmalloc @ 0x{start:x}")
                            found_keys.extend(matches)

                        scanned_bytes += len(region_data)

                except Exception as e:
                    continue  # Skip this vmap_area

            print(f"[✓] Scanned {scanned_regions} vmalloc regions ({scanned_bytes // 1024}KB)")
            print(f"[✓] Found {len(found_keys)} key residues in vmalloc")

        except Exception as e:
            print(f"[ERROR] vmalloc scan failed: {e}")

        return found_keys

    def dump_xfrm_memory(self, checkpoint_name: str, keys: List[XFRMKey]) -> str:
        """Dump kernel memory regions containing XFRM state and keys

        Args:
            checkpoint_name: Name of checkpoint
            keys: List of XFRM keys with their kernel addresses

        Returns:
            Path to the memory dump file
        """
        if not keys:
            print("[*] No keys to dump memory for")
            return None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dump_file = os.path.join(self.output_dir, f"xfrm_memory_{checkpoint_name}_{timestamp}.bin")
        metadata_file = os.path.join(self.output_dir, f"xfrm_memory_{checkpoint_name}_{timestamp}.json")

        print(f"[*] Dumping kernel XFRM memory regions...")

        dump_regions = []

        try:
            with open(dump_file, "wb") as f:
                for key in keys:
                    # Dump a region around each key address
                    # XFRM state structures and key material typically within 4KB
                    dump_size = 4096
                    start_addr = key.addr

                    try:
                        # Read kernel memory using drgn
                        mem_data = self.prog.read(start_addr, dump_size)

                        # Write to dump file
                        offset = f.tell()
                        f.write(mem_data)

                        dump_regions.append({
                            "key_kind": key.kind,
                            "spi": key.spi,
                            "kernel_addr": f"0x{start_addr:x}",
                            "dump_size": dump_size,
                            "dump_offset": offset,
                            "route": f"{key.src} -> {key.dst}"
                        })

                        print(f"  [✓] Dumped {key.kind} key @ 0x{start_addr:x} ({dump_size} bytes)")

                    except Exception as e:
                        print(f"  [WARN] Failed to dump memory @ 0x{start_addr:x}: {e}")
                        continue

            # Save metadata
            metadata = {
                "checkpoint": checkpoint_name,
                "timestamp": timestamp,
                "netns_file": self.netns_file,
                "dump_file": os.path.basename(dump_file),
                "total_regions": len(dump_regions),
                "regions": dump_regions
            }

            with open(metadata_file, "w") as f:
                json.dump(metadata, f, indent=2)

            print(f"[✓] Memory dump saved: {dump_file} ({len(dump_regions)} regions)")
            print(f"[✓] Metadata saved: {metadata_file}")

            return dump_file

        except Exception as e:
            print(f"[ERROR] Memory dump failed: {e}")
            return None

    def dump_checkpoint(self, checkpoint_name: str):
        """Perform a checkpoint scan and dump"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        checkpoint_file = os.path.join(self.output_dir, f"xfrm_{checkpoint_name}_{timestamp}.json")

        print(f"\n{'='*70}")
        print(f"Kernel XFRM Checkpoint: {checkpoint_name}")
        print(f"{'='*70}\n")

        keys = self.scan_xfrm_keys()

        # Display results
        if keys:
            print(f"\nFound Keys:")
            print(f"{'Kind':<8} {'SPI':<12} {'Route':<25} {'Key (hex)':}")
            for k in keys:
                route = f"{k.src}->{k.dst}"
                print(f"{k.kind:<8} {k.spi:<12} {route:<25} {k.key_hex[:64]}{'...' if len(k.key_hex) > 64 else ''}")
        else:
            print("[*] No keys found (may not be established yet)")

        # Save extracted keys to JSON
        checkpoint_data = {
            "checkpoint": checkpoint_name,
            "timestamp": timestamp,
            "netns_file": self.netns_file,
            "key_count": len(keys),
            "keys": [
                {
                    "kind": k.kind,
                    "spi": k.spi,
                    "src": k.src,
                    "dst": k.dst,
                    "key_hex": k.key_hex,
                    "key_length": len(k.key_bytes),
                    "kernel_addr": f"0x{k.addr:x}"
                }
                for k in keys
            ]
        }

        with open(checkpoint_file, "w") as f:
            json.dump(checkpoint_data, f, indent=2)

        print(f"\n[✓] Keys saved: {checkpoint_file}")

        # Dump kernel memory regions
        if keys:
            print()
            self.dump_xfrm_memory(checkpoint_name, keys)

        # Forensic scanning: Only run after terminate checkpoints
        # This catches keys that have been freed or left as residue
        forensic_enabled = "terminate" in checkpoint_name.lower()

        freelist_keys = []
        stack_keys = []
        vmalloc_keys = []

        if forensic_enabled and keys:  # Only scan if we found live keys
            # Optional: Scan freelists for freed keys
            if self.scan_freelists:
                freelist_keys = self.scan_slub_freelists()

            # Optional: Scan kernel stacks for key residue
            if self.scan_stacks:
                stack_keys = self.scan_kernel_stacks()

            # Optional: Scan vmalloc regions
            if self.scan_vmalloc:
                vmalloc_keys = self.scan_vmalloc_regions()

        # Save forensic findings if any
        if freelist_keys or stack_keys or vmalloc_keys:
            forensic_file = os.path.join(self.output_dir,
                                        f"xfrm_forensic_{checkpoint_name}_{timestamp}.json")
            forensic_data = {
                "checkpoint": checkpoint_name,
                "timestamp": timestamp,
                "freelist_residues": len(freelist_keys),
                "stack_residues": len(stack_keys),
                "vmalloc_residues": len(vmalloc_keys),
                "findings": [
                    {
                        "kind": k.kind,
                        "source": k.kind.split('_')[1] if '_' in k.kind else "unknown",
                        "key_hex": k.key_hex,
                        "key_length": len(k.key_bytes),
                        "kernel_addr": f"0x{k.addr:x}"
                    }
                    for k in (freelist_keys + stack_keys + vmalloc_keys)
                ]
            }

            with open(forensic_file, "w") as f:
                json.dump(forensic_data, f, indent=2)

            print(f"\n[✓] Forensic findings saved: {forensic_file}")
            print(f"    Freelist residues: {len(freelist_keys)}")
            print(f"    Stack residues: {len(stack_keys)}")
            print(f"    vmalloc residues: {len(vmalloc_keys)}")

        elif forensic_enabled and not keys:
            print("\n[*] Forensic scan skipped: no active keys found to match against")

        print()


def main():
    parser = argparse.ArgumentParser(
        description="Monitor kernel XFRM state using drgn",
        epilog="Forensic options enable deep memory scanning to find freed or residual keys. "
               "These only run on 'terminate' checkpoints and are more invasive/slower. "
               "Integrated from scan_kernel_for_xfrm_keys.py research tool.")
    parser.add_argument("--checkpoint", required=True,
                        help="Checkpoint name (init, handshake, rekey, terminate)")
    parser.add_argument("--netns-file", default=os.environ.get("NETNS_FILE", "/var/run/netns/left"),
                        help="Path to netns file (default: /var/run/netns/left)")
    parser.add_argument("--output-dir", default=os.environ.get("IPSEC_OUTPUT_DIR", "./results/kernel"),
                        help="Output directory for results")
    parser.add_argument("--scan-freelists", action="store_true",
                        help="Scan SLUB freelists for freed keys (forensic, terminate only)")
    parser.add_argument("--scan-stacks", action="store_true",
                        help="Scan kernel thread stacks for key residue (forensic, terminate only)")
    parser.add_argument("--scan-vmalloc", action="store_true",
                        help="Scan vmalloc regions for keys (forensic, terminate only)")

    args = parser.parse_args()

    try:
        monitor = KernelXFRMMonitor(args.netns_file, args.output_dir,
                                   scan_freelists=args.scan_freelists,
                                   scan_stacks=args.scan_stacks,
                                   scan_vmalloc=args.scan_vmalloc)
        monitor.dump_checkpoint(args.checkpoint)
    except KeyboardInterrupt:
        print("\n[*] Interrupted")
        sys.exit(0)
    except Exception as e:
        print(f"[ERROR] {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
