#!/usr/bin/env python3
"""
SSH Memory Dump Utilities

Memory dumping infrastructure for SSH key lifecycle experiments.
Modeled after TLS framework (../../../lldb/shared.py) with SSH-specific adaptations.

Provides functions to dump process memory at critical protocol state transitions
to analyze cryptographic key persistence.

Author: SSH Lifecycle Experiment Framework
Date: 2025-10-24
"""

import lldb
import os
import sys
from datetime import datetime


def dump_process_memory(process, output_dir, label, timestamp=None):
    """
    Dump ALL memory regions from the process (like TLS shared.py).

    This is the comprehensive approach - dumps every mapped region including
    heap, stack, data segments, shared libraries, etc.

    Args:
        process (lldb.SBProcess): The LLDB process to dump
        output_dir (str): Directory to save dumps
        label (str): Event label (e.g., "post_kex", "pre_rekey")
        timestamp (str, optional): Timestamp string. If None, auto-generated.

    Returns:
        tuple: (dump_path, bytes_written, regions_dumped)
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    # Ensure directory exists
    os.makedirs(output_dir, exist_ok=True)

    dump_filename = f"{timestamp}_{label}.dump"
    dump_path = os.path.join(output_dir, dump_filename)

    try:
        with open(dump_path, "wb") as out_f:
            regions = process.GetMemoryRegions()
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()

            total_written = 0
            regions_dumped = 0

            for i in range(num_regions):
                regions.GetMemoryRegionAtIndex(i, region_info)

                # Get region boundaries
                region_start = region_info.GetRegionBase()
                region_end = region_info.GetRegionEnd()
                region_size = region_end - region_start

                # Skip unmapped or inaccessible regions
                if not region_info.IsMapped() or region_size == 0:
                    continue

                # Try to read this region
                error = lldb.SBError()
                data = process.ReadMemory(region_start, region_size, error)

                if error.Success() and data:
                    out_f.write(data)
                    total_written += len(data)
                    regions_dumped += 1

            print(f"[MEMORY_DUMP] ✓ Dumped {regions_dumped}/{num_regions} regions ({total_written} bytes)")
            print(f"[MEMORY_DUMP]   File: {dump_path}")

            return (dump_path, total_written, regions_dumped)

    except Exception as e:
        print(f"[MEMORY_DUMP] ✗ Error: {e}")
        return (None, 0, 0)


def dump_heap_regions(process, output_dir, label, timestamp=None):
    """
    Dump all readable memory regions (hybrid TLS/mrl-style approach).

    NOTE: Despite the name "heap_regions", this now dumps ALL readable regions
    to ensure cross-platform compatibility. Region names are not reliably available
    on all platforms, so we dump everything readable instead.

    Uses hybrid approach:
    1. Try TLS-style (GetMemoryRegions().GetSize()) - faster when available
    2. Fall back to mrl-style (address iteration) - works in containers

    Args:
        process (lldb.SBProcess): The LLDB process to dump
        output_dir (str): Directory to save dumps
        label (str): Event label
        timestamp (str, optional): Timestamp string. If None, auto-generated.

    Returns:
        tuple: (dump_path, bytes_written, regions_dumped)
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    os.makedirs(output_dir, exist_ok=True)

    dump_filename = f"{timestamp}_{label}_heap.dump"
    dump_path = os.path.join(output_dir, dump_filename)

    try:
        with open(dump_path, "wb") as out_f:
            regions = process.GetMemoryRegions()
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()

            total_written = 0
            regions_dumped = 0

            if num_regions > 0:
                # TLS-style: Use GetMemoryRegions() API (fast path)
                for i in range(num_regions):
                    if not regions.GetMemoryRegionAtIndex(i, region_info):
                        continue

                    region_start = int(region_info.GetRegionBase())
                    region_end = int(region_info.GetRegionEnd())
                    region_size = max(0, region_end - region_start)

                    if region_size == 0:
                        continue

                    error = lldb.SBError()
                    data = process.ReadMemory(region_start, region_size, error)

                    if error.Success() and data:
                        out_f.write(data)
                        total_written += len(data)
                        regions_dumped += 1

                print(f"[HEAP_DUMP] ✓ Dumped {regions_dumped}/{num_regions} regions ({total_written} bytes) [TLS-style]")

            else:
                # mrl-style: Iterate by address (fallback for containers)
                # Need to find first valid address from /proc/[pid]/maps (Linux)
                print(f"[HEAP_DUMP] DEBUG: Starting mrl-style iteration (TLS API returned 0 regions)")

                # Get first valid address from loaded modules (alternative to /proc/maps)
                # process.GetProcessID() returns 0 during callbacks, so we can't use /proc/[pid]/maps
                start_addr = None

                try:
                    # Get target and find first module with a valid load address
                    target = process.GetTarget()
                    num_modules = target.GetNumModules()
                    print(f"[HEAP_DUMP] DEBUG: Target has {num_modules} modules")

                    for i in range(num_modules):
                        module = target.GetModuleAtIndex(i)
                        if module and module.IsValid():
                            section = module.GetSectionAtIndex(0)
                            if section and section.IsValid():
                                load_addr = section.GetLoadAddress(target)
                                if load_addr != lldb.LLDB_INVALID_ADDRESS:
                                    start_addr = int(load_addr)
                                    module_name = module.GetFileSpec().GetFilename()
                                    print(f"[HEAP_DUMP] DEBUG: Found first module '{module_name}' at 0x{start_addr:x}")
                                    break
                except Exception as e:
                    print(f"[HEAP_DUMP] DEBUG: Error getting module base address: {e}")
                    import traceback
                    traceback.print_exc()

                # Fallback: use a sensible default if module lookup failed
                if start_addr is None:
                    start_addr = 0x10000  # Typical low address on many systems
                    print(f"[HEAP_DUMP] DEBUG: Using fallback start address: 0x{start_addr:x}")

                addr = start_addr
                iteration = 0
                max_iterations = 1000  # Safety limit to prevent infinite loops

                while iteration < max_iterations:
                    iteration += 1
                    error = lldb.SBError()
                    success = process.GetMemoryRegionInfo(addr, region_info)

                    if iteration <= 5:  # Log first 5 iterations for debugging
                        print(f"[HEAP_DUMP] DEBUG: Iteration {iteration}: GetMemoryRegionInfo(0x{addr:x}) success={success.Success()}")

                    if not success.Success():
                        print(f"[HEAP_DUMP] DEBUG: GetMemoryRegionInfo failed at iteration {iteration}, addr=0x{addr:x}")
                        break

                    region_start = int(region_info.GetRegionBase())
                    region_end = int(region_info.GetRegionEnd())
                    region_size = max(0, region_end - region_start)
                    is_readable = region_info.IsReadable()
                    is_mapped = region_info.IsMapped()

                    if iteration <= 5:  # Log first 5 regions
                        print(f"[HEAP_DUMP] DEBUG: Region {iteration}: 0x{region_start:x}-0x{region_end:x} (size={region_size}, readable={is_readable}, mapped={is_mapped})")

                    if region_size == 0:
                        print(f"[HEAP_DUMP] DEBUG: Breaking due to region_size=0 at iteration {iteration}")
                        break

                    # Only dump readable regions
                    if is_readable:
                        error = lldb.SBError()
                        data = process.ReadMemory(region_start, region_size, error)

                        if error.Success() and data:
                            out_f.write(data)
                            total_written += len(data)
                            regions_dumped += 1
                            if regions_dumped <= 3:  # Log first 3 successful dumps
                                print(f"[HEAP_DUMP] DEBUG: Successfully dumped region {regions_dumped}: {len(data)} bytes")
                        elif iteration <= 5:
                            print(f"[HEAP_DUMP] DEBUG: ReadMemory failed: {error}")

                    # Move to next region
                    if region_end <= addr:
                        print(f"[HEAP_DUMP] DEBUG: Breaking due to region_end ({region_end}) <= addr ({addr})")
                        break
                    addr = region_end

                if iteration >= max_iterations:
                    print(f"[HEAP_DUMP] WARNING: Reached max iterations ({max_iterations})")

                print(f"[HEAP_DUMP] ✓ Dumped {regions_dumped} regions ({total_written} bytes) [mrl-style]")

            print(f"[HEAP_DUMP]   File: {dump_path}")
            return (dump_path, total_written, regions_dumped)

    except Exception as e:
        print(f"[HEAP_DUMP] ✗ Error: {e}")
        return (None, 0, 0)


def dump_key_regions(process, key_addresses, output_dir, label, timestamp=None, context_bytes=4096):
    """
    Targeted dump around known key addresses.

    When you know where keys are located in memory, this dumps a small region
    around each address (±context_bytes). Much faster than full dumps.

    Args:
        process (lldb.SBProcess): The LLDB process to dump
        key_addresses (list): List of memory addresses (integers) where keys are located
        output_dir (str): Directory to save dumps
        label (str): Event label
        timestamp (str, optional): Timestamp string. If None, auto-generated.
        context_bytes (int): Bytes to dump before/after each address (default: 4KB)

    Returns:
        tuple: (dump_path, bytes_written, keys_dumped)
    """
    if timestamp is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    os.makedirs(output_dir, exist_ok=True)

    dump_filename = f"{timestamp}_{label}_keys.dump"
    dump_path = os.path.join(output_dir, dump_filename)

    try:
        with open(dump_path, "wb") as out_f:
            total_written = 0
            keys_dumped = 0

            for key_addr in key_addresses:
                # Dump region around key address
                start_addr = max(0, key_addr - context_bytes)
                read_size = context_bytes * 2

                error = lldb.SBError()
                data = process.ReadMemory(start_addr, read_size, error)

                if error.Success() and data:
                    # Write header with address info
                    header = f"KEY_REGION_{keys_dumped:03d} @ 0x{key_addr:016x}\n".encode('utf-8')
                    out_f.write(header)
                    out_f.write(data)
                    total_written += len(header) + len(data)
                    keys_dumped += 1

            print(f"[KEY_DUMP] ✓ Dumped {keys_dumped} key regions ({total_written} bytes)")
            print(f"[KEY_DUMP]   File: {dump_path}")

            return (dump_path, total_written, keys_dumped)

    except Exception as e:
        print(f"[KEY_DUMP] ✗ Error: {e}")
        return (None, 0, 0)


def find_heap_regions(process):
    """
    Find all readable memory regions in the process (TLS-style).

    NOTE: Despite the name "heap_regions", this now returns ALL readable regions
    for cross-platform compatibility. Region names are not reliably available.

    Args:
        process (lldb.SBProcess): The LLDB process

    Returns:
        list: List of tuples (start_addr, end_addr, size) for each readable region
    """
    readable_regions = []

    regions = process.GetMemoryRegions()
    region_info = lldb.SBMemoryRegionInfo()
    num_regions = regions.GetSize()

    for i in range(num_regions):
        # TLS-style: Try to get region, skip if failed
        if not regions.GetMemoryRegionAtIndex(i, region_info):
            continue

        start = int(region_info.GetRegionBase())
        end = int(region_info.GetRegionEnd())
        size = max(0, end - start)

        # Include all non-empty regions
        if size > 0:
            readable_regions.append((start, end, size))

    return readable_regions


def dump_with_metadata(process, output_dir, label, metadata=None, dump_type="full"):
    """
    Dump memory with accompanying metadata JSON file.

    Creates two files:
    1. {timestamp}_{label}.dump - The memory dump
    2. {timestamp}_{label}.json - Metadata (timestamp, PID, event, etc.)

    Args:
        process (lldb.SBProcess): The LLDB process
        output_dir (str): Directory to save dumps
        label (str): Event label
        metadata (dict, optional): Additional metadata to save
        dump_type (str): "full", "heap", or "keys" (requires metadata['key_addresses'])

    Returns:
        tuple: (dump_path, metadata_path, bytes_written)
    """
    import json

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    # Choose dump function
    if dump_type == "full":
        dump_path, bytes_written, regions = dump_process_memory(process, output_dir, label, timestamp)
    elif dump_type == "heap":
        dump_path, bytes_written, regions = dump_heap_regions(process, output_dir, label, timestamp)
    elif dump_type == "keys":
        if not metadata or 'key_addresses' not in metadata:
            print("[DUMP_METADATA] ✗ Error: 'keys' dump type requires metadata['key_addresses']")
            return (None, None, 0)
        dump_path, bytes_written, regions = dump_key_regions(
            process, metadata['key_addresses'], output_dir, label, timestamp
        )
    else:
        print(f"[DUMP_METADATA] ✗ Unknown dump_type: {dump_type}")
        return (None, None, 0)

    if not dump_path:
        return (None, None, 0)

    # Create metadata file
    metadata_dict = {
        'timestamp': timestamp,
        'label': label,
        'pid': process.GetProcessID(),
        'dump_type': dump_type,
        'dump_file': os.path.basename(dump_path),
        'bytes_written': bytes_written,
        'regions_dumped': regions
    }

    # Add custom metadata
    if metadata:
        metadata_dict.update(metadata)

    metadata_filename = f"{timestamp}_{label}.json"
    metadata_path = os.path.join(output_dir, metadata_filename)

    try:
        with open(metadata_path, 'w') as f:
            json.dump(metadata_dict, f, indent=2)

        print(f"[DUMP_METADATA] ✓ Metadata: {metadata_path}")
        return (dump_path, metadata_path, bytes_written)

    except Exception as e:
        print(f"[DUMP_METADATA] ✗ Metadata error: {e}")
        return (dump_path, None, bytes_written)


# Example usage (for documentation):
"""
import ssh_memory_dump

# Full process dump
dump_path, bytes, regions = ssh_memory_dump.dump_process_memory(
    process, "/data/dumps", "post_kex"
)

# Heap-only dump (faster)
dump_path, bytes, regions = ssh_memory_dump.dump_heap_regions(
    process, "/data/dumps", "pre_rekey"
)

# Targeted dump around known key addresses
key_addrs = [0x1234567890, 0x0987654321]
dump_path, bytes, keys = ssh_memory_dump.dump_key_regions(
    process, key_addrs, "/data/dumps", "post_session_close"
)

# Dump with metadata
dump_path, meta_path, bytes = ssh_memory_dump.dump_with_metadata(
    process, "/data/dumps", "post_rekey",
    metadata={'kex_session': 2, 'keys_extracted': 6},
    dump_type="full"
)
"""
