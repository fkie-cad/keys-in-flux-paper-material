#!/usr/bin/env python3
"""
Manual dump trigger for interactive LLDB debugging.
Load this after your callbacks to get convenient dump functions.
"""

import lldb
import sys
import os

def manual_dump_now(debugger, command, result, internal_dict):
    """
    Manually trigger a memory dump from LLDB interactive prompt.

    Usage:
        (lldb) manual_dump_now post_kex
        (lldb) manual_dump_now after_rekey
    """
    # Parse label from command (default if empty)
    label = command.strip() if command.strip() else "manual_checkpoint"

    # Get target and process
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()

    if not process or not process.IsValid():
        print("[MANUAL_DUMP] ✗ No valid process")
        return

    # Import dump module
    sys.path.insert(0, '/opt/lldb')
    import ssh_memory_dump
    from datetime import datetime

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    dump_dir = os.getenv("LLDB_DUMPS_DIR", "/data/dumps")
    os.makedirs(dump_dir, exist_ok=True)

    print(f"\n[MANUAL_DUMP] === Dump Trigger ===")
    print(f"[MANUAL_DUMP] Label: {label}")
    print(f"[MANUAL_DUMP] Target modules: {target.GetNumModules()}")
    print(f"[MANUAL_DUMP] Process valid: {process.IsValid()}")
    print(f"[MANUAL_DUMP] Process state: {process.GetState()}")
    print(f"[MANUAL_DUMP] Output: {dump_dir}")

    # Use dump_process_memory (simple, reliable approach)
    dump_path, bytes_written, regions = ssh_memory_dump.dump_process_memory(
        process, dump_dir, label, timestamp
    )

    if dump_path and bytes_written > 0:
        print(f"[MANUAL_DUMP] ✓ Success: {bytes_written} bytes ({regions} regions)")
        print(f"[MANUAL_DUMP] File: {dump_path}\n")
    else:
        print(f"[MANUAL_DUMP] ✗ Failed: 0 bytes\n")

def dump(debugger, command, result, internal_dict):
    """Quick dump with default label"""
    label = command.strip() if command.strip() else "interactive"
    manual_dump_now(debugger, label, result, internal_dict)

def d(debugger, command, result, internal_dict):
    """Even quicker: single-letter dump command"""
    manual_dump_now(debugger, "quick", result, internal_dict)

def findkey(debugger, command, result, internal_dict):
    """
    Search for a hex key in process memory (both endianness).

    Usage:
        (lldb) findkey 84cf99df57f03769c8df5cf462c9a8ef5f43856271ce5c52fab6346ed7451f5b
        (lldb) findkey 84 cf 99 df 57 f0 37 69  # spaces ignored

    Features:
        - Case-insensitive hex input
        - Searches both big-endian and little-endian byte order
        - Shows all matches with addresses, regions, and hex context
        - Useful for verifying key presence during debugging
    """
    # Parse hex input (case-insensitive, ignore spaces)
    key_hex = command.replace(' ', '').strip().lower()

    if not key_hex:
        print("[FINDKEY] Error: No hex string provided")
        print("Usage: findkey <hex_bytes>")
        print("Example: findkey 84cf99df57f03769c8df5cf462c9a8ef")
        return

    # Validate hex string
    try:
        key_bytes = bytes.fromhex(key_hex)
        key_bytes_le = key_bytes[::-1]  # Little-endian version
    except ValueError:
        print(f"[FINDKEY] Error: Invalid hex string: {command}")
        print("Hex string must contain only 0-9, a-f, A-F characters")
        return

    print(f"[FINDKEY] Searching for: {key_hex[:32]}...")
    if len(key_hex) > 32:
        print(f"[FINDKEY]              ...{key_hex[32:64]}...")
    print(f"[FINDKEY] Key length: {len(key_bytes)} bytes ({len(key_bytes)*8} bits)")
    print()

    # Get target and process
    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        print("[FINDKEY] ✗ No valid target")
        return

    process = target.GetProcess()
    if not process or not process.IsValid():
        print("[FINDKEY] ✗ No valid process")
        return

    # Search all memory regions
    matches = []
    total_regions = 0
    searchable_regions = 0

    print("[FINDKEY] Scanning memory regions...")

    # Iterate through all memory regions
    region_list = process.GetMemoryRegions()
    total_regions = region_list.GetSize()

    for i in range(total_regions):
        region = lldb.SBMemoryRegionInfo()
        if region_list.GetMemoryRegionAtIndex(i, region):
            # Skip unreadable regions
            if not region.IsReadable():
                continue

            searchable_regions += 1
            region_start = region.GetRegionBase()
            region_size = region.GetRegionEnd() - region_start

            # Skip extremely large regions (> 1GB) to avoid hang
            if region_size > 1073741824:
                continue

            # Read region memory
            error = lldb.SBError()
            data = process.ReadMemory(region_start, region_size, error)

            if error.Success() and data:
                # Search for key in both endianness
                offset_be = data.find(key_bytes)
                offset_le = data.find(key_bytes_le) if len(key_bytes) > 1 else -1

                if offset_be >= 0:
                    matches.append({
                        'address': region_start + offset_be,
                        'endianness': 'BIG-ENDIAN',
                        'region_name': region.GetName() if region.GetName() else f"0x{region_start:016x}",
                        'region_start': region_start,
                        'region_size': region_size,
                        'offset': offset_be,
                        'data': data[offset_be:offset_be+min(64, len(key_bytes)+16)]
                    })

                if offset_le >= 0 and offset_le != offset_be:
                    matches.append({
                        'address': region_start + offset_le,
                        'endianness': 'LITTLE-ENDIAN',
                        'region_name': region.GetName() if region.GetName() else f"0x{region_start:016x}",
                        'region_start': region_start,
                        'region_size': region_size,
                        'offset': offset_le,
                        'data': data[offset_le:offset_le+min(64, len(key_bytes)+16)]
                    })

    print(f"[FINDKEY] Scanned {searchable_regions}/{total_regions} readable regions")
    print()

    # Display results
    if matches:
        print(f"[FINDKEY] ✓ Found {len(matches)} match(es):\n")

        for idx, match in enumerate(matches, 1):
            print(f"Match #{idx} ({match['endianness']}):")
            print(f"  Address:      0x{match['address']:016x}")
            print(f"  Region:       {match['region_name']}")
            print(f"  Region start: 0x{match['region_start']:016x}")
            print(f"  Region size:  {match['region_size']} bytes")
            print(f"  Offset:       +0x{match['offset']:x}")

            # Show hex dump context (first 64 bytes or less)
            hex_context = match['data']
            if hex_context:
                print(f"  Hex context:")
                for i in range(0, len(hex_context), 16):
                    chunk = hex_context[i:i+16]
                    hex_str = ' '.join(f"{b:02x}" for b in chunk)
                    ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                    print(f"    {hex_str:<48}  {ascii_str}")

            print()

        # Suggest LLDB commands for further inspection
        print("To inspect memory at match locations:")
        for idx, match in enumerate(matches, 1):
            print(f"  (lldb) memory read --size 1 --format x --count {len(key_bytes)} 0x{match['address']:x}")

    else:
        print(f"[FINDKEY] ✗ Key not found in process memory")
        print(f"[FINDKEY] Searched {searchable_regions} readable regions")
        print()
        print("Possible reasons:")
        print("  - Key has been cleared/overwritten")
        print("  - Key is in a region that couldn't be read")
        print("  - Key hasn't been derived yet (try continuing execution)")
        print("  - Different endianness or encoding (but both were searched)")

    print()

def __lldb_init_module(debugger, internal_dict):
    """Register commands when module is imported"""
    debugger.HandleCommand('command script add -f manual_dump_helper.manual_dump_now manual_dump_now')
    debugger.HandleCommand('command script add -f manual_dump_helper.dump dump')
    debugger.HandleCommand('command script add -f manual_dump_helper.d d')
    debugger.HandleCommand('command script add -f manual_dump_helper.findkey findkey')
    print("[MANUAL_DUMP_HELPER] Loaded. Available commands:")
    print("  manual_dump_now [label]  - Full-featured dump")
    print("  dump [label]             - Quick dump")
    print("  d                        - One-letter dump")
    print("  findkey <hexkey>         - Search for hex bytes in memory (both endianness)")
    print("\nExamples:")
    print("  (lldb) d")
    print("  (lldb) dump post_kex")
    print("  (lldb) manual_dump_now after_rekey")
    print("  (lldb) findkey 84cf99df57f03769c8df5cf462c9a8ef")
