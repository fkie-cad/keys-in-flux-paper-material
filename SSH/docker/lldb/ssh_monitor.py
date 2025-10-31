#!/usr/bin/env python3
"""
SSH Key Lifecycle LLDB Monitor
Tracks SSH key derivation and memory clearing using hardware watchpoints

Based on the IPsec strongSwan monitoring approach.
Usage:
    lldb -s ssh_monitor.py -- /usr/sbin/sshd -D -e
"""

import lldb
import json
import time
import os
import sys
from datetime import datetime

# Configuration
SERVER_TYPE = os.getenv('SSH_SERVER_TYPE', 'openssh')
RESULTS_DIR = os.getenv('LLDB_RESULTS_DIR', '/data/lldb_results')
DUMPS_DIR = os.getenv('LLDB_DUMPS_DIR', '/data/dumps')
TIMING_CSV = os.path.join(RESULTS_DIR, f'timing_{SERVER_TYPE}.csv')
EVENTS_LOG = os.path.join(RESULTS_DIR, f'events_{SERVER_TYPE}.log')
EVENTS_JSONL = os.path.join(RESULTS_DIR, f'events_{SERVER_TYPE}.jsonl')

# Key tracking state
active_keys = {}  # {key_id: {address, size, derived_at, ...}}
watchpoint_map = {}  # {watchpoint_id: key_id}
next_key_id = 0

def log_event(event_type, message, metadata=None):
    """Log event to both human-readable and JSON formats"""
    timestamp = time.time()

    # Human-readable log
    with open(EVENTS_LOG, 'a') as f:
        f.write(f"[{datetime.now().isoformat()}] {event_type}: {message}\n")

    # Machine-readable JSONL
    event = {
        'timestamp': timestamp,
        'type': event_type,
        'message': message,
        'metadata': metadata or {}
    }
    with open(EVENTS_JSONL, 'a') as f:
        f.write(json.dumps(event) + '\n')

    # Also print to console
    print(f"[{event_type}] {message}")

def log_timing(key_id, event, timestamp=None):
    """Log timing data to CSV (compatible with TLS timing format)"""
    if timestamp is None:
        timestamp = time.time()

    # CSV format: timestamp,key_id,event,details
    with open(TIMING_CSV, 'a') as f:
        f.write(f"{timestamp},{key_id},{event},\n")

def dump_memory(process, address, size, event_type, key_id=None):
    """
    Dump memory region to file for later analysis.

    Args:
        process: lldb.SBProcess
        address: Memory address to dump from
        size: Number of bytes to dump
        event_type: Event name (kex_entry, kex_exit, bzero, etc.)
        key_id: Optional key identifier

    Returns:
        Dump filename or None if failed
    """
    try:
        timestamp = time.time()
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

        # Create filename
        if key_id:
            filename = f"{timestamp_str}_{event_type}_{key_id}_{address:016x}.dump"
        else:
            filename = f"{timestamp_str}_{event_type}_{address:016x}.dump"

        filepath = os.path.join(DUMPS_DIR, filename)

        # Read memory from process
        error = lldb.SBError()
        memory_data = process.ReadMemory(address, size, error)

        if error.Fail():
            log_event("DUMP_ERROR", f"Failed to dump memory at {address:#x}: {error.GetCString()}")
            return None

        # Write to file
        with open(filepath, 'wb') as f:
            f.write(memory_data)

        log_event("DUMP_SUCCESS", f"Dumped {size} bytes from {address:#x} to {filename}", {
            'timestamp': timestamp,
            'address': address,
            'size': size,
            'filename': filename
        })

        return filename

    except Exception as e:
        log_event("DUMP_EXCEPTION", f"Exception dumping memory: {str(e)}")
        return None

def dump_full_memory(process, event_type, key_id=None):
    """
    Dump all readable memory regions of the process.

    Args:
        process: lldb.SBProcess
        event_type: Event name
        key_id: Optional key identifier

    Returns:
        List of dump filenames
    """
    try:
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        dump_files = []

        # Get all memory regions
        target = process.GetTarget()
        module = target.GetModuleAtIndex(0)  # Main executable

        for section in module.section_iter():
            addr = section.GetLoadAddress(target)
            size = section.GetByteSize()

            if addr != lldb.LLDB_INVALID_ADDRESS and size > 0:
                # Only dump readable sections
                permissions = section.GetPermissions()
                if permissions & lldb.ePermissionsReadable:
                    section_name = section.GetName()
                    if key_id:
                        filename = f"{timestamp_str}_{event_type}_{key_id}_{section_name}.dump"
                    else:
                        filename = f"{timestamp_str}_{event_type}_{section_name}.dump"

                    filepath = os.path.join(DUMPS_DIR, filename)

                    error = lldb.SBError()
                    memory_data = process.ReadMemory(addr, size, error)

                    if not error.Fail():
                        with open(filepath, 'wb') as f:
                            f.write(memory_data)
                        dump_files.append(filename)

        if dump_files:
            log_event("FULL_DUMP", f"Dumped {len(dump_files)} memory regions for event {event_type}")

        return dump_files

    except Exception as e:
        log_event("DUMP_EXCEPTION", f"Exception in full memory dump: {str(e)}")
        return []

def create_watchpoint_callback(debugger, key_id, key_address):
    """
    Create a Python callback for hardware watchpoint.
    Uses the proven pattern from IPsec strongSwan monitoring.
    """
    callback_name = f"wp_callback_{key_id}"

    # Generate callback as f-string with full function definition
    callback_code = f"""
def {callback_name}(frame, bp_loc, internal_dict):
    '''Watchpoint callback for key {key_id}'''
    import time
    import json

    timestamp = time.time()
    key_id = "{key_id}"

    # Log the overwrite event
    with open("{EVENTS_LOG}", "a") as f:
        f.write(f"[{{time.strftime('%Y-%m-%d %H:%M:%S')}}] KEY_CLEARED: Key {{key_id}} overwritten at address {key_address:#x}\\n")

    with open("{EVENTS_JSONL}", "a") as f:
        event = {{
            'timestamp': timestamp,
            'type': 'KEY_CLEARED',
            'key_id': key_id,
            'address': {key_address:#x}
        }}
        f.write(json.dumps(event) + "\\n")

    with open("{TIMING_CSV}", "a") as f:
        f.write(f"{{timestamp}},{{key_id}},memory_cleared,\\n")

    print(f"[KEY_CLEARED] Key {{key_id}} cleared from memory at {key_address:#x}")

    # Return False to make this a one-shot watchpoint (disable after first hit)
    # One-shot behavior: watchpoint fires once on first overwrite, then disables
    return False
"""

    # Inject callback into Python namespace
    debugger.HandleCommand(f"script {callback_code}")

    return callback_name

def setup_key_watchpoint(debugger, target, key_address, key_size, key_id):
    """
    Set hardware watchpoint on key memory to detect when it's cleared/overwritten.
    Returns watchpoint ID or None if failed.
    """
    # ARM64/x86_64 CPUs support 4 hardware watchpoints
    # Each watchpoint can monitor up to 8 bytes

    log_event("WATCHPOINT_SETUP", f"Setting watchpoint on key {key_id} at {key_address:#x} (size: {key_size} bytes)")

    # For simplicity, watch the first 8 bytes of the key
    # (most critical part, and fits in one watchpoint)
    watch_size = min(key_size, 8)

    # Create hardware watchpoint
    error = lldb.SBError()
    watchpoint = target.WatchAddress(
        key_address,
        watch_size,
        False,  # read
        True,   # write
        error
    )

    if error.Fail():
        log_event("WATCHPOINT_ERROR", f"Failed to set watchpoint: {error.GetCString()}")
        return None

    wp_id = watchpoint.GetID()
    log_event("WATCHPOINT_CREATED", f"Watchpoint {wp_id} set on key {key_id}")

    # Attach Python callback using -F (function name) pattern
    callback_name = create_watchpoint_callback(debugger, key_id, key_address)
    result = debugger.HandleCommand(f"watchpoint command add -F {callback_name} {wp_id}")

    log_event("WATCHPOINT_CALLBACK", f"Attached callback {callback_name} to watchpoint {wp_id}")

    # Track mapping
    watchpoint_map[wp_id] = key_id

    return wp_id

def kex_derive_keys_callback(frame, bp_loc, internal_dict):
    """
    Breakpoint callback when SSH key derivation function is called.
    This captures when keys are created.
    """
    global next_key_id

    timestamp = time.time()
    key_id = f"ssh_key_{next_key_id}"
    next_key_id += 1

    log_event("KEY_DERIVED", f"Key {key_id} derived", {'timestamp': timestamp})
    log_timing(key_id, "derived", timestamp)

    # Try to capture key memory address from newkeys structures
    # This is OpenSSH-specific and may need adjustment for other implementations

    # For now, just log that derivation happened
    # We'll need to inspect the frame to find actual key addresses

    print(f"[KEX] Key derivation detected at {timestamp}")
    return False  # Continue execution

def __lldb_init_module(debugger, internal_dict):
    """
    Initialize the SSH monitor when imported by LLDB.
    This function is automatically called by LLDB when using 'command script import'.
    """
    # Create results and dumps directories
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(DUMPS_DIR, exist_ok=True)

    # Initialize CSV with header
    if not os.path.exists(TIMING_CSV):
        with open(TIMING_CSV, 'w') as f:
            f.write("timestamp,key_id,event,details\n")

    log_event("MONITOR_START", f"SSH LLDB Monitor started for {SERVER_TYPE}")
    log_event("DUMPS_DIR", f"Memory dumps will be saved to: {DUMPS_DIR}")

    # Get target (the process being debugged)
    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        print("WARNING: No target selected yet - breakpoints will be set after target is loaded")
        return

    log_event("TARGET_INFO", f"Target: {target.GetExecutable().GetFilename()}")
    log_event("MONITOR_READY", "SSH monitoring initialized - callbacks will be loaded next")

def main():
    """Main LLDB monitoring setup (for standalone use)"""

    # Create results directory
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Initialize CSV with header
    with open(TIMING_CSV, 'w') as f:
        f.write("timestamp,key_id,event,details\n")

    log_event("MONITOR_START", f"SSH LLDB Monitor started for {SERVER_TYPE}")

    # Get debugger instance
    debugger = lldb.debugger
    if not debugger:
        print("ERROR: No debugger instance available")
        return

    # Get target (the process being debugged)
    target = debugger.GetSelectedTarget()
    if not target:
        print("ERROR: No target selected")
        return

    log_event("TARGET_INFO", f"Target: {target.GetExecutable().GetFilename()}")

    # Set breakpoint on key derivation function
    # For OpenSSH: kex_derive_keys
    bp = target.BreakpointCreateByName("kex_derive_keys")
    if bp.GetNumLocations() > 0:
        log_event("BREAKPOINT_SET", f"Breakpoint set on kex_derive_keys ({bp.GetNumLocations()} locations)")
        bp.SetScriptCallbackFunction("ssh_monitor.kex_derive_keys_callback")
    else:
        log_event("BREAKPOINT_WARN", "Could not set breakpoint on kex_derive_keys - will try pattern matching")
        # TODO: Implement pattern-based breakpoint like TLS monitoring

    log_event("MONITOR_READY", "SSH monitoring active - waiting for key derivation events")

    # Start execution
    debugger.HandleCommand("process continue")

# Run main if loaded as script
if __name__ == '__main__':
    main()
