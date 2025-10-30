import lldb
from datetime import datetime
import os
import sys
import json


script_dir = os.path.dirname(__file__)
if script_dir and script_dir not in sys.path:
    sys.path.insert(0, script_dir)

try:
    import shared
except ModuleNotFoundError:
    # If still fails, try absolute path
    abs_script_dir = os.path.abspath(os.path.dirname(__file__))
    if abs_script_dir not in sys.path:
        sys.path.insert(0, abs_script_dir)
    import shared

file_path = "/tmp/gotls/timing_13.csv"
SECRET_SIZE = 32
save_interval = 6
auto_exit = True

ret_bp_map = {}
active_secrets = {}

# Define labels for which we want to set watchpoints
labels = {"c hs traffic", "s hs traffic", "c ap traffic", "s ap traffic"}

logger = shared.CSVLogger(file_path, save_interval, auto_exit)

# Helpers to read registers/memory robustly (LLDB EvaluateExpression can return 0 on some targets)

def get_reg_u64(frame: lldb.SBFrame, name: str):
    rv = frame.FindRegister(name)
    if rv and rv.IsValid() and rv.GetValue():
        try:
            return int(rv.GetValue(), 16)
        except Exception:
            pass
    try:
        return frame.EvaluateExpression(f"${name}", lldb.SBExpressionOptions()).GetValueAsUnsigned()
    except Exception:
        return None


def read_bytes(process: lldb.SBProcess, addr: int, size: int):
    if not addr or size <= 0:
        return None
    err = lldb.SBError()
    data = process.ReadMemory(addr, size, err)
    if err.Success() and data:
        return data
    return None


def read_c_string(process: lldb.SBProcess, addr: int, max_len: int = 256):
    err = lldb.SBError()
    buf = process.ReadMemory(addr, max_len, err)
    if not (err.Success() and buf):
        return None
    nul = buf.find(b"\x00")
    end = nul if nul >= 0 else min(len(buf), max_len)
    try:
        return buf[:end].decode("utf-8", errors="ignore").strip()
    except Exception:
        return None

# Read a little-endian u64 from process memory

def read_u64(process: lldb.SBProcess, addr: int):
    data = read_bytes(process, addr, 8)
    if not data:
        return None
    try:
        return int.from_bytes(data, byteorder="little", signed=False)
    except Exception:
        return None


def derive_secrets_callback(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback Invoked ===")

    global active_debugger
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    label_size = get_reg_u64(frame, "r8") or 0
    label = read_c_string(process, get_reg_u64(frame, "rsi"), label_size) or "Unknown"
    
    set_WP = False
    if label in labels:
        set_WP = True

    if set_WP:

        # Compute return address by reading [rsp] (not rsp itself)
        rsp = get_reg_u64(frame, "rsp")
        ret_addr = read_u64(process, rsp) if rsp else None
        if not ret_addr:
            print("Failed to read return address from [rsp]")
            process.Continue()
            return False

        ret_bp = target.BreakpointCreateByAddress(ret_addr)
        if not ret_bp.IsValid():
            print("Failed to create return breakpoint")
            process.Continue()
            return False
        
        ret_bp.SetOneShot(True)
        ret_bp.SetThreadID(thread.GetThreadID())

        # Prefer mapping by location ID to match bp_loc in callback
        if ret_bp.GetNumLocations() > 0:
            loc = ret_bp.GetLocationAtIndex(0)
            ret_bp_map[loc.GetID()] = label
        else:
            ret_bp_map[ret_bp.GetID()] = label

        ret_bp.SetScriptCallbackFunction("gotls_cb_13.return_callback")

    process.Continue()
    return False


def return_callback(frame, bp_loc, internal_dict):
    import gotls_cb_13
    hit_time = datetime.now()

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    ret_val = get_reg_u64(frame, "rax")

    ret_data = read_bytes(process, ret_val, SECRET_SIZE)
    if not ret_data:
        print(f"Failed to read return value memory: {error.GetCString()}")
        return False
    
    # Try location ID first, then fallback to breakpoint ID
    label = ret_bp_map.get(bp_loc.GetID()) or ret_bp_map.get(bp_loc.GetBreakpoint().GetID(), "Unknown")
    if not label:
        print("No label found for this breakpoint")
        return False

    # Add so we can check availability again on exit (not used at the moment)
    active_secrets[label] = ret_val

    print(f"==!!!== RETURN BREAKPOINT HIT for '{label}' at on Timestamp {hit_time} ==!!!==")
    secret = ' '.join(f'{b:02x}' for b in ret_data[:SECRET_SIZE])
    gotls_cb_13.logger.queue_for_write(str(hit_time), label, secret)

    # Set WP on the secret
    wp = target.WatchAddress(ret_val, 1, False, True, error)
    if not error.Success() or not wp.IsValid():
        print(f"Failed to create watchpoint: {error.GetCString()}")
        return False
    else:
        watch_ID = wp.GetID()
        callback_name = f"watchpoint_cb_{watch_ID}"
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import lldb
    import gotls_cb_13
    hit_time = datetime.now()
    
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{ret_val:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    secret_data = gotls_cb_13.read_bytes(process, ret_val, {SECRET_SIZE})
    if secret_data:
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])
        gotls_cb_13.logger.queue_for_write(str(hit_time), "{label}", data_hex)
        print(f"Secret data: {{data_hex}}")

    return False
'''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

    process.Continue()
    return False

def derive_secrets_callback_12(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback (TLS 1.2) Invoked ===")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    expr_options = lldb.SBExpressionOptions()

    #shared.dump_args(frame)

    # Get RSP value first
    rsp_val = get_reg_u64(frame, "rsp")
    if not rsp_val:
        print("Failed to get RSP value")
        process.Continue()
        return False

    # Read the value at this stack position
    ptr_value = read_u64(process, rsp_val + 40)
    if not ptr_value:
        process.Continue()
        return False

    # Test if this looks like a valid memory address by trying to read from it
    test_data = read_bytes(process, ptr_value, 8)
    if not test_data:
        print(f"Cannot read from 0x{ptr_value:x}, probably not a valid buffer")

    out_size = 48
    label = "MASTER_SECRET"
                
    # Try to set watchpoint on this address
    wp = target.WatchAddress(ptr_value, 1, False, True, error)
    if error.Success() and wp.IsValid():
        print(f"*** Set 1-byte watchpoint on  candidate at 0x{ptr_value:x} ***")
        
        watch_ID = wp.GetID()
        callback_name = f"watchpoint_cb_{watch_ID}"
        fixed_ptr = ptr_value  # Use a fixed value to avoid closure issues
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    hit_time = datetime.now()
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    print(f"==!!!== WATCHPOINT HIT for  at 0x{fixed_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    secret_data = gotls_cb_13.read_bytes(process, {fixed_ptr}, {out_size})
    if secret_data:
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_size}])
        gotls_cb_13.logger.queue_for_write(str(hit_time), "{label}", data_hex)
        print(f"Secret data: {{data_hex}}")
    
    return False
'''
        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    else:
        print(f"Failed to set watchpoint for  at 0x{ptr_value:x}: {error.GetCString()}")

    # Monitor last byte aswell
    wp_tail = target.WatchAddress(ptr_value + out_size - 1, 1, False, True, error)
    if error.Success() and wp_tail.IsValid():
        print(f"*** Set 1-byte watchpoint on  candidate at 0x{ptr_value + out_size - 1:x} ***")

        watch_ID_tail = wp_tail.GetID()
        callback_name_tail = f"watchpoint_cb_{watch_ID_tail}"
        fixed_ptr = ptr_value + out_size - 1  # Use a fixed value to avoid closure issues
        callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    hit_time = datetime.now()
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    print(f"==!!!== TAIL WATCHPOINT HIT for  at 0x{fixed_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    secret_data = gotls_cb_13.read_bytes(process, {ptr_value}, {out_size})
    if secret_data:
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_size}])
        gotls_cb_13.logger.queue_for_write(str(hit_time), "{label}", data_hex)
        print(f"Secret data: {{data_hex}}")
    
    return False
'''
        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code_tail}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name_tail} {watch_ID_tail}")
    else:
        print(f"Failed to set watchpoint for  at 0x{fixed_ptr:x}: {error.GetCString()}")

    process.Continue()
    return False

# Should be triggered on session shutdown
def shutdown_callback(frame, bp_loc, internal_dict):
    print("=== Shutdown Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    shared.dump_memory_onEntry(process, file_path, "shutdown")


    exp_options = lldb.SBExpressionOptions()

    rsp = get_reg_u64(frame, "rsp")
    ret_addr = read_u64(process, rsp) if rsp else None
    if not ret_addr:
        print("Failed to read return address from [rsp]")
        process.Continue()
        return False
    ret_bp = target.BreakpointCreateByAddress(ret_addr)
    ret_bp.SetOneShot(True)

    args_dict = {'file_path': file_path, 'kind': 'shutdown'}

    # Create an SBStructuredData object from a JSON representation of our arguments.
    extra_args = lldb.SBStructuredData()
    extra_args.SetFromJSON(json.dumps(args_dict))

    debugger = target.GetDebugger()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    debugger.HandleCommand(f"command script import {script_dir}/shared.py")

    # Set the callback correctly with the function name and the extra_args object.
    ret_bp.SetScriptCallbackFunction("shared.dump_memory", extra_args)

    process.Continue()
    return False

def key_update_callback(frame, bp_loc, internal_dict):
    print("=== Key Update Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    shared.dump_memory_onEntry(process, file_path, "server_key_update")

    # Use the same robust method as other callbacks
    rsp = get_reg_u64(frame, "rsp")
    if not rsp:
        print("Failed to get RSP register value")
        process.Continue()
        return False
        
    ret_addr = read_u64(process, rsp)
    if not ret_addr:
        print("Failed to read return address from [rsp]")
        process.Continue()
        return False
            
    ret_bp = target.BreakpointCreateByAddress(ret_addr)        
    ret_bp.SetOneShot(True)
    ret_bp.SetThreadID(thread.GetThreadID())

    args_dict = {'file_path': file_path, 'kind': 'server_key_update'}

    # Create an SBStructuredData object from a JSON representation of our arguments.
    extra_args = lldb.SBStructuredData()
    extra_args.SetFromJSON(json.dumps(args_dict))

    debugger = target.GetDebugger()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    debugger.HandleCommand(f"command script import {script_dir}/shared.py")

    # Set the callback correctly with the function name and the extra_args object.
    ret_bp.SetScriptCallbackFunction("shared.dump_memory", extra_args)

    process.Continue()
    return False