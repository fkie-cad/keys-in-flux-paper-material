import lldb
from datetime import datetime
import os
import sys
import json

try: 
    import shared
except ModuleNotFoundError:
    script_dir = os.path.dirname(__file__)
    if script_dir and script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import shared

csvData = []
file_path = "/tmp/botanssl/timing_13.csv"
save_interval = 6
SECRET_SIZE = 32
auto_exit = True

logger = shared.CSVLogger(file_path, save_interval, auto_exit)
ret_bp_map = {}

'''
Label and labe size parsed correctly.
Secret size correctly parsed
hidden return : secure_vector<uint8_t>        ($RDI)
       : this                                 ($RSI)
args[0]: const secure_vector<uint8_t>& secret ($RDX) input secret
args[1]: std::string_view label               ($RCX, $R8) (size, ptr) [may be ptr,size depending on compiler]
args[2]: const Transcript_Hash& messages_hash
'''
def derive_secrets_callback(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback Invoked ===")

    global ret_bp_map
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()
    
    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        logger.start_save_timer()

    expr_options = lldb.SBExpressionOptions()

    # Read arguments
    label_ptr = frame.EvaluateExpression("$r8", expr_options).GetValueAsUnsigned()
    label_size = frame.EvaluateExpression("$rcx", expr_options).GetValueAsUnsigned()
    secret_vec  = frame.EvaluateExpression("$rdi", expr_options).GetValueAsUnsigned()

    label_data = process.ReadMemory(label_ptr, label_size, error)
    if error.Fail():
        print(f"Failed to read label memory: {error.GetCString()}")
        return False
    label = label_data.decode('utf-8', errors='ignore').strip() or "Unknown"


    # Only track traffic secrets
    if not (label.startswith("c hs traffic") or label.startswith("s hs traffic") or
            label.startswith("c ap traffic") or label.startswith("s ap traffic")):
        process.Continue()
        return False

    # Set return BP (one-shot)
    try:
        return_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", expr_options).GetValueAsUnsigned()
        ret_bp = target.BreakpointCreateByAddress(return_addr)
        if not ret_bp.IsValid():
            print(f"Failed to create return breakpoint: {error.GetCString()}")
            process.Continue()
            return False

        ret_bp.SetOneShot(True)
        ret_bp.SetThreadID(thread.GetThreadID())

        # Store metadata for static callback
        ret_bp_map[ret_bp.GetID()] = {
            'label': label,
            'vec_addr': secret_vec,
        }

        # Use direct script callback
        ret_bp.SetScriptCallbackFunction("botanssl_cb_13.return_callback")
        print(f"Set one-shot return breakpoint {ret_bp.GetID()} at 0x{return_addr:x} for label '{label}'")
    except Exception as e:
        print(f"Error arming return breakpoint: {e}")

    process.Continue()
    return False


def return_callback(frame, bp_loc, internal_dict):
    import botanssl_cb_13
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    bp_id = bp_loc.GetBreakpoint().GetID()
    meta = botanssl_cb_13.ret_bp_map.get(bp_id)
    if not meta:
        print(f"No metadata for breakpoint {bp_id}")
        return False

    label = meta['label']
    vec_addr = meta['vec_addr']

    # Read std::vector<uint8_t> {begin, end}
    begin = process.ReadPointerFromMemory(vec_addr + 0x0, error)
    if error.Fail():
        print(f"Failed to read vector.begin(): {error.GetCString()}")
        process.Continue()
        return False
    end = process.ReadPointerFromMemory(vec_addr + 0x8, error)
    if error.Fail():
        print(f"Failed to read vector.end(): {error.GetCString()}")
        process.Continue()
        return False

    if begin == 0 or end < begin:
        process.Continue()
        return False

    size = end - begin
    if size <= 0:
        process.Continue()
        return False

    size = min(64, size)
    data = process.ReadMemory(begin, size, error)
    if error.Fail() or not data:
        print(f"Failed to read secret memory: {error.GetCString()}")
        # Remove the return breakpoint to avoid repeated failures
        target.BreakpointDelete(bp_id)
        return False

    hit_time = datetime.now()
    data_hex = ' '.join(f'{b:02x}' for b in data[:SECRET_SIZE])
    print(f"==!!!== RETURN BREAKPOINT HIT for '{label}' at 0x{begin:x} on Timestamp {hit_time} ==!!!==")

    botanssl_cb_13.logger.queue_for_write(str(hit_time), label, data_hex)
    print(f"Secret data: {data_hex}")

    # Set a 1-byte watchpoint
    wperr = lldb.SBError()
    wp = target.WatchAddress(begin, 1, False, True, wperr)
    if not wperr.Success() or not wp.IsValid():
        print(f"Failed to set watchpoint on 0x{begin:x}: {wperr.GetCString()}")
    else:
        # Disable temporarily to avoid race while attaching command
        wp.SetEnabled(False)
        watch_ID = wp.GetID()
        callback_name = f"watchpoint_cb_{watch_ID}"
        dbg = target.GetDebugger()
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import lldb
    import botanssl_cb_13
    hit_time = datetime.now()
    addr = 0x{begin:x}
    watch_id = {watch_ID}
    # Dynamic label lookup so address reuse gets latest label
    label = "{label}"
    try:
        thread = frame.GetThread()
        process = thread.GetProcess()
        err = lldb.SBError()
        secret_data = process.ReadMemory(addr, {SECRET_SIZE}, err)
        if err.Success() and secret_data:
            data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])
            botanssl_cb_13.logger.queue_for_write(str(hit_time), label, data_hex)
            print(f"==!!!== WATCHPOINT HIT for '{{label}}' at 0x{{addr:x}} on {{hit_time}}")
            print(data_hex)
        # One-shot removal for handshake traffic
        if label.startswith('c hs traffic') or label.startswith('s hs traffic'):
            tgt = process.GetTarget()
            try:
                tgt.DeleteWatchpoint(watch_id)
            except Exception:
                try:
                    wp = tgt.FindWatchpointByID(watch_id)
                    if wp and wp.IsValid():
                        wp.Clear()
                except Exception:
                    pass
            print(f"[watch] one-shot: removed watchpoint {{watch_id}} for '{{label}}' at 0x{{addr:x}}")
    except Exception as e:
        print(f"[watch] error: {{e}}")
    return False
'''
        # Define function then attach as command
        dbg.HandleCommand(f"script {callback_code}")
        dbg.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
        wp.SetEnabled(True)
        print(f"*** Watchpoint set at address: 0x{begin:x} (id {watch_ID}) ***")

    # Delete the return breakpoint now that we handled setup
    target.BreakpointDelete(bp_id)
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

    ret_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", expr_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(ret_addr)
    if not ret_bp.IsValid():
        print(f"Failed to create return breakpoint: {error.GetCString()}")
        process.Continue()
        return False
    
    ret_bp.SetScriptCallbackFunction("botanssl_cb_13.return_callback_12")
    ret_bp.SetOneShot(True)

    process.Continue()
    return False

def return_callback_12(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback onReturn (TLS 1.2) Invoked ===")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    expr_options = lldb.SBExpressionOptions()

    # Get the real PRF
    rax = frame.EvaluateExpression("$rax", expr_options).GetValueAsUnsigned()
    if rax == 0:
        print("RAX is NULL")
        return False

    # First dereference
    ptr1 = process.ReadPointerFromMemory(rax, error)
    if error.Fail() or ptr1 == 0:
        print(f"Failed to read first pointer: {error.GetCString()}")
        return False

    # Second dereference
    ptr2 = process.ReadPointerFromMemory(ptr1, error)
    if error.Fail() or ptr2 == 0:
        print(f"Failed to read second pointer: {error.GetCString()}")
        return False

    # Now add offset and read the final pointer
    prf_addr = process.ReadPointerFromMemory(ptr2 + 0x20, error)
    if error.Fail() or prf_addr == 0:
        print(f"Failed to read PRF function pointer: {error.GetCString()}")
        return False

    print(f"Found PRF function at address: 0x{prf_addr:x}")

    prf_bp = target.BreakpointCreateByAddress(prf_addr)
    if not prf_bp.IsValid():
        print(f"Failed to create PRF breakpoint: {error.GetCString()}")
        process.Continue()
        return False
    else:
        print(f"Set PRF breakpoint at 0x{prf_addr:x}")

    prf_bp.SetScriptCallbackFunction("botanssl_cb_13.prf_callback_12")

    process.Continue()
    return False

'''
args[3]: out*       ($rcx)
args[4]: out_len    ($r8)
'''
def prf_callback_12(frame, bp_loc, internal_dict):
    print("=== PRF Callback (TLS 1.2) Invoked ===")
    from datetime import datetime
    import botanssl_cb_13
    # save the time directly on hit
    hit_time = datetime.now()
    
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        label_str = "PRE_MASTER_SECRET"
    elif hit_count == 2:
        label_str = "MASTER_SECRET"
    else:
        process.Continue()
        return False

    expr_options = lldb.SBExpressionOptions()
    #shared.dump_args(frame)

    rcx = frame.EvaluateExpression("$rcx", expr_options).GetValueAsUnsigned()
    r8 = frame.EvaluateExpression("$r8", expr_options).GetValueAsUnsigned()
    print(f"out ptr: 0x{rcx:x}, out len: {r8}")

    out_data = process.ReadMemory(rcx, r8, error)
    if error.Fail() or not out_data:
        print(f"Failed to read out memory: {error.GetCString()}")
        process.Continue()
        return False
    data_hex = ' '.join(f'{b:02x}' for b in out_data)
    print(f"*** Out buffer data: {data_hex} ***")


    timestamp_str = str(hit_time)
    botanssl_cb_13.logger.queue_for_write(timestamp_str, label_str, data_hex)

    watchpoint = target.WatchAddress(rcx, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Set 1-byte watchpoint on '{label_str}' at 0x{rcx:x} ***")
        print(" ")
        watch_ID = watchpoint.GetID()

        callback_name = f"watchpoint_callback_{watch_ID}"
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    import struct
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label_str}' at 0x{rcx:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    out_data = process.ReadMemory({rcx}, {r8}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in out_data)
        print(f"*** Out buffer data: {{data_hex}} ***")

        import botanssl_cb_13
        timestamp_str = str(hit_time)
        botanssl_cb_13.logger.queue_for_write(timestamp_str, "{label_str}", data_hex)

    return False
'''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")

        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    
    else:
        print(f"Failed to set watchpoint: {error.GetCString()}")


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

    return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
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

# Should be triggered when key update is done
def key_update_callback(frame, bp_loc, internal_dict):
    print("=== Key Update Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    shared.dump_memory_onEntry(process, file_path, "server_key_update")


    exp_options = lldb.SBExpressionOptions()

    return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
    ret_bp.SetOneShot(True)

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

# Should be triggered on session abort
def abort_callback(frame, bp_loc, internal_dict):
    print("=== Abort Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    shared.dump_memory_onEntry(process, file_path, "abort")

    exp_options = lldb.SBExpressionOptions()

    return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
    ret_bp.SetOneShot(True)

    args_dict = {'file_path': file_path, 'kind': 'abort'}

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