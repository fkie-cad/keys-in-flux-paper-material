import lldb
from datetime import datetime
import threading
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



file_path = "/tmp/s2ntls/timing_13.csv"
save_interval = 6
auto_exit = True
SECRET_SIZE = 32

logger = shared.CSVLogger(file_path, save_interval, auto_exit)

def parse_s2n_blob(process, blob_ptr):
    error = lldb.SBError()
    data_ptr = process.ReadPointerFromMemory(blob_ptr, error)
    if not error.Success() or data_ptr == 0:
        return None, None
    
    size = process.ReadUnsignedFromMemory(blob_ptr + 8, 4, error)
    if not error.Success():
        return None, None
        
    return data_ptr, size

'''
struct s2n_blob {
    uint8_t *data;
    size_t size;
    uint32_t allocated;
    unsigned growable:1;
};

s2n_derive_secrets
args[0]: s2n_hmac_algorithm hmac_alg                            ($RDI)
args[1]: const struct s2n_blob *previous_secret_material        ($RSI)
args[2]: const struct s2n_blob *label                           ($RDX)
args[3]: const struct s2n_blob *context                         ($RCX)
args[4]: struct s2n_blob *output                                ($R8)
==> This would produce invalid label and out pointer

s2n_hkdf_expand_label          
args[0]: struct s2n_hmac_state *hmac    ($RDI)
args[1]: s2n_hmac_algorithm alg         ($RSI)
args[2]: const struct s2n_blob *secret  ($RDX)
args[3]: const struct s2n_blob *label   ($RCX)
args[4]: const struct s2n_blob *context ($R8)
args[5]: struct s2n_blob *output        ($R9)
'''
def derive_secrets_callback(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback Invoked ===")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()
    
    exp_options = lldb.SBExpressionOptions()

    # Parse the label
    label_ptr = frame.EvaluateExpression("$rcx", exp_options).GetValueAsUnsigned()
    label_tupele = parse_s2n_blob(process, label_ptr)
    if label_tupele is None:
        print("*** Failed to read label blob ***")
        return False
    else:
        label_content = process.ReadMemory(label_tupele[0], label_tupele[1], error)
        if error.Success():
            label = label_content.decode('utf-8', errors='ignore')
        else:
            print(f"Error reading label memory: {error.GetCString()}")

    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        out_ptr = frame.EvaluateExpression("$r9", exp_options).GetValueAsUnsigned()
        out_tuple = parse_s2n_blob(process, out_ptr)
        watchpoint = target.WatchAddress(out_tuple[0], 1, False, True, error)

        if error.Success() and watchpoint.IsValid():
            print(f"*** Watchpoint set for label {label} blob at {out_tuple[0]:#x} ***")
            
            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{out_tuple[0]:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_tuple[0]}, {out_tuple[1]}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_tuple[1]}])

        import s2n_cb_13
        timestamp_str = str(hit_time)
        s2n_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

    process.Continue()
    return False

'''
S2N_RESULT s2n_prf_custom(struct s2n_connection *conn, 
                          struct s2n_blob *secret, 
                          struct s2n_blob *label,
                          struct s2n_blob *seed_a, 
                          struct s2n_blob *seed_b, 
                          struct s2n_blob *seed_c, 
                          struct s2n_blob *out)

'''
def derive_secrets_callback_12(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback (TLS 1.2) Invoked ===")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    exp_options = lldb.SBExpressionOptions()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    shared.dump_args(frame)

    label = "MASTER SECRET"
    out_ptr = frame.EvaluateExpression("*(unsigned long*)($rsp + 8)", exp_options).GetValueAsUnsigned()
    if not error.Success() or out_ptr == 0:
        print("*** Failed to read out blob pointer ***")
        return False
    
    out_tuple = parse_s2n_blob(process, out_ptr)
    if out_tuple[0] is None:
        print("*** Failed to read out blob ***")
        return False

    watchpoint = target.WatchAddress(out_tuple[0], 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
            print(f"*** Watchpoint set for label {label} blob at {out_tuple[0]:#x} ***")
            
            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{out_tuple[0]:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_tuple[0]}, {out_tuple[1]}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_tuple[1]}])
        print(f"    Data (hex): {{data_hex}}")
        import s2n_cb_13
        timestamp_str = str(hit_time)
        s2n_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

    # Set a watchpoint on the last byte as well
    # Data is written in 32 byte chunks, so we want to catch the write that completes the secret
    watchpoint_tail = target.WatchAddress(out_tuple[0] + out_tuple[1] - 1, 1, False, True, error)
    if error.Success() and watchpoint_tail.IsValid():
            print(f"*** Watchpoint set for label {label} blob at {out_tuple[0]:#x} ***")
            
            watch_ID_tail = watchpoint_tail.GetID()
            callback_name_tail = f"watchpoint_callback_{watch_ID_tail}"
            callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== TAIL WATCHPOINT HIT for '{label}' at 0x{out_tuple[0]:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_tuple[0]}, {out_tuple[1]}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_tuple[1]}])
        print(f"    Data (hex): {{data_hex}}")
        import s2n_cb_13
        timestamp_str = str(hit_time)
        s2n_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code_tail}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name_tail} {watch_ID_tail}")

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

# Should be triggered on session cleanup
def cleanup_callback(frame, bp_loc, internal_dict):
    print("=== Cleanup Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    shared.dump_memory_onEntry(process, file_path, "cleanup")

    exp_options = lldb.SBExpressionOptions()

    return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
    ret_bp.SetOneShot(True)

    args_dict = {'file_path': file_path, 'kind': 'cleanup'}

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