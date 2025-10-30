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


file_path = "/tmp/gnutls/timing_13.csv"
SECRET_SIZE = 32
save_interval = 6
auto_exit = True

logger = shared.CSVLogger(file_path, save_interval, auto_exit)


'''
GnuTLS writes secrets byte by byte.
Therefore we set a WP on the last byte of secret for detecting the moment when the secret is fully written.

(After the WP is hit, we set a WP on the first byte of secret to detect the next write (removal)).
The last byte WP is never hit after the secret hase been written, indicating that the secret is not (completely) removed.
TODO: Exit check on Secrets to check for removal


args[0]: gnutls_session_t session ($RDI)
args[1]: char *label              ($RSI)
args[2]: uint label_size          ($RDX)
args[3]: uint8_t *hash            ($RCX)
args[4]: size_t hash_size         ($R8)
args[5]: uint8_t *secret          ($R9)
args[6]: void *out                ($RSP + 8)
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

    # Get the registers
    label_ptr = frame.EvaluateExpression("$rsi", exp_options).GetValueAsUnsigned()
    label_size = frame.EvaluateExpression("$rdx", exp_options).GetValueAsUnsigned()

    string_data = process.ReadMemory(label_ptr, label_size, error)
    if error.Success():
        label = string_data.decode('utf-8')
    else:
        print(f"Failed to read memory at {label_ptr:#x}: {error.GetCString()}")
        label = "Unknown"

    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True
    
    if set_watchpoint:
        # parsing arguments
        out_ptr_addr = frame.EvaluateExpression("$rsp + 8", exp_options).GetValueAsUnsigned()
        secret_ptr = process.ReadPointerFromMemory(out_ptr_addr, error) + (SECRET_SIZE - 1)
        secret_start_ptr = secret_ptr - (SECRET_SIZE - 1)

        # Set WP on tail of the secret
        watchpoint = target.WatchAddress(secret_ptr, 1, False, True, error)
        if error.Success() and watchpoint.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{secret_ptr:x} ***")
            print(" ")
        
            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{secret_start_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    secret_data = process.ReadMemory({secret_start_ptr}, {SECRET_SIZE}, error)

    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])
        
        import gnutls_cb_13
        timestamp_str = str(hit_time)
        gnutls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

        else:
            print(f"Failed to set watchpoint: {error.GetCString()}")
    
    process.Continue()
    return False

'''
_gnutls_prf_raw()

args[7]: size_t out_size    ($rsp + 16)
args[8]: char *out          ($rsp + 24)
'''
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

    shared.dump_args(frame)

    label = "MASTER_SECRET"

    args = frame.GetVariables(True, False, False, True)
    out_ptr = None
    for var in args:
        if var.GetName() == "dst":
            out_ptr = var.GetValueAsUnsigned()
            break

    #out_ptr = frame.EvaluateExpression("$rsp + 32", expr_options).GetValueAsUnsigned()
    out_size = 48

    watchpoint = target.WatchAddress(out_ptr, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{out_ptr:x} ***")
            print(" ")
        
            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{out_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_ptr}, {out_size}, error)

    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_size}])
        print(f"{{data_hex}}")
        import gnutls_cb_13
        timestamp_str = str(hit_time)
        gnutls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

    watchpoint_tail = target.WatchAddress(out_ptr + out_size - 1, 1, False, True, error)
    if error.Success() and watchpoint_tail.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{out_ptr:x} ***")
            print(" ")

            watch_ID_tail = watchpoint_tail.GetID()
            callback_name_tail = f"watchpoint_callback_{watch_ID_tail}"
            callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== TAIL WATCHPOINT HIT for '{label}' at 0x{out_ptr + out_size - 1:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_ptr}, {out_size}, error)

    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_size}])
        print(f"{{data_hex}}")
        import gnutls_cb_13
        timestamp_str = str(hit_time)
        gnutls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

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
    ret_bp.SetScriptCallbackFunction("shared.dump_memory_error_check", extra_args)

    process.Continue()
    return False