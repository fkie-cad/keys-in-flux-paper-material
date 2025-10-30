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
    

file_path = "/tmp/mbedtls/timing_13.csv"
save_interval = 6
auto_exit = True

SECRET_SIZE = 32

logger = shared.CSVLogger(file_path, save_interval, auto_exit)

'''
args[0]: psa_algorithm_t hash_alg                 ($RDI)
args[1]: const unsigned char *secret              ($RSI)
args[2]: size_t secret_len                        ($RDX)
args[3]: unsigned char *label                     ($RCX)
args[4]: size_t label_len                         ($R8)
args[5]: unsigned char *ctx                       ($R9)
args[6]: size_t ctx_len                           ($RSP + 8)
args[7]: int ctx_hashed                           ($RSP + 16)
args[8]: unsigned char *dstbuf                    ($RSP + 24)
args[9]: size_t dstbuf_len                        ($RSP + 32)
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
    rcx_expr = frame.EvaluateExpression("$rcx", exp_options)
    r8_expr = frame.EvaluateExpression("$r8", exp_options)

    # Get the values
    rcx_value = rcx_expr.GetValueAsUnsigned()
    r8_value = r8_expr.GetValueAsUnsigned()

    string_data = process.ReadMemory(rcx_value, r8_value, error)
    if error.Success():
        label = string_data.decode('utf-8', errors='ignore')
    else:
        print(f"Error reading memory: {error.GetCString()}")
        return False

    
    # We are only interested in certain labels
    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        # parsing arguments
        args_8 = frame.EvaluateExpression("*(unsigned char**)($rsp + 24)", exp_options)
        args_9 = frame.EvaluateExpression("*(size_t*)($rsp + 32)", exp_options)

        # Get the values
        secret_addr = args_8.GetValueAsUnsigned()

        watchpoint = target.WatchAddress(secret_addr, 1, False, True, error)
        if error.Success() and watchpoint.IsValid():
            print(f"*** Set watchpoint on '{label}' at 0x{secret_addr:#x} with size 1 ***")
            print("")

            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{secret_addr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({secret_addr}, {SECRET_SIZE}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])

        import mbedtls_cb_13
        timestamp_str = str(hit_time)
        mbedtls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

        else:
            print(f"Failed to set watchpoint: {error.GetCString()}")

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

    #shared.dump_args(frame)

    label = "MASTER SECRET"
    out_len = 48;
    out_ptr = frame.EvaluateExpression("$rsi").GetValueAsUnsigned()
    
    watchpoint = target.WatchAddress(out_ptr, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Set watchpoint on '{label}' at 0x{out_ptr:#x} with size 1 ***")
        print("")

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
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_len}])
        print(f"   Data: {{data_hex}}")

        import mbedtls_cb_13
        timestamp_str = str(hit_time)
        mbedtls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")


    watchpoint_tail = target.WatchAddress(out_ptr + out_len - 1, 1, False, True, error)
    if error.Success() and watchpoint_tail.IsValid():
        print(f"*** Set watchpoint on '{label}' at 0x{out_ptr + out_len - 1:#x} with size 1 ***")
        print("")

        watch_ID_tail = watchpoint_tail.GetID()
        callback_name_tail = f"watchpoint_callback_{watch_ID_tail}"
        callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{out_ptr + out_len - 1:#x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_len}])
        print(f"   Data: {{data_hex}}")

        import mbedtls_cb_13
        timestamp_str = str(hit_time)
        mbedtls_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

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