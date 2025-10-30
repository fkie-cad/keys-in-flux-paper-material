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


file_path = "/tmp/openssl/timing_13.csv"
save_interval = 6
auto_exit = True
SECRET_SIZE = 32 # Change as needed

logger = shared.CSVLogger(file_path, save_interval, auto_exit)

'''

args[0]: SSL_CONNECTION *s             ($RDI)
args[1]: const EVP_MD *md              ($RSI)
args[2]: const EVP_CIPHER *ciph        ($RDX)
args[3]: int mac_type                  ($RCX)
args[4]: const EVP_MD *mac_md          ($R8)
args[5]: const unsigned char *insecret ($R9)
args[6]: const unsigned char *hash     ($RSP + 8)
args[7]: const unsigned char *label    ($RSP + 16)
args[8]: size_t labellen               ($RSP + 24)
args[9]: unsigned char *secret         ($RSP + 32)
args[10]: unsigned char *key           ($RSP + 40)
args[11]: size_t *keylen               ($RSP + 48)
args[12]: unsigned char **iv           ($RSP + 56)
args[13]: size_t *ivlen                ($RSP + 64)
args[14]: size_t *taglen               ($RSP + 72)
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

    label_ptr = frame.EvaluateExpression("*(unsigned char**)(void*)($rsp + 16)", exp_options).GetValueAsUnsigned()
    label_size = 12

    string_data = process.ReadMemory(label_ptr, label_size, error)
    if error.Success():
        label = string_data.decode('utf-8', errors='ignore')
    else:
        print(f"Error reading label: {error.GetCString()}")
        return False

    # We are only interested in certain labels
    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        secret_ptr = frame.EvaluateExpression("*(unsigned char**)(void*)($rsp + 32)", exp_options).GetValueAsUnsigned()
        watchpoint = target.WatchAddress(secret_ptr, 1, False, True, error)
        if error.Success() and watchpoint.IsValid():
            print(f"*** Set watchpoint on label '{label}' at address {secret_ptr:#x} ***")
            print("")

            watch_ID = watchpoint.GetID()

            callback_name = f"watchpoint_callback_{watch_ID}"
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{secret_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({secret_ptr}, {SECRET_SIZE}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])

        import openssl_cb_13
        timestamp_str = str(hit_time)
        openssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

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

    exp_options = lldb.SBExpressionOptions()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    label = "MASTER SECRET"
    out_len = 48
    out_ptr = frame.EvaluateExpression("$rsi", exp_options).GetValueAsUnsigned()

    watchpoint = target.WatchAddress(out_ptr, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Set watchpoint on label '{label}' at address {out_ptr:#x} ***")
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
        print(f"Secret Data: {{data_hex}}")

        import openssl_cb_13
        timestamp_str = str(hit_time)
        openssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")


    watchpoint_tail = target.WatchAddress(out_ptr + out_len -1, 1, False, True, error)
    if error.Success() and watchpoint_tail.IsValid():
        print(f"*** Set watchpoint on label '{label}' at address {out_ptr + out_len - 1:#x} ***")
        print("")

        watch_ID_tail = watchpoint_tail.GetID()

        callback_name_tail = f"watchpoint_callback_{watch_ID_tail}"
        callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== TAIL WATCHPOINT HIT for '{label}' at 0x{out_ptr + out_len - 1:#x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{out_len}])
        print(f"Secret Data: {{data_hex}}")

        import openssl_cb_13
        timestamp_str = str(hit_time)
        openssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

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