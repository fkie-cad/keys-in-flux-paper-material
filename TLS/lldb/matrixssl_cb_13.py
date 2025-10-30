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
    

file_path = "/tmp/matrixssl/timing_13.csv"
save_interval = 6
auto_exit = True
SECRET_SIZE = 32 # Change as needed

logger = shared.CSVLogger(file_path, save_interval, auto_exit)


'''
args[0]: psPool_t *pool                 ($RDI)
args[1]: psCipherType_e hmacAlg         ($RSI)
args[2]: const unsigned char *secret    ($RDX)
args[3]: psSize_t secretLen             ($RCX)
args[4]: const char *label              ($R8)
args[5]: psSize_t labelLen              ($R9)
args[6]: const unsigned char *context   ($RSP + 8)
args[7]: psSize_t contextLen            ($RSP + 16)
args[8]: psSize_t length                ($RSP + 24)
args[9]: unsigned char *out             ($RSP + 32)
'''
def derive_secrets_callback(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback Invoked ===")

    global active_debugger
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()
    
    exp_options = lldb.SBExpressionOptions()
    
    label_ptr = frame.EvaluateExpression("$r8").GetValueAsUnsigned()
    label_size = frame.EvaluateExpression("$r9").GetValueAsUnsigned()

    string_data = process.ReadMemory(label_ptr, label_size, error)
    if error.Success():
        label = string_data.decode('utf-8', errors='ignore')
    else:
        print(f"Failed to read label memory: {error.GetCString()}")
        label = "Unknown"
    
     # We are only interested in certain labels
    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        out_addr = frame.EvaluateExpression("$rsp + 32", exp_options).GetValueAsUnsigned()
        secret_ptr = process.ReadPointerFromMemory(out_addr, error)

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

        import matrixssl_cb_13
        timestamp_str = str(hit_time)
        matrixssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
        

    process.Continue()
    return False

'''
int32_t prf2(const unsigned char *sec, uint16_t secLen,
			 const unsigned char *seed, uint16_t seedLen,
			 unsigned char *out, uint16_t outLen, uint32_t flags)
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

    #shared.dump_args(frame)

    exp_options = lldb.SBExpressionOptions()

    out_len = frame.EvaluateExpression("$r9").GetValueAsUnsigned()
 ##   if out_len != 0x30:
  #      print(f"Unexpected outLen: {out_len}, expected 48")
   #     process.Continue()
    #    return False 
    
    out_ptr = frame.EvaluateExpression("$r8").GetValueAsUnsigned()
    print(f"Output pointer: {out_ptr:#x}")
    label = "MASTER_SECRET"

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
        print(f"   Data: {{data_hex}}")

        import matrixssl_cb_13
        timestamp_str = str(hit_time)
        matrixssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)
    
    else:
        print(f"Failed to read secret memory: {{error.GetCString()}}")

    return False
'''
        
        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

    watchpoint_tail = target.WatchAddress(out_ptr + out_len - 1, 1, False, True, error)

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
        print(f"   Data: {{data_hex}}")

        import matrixssl_cb_13
        timestamp_str = str(hit_time)
        matrixssl_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)
    
    else:
        print(f"Failed to read secret memory: {{error.GetCString()}}")

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
    ret_bp.SetScriptCallbackFunction("shared.dump_memory_error_check", extra_args)

    process.Continue()
    return False