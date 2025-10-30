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
    

file_path = "/tmp/libressl/timing_13.csv"
save_interval = 6
auto_exit = True

SECRET_SIZE = 32

logger = shared.CSVLogger(file_path, save_interval, auto_exit)


'''
The secrets are written in 32 byte chunks. 
TODO: Monitor the last 16 bytes for 48 byte secrets.
At the moment only the first 32 bytes are checked.

args[0]: tls13_secret *out                  ($RDI)
args[1]: const EVP_MD *digest               ($RSI)  
args[2]: const struct tls13_secret *secret  ($RDX)
args[3]: const uint8_t *label               ($RCX)
args[4]: size_t label_len                   ($R8)
args[5]: const struct tls13_secret *context ($R9)
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
        logger.start_save_timer()

    expr_options = lldb.SBExpressionOptions()

    # Get the registers
    rcx_expr = frame.EvaluateExpression("$rcx", expr_options)
    r8_expr = frame.EvaluateExpression("$r8", expr_options)

    # Get values
    rcx_value = rcx_expr.GetValueAsUnsigned()
    r8_value = r8_expr.GetValueAsUnsigned()

    string_data = process.ReadMemory(rcx_value, r8_value, error)
    if error.Success():
        label = string_data.decode('utf-8', errors='ignore')
    else:
        print(f"Failed to read memory at {rcx_value:#x}: {error.GetCString()}")
        label = "Unknown"   

    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        rdi_expr = frame.EvaluateExpression("$rdi", expr_options)
        out_ptr = rdi_expr.GetValueAsUnsigned()
        
        # Get the data pointer from the tls13_secret structure (first field)
        data_ptr = process.ReadPointerFromMemory(out_ptr, error)
        
        if error.Success():
            watchpoint = target.WatchAddress(data_ptr, 1, False, True, error)
        else:
            print(f"Failed to access data pointer: {error.GetCString()}")
    

        if error.Success() and watchpoint.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{out_ptr:#x} ***")
            print("")

            watch_ID = watchpoint.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            fixed_out_ptr = out_ptr
            fixed_label = label
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import lldb

    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_label}' at 0x{fixed_out_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    
    # Read the data pointer from tls13_secret structure
    data_ptr = process.ReadPointerFromMemory({fixed_out_ptr}, error)
    if not error.Success():
        print(f"Error reading data pointer: {{error.GetCString()}}")
        return False
        
    data_len = {SECRET_SIZE}
    
    if data_ptr != 0 and data_len > 0:

        secret_data = process.ReadMemory(data_ptr, data_len, error)
        if error.Success():

            data_hex = ' '.join(f'{{b:02x}}' for b in secret_data)

            import libressl_cb_13
            libressl_cb_13.logger.queue_for_write(str(hit_time), "{fixed_label}", data_hex)
            
        else:
            print(f"Error reading secret data: {{error.GetCString()}}")
    else:
        print(f"Invalid data pointer or length: ptr=0x{{data_ptr:x}}, len={{data_len}}")

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

    expr_options = lldb.SBExpressionOptions()
    label = "MASTER_SECRET"

    # Get RSP
    rsp = frame.FindRegister("rsp").GetValueAsUnsigned()

    # Calculate address of stack[7]
    stack7_addr = rsp + 8 + (7 * 8) 

    # Read the value at this address
    error = lldb.SBError()
    out_ptr = process.ReadPointerFromMemory(stack7_addr, error)
    if error.Success():
        print(f"out_ptr: 0x{out_ptr:x}")  
        
        # Next argument is out_len at stack[8]
        stack8_addr = rsp + 8 + (8 * 8)
        out_len = process.ReadPointerFromMemory(stack8_addr, error)
        if error.Success():
            print(f"out_len: {out_len}")
        else:
            out_len = 48 #default
        
        wp = target.WatchAddress(out_ptr, 1, False, True, error)
        if error.Success() and wp.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{out_ptr:#x} ***")
            print("")

            watch_ID = wp.GetID()
            callback_name = f"watchpoint_callback_{watch_ID}"
            fixed_out_ptr = out_ptr
            fixed_label = label
            callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import lldb

    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{out_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    secret_data = process.ReadMemory({fixed_out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data)
        import libressl_cb_13
        libressl_cb_13.logger.queue_for_write(str(hit_time), "{fixed_label}", data_hex)
        print(f"Secret data: {{data_hex}}")

    return False
'''
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

        else:
            print(f"Failed to set watchpoint: {error.GetCString()}")

        # The secret is written byte by byte, so also monitor the last byte of the secret to catch the end of the write
        tail_pointer = out_ptr + out_len - 1
        wp_tail = target.WatchAddress(tail_pointer, 1, False, True, error)
        if error.Success() and wp_tail.IsValid():
            print(f"*** Set 1-byte watchpoint on '{label}' at 0x{tail_pointer:#x} ***")
            print("")

            watch_ID = wp_tail.GetID()
            callback_name_tail = f"watchpoint_callback_{watch_ID}"
            fixed_label = label
            callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import lldb

    hit_time = datetime.now()
    print(f"==!!!== TAIL WATCHPOINT HIT for '{label}' at 0x{tail_pointer:x} on Timestamp {{hit_time}} ==!!!==")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    secret_data = process.ReadMemory({fixed_out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data)
        import libressl_cb_13
        libressl_cb_13.logger.queue_for_write(str(hit_time), "{fixed_label}", data_hex)
        print(f"Secret data: {{data_hex}}")

    return False
'''
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code_tail}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name_tail} {watch_ID}")

        else:
            print(f"Failed to set tail watchpoint: {error.GetCString()}")
    
    #shared.dump_args(frame)

    process.Continue()
    return False

# Should be triggered on session shutdown
def shutdown_callback(frame, bp_loc, internal_dict):
    print("=== Shutdown Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    
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