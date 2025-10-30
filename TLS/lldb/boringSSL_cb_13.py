import lldb
from datetime import datetime
import sys, os
import json
import struct

try: 
    import shared
except ModuleNotFoundError:
    script_dir = os.path.dirname(__file__)
    if script_dir and script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import shared
    

file_path = "/tmp/boringssl/timing_13.csv"
save_interval = 6
auto_exit = True
SECRET_SIZE = 32


logger = shared.CSVLogger(file_path, save_interval, auto_exit)

"""
GetVariables() does not return the arguments as expected, so we parse the arguments manually.

args[0]: SSL_HANDSHAKE* context
args[1]: InplaceVector<unsigned char, 48> * out
args[2]: std::string_view label
"""

def derive_secrets_callback(frame, bp_loc, internal_dict):
    import struct
    error = lldb.SBError()

    print("=== Derive Secret Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    expr_options = lldb.SBExpressionOptions()
    label_found = False
    
    rdx_expr = frame.EvaluateExpression("$rdx", expr_options)
    rcx_expr = frame.EvaluateExpression("$rcx", expr_options)
    
    if rdx_expr.IsValid() and rcx_expr.IsValid():
        rdx_value = rdx_expr.GetValueAsUnsigned()
        rcx_value = rcx_expr.GetValueAsUnsigned()
        
        if 0 < rdx_value <= 50 and 0x1000 <= rcx_value < 0x7fffffffffff:
            string_data = process.ReadMemory(rcx_value, rdx_value, error)
            if error.Success():
                try:
                    label_str = string_data.decode('utf-8')
                    print(f"*** SUCCESS (registers): Label = '{label_str}' ***")
                    label_found = True
                except:
                    pass
    
    if not label_found:
        print("*** No valid label found ***")
        return False

    set_watchpoint = False
    if label_str in shared.labels:
        set_watchpoint = True

    if set_watchpoint:
        rsi_expr = frame.EvaluateExpression("$rsi", expr_options)
        out_ptr = None

        if rsi_expr.IsValid():
            out_ptr_candidate = rsi_expr.GetValueAsUnsigned()

            # Validate if this looks like a valid pointer
            if 0x1000 <= out_ptr_candidate < 0x7fffffffffff:
                out_ptr = out_ptr_candidate
        
        if out_ptr and out_ptr != 0:
            # Read the current InplaceVector state
            vector_data = process.ReadMemory(out_ptr, SECRET_SIZE + 8, error)  # 8 bytes size + SECRET_SIZE bytes data
            if error.Success(): 
                # struct has not the expected layout (no size, just data)
                current_size = struct.unpack('Q', vector_data[:8])[0]

                if 0 <= current_size <= SECRET_SIZE:
                    current_data = vector_data[8:8+SECRET_SIZE]  # Full data buffer
                    current_hex = ' '.join(f'{b:02x}' for b in current_data[:SECRET_SIZE])
                    print(f"Current data : {current_hex}")
            
            # Set watchpoint on the data portion 
            # dont skip size field because there is none
            data_addr = out_ptr
            print(f"Attempting to set watchpoint at data address: 0x{data_addr:x}")
            

            # We are setting a 1-byte watchpoint on the data address, this should trigger on any write
            # for 8-bytes only 2 WP could be set
            # for 24-bytes only 1 WP could be set
            # for larger sizes no WP could be set

            watchpoint = target.WatchAddress(data_addr, 1, False, True, error)
            
            if error.Success() and watchpoint.IsValid():
                print(f"*** Set 1-byte watchpoint on '{label_str}' at 0x{data_addr:x} ***")
                print(" ")
                watch_ID = watchpoint.GetID()

                callback_name = f"watchpoint_cb_{watch_ID}"
                fixed_addr = data_addr
                fixed_label = label_str
                fixed_out_ptr = out_ptr
                callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{fixed_label}' at 0x{fixed_addr:x} on Timestamp {{hit_time}} ==!!!==")


    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    # Read the current InplaceVector state
    vector_data = process.ReadMemory({fixed_out_ptr}, {SECRET_SIZE}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in vector_data[:{SECRET_SIZE}])

        import boringSSL_cb_13
        timestamp_str = str(hit_time)
        boringSSL_cb_13.logger.queue_for_write(timestamp_str, "{fixed_label}", data_hex)

    return False
'''

                frame_debugger = target.GetDebugger()
                frame_debugger.HandleCommand(f"script {callback_code}")

                frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")

            else:
                print(f"Failed to set 1-byte watchpoint: {error.GetCString()}")

    process.Continue()
    return False


"""
args[0]: const EVP_MD *digest        ($rdi)
args[1]: Span<uint8_t>* out          ($rsi), ($rdx)
args[2]: Span<const uint8_t> secret  ($rcx), ($r8)
args[3]: std::string_view label      
args[4]: Span<const uint8_t> seed1   
args[5]: Span<const uint8_t> seed2   

label_size: $rdx

secret_size: $r8
"""

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

    # out.len
    rdx_expr = frame.EvaluateExpression("$rdx", expr_options)
    if rdx_expr.IsValid():
        out_len = rdx_expr.GetValueAsUnsigned()
        print(f"*** Detected output length: {out_len} ***")
    
    if out_len != 48:
        print(f"Unexpected output length {out_len}, expected 48")
        return False
    
    # out.ptr
    rsi_expr = frame.EvaluateExpression("$rsi", expr_options)
    if rsi_expr.IsValid():
        out_ptr = rsi_expr.GetValueAsUnsigned()

    out_data = process.ReadMemory(out_ptr, out_len, error)
    if error.Success():
        data_hex = ' '.join(f'{b:02x}' for b in out_data)
        print(f"*** Out buffer data: {data_hex} ***")

    label_str = "MASTER_SECRET"

    watchpoint = target.WatchAddress(out_ptr, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Set 1-byte watchpoint on '{label_str}' at 0x{out_ptr:x} ***")
        print(" ")
        watch_ID = watchpoint.GetID()

        callback_name = f"watchpoint_callback_{watch_ID}"
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    import struct
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label_str}' at 0x{out_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    out_data = process.ReadMemory({out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in out_data)
        print(f"*** Out buffer data: {{data_hex}} ***")

        import boringSSL_cb_13
        timestamp_str = str(hit_time)
        boringSSL_cb_13.logger.queue_for_write(timestamp_str, "{label_str}", data_hex)

    return False
'''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")

        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    
    else:
        print(f"Failed to set watchpoint: {error.GetCString()}")

    watchpoint_tail = target.WatchAddress(out_ptr + out_len - 1, 1, False, True, error)
    if error.Success() and watchpoint_tail.IsValid():
        print(f"*** Set 1-byte watchpoint on tail of '{label_str}' at 0x{out_ptr + out_len - 1:x} ***")
        print(" ")
        watch_ID_tail = watchpoint_tail.GetID()

        callback_name_tail = f"watchpoint_callback_{watch_ID_tail}"
        callback_code_tail = f'''
def {callback_name_tail}(frame, bp_loc, internal_dict):
    import struct
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label_str}' at 0x{out_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    out_data = process.ReadMemory({out_ptr}, {out_len}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in out_data)
        print(f"*** Out buffer data: {{data_hex}} ***")

        import boringSSL_cb_13
        timestamp_str = str(hit_time)
        boringSSL_cb_13.logger.queue_for_write(timestamp_str, "{label_str}", data_hex)

    return False
'''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code_tail}")

        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name_tail} {watch_ID_tail}")

    else:
        print(f"Failed to set watchpoint: {error.GetCString()}")

    # Constructing args for return callback
    #args_dict = {'out_ptr': out_ptr, 'label_str': f"unknown_{hit_count}"}
    #extra_args = lldb.SBStructuredData()
    #extra_args.SetFromJSON(json.dumps(args_dict))

    # Setting BP onn return address (the out_ptr will then be populated)
    #return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", lldb.SBExpressionOptions()).GetValueAsUnsigned()
    #ret_bp = target.BreakpointCreateByAddress(return_addr)

    # Call back with args
    #ret_bp.SetScriptCallbackFunction("boringSSL_cb_13.on_return_callback_12", extra_args)
    #ret_bp.SetEnabled(True)

    # secret.ptr
    rcx_expr = frame.EvaluateExpression("$rcx", expr_options)
    if rcx_expr.IsValid():
        secret_ptr = rcx_expr.GetValueAsUnsigned()
    
    #secret.len
    r8_expr = frame.EvaluateExpression("$r8", expr_options)
    if r8_expr.IsValid():
        secret_size = r8_expr.GetValueAsUnsigned()
    
    try:
        secret_data = process.ReadMemory(secret_ptr, secret_size, error)
        if error.Success():
            secret_hex = ' '.join(f'{b:02x}' for b in secret_data[:secret_size])
            print(f"*** SUCCESS: Secret data (first {secret_size} bytes): {secret_hex} ***")
        else:
            print(f"Failed to read secret data at {secret_ptr:#x}: {error.GetCString()}")
    except Exception as e:
        print(f"Exception reading secret data: {e}")
        
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