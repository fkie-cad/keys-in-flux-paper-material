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


file_path = "/tmp/rustls/timing_13.csv"
save_interval = 6
auto_exit = True
SECRET_SIZE = 32 # Change as needed

ret_bp_map = {}
logger = shared.CSVLogger(file_path, save_interval, auto_exit)

secret_kinds = ["ResumptionPskBinderKey",
                 "ClientEarlyTrafficSecret",
                 "ClientHandshakeTrafficSecret",
                 "ServerHandshakeTrafficSecret",
                 "ClientApplicationTrafficSecret",
                 "ServerApplicationTrafficSecret",
                 "ExporterMasterSecret",
                 "ResumptionMasterSecret",
                 "DerivedSecret",
                 "ServerEchConfirmationSecret",
                 "ServerEchHrrConfirmationSecret"]

label_map = {
    "ResumptionPskBinderKey": "res binder",
    "ClientEarlyTrafficSecret": "c e traffic",
    "ClientHandshakeTrafficSecret": "c hs traffic",
    "ServerHandshakeTrafficSecret": "s hs traffic",
    "ClientApplicationTrafficSecret": "c ap traffic",
    "ServerApplicationTrafficSecret": "s ap traffic",
    "ExporterMasterSecret": "exp master",
    "ResumptionMasterSecret": "res master",
    "DerivedSecret": "derived",
    "ServerEchConfirmationSecret": "ech accept confirmation",
    "ServerEchHrrConfirmationSecret": "hhr ech accept confirmation",
}


'''
fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> OkmBlock

args[0]: &self ($r9)
args[1]: kind  ($rdx)
args[2]: hs_hash ($rci)

salt in $rdi or $rsi
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

    secret_kind_arg = frame.EvaluateExpression("$rdx", exp_options).GetValueAsUnsigned()
    secret_kind = secret_kinds[secret_kind_arg]
    label = label_map.get(secret_kind, "Unknown")

    set_WP = False
    if label in shared.labels: 
        set_WP = True

    if set_WP:

        # Set BP on return address
        return_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", exp_options).GetValueAsUnsigned()
        ret_bp = target.BreakpointCreateByAddress(return_addr)
        if not ret_bp.IsValid():
            print(f"Failed to create return breakpoint: {error.GetCString()}")
            process.Continue()
            return False
        
        ret_bp.SetOneShot(True)
        ret_bp.SetThreadID(thread.GetThreadID())

        ret_bp_map[ret_bp.GetID()] = label
        ret_bp.SetScriptCallbackFunction("rustls_cb_13.return_callback")

    process.Continue()
    return False


def return_callback(frame, bp_loc, internal_dict):
    import rustls_cb_13
    hit_time = datetime.now()

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()    

    ret_val = frame.EvaluateExpression("$rax", lldb.SBExpressionOptions()).GetValueAsUnsigned()
    ret_data = process.ReadMemory(ret_val, SECRET_SIZE, error)   
    if error.Fail():
        print(f"Failed to read return value memory: {error.GetCString()}")
        return False
    
    label = ret_bp_map.get(bp_loc.GetBreakpoint().GetID(), "Unknown")
    if not label:
        print("No label found for return breakpoint")
        return False
    
    print(f"==!!!== RETURN BREAKPOINT HIT for '{label}' at on Timestamp {hit_time} ==!!!==")
    secret = ' '.join(f'{b:02x}' for b in ret_data[:SECRET_SIZE])
    rustls_cb_13.logger.queue_for_write(str(hit_time), label, secret)
    
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
    import rustls_cb_13
    hit_time = datetime.now()
    
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{ret_val:x} on Timestamp {{hit_time}} ==!!!==")


    error = lldb.SBError()
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    secret_data = process.ReadMemory({ret_val}, {SECRET_SIZE}, error)
    if error.Success() and secret_data:
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])
        rustls_cb_13.logger.queue_for_write(str(hit_time), "{label}", data_hex)

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

    # get the return address
    return_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
    if not ret_bp.IsValid():
        print(f"Failed to create return breakpoint: {error.GetCString()}")
        process.Continue()
        return False
    
    ret_bp.SetOneShot(True)
    ret_bp.SetThreadID(thread.GetThreadID())

    ret_bp.SetScriptCallbackFunction("rustls_cb_13.return_callback_12")

    process.Continue()
    return False

def return_callback_12(frame, bp_loc, internal_dict):
    import rustls_cb_13
    hit_time = datetime.now()
    print("=== Derive Secret Callback (TLS 1.2) RETURN Invoked ===")

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    exp_options = lldb.SBExpressionOptions()

    array_ptr = frame.EvaluateExpression("$rax", exp_options).GetValueAsUnsigned()
    if array_ptr == 0:
        print("Error: Return value is NULL")
        process.Continue()
        return False
        
    # For TLS 1.2, the master secret is 48 bytes
    secret_size = 48  # Use actual size for TLS 1.2 master secret
    
    # Read the array data
    secret_data = process.ReadMemory(array_ptr, secret_size, error)
    if error.Fail() or not secret_data:
        print(f"Failed to read master secret: {error.GetCString()}")
        process.Continue()
        return False
    
    # Print and log the master secret
    label = "master_secret"  # TLS 1.2 master secret label
    print(f"==!!!== RETURN BREAKPOINT HIT for '{label}' on Timestamp {hit_time} ==!!!==")
    secret_hex = ' '.join(f'{b:02x}' for b in secret_data[:secret_size])
    print(f"Secret data ({secret_size} bytes): {secret_hex}")
    
    # Log the secret
    timestamp_str = str(hit_time)
    rustls_cb_13.logger.queue_for_write(timestamp_str, label, secret_hex)
    
    # Set a watchpoint on the secret to detect modifications
    wp = target.WatchAddress(array_ptr, 1, False, True, error)  # Watch first byte
    if error.Success() and wp.IsValid():
        print(f"*** Set watchpoint on master_secret at 0x{array_ptr:x} ***")
        
        watch_ID = wp.GetID()
        callback_name = f"watchpoint_cb_ms_{watch_ID}"
        fixed_ptr = array_ptr  # Use fixed value to avoid closure issues
        fixed_size = secret_size
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    import rustls_cb_13
    hit_time = datetime.now()
    
    print(f"==!!!== WATCHPOINT HIT for 'master_secret' at 0x{fixed_ptr:x} on Timestamp {{hit_time}} ==!!!==")

    error = lldb.SBError()
    thread = frame.GetThread()
    process = thread.GetProcess()

    # Read the potentially modified data
    secret_data = process.ReadMemory({fixed_ptr}, {fixed_size}, error)
    if error.Success() and secret_data:
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{fixed_size}])
        print(f"Updated master_secret: {{data_hex}}")
        
        rustls_cb_13.logger.queue_for_write(str(hit_time), "master_secret", data_hex)

    return False
'''
        # Register the watchpoint callback
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

# Should be triggered on session ABORT
def cleanup_callback(frame, bp_loc, internal_dict):
    print("=== abort Callback Invoked ===")
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