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

'''
Replace the file path with your desired location.
The File will be created if it does not exist.
'''
file_path = "/tmp/wolf/timing_13.csv"
dir_path = "/tmp/wolf/"

'''
This is the interval in seconds after which the data will be saved to the CSV file.
You can adjust this value as needed.
'''
save_interval = 3

'''
If enabled, the script will automatically exit after saving the data.
'''
auto_exit = True

'''
Set a SECRET_SIZE to the size of the secret you want to monitor.
Use this if you know the size of the secret in advance and dont want to read it dynamically. (Which sometime fails)
'''
SECRET_SIZE = 32

logger = shared.CSVLogger(file_path, save_interval, auto_exit)


'''
This callback is invoked when the breakpoint, set on the function specified by pattern in the monitoring.py file, is hit.
This exampe is based on wolfSSL
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

    '''
    -------TEMPLATE-------
    This Template present a rough outline of how to implement the callback. 
    The concrete implementation depends on the library and the specific function.
    For further help, refer to existing implementations in this same directory.


    1) Read the arguments containing the label and its size, so we filter for specific labels.


    '''
    label_ptr = frame.EvaluateExpression("$r8", exp_options).GetValueAsUnsigned()
    label_size = frame.EvaluateExpression("$r9", exp_options).GetValueAsUnsigned()

    label_content = process.ReadMemory(label_ptr, label_size, error)
    if error.Success():
        label = label_content.decode('utf-8', errors='ignore')
    else:
        print(f"Failed to read label memory: {error.GetCString()}")
    
    set_watchpoint = False
    if label in shared.labels:
        set_watchpoint = True

    if set_watchpoint:

        '''

        2) Read the arguments containing Cryptographic Material. (in this case from $rsi)

        '''

        secret_ptr = frame.EvaluateExpression("$rsi", exp_options).GetValueAsSigned()


        '''
        
        3) Set a Watchpoint in order to get notified every time the secret is modified.
        The number of available Watchpoints is limited and depends on the architecture and so is the size of the Watchpoint.
        Therefore we are monitoring only 1 byte in this example, which is based on TLS 1.3 where multiple secrets need to be monitored.
        If extending this for other protocols, consider adjusting the size accordingly to your needs.
        The Boolean tuple (False, True) sets the watchpoint to be triggered on write access and to ignore read access. Adjust this as needed.

        
        '''

        watchpoint = target.WatchAddress(secret_ptr, 1, False, True, error)
        if error.Success() and watchpoint.IsValid():
            print(f"*** Watchpoint set at address: {secret_ptr:#x} for label: '{label}' ***")


            ''' 
            
            4) Attach a Callback to the Watchpoint. When hit, we read the changes and write them to a CSV file for further analysis.

            '''


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

        import template_cb
        timestamp_str = str(hit_time)
        template_cb.logger.queue_for_write(timestamp_str, "{label}", data_hex)

    return False
'''
            
            frame_debugger = target.GetDebugger()
            frame_debugger.HandleCommand(f"script {callback_code}")
            frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    

    process.Continue()
    return False;


'''
In most cases the following callbacks should work without modification.
They should be triggered on the library's KeyUpdate() and Shutdown() functions.
These Callbacks set a one-shot breakpoint on the return address of the function which will trigger
a memory dump via the shared.dump_memory() function on hit.
'''

# Should be triggered when key update is done
def key_update_callback(frame, bp_loc, internal_dict):
    print("=== Key Update Callback Invoked ===")
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    exp_options = lldb.SBExpressionOptions()

    return_addr = frame.EvaluateExpression("*(unsigned long*)($rsp)", exp_options).GetValueAsUnsigned()
    ret_bp = target.BreakpointCreateByAddress(return_addr)
    ret_bp.SetOneShot(True)

    args_dict = {'file_path': file_path}

    # Create an SBStructuredData object from a JSON representation of our arguments.
    extra_args = lldb.SBStructuredData()
    extra_args.SetFromJSON(json.dumps(args_dict))

    debugger = target.GetDebugger()
    debugger.HandleCommand(f"command script import {os.path.dirname(os.path.abspath(__name__))}/shared.py")

    # Set the callback correctly with the function name and the extra_args object.
    ret_bp.SetScriptCallbackFunction("shared.dump_memory", extra_args)

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

    args_dict = {'file_path': file_path}

    # Create an SBStructuredData object from a JSON representation of our arguments.
    extra_args = lldb.SBStructuredData()
    extra_args.SetFromJSON(json.dumps(args_dict))

    debugger = target.GetDebugger()
    debugger.HandleCommand(f"command script import {os.path.dirname(os.path.abspath(__name__))}/shared.py")

    # Set the callback correctly with the function name and the extra_args object.
    ret_bp.SetScriptCallbackFunction("shared.dump_memory", extra_args)

    process.Continue()
    return False