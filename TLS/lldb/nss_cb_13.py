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
    

file_path = "/tmp/nss/timing_13.csv"
save_interval = 6
SECRET_SIZE = 32
auto_exit = True

# Map return breakpoint id -> metadata (label, dest_ptr_addr)
ret_bp_map = {}

logger = shared.CSVLogger(file_path, save_interval, auto_exit)


'''
args[0]: sslSocket *ss                 ($RDI)
args[1]: PK11SymKey *key               ($RSI)
args[2]: char *prefix                  ($RDX)
args[3]: char *suffix                  ($RCX)
args[4]: char *keylogLabel             ($R8)
args[5]: PK11SymKey **dest             ($R9)

typedef struct PK11SymKeyStr PK11SymKey;

struct PK11SymKeyStr {
    CK_MECHANISM_TYPE type;    /* type of operation this key was created for*/
    CK_OBJECT_HANDLE objectID; /* object id of this key in the slot */
    PK11SlotInfo *slot;        /* Slot this key is loaded into */
    void *cx;                  /* window context in case we need to loggin */
    PK11SymKey *next;
    PRBool owner;
    SECItem data; /* raw key data if available */
    CK_SESSION_HANDLE session;
    PRBool sessionOwner;
    PRInt32 refCount;          /* number of references to this key */
    int size;                  /* key size in bytes */
    PK11Origin origin;         /* where this key came from
                                * (see def in secmodt.h) */
    PK11SymKey *parent;        /* potential owner key of the session */
    PRUint16 series;           /* break up the slot info into various groups
                                * of inserted tokens so that keys and certs
                                * can be invalidated */
    void *userData;            /* random data the application can attach to
                                * this key */
    PK11FreeDataFunc freeFunc; /* function to free the user data */
};

typedef struct SECItemStr SECItem;

struct SECItemStr {
    SECItemType type;
    unsigned char *data;
    unsigned int len;
};
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
        # Start logging timer on first hit
        logger.start_save_timer()
    
    exp_options = lldb.SBExpressionOptions()

    shared.dump_args(frame)

    # The label is split into prefix and suffix
    prefix_addr = frame.EvaluateExpression("$rdx", exp_options).GetValueAsUnsigned()
    suffix_addr = frame.EvaluateExpression("$rcx", exp_options).GetValueAsUnsigned()

    # Read the C-strings from memory, checking for NULL pointers first
    prefix_str = ""
    if prefix_addr != 0:
        prefix_str = process.ReadCStringFromMemory(prefix_addr, 256, error)
        if error.Fail():
            print(f"Error reading prefix string: {error.GetCString()}")

    suffix_str = ""
    if suffix_addr != 0:
        suffix_str = process.ReadCStringFromMemory(suffix_addr, 256, error)
        if error.Fail():
            print(f"Error reading suffix string: {error.GetCString()}")

    # Combine prefix and suffix to form the full label
    label = f"{prefix_str} {suffix_str}".strip()


    # We are only interested in certain labels
    if label not in shared.labels:
        process.Continue()
        return False

    dest_ptr_addr = frame.EvaluateExpression("$r9", exp_options).GetValueAsUnsigned()
    if dest_ptr_addr == 0:
        print("Destination pointer is NULL, cannot set return breakpoint.")
        process.Continue()
        return False

    # Set one-shot breakpoint on the return address
    return_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", exp_options).GetValueAsUnsigned()
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
        'dest_ptr_addr': dest_ptr_addr
    }

    # Use direct script callback to avoid autogen name KeyErrors on reload
    ret_bp.SetScriptCallbackFunction("nss_cb_13.return_callback")

    process.Continue()
    return False

# Static return breakpoint callback (avoids dynamic function KeyError)
def return_callback(frame, bp_loc, internal_dict):
    import nss_cb_13  # ensure module namespace
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    bp_id = bp_loc.GetBreakpoint().GetID()
    meta = nss_cb_13.ret_bp_map.get(bp_id)
    if not meta:
        print(f"No metadata for breakpoint {bp_id}")
        return False

    label = meta['label']
    dest_ptr_addr = meta['dest_ptr_addr']

    # Read PK11SymKey* from dest (dest is PK11SymKey **)
    key_struct_ptr = process.ReadPointerFromMemory(dest_ptr_addr, error)
    if error.Fail() or key_struct_ptr == 0:
        print(f"Failed to read PK11SymKey pointer from {dest_ptr_addr:#x}")
        process.Continue()
        return False

    exp_options = lldb.SBExpressionOptions()
    secret_ptr_expr = f"((PK11SymKey*){key_struct_ptr})->data.data"
    length_expr = f"((PK11SymKey*){key_struct_ptr})->data.len"

    secret_ptr_val = frame.EvaluateExpression(secret_ptr_expr, exp_options).GetValueAsUnsigned()
    length_val = frame.EvaluateExpression(length_expr, exp_options).GetValueAsUnsigned()

    # If missing, attempt to force materialization via PK11_ExtractKeyValue
    if (secret_ptr_val == 0 or length_val == 0):
        extract_expr = f"(int)PK11_ExtractKeyValue((PK11SymKey*){key_struct_ptr})"
        extract_ret = frame.EvaluateExpression(extract_expr, exp_options).GetValueAsSigned()
        # Re-evaluate
        secret_ptr_val = frame.EvaluateExpression(secret_ptr_expr, exp_options).GetValueAsUnsigned()
        length_val = frame.EvaluateExpression(length_expr, exp_options).GetValueAsUnsigned()

    used_offset = None
    # Fallback: manual memory parsing if still zero
    if secret_ptr_val == 0 or length_val == 0:
        fallback_ptr, fallback_len, used_offset = _read_secitem_via_memory(process, key_struct_ptr, error)
        if fallback_ptr != 0 and fallback_len != 0:
            secret_ptr_val, length_val = fallback_ptr, fallback_len
            print(f"Fallback SECItem parse succeeded (offset=0x{used_offset:x})")

    if secret_ptr_val == 0 or length_val == 0:
        print(f"Secret pointer/length invalid after attempts (ptr={secret_ptr_val:#x}, len={length_val}) for {label}")
        process.Continue()
        return False

    secret_bytes = process.ReadMemory(secret_ptr_val, SECRET_SIZE, error)
    if error.Fail():
        print(f"Failed to read secret memory: {error.GetCString()}")
        process.Continue()
        return False
    
    hit_time = datetime.now()
    print(f"==!!!== RETURN BRAKPOINT HIT for '{label}' at 0x{secret_ptr_val:x} on Timestamp {hit_time} ==!!!==")
    data_hex = ' '.join(f'{b:02x}' for b in secret_bytes[:SECRET_SIZE])

    timestamp_str = str(hit_time)
    nss_cb_13.logger.queue_for_write(timestamp_str, label, data_hex)
    
    # Set Watchpoint on the secret data
    watchpoint = target.WatchAddress(secret_ptr_val, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Watchpoint set at address: {secret_ptr_val:#x} for label: '{label}' ***")
        
        watch_ID = watchpoint.GetID()
        callback_name = f'''watchpoint_callback_{watch_ID}'''
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{secret_ptr_val:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({secret_ptr_val}, {SECRET_SIZE}, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:{SECRET_SIZE}])

        import nss_cb_13
        timestamp_str = str(hit_time)
        nss_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)
        
    return False
        '''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    else:
        print(f"Failed to set watchpoint on secret buffer: {error.GetCString()}")

    process.Continue()
    return False

def _read_secitem_via_memory(process, key_struct_ptr, error):
    """Attempt to deduce SECItem offset heuristically and read pointer+len manually.
    Returns (secret_ptr, length, used_offset) or (0,0,None)."""
    pointer_size = process.GetTarget().GetAddressByteSize()
    # Candidate offsets seen in NSS builds (48 / 0x30 and 56 / 0x38 etc.)
    candidate_offsets = [0x30, 0x38, 0x28]
    for off in candidate_offsets:
        secitem_addr = key_struct_ptr + off
        # Layout: type (4) + padding(4) -> pointer (8) -> len (4) (+ padding 4)
        type_bytes = process.ReadMemory(secitem_addr, 4, error)
        if error.Fail():
            continue
        data_ptr = process.ReadPointerFromMemory(secitem_addr + 8, error)
        if error.Fail():
            continue
        length_bytes = process.ReadMemory(secitem_addr + 16, 4, error)
        if error.Fail():
            continue
        if len(length_bytes) == 4:
            length_val = int.from_bytes(length_bytes, byteorder='little')
            if data_ptr != 0 and 0 < length_val <= 512:  # heuristic bounds
                return data_ptr, length_val, off
    return 0, 0, None

def derive_secrets_callback_12(frame, bp_loc, internal_dict):
    print("=== Derive Secret Callback (TLS 1.2) Invoked ===")
    
    global ret_bp_map
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    hit_count = bp_loc.GetHitCount()
    if hit_count == 1:
        # Start logging timer on first hit
        logger.start_save_timer()

    exp_options = lldb.SBExpressionOptions()
    label = "MASTER_SECRET"

    shared.dump_args(frame)

    dest_ptr_addr = frame.EvaluateExpression("$rdx", exp_options).GetValueAsUnsigned()
    if dest_ptr_addr == 0:
        print("Destination pointer is NULL, cannot set return breakpoint.")
        process.Continue()
        return False

    # Set one-shot breakpoint on the return address
    return_addr = frame.EvaluateExpression("*(unsigned long*)$rsp", exp_options).GetValueAsUnsigned()
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
        'dest_ptr_addr': dest_ptr_addr
    }

    # Use direct script callback to avoid autogen name KeyErrors on reload
    ret_bp.SetScriptCallbackFunction("nss_cb_13.return_callback_12")

    process.Continue()
    return False


def return_callback_12(frame, bp_loc, internal_dict):
    import nss_cb_13  # ensure module namespace
    process = frame.GetThread().GetProcess()
    target = process.GetTarget()
    error = lldb.SBError()

    bp_id = bp_loc.GetBreakpoint().GetID()
    meta = nss_cb_13.ret_bp_map.get(bp_id)
    if not meta:
        print(f"No metadata for breakpoint {bp_id}")
        return False

    label = meta['label']
    dest_ptr_addr = meta['dest_ptr_addr']

    # Read PK11SymKey* from dest (dest is PK11SymKey **)
    key_struct_ptr = process.ReadPointerFromMemory(dest_ptr_addr, error)
    if error.Fail() or key_struct_ptr == 0:
        print(f"Failed to read PK11SymKey pointer from {dest_ptr_addr:#x}")
        process.Continue()
        return False

    exp_options = lldb.SBExpressionOptions()
    secret_ptr_expr = f"((PK11SymKey*){key_struct_ptr})->data.data"
    length_expr = f"((PK11SymKey*){key_struct_ptr})->data.len"

    secret_ptr_val = frame.EvaluateExpression(secret_ptr_expr, exp_options).GetValueAsUnsigned()
    length_val = frame.EvaluateExpression(length_expr, exp_options).GetValueAsUnsigned()

    # If missing, attempt to force materialization via PK11_ExtractKeyValue
    if (secret_ptr_val == 0 or length_val == 0):
        extract_expr = f"(int)PK11_ExtractKeyValue((PK11SymKey*){key_struct_ptr})"
        extract_ret = frame.EvaluateExpression(extract_expr, exp_options).GetValueAsSigned()
        # Re-evaluate
        secret_ptr_val = frame.EvaluateExpression(secret_ptr_expr, exp_options).GetValueAsUnsigned()
        length_val = frame.EvaluateExpression(length_expr, exp_options).GetValueAsUnsigned()

    used_offset = None
    # Fallback: manual memory parsing if still zero
    if secret_ptr_val == 0 or length_val == 0:
        fallback_ptr, fallback_len, used_offset = _read_secitem_via_memory(process, key_struct_ptr, error)
        if fallback_ptr != 0 and fallback_len != 0:
            secret_ptr_val, length_val = fallback_ptr, fallback_len
            print(f"Fallback SECItem parse succeeded (offset=0x{used_offset:x})")

    if secret_ptr_val == 0 or length_val == 0:
        print(f"Secret pointer/length invalid after attempts (ptr={secret_ptr_val:#x}, len={length_val}) for {label}")
        process.Continue()
        return False

    secret_bytes = process.ReadMemory(secret_ptr_val, 48, error)
    if error.Fail():
        print(f"Failed to read secret memory: {error.GetCString()}")
        process.Continue()
        return False
    
    hit_time = datetime.now()
    print(f"==!!!== RETURN BRAKPOINT HIT for '{label}' at 0x{secret_ptr_val:x} on Timestamp {hit_time} ==!!!==")
    data_hex = ' '.join(f'{b:02x}' for b in secret_bytes[:48])
    print(f"Secret data (first 48 bytes): {data_hex}")

    timestamp_str = str(hit_time)
    nss_cb_13.logger.queue_for_write(timestamp_str, label, data_hex)
    
    # Set Watchpoint on the secret data
    watchpoint = target.WatchAddress(secret_ptr_val, 1, False, True, error)
    if error.Success() and watchpoint.IsValid():
        print(f"*** Watchpoint set at address: {secret_ptr_val:#x} for label: '{label}' ***")
        
        watch_ID = watchpoint.GetID()
        callback_name = f'''watchpoint_callback_{watch_ID}'''
        callback_code = f'''
def {callback_name}(frame, bp_loc, internal_dict):
    from datetime import datetime
    # save the time directly on hit
    hit_time = datetime.now()
    print(f"==!!!== WATCHPOINT HIT for '{label}' at 0x{secret_ptr_val:x} on Timestamp {{hit_time}} ==!!!==")

    # Read the updated secret data
    thread = frame.GetThread()
    process = thread.GetProcess()
    error = lldb.SBError()

    secret_data = process.ReadMemory({secret_ptr_val}, 48, error)
    if error.Success():
        data_hex = ' '.join(f'{{b:02x}}' for b in secret_data[:48])
        print(f"Updated secret data: {{data_hex}}")
        import nss_cb_13
        timestamp_str = str(hit_time)
        nss_cb_13.logger.queue_for_write(timestamp_str, "{label}", data_hex)
        
    return False
        '''

        frame_debugger = target.GetDebugger()
        frame_debugger.HandleCommand(f"script {callback_code}")
        frame_debugger.HandleCommand(f"watchpoint command add -F {callback_name} {watch_ID}")
    else:
        print(f"Failed to set watchpoint on secret buffer: {error.GetCString()}")

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