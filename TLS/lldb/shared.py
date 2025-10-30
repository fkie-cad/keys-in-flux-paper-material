import lldb
import os
import sys
import threading
from datetime import datetime
import time

# Define labels for which we want to set watchpoints
labels = {"c hs traffic", "s hs traffic", "c ap traffic", "s ap traffic"}

class CSVLogger:
    
    def __init__(self, file_path: str, save_interval: int = 5, auto_exit: bool = True):
        self.file_path = file_path
        self.save_interval = save_interval
        self.auto_exit = auto_exit
        
        self.header = "ID, timestamp, label, secret\n"
        self.csvData = []

        self.LOGFILE = None

    def init_log_file(self):
        # Ensure directory exists
        os.makedirs(os.path.dirname(self.file_path), exist_ok=True)

        file_exists = os.path.exists(self.file_path) and os.path.getsize(self.file_path) > 0

        try:
            # Open in append mode if file exists with content, otherwise write mode
            mode = "a" if file_exists else "w"
            self.LOGFILE = open(self.file_path, mode)

            # Write header only if the file is new or empty
            if not file_exists:
                header = "ID, timestamp, label, secret\n"
                self.LOGFILE.write(header)
                self.LOGFILE.flush()
        except Exception as e:
            print(f"Failed to open log file: {e}")
            self.LOGFILE = None
    
    def deinit_log_file(self):
        if self.LOGFILE:
            self.LOGFILE.close()
            self.LOGFILE = None

    def write_to_csv(self):
        self.init_log_file()

        # Get the highest ID from existing data
        max_id = 0
        if os.path.exists(self.file_path):
            try:
                with open(self.file_path, "r") as f:
                    for line in f:
                        if line.strip():  # Skip empty lines
                            parts = line.split(',')
                            if len(parts) > 0 and parts[0].isdigit():
                                max_id = max(max_id, int(parts[0]))
            except Exception as e:
                print(f"Error reading existing file: {e}")


        for data in self.csvData:
            try:
                # Write Data with incremented ID
                self.LOGFILE.write(f"{max_id + 1}, {data}\n")
            except Exception as e:
                print(f"Failed to write to log file: {e}")

        self.LOGFILE.flush()
        self.deinit_log_file()
        self.csvData.clear()

        if self.save_timer:
            self.save_timer.cancel()

        if self.auto_exit:
            print("Auto-exit enabled, terminating ...")
            sys.stdout.flush()
            
            print("forcing exit")
            sys.stdout.flush()
            os._exit(1)

        return True

    def queue_for_write(self, timestamp, label, secret):
        data_entry = f"{timestamp}, {label}, {secret}"
        self.csvData.append(data_entry)


    def start_save_timer(self):
        self.save_timer = threading.Timer(self.save_interval, self.write_to_csv)
        self.save_timer.daemon = True
        self.save_timer.start()

def dump_memory(frame, bp_loc, extra_args, internal_dict):
    print("=== Dump Memory Callback Invoked ===")
    sys.stdout.flush()
    # Save time on hit (use datetime.now() only)
    hit_time = datetime.now()
    timestamp = hit_time.strftime("%Y%m%d_%H%M%S_%f")  # includes microseconds

    # Extract the file_path from the SBStructuredData object
    if not extra_args or not extra_args.IsValid():
        print("[dump] error: No extra_args provided to callback.")
        return

    file_path_val = extra_args.GetValueForKey("file_path")
    if not file_path_val or not file_path_val.IsValid():
        print("[dump] error: 'file_path' key not found in extra_args.")
        return

    # The SBValue for a string is often quoted; GetSummary() provides the clean, unquoted string.
    file_path = file_path_val.GetStringValue(1024)
    if not file_path:
        print("[dump] error: Could not extract string from file_path value.")
        return
    
    dump_kind_val = extra_args.GetValueForKey("kind")
    if not dump_kind_val or not dump_kind_val.IsValid():
        dump_kind_val = "unknown"
    
    dump_kind = dump_kind_val.GetStringValue(1024)
    if not dump_kind:
        dump_kind = "unknown"


    # Ensure directory exists
    dump_dir = os.path.dirname(file_path)
    os.makedirs(dump_dir, exist_ok=True)

    thread = frame.GetThread()
    process = thread.GetProcess()

    # Prepare dump file path (use timestamp to name the file)
    dump_path = os.path.join(dump_dir, f"{timestamp}_post_{dump_kind}.dump")

    try:
        with open(dump_path, "wb") as out_f:
            thread = frame.GetThread()
            process = thread.GetProcess()
            regions = process.GetMemoryRegions()

            total_written = 0
            
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()

            for i in range(num_regions):
                if not regions.GetMemoryRegionAtIndex(i, region_info):
                    continue # Failed to get region info, skip to next

                start = int(region_info.GetRegionBase())
                end = int(region_info.GetRegionEnd())
                size = max(0, end - start)

                if size == 0:
                    continue
                
                err = lldb.SBError()
                data = process.ReadMemory(start, size, err)
                if not err.Success() or not data:
                    break
                out_f.write(data)
                total_written += len(data)

        print(f"[dump] Wrote {total_written} bytes to {dump_path}")
    except Exception as e:
        print(f"[dump] error: {e}")

    process.Continue()
    return False

def remove_false_pre_dump(file_path):
    try:
        dump_dir = os.path.dirname(file_path)
        if os.path.isdir(dump_dir):
            for fname in os.listdir(dump_dir):
                if fname.endswith("_pre_abort.dump"):
                    fp = os.path.join(dump_dir, fname)
                    if os.path.isfile(fp):
                        try:
                            os.remove(fp)
                            print(f"[dump] removed pre-abort file: {fp}")
                        except Exception as e:
                            print(f"[dump] failed to remove {fp}: {e}")
    except Exception as e:
        print(f"[dump] error checking pre-abort files: {e}")

def dump_memory_error_check(frame, bp_loc, extra_args, internal_dict):
    print("=== Dump Memory (with error check) Callback Invoked ===")
    sys.stdout.flush()
    # Save time on hit (use datetime.now() only)
    hit_time = datetime.now()
    timestamp = hit_time.strftime("%Y%m%d_%H%M%S_%f")  # includes microseconds

    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    exp_options = lldb.SBExpressionOptions()

    ret_val = frame.EvaluateExpression("$rax", exp_options).GetValueAsSigned()
    print(f"Return value in rax: {ret_val}")
    sys.stdout.flush()   

    # Extract the file_path from the SBStructuredData object
    if not extra_args or not extra_args.IsValid():
        print("[dump] error: No extra_args provided to callback.")
        return

    file_path_val = extra_args.GetValueForKey("file_path")
    if not file_path_val or not file_path_val.IsValid():
        print("[dump] error: 'file_path' key not found in extra_args.")
        return

    # The SBValue for a string is often quoted; GetSummary() provides the clean, unquoted string.
    file_path = file_path_val.GetStringValue(1024)
    if not file_path:
        print("[dump] error: Could not extract string from file_path value.")
        return
    
    if 'gnu' in file_path:
        if ret_val != -12: # gnutls Fatal code
            # If we reached this point we mistakenly created a pre_abort dump which needs to be removed
            remove_false_pre_dump(file_path)
            # only continue for alerts
            process.Continue()
            return False   
    elif 'openssl' in file_path:
        if ret_val > 0:# openSSL error code
            # If we reached this point we mistakenly created a pre_abort dump which needs to be removed
            remove_false_pre_dump(file_path)
            # only continue for alerts
            process.Continue()
            return False
    elif 'wolf' in file_path:
        unsigned_val = ret_val & 0xFFFFFFFF
        if unsigned_val != 0xFFFFFFFF: # wolfSSL Fatal error code
            # If we reached this point we mistakenly created a pre_abort dump which needs to be removed
            remove_false_pre_dump(file_path)
            # only continue for alerts
            process.Continue()
            return False
    elif 'matrix' in file_path:
        # PS_PROTOCOL_FAIL = -12
        # PS_FAILURE = -1
        if ret_val > 0: # matrixSsl Fatal error
            # only continue for alerts
            # If we reached this point we mistakenly created a pre_abort dump which needs to be removed
            remove_false_pre_dump(file_path)
            process.Continue()
            return False

    dump_kind_val = extra_args.GetValueForKey("kind")
    if not dump_kind_val or not dump_kind_val.IsValid():
        dump_kind_val = "unknown"
    
    dump_kind = dump_kind_val.GetStringValue(1024)
    if not dump_kind:
        dump_kind = "unknown"


    # Ensure directory exists
    dump_dir = os.path.dirname(file_path)
    os.makedirs(dump_dir, exist_ok=True)

    thread = frame.GetThread()
    process = thread.GetProcess()

    # Prepare dump file path (use timestamp to name the file)
    dump_path = os.path.join(dump_dir, f"{timestamp}_post_{dump_kind}.dump")

    try:
        with open(dump_path, "wb") as out_f:
            thread = frame.GetThread()
            process = thread.GetProcess()
            regions = process.GetMemoryRegions()

            total_written = 0
            
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()

            for i in range(num_regions):
                if not regions.GetMemoryRegionAtIndex(i, region_info):
                    continue # Failed to get region info, skip to next

                start = int(region_info.GetRegionBase())
                end = int(region_info.GetRegionEnd())
                size = max(0, end - start)

                if size == 0:
                    continue
                
                err = lldb.SBError()
                data = process.ReadMemory(start, size, err)
                if not err.Success() or not data:
                    break
                out_f.write(data)
                total_written += len(data)

        print(f"[dump] Wrote {total_written} bytes to {dump_path}")
    except Exception as e:
        print(f"[dump] error: {e}")

    process.Continue()
    return False

def dump_args(frame: lldb.SBFrame):
    try:
        process = frame.GetThread().GetProcess()
        target = process.GetTarget()

        # 1) Try to get arguments via debug info (best case)
        args = frame.GetVariables(True, False, False, True)  # (include_args, include_locals, include_statics, in_scope_only)
        if args and args.GetSize() > 0:
            func_name = frame.GetFunctionName() or (frame.GetFunction().GetName() if frame.GetFunction() and frame.GetFunction().IsValid() else "<unknown>")
            print(f"[args] Function: {func_name}")
            for v in args:
                # v.GetValue() may be None for complex types; fall back to summary
                val = v.GetValue()
                if not val:
                    val = v.GetSummary() or "<unavailable>"
                print(f"  - {v.GetName()} : {v.GetTypeName()} = {val}")

        # 2) Register arguments (first 6 integer arguments on x86_64 SysV ABI)
        reg_names = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        for i, rn in enumerate(reg_names):
            rv = frame.FindRegister(rn)
            if rv and rv.IsValid() and rv.GetValue():
                try:
                    ival = int(rv.GetValue(), 0)  # Auto-detect base (hex or decimal)
                    print(f"  - arg{i} ({rn}) = 0x{ival:x}")
                except Exception:
                    print(f"  - arg{i} ({rn}) = {rv.GetValue()}")
            else:
                print(f"  - arg{i} ({rn}) = <unavailable>")

        # 3) Stack arguments (arguments beyond the first 6 on x86_64 SysV ABI)
        # First, get the stack pointer
        rsp = frame.FindRegister("rsp")
        if rsp and rsp.IsValid() and rsp.GetValue():
            sp_value = int(rsp.GetValue(), 0)
            
            # Read more stack arguments: originally 4, now print 6 more (total 10)
            total_stack_args = 10  # 4 original + 6 more
            for i in range(total_stack_args):
                offset = 8 + (i * 8)  # Start at rsp+8, then rsp+16, rsp+24, etc.
                addr = sp_value + offset

                err = lldb.SBError()
                data = process.ReadMemory(addr, 8, err)
                stack_arg_index = i + 6  # Stack args start after the 6 register args
                if err.Success() and data:
                    # Convert bytes to integer (little-endian)
                    value = int.from_bytes(data, byteorder='little', signed=False)
                    print(f"  - arg{stack_arg_index} (stack[{i}]) = 0x{value:x}")
                else:
                    print(f"  - arg{stack_arg_index} (stack[{i}]) = <read error: {err.GetCString()}>")

            # Read a block of stack memory for debugging
            err = lldb.SBError()
            stack_dump = process.ReadMemory(sp_value, 64, err)
            if err.Success() and stack_dump:
                hex_dump = ' '.join(f'{b:02x}' for b in stack_dump)
                print(f"  - Stack dump (64 bytes from RSP): {hex_dump}")
        else:
            print("  - RSP register not available, can't read stack arguments")
            
    except Exception as e:
        print(f"[args] dump error: {e}")


def dump_memory_onEntry(process, file_path, dump_kind):
    print("=== Dump Memory onEntry ===")
    sys.stdout.flush()
    # Save time on hit (use datetime.now() only)
    hit_time = datetime.now()
    timestamp = hit_time.strftime("%Y%m%d_%H%M%S_%f")  # includes microseconds

    # Ensure directory exists
    dump_dir = os.path.dirname(file_path)
    os.makedirs(dump_dir, exist_ok=True)

    # Prepare dump file path (use timestamp to name the file)
    dump_path = os.path.join(dump_dir, f"{timestamp}_pre_{dump_kind}.dump")

    try:
        with open(dump_path, "wb") as out_f:
            regions = process.GetMemoryRegions()

            total_written = 0
            
            region_info = lldb.SBMemoryRegionInfo()
            num_regions = regions.GetSize()

            for i in range(num_regions):
                if not regions.GetMemoryRegionAtIndex(i, region_info):
                    continue # Failed to get region info, skip to next

                start = int(region_info.GetRegionBase())
                end = int(region_info.GetRegionEnd())
                size = max(0, end - start)

                if size == 0:
                    continue
                
                err = lldb.SBError()
                data = process.ReadMemory(start, size, err)
                if not err.Success() or not data:
                    break
                out_f.write(data)
                total_written += len(data)

        print(f"[dump] Wrote {total_written} bytes to {dump_path}")
    except Exception as e:
        print(f"[dump] error: {e}")
    
    return True