# hook_kex.py
import lldb
import os
import time
import binascii

KEYLOG_PATH = "/tmp/ssh-keys/ssh_keylog.txt"

def write_keylog_line(label, data_bytes):
    hexdata = binascii.hexlify(data_bytes).decode()
    ts = time.strftime("%Y-%m-%dT%H:%M:%S")
    line = f"{ts} {label} {hexdata}\n"
    with open(KEYLOG_PATH, "a") as fh:
        fh.write(line)
    print("[keylog] wrote:", label)

def read_process_memory(process, addr, size):
    error = lldb.SBError()
    data = process.ReadMemory(addr, size, error)
    if not error.Success():
        print("[readmem] failed at 0x%x size=%d: %s" % (addr, size, error.GetCString()))
        return b""
    return data

def kex_bp_callback(frame, bp_loc, dict):
    # note: designed for x86_64 SysV ABI (rdi, rsi, rdx)
    thread = frame.GetThread()
    process = thread.GetProcess()
    target = process.GetTarget()

    # figure out arch
    addr_size = process.GetAddressByteSize()
    arch = target.GetTriple()
    print("[kex_bp] hit on arch:", arch)

    # registers (x86_64)
    try:
        regs = frame.GetRegisters()  # returns SBValueList
    except Exception:
        regs = None

    # fallback read registers directly
    try:
        rdi = int(frame.FindRegister("rdi").GetValue(), 0)
        rsi = int(frame.FindRegister("rsi").GetValue(), 0)
        rdx = int(frame.FindRegister("rdx").GetValue(), 0)
    except Exception as e:
        print("[kex_bp] couldn't read rdi/rsi/rdx:", e)
        return False  # continue

    kex_ptr = rdi
    hash_ptr = rsi
    shared_ptr = rdx

    print("[kex_bp] kex=0x%x hash=0x%x shared=0x%x" % (kex_ptr, hash_ptr, shared_ptr))

    # strategy:
    # call derive_key((Kex*)kex_ptr, 'A'+i, ((Kex*)kex_ptr)->we_need, (u_char*)hash_ptr, (BIGNUM*)shared_ptr)
    # express as an LLDB expression. This relies on symbols being available (we built with -g).
    # We'll try up to NKEYS (6), and try to read 64 bytes from returned pointer.

    NKEYS = 6
    MAX_READ = 64

    for i in range(NKEYS):
        ch = chr(ord('A') + i)
        # Note: we avoid including format specifiers that confuse the expression parser.
        expr = ' (unsigned char *) derive_key((Kex *) {kex}, \'{c}\', ((Kex*){kex})->we_need, (unsigned char*) {h}, (BIGNUM*) {s})'.format(
            kex=kex_ptr, c=ch, h=hash_ptr, s=shared_ptr
        )
        try:
            val = frame.EvaluateExpression(expr)
            if val.error and val.error.Fail():
                print("[derive_key] eval error:", val.error.GetCString())
                continue
            # val may be a pointer value; get address
            try:
                ptr_addr = int(val.GetValue(), 0)
            except Exception:
                # sometimes GetValue returns e.g. '0x7f...' or '(void*)0x..'
                raw = val.GetSummary() or val.GetValue()
                ptr_addr = int(str(raw).split()[-1], 0)
            if ptr_addr == 0:
                print("[derive_key] returned NULL for key", ch)
                continue

            # read bytes
            data = read_process_memory(process, ptr_addr, MAX_READ)
            if not data:
                continue
            label = f"KEX-{ch}-kexptr=0x{kex_ptr:x}"
            write_keylog_line(label, data)
        except Exception as e:
            print("[derive_key] exception:", e)
            continue

    # continue process
    return False  # return False -> let the process continue normally

def __lldb_init_module(debugger, internal_dict):
    # create breakpoint by function name
    target = debugger.GetSelectedTarget()
    if not target:
        print("[lldb init] no target; attach shell then import this script and run manually")
        return
    bp = target.BreakpointCreateByName("kex_derive_keys")
    bp.SetScriptCallbackFunction("hook_kex.kex_bp_callback")
    print("[lldb init] breakpoint set on kex_derive_keys (id=%d), output keylog -> %s" % (bp.GetID(), KEYLOG_PATH))
