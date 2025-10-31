# Minimal KEX extraction for breakpoint command
import lldb
import struct
import os

frame = lldb.thread.GetFrameAtIndex(0)
process = lldb.process
target = lldb.target
arch = target.GetTriple().lower()

# Determine architecture
is_arm64 = "arm64" in arch or "aarch64" in arch

# Get registers based on architecture
# kex_derive_keys(struct ssh *ssh, u_char *hash, u_int hashlen, const struct sshbuf *shared_secret)
if is_arm64:
    ssh_ptr = frame.FindRegister("x0").GetValueAsUnsigned()
    hash_ptr = frame.FindRegister("x1").GetValueAsUnsigned()
    hashlen = frame.FindRegister("x2").GetValueAsUnsigned()
    shared_secret_ptr = frame.FindRegister("x3").GetValueAsUnsigned()
else:
    ssh_ptr = frame.FindRegister("rdi").GetValueAsUnsigned()
    hash_ptr = frame.FindRegister("rsi").GetValueAsUnsigned()
    hashlen = frame.FindRegister("rdx").GetValueAsUnsigned()
    shared_secret_ptr = frame.FindRegister("rcx").GetValueAsUnsigned()

error = lldb.SBError()

# Extract hash/cookie
if hash_ptr and hashlen > 0 and hashlen < 1024:
    hash_data = process.ReadMemory(hash_ptr, min(hashlen, 64), error)
    if not error.Fail():
        cookie_hex = hash_data.hex()
        
        # Extract shared secret from sshbuf
        # struct sshbuf { u_char *d; size_t off; size_t size; ... }
        if shared_secret_ptr:
            data_ptr_bytes = process.ReadMemory(shared_secret_ptr, 8, error)
            if not error.Fail():
                data_ptr = struct.unpack("<Q" if is_arm64 else "<Q", data_ptr_bytes)[0]
                
                off_bytes = process.ReadMemory(shared_secret_ptr + 8, 8, error)
                off = struct.unpack("<Q" if is_arm64 else "<Q", off_bytes)[0] if not error.Fail() else 0
                
                size_bytes = process.ReadMemory(shared_secret_ptr + 16, 8, error)
                size = struct.unpack("<Q" if is_arm64 else "<Q", size_bytes)[0] if not error.Fail() else 0
                
                if data_ptr and size > 0 and size < 4096:
                    secret_data = process.ReadMemory(data_ptr + off, size - off, error)
                    if not error.Fail():
                        secret_hex = secret_data.hex()
                        
                        # Write keylog
                        keylog_path = os.getenv("LLDB_KEYLOG", "/data/keylogs/ssh_keylog.log")
                        with open(keylog_path, "a") as f:
                            f.write(f"{cookie_hex} SHARED_SECRET {secret_hex}\n")
                        
                        print(f"[KEX] ✓ Keys extracted: cookie={cookie_hex[:32]}... secret={secret_hex[:32]}...")
