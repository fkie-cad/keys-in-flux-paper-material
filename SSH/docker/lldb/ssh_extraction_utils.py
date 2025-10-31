#!/usr/bin/env python3
"""
SSH Key Extraction Utilities - Shared Hybrid Extraction Functions

This module provides cross-platform hybrid parameter extraction for SSH key
monitoring across multiple SSH implementations (OpenSSH, wolfSSH, etc.).

Hybrid Approach:
1. Symbol-Aware: Try frame.FindVariable() first (requires debug symbols)
2. Register Fallback: Fall back to direct register reading (works without symbols)

Cross-Platform Support:
- ARM64 (aarch64): Apple M1, Ubuntu ARM64
- x86-64 (amd64): Standard Intel/AMD platforms
"""

import lldb

# ═══════════════════════════════════════════════════════════════════════════
# ARCHITECTURE DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def detect_architecture(target):
    """
    Detect CPU architecture from LLDB target

    Args:
        target: lldb.SBTarget object

    Returns:
        str: 'aarch64', 'x86_64', or 'unknown'
    """
    triple = target.GetTriple()

    if 'aarch64' in triple or 'arm64' in triple:
        return 'aarch64'
    elif 'x86_64' in triple or 'amd64' in triple:
        return 'x86_64'
    else:
        return 'unknown'

# ═══════════════════════════════════════════════════════════════════════════
# HYBRID SSH POINTER EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def extract_ssh_pointer_hybrid_aarch64(frame):
    """
    Extract SSH struct pointer on ARM64 (aarch64) using hybrid approach

    Hybrid Strategy:
    1. Try: frame.FindVariable("ssh") - symbol-aware (requires debug symbols)
    2. Fallback: frame.FindRegister("x0") - register-based (works without symbols)

    ARM64 Calling Convention (AAPCS64):
    - First 8 parameters: x0, x1, x2, x3, x4, x5, x6, x7
    - Remaining parameters: stack
    - Return address: LR (link register)

    For kex_derive_keys(struct ssh *ssh):
    - ssh pointer is in x0

    Args:
        frame: lldb.SBFrame object

    Returns:
        dict: {'ssh_ptr': int, 'method': str} or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ssh_var = frame.FindVariable("ssh")

    if ssh_var.IsValid():
        ssh_ptr = ssh_var.GetValueAsUnsigned()
        if ssh_ptr != 0:
            return {
                'ssh_ptr': ssh_ptr,
                'method': 'symbol-aware'
            }

    # METHOD 2: Register fallback
    x0_reg = frame.FindRegister("x0")
    if x0_reg:
        ssh_ptr = x0_reg.GetValueAsUnsigned()
        if ssh_ptr != 0:
            return {
                'ssh_ptr': ssh_ptr,
                'method': 'register'
            }

    return None

def extract_ssh_pointer_hybrid_x86_64(frame):
    """
    Extract SSH struct pointer on x86-64 (amd64) using hybrid approach

    Hybrid Strategy:
    1. Try: frame.FindVariable("ssh") - symbol-aware (requires debug symbols)
    2. Fallback: frame.FindRegister("rdi") - register-based (works without symbols)

    x86-64 Calling Convention (System V AMD64 ABI):
    - First 6 parameters: rdi, rsi, rdx, rcx, r8, r9
    - Remaining parameters: stack (right-to-left)
    - Return address: top of stack (RSP)

    For kex_derive_keys(struct ssh *ssh):
    - ssh pointer is in rdi

    Args:
        frame: lldb.SBFrame object

    Returns:
        dict: {'ssh_ptr': int, 'method': str} or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ssh_var = frame.FindVariable("ssh")

    if ssh_var.IsValid():
        ssh_ptr = ssh_var.GetValueAsUnsigned()
        if ssh_ptr != 0:
            return {
                'ssh_ptr': ssh_ptr,
                'method': 'symbol-aware'
            }

    # METHOD 2: Register fallback
    rdi_reg = frame.FindRegister("rdi")
    if rdi_reg:
        ssh_ptr = rdi_reg.GetValueAsUnsigned()
        if ssh_ptr != 0:
            return {
                'ssh_ptr': ssh_ptr,
                'method': 'register'
            }

    return None

# ═══════════════════════════════════════════════════════════════════════════
# HYBRID EVP_KDF PARAMETERS EXTRACTION (OpenSSL 3.0+)
# ═══════════════════════════════════════════════════════════════════════════

def extract_evp_kdf_params_hybrid_aarch64(frame):
    """
    Extract EVP_KDF_derive() parameters on ARM64 using hybrid approach

    Function Signature:
    int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[])

    Hybrid Strategy:
    1. Try: FindVariable for each parameter (symbol-aware)
    2. Fallback: Read from x0, x1, x2, x3 registers

    ARM64 Mapping:
    - ctx = x0
    - key = x1
    - keylen = x2
    - params = x3

    Args:
        frame: lldb.SBFrame object

    Returns:
        dict: {'ctx': int, 'key_ptr': int, 'keylen': int, 'params': int, 'method': str}
              or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ctx_var = frame.FindVariable("ctx")
    key_var = frame.FindVariable("key")
    keylen_var = frame.FindVariable("keylen")
    params_var = frame.FindVariable("params")

    if ctx_var.IsValid() and key_var.IsValid():
        return {
            'ctx': ctx_var.GetValueAsUnsigned(),
            'key_ptr': key_var.GetValueAsUnsigned(),
            'keylen': keylen_var.GetValueAsUnsigned() if keylen_var.IsValid() else 0,
            'params': params_var.GetValueAsUnsigned() if params_var.IsValid() else 0,
            'method': 'symbol-aware'
        }

    # METHOD 2: Register fallback
    x0 = frame.FindRegister("x0")
    x1 = frame.FindRegister("x1")
    x2 = frame.FindRegister("x2")
    x3 = frame.FindRegister("x3")

    if x0 and x1:
        return {
            'ctx': x0.GetValueAsUnsigned(),
            'key_ptr': x1.GetValueAsUnsigned(),
            'keylen': x2.GetValueAsUnsigned() if x2 else 0,
            'params': x3.GetValueAsUnsigned() if x3 else 0,
            'method': 'register'
        }

    return None

def extract_evp_kdf_params_hybrid_x86_64(frame):
    """
    Extract EVP_KDF_derive() parameters on x86-64 using hybrid approach

    Function Signature:
    int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
                       const OSSL_PARAM params[])

    Hybrid Strategy:
    1. Try: FindVariable for each parameter (symbol-aware)
    2. Fallback: Read from rdi, rsi, rdx, rcx registers

    x86-64 Mapping:
    - ctx = rdi
    - key = rsi
    - keylen = rdx
    - params = rcx

    Args:
        frame: lldb.SBFrame object

    Returns:
        dict: {'ctx': int, 'key_ptr': int, 'keylen': int, 'params': int, 'method': str}
              or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ctx_var = frame.FindVariable("ctx")
    key_var = frame.FindVariable("key")
    keylen_var = frame.FindVariable("keylen")
    params_var = frame.FindVariable("params")

    if ctx_var.IsValid() and key_var.IsValid():
        return {
            'ctx': ctx_var.GetValueAsUnsigned(),
            'key_ptr': key_var.GetValueAsUnsigned(),
            'keylen': keylen_var.GetValueAsUnsigned() if keylen_var.IsValid() else 0,
            'params': params_var.GetValueAsUnsigned() if params_var.IsValid() else 0,
            'method': 'symbol-aware'
        }

    # METHOD 2: Register fallback
    rdi = frame.FindRegister("rdi")
    rsi = frame.FindRegister("rsi")
    rdx = frame.FindRegister("rdx")
    rcx = frame.FindRegister("rcx")

    if rdi and rsi:
        return {
            'ctx': rdi.GetValueAsUnsigned(),
            'key_ptr': rsi.GetValueAsUnsigned(),
            'keylen': rdx.GetValueAsUnsigned() if rdx else 0,
            'params': rcx.GetValueAsUnsigned() if rcx else 0,
            'method': 'register'
        }

    return None

# ═══════════════════════════════════════════════════════════════════════════
# RETURN ADDRESS EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def get_return_address_aarch64(frame):
    """
    Get function return address on ARM64

    On ARM64, the return address is stored in the LR (link register) before
    the function prologue executes.

    Args:
        frame: lldb.SBFrame object

    Returns:
        int: Return address or 0 on failure
    """
    lr_reg = frame.FindRegister("lr")
    if lr_reg:
        return lr_reg.GetValueAsUnsigned()
    return 0

def get_return_address_x86_64(frame, process):
    """
    Get function return address on x86-64

    On x86-64, the return address is at the top of the stack (RSP) when the
    function is entered (before prologue moves it).

    Args:
        frame: lldb.SBFrame object
        process: lldb.SBProcess object

    Returns:
        int: Return address or 0 on failure
    """
    rsp_reg = frame.FindRegister("rsp")
    if not rsp_reg:
        return 0

    rsp_value = rsp_reg.GetValueAsUnsigned()
    error = lldb.SBError()
    ret_addr = process.ReadPointerFromMemory(rsp_value, error)

    if error.Success():
        return ret_addr
    return 0

# ═══════════════════════════════════════════════════════════════════════════
# OPENSSH derive_key() PARAMETERS EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def extract_derive_key_params_hybrid_aarch64(frame):
    """
    Extract OpenSSH derive_key() parameters on ARM64 using hybrid approach

    Function Signature:
    static int derive_key(struct ssh *ssh, int id, u_int need, u_char *hash,
                          u_int hashlen, const struct sshbuf *shared_secret,
                          u_char **keyp)

    Hybrid Strategy:
    1. Try: FindVariable for each parameter (symbol-aware)
    2. Fallback: Read from registers (x0-x6)

    ARM64 Mapping:
    - ssh = x0 (struct ssh*)
    - id = w1 (32-bit int - 65-70 for A-F keys)
    - need = w2 (32-bit u_int - bytes needed)
    - hash = x3 (u_char* - exchange hash)
    - hashlen = w4 (32-bit u_int - hash length)
    - shared_secret = x5 (const struct sshbuf*)
    - keyp = x6 (u_char** - OUT parameter address)

    Args:
        frame: lldb.SBFrame object

    Returns:
        dict: {'ssh': int, 'id': int, 'need': int, 'hash': int, 'hashlen': int,
               'shared_secret': int, 'keyp': int, 'method': str}
              or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ssh_var = frame.FindVariable("ssh")
    id_var = frame.FindVariable("id")
    need_var = frame.FindVariable("need")
    hash_var = frame.FindVariable("hash")
    hashlen_var = frame.FindVariable("hashlen")
    shared_secret_var = frame.FindVariable("shared_secret")
    keyp_var = frame.FindVariable("keyp")

    if ssh_var.IsValid() and id_var.IsValid() and keyp_var.IsValid():
        return {
            'ssh': ssh_var.GetValueAsUnsigned(),
            'id': id_var.GetValueAsUnsigned(),
            'need': need_var.GetValueAsUnsigned() if need_var.IsValid() else 0,
            'hash': hash_var.GetValueAsUnsigned() if hash_var.IsValid() else 0,
            'hashlen': hashlen_var.GetValueAsUnsigned() if hashlen_var.IsValid() else 0,
            'shared_secret': shared_secret_var.GetValueAsUnsigned() if shared_secret_var.IsValid() else 0,
            'keyp': keyp_var.GetValueAsUnsigned(),
            'method': 'symbol-aware'
        }

    # METHOD 2: Register fallback
    x0 = frame.FindRegister("x0")
    w1 = frame.FindRegister("w1")  # 32-bit id
    w2 = frame.FindRegister("w2")  # 32-bit need
    x3 = frame.FindRegister("x3")
    w4 = frame.FindRegister("w4")  # 32-bit hashlen
    x5 = frame.FindRegister("x5")
    x6 = frame.FindRegister("x6")

    if x0 and w1 and x6:
        return {
            'ssh': x0.GetValueAsUnsigned(),
            'id': w1.GetValueAsUnsigned(),
            'need': w2.GetValueAsUnsigned() if w2 else 0,
            'hash': x3.GetValueAsUnsigned() if x3 else 0,
            'hashlen': w4.GetValueAsUnsigned() if w4 else 0,
            'shared_secret': x5.GetValueAsUnsigned() if x5 else 0,
            'keyp': x6.GetValueAsUnsigned(),
            'method': 'register'
        }

    return None

def extract_derive_key_params_hybrid_x86_64(frame, process):
    """
    Extract OpenSSH derive_key() parameters on x86-64 using hybrid approach

    Function Signature:
    static int derive_key(struct ssh *ssh, int id, u_int need, u_char *hash,
                          u_int hashlen, const struct sshbuf *shared_secret,
                          u_char **keyp)

    Hybrid Strategy:
    1. Try: FindVariable for each parameter (symbol-aware)
    2. Fallback: Read from registers/stack

    x86-64 Mapping:
    - ssh = rdi (struct ssh*)
    - id = esi (32-bit int)
    - need = edx (32-bit u_int)
    - hash = rcx (u_char*)
    - hashlen = r8d (32-bit u_int)
    - shared_secret = r9 (const struct sshbuf*)
    - keyp = [rsp+8] (u_char** - 7th parameter on stack)

    Args:
        frame: lldb.SBFrame object
        process: lldb.SBProcess object

    Returns:
        dict: {'ssh': int, 'id': int, 'need': int, 'hash': int, 'hashlen': int,
               'shared_secret': int, 'keyp': int, 'method': str}
              or None on failure
    """
    # METHOD 1: Symbol-aware extraction
    ssh_var = frame.FindVariable("ssh")
    id_var = frame.FindVariable("id")
    need_var = frame.FindVariable("need")
    hash_var = frame.FindVariable("hash")
    hashlen_var = frame.FindVariable("hashlen")
    shared_secret_var = frame.FindVariable("shared_secret")
    keyp_var = frame.FindVariable("keyp")

    if ssh_var.IsValid() and id_var.IsValid() and keyp_var.IsValid():
        return {
            'ssh': ssh_var.GetValueAsUnsigned(),
            'id': id_var.GetValueAsUnsigned(),
            'need': need_var.GetValueAsUnsigned() if need_var.IsValid() else 0,
            'hash': hash_var.GetValueAsUnsigned() if hash_var.IsValid() else 0,
            'hashlen': hashlen_var.GetValueAsUnsigned() if hashlen_var.IsValid() else 0,
            'shared_secret': shared_secret_var.GetValueAsUnsigned() if shared_secret_var.IsValid() else 0,
            'keyp': keyp_var.GetValueAsUnsigned(),
            'method': 'symbol-aware'
        }

    # METHOD 2: Register fallback
    rdi = frame.FindRegister("rdi")
    esi = frame.FindRegister("esi")  # 32-bit id
    edx = frame.FindRegister("edx")  # 32-bit need
    rcx = frame.FindRegister("rcx")
    r8d = frame.FindRegister("r8d")  # 32-bit hashlen
    r9 = frame.FindRegister("r9")
    rsp = frame.FindRegister("rsp")

    if rdi and esi and rsp:
        # Read keyp from stack (7th parameter at rsp+8)
        error = lldb.SBError()
        keyp_val = process.ReadPointerFromMemory(rsp.GetValueAsUnsigned() + 8, error)
        if not error.Success():
            keyp_val = 0

        return {
            'ssh': rdi.GetValueAsUnsigned(),
            'id': esi.GetValueAsUnsigned(),
            'need': edx.GetValueAsUnsigned() if edx else 0,
            'hash': rcx.GetValueAsUnsigned() if rcx else 0,
            'hashlen': r8d.GetValueAsUnsigned() if r8d else 0,
            'shared_secret': r9.GetValueAsUnsigned() if r9 else 0,
            'keyp': keyp_val,
            'method': 'register'
        }

    return None

# ═══════════════════════════════════════════════════════════════════════════
# OPENSSH sshbuf DATA EXTRACTION
# ═══════════════════════════════════════════════════════════════════════════

def read_sshbuf_data(process, sshbuf_ptr):
    """
    Read data from OpenSSH struct sshbuf

    struct sshbuf approximate layout (may vary by version):
    - offset 0:  u_char *d (data pointer)
    - offset 8:  size_t size (allocated size)
    - offset 16: size_t off (current offset)
    - offset 24: size_t max_size (max allowed size)

    Args:
        process: lldb.SBProcess object
        sshbuf_ptr: int - Address of struct sshbuf*

    Returns:
        bytes: Buffer contents, or empty bytes on failure
    """
    if sshbuf_ptr == 0:
        return b''

    error = lldb.SBError()

    # Read data pointer (offset 0)
    data_ptr = process.ReadPointerFromMemory(sshbuf_ptr, error)
    if not error.Success() or data_ptr == 0:
        return b''

    # Read size (offset 8, assuming 64-bit pointers)
    size = process.ReadUnsignedFromMemory(sshbuf_ptr + 8, 8, error)
    if not error.Success() or size == 0:
        return b''

    # Limit size to reasonable maximum (avoid huge reads)
    if size > 8192:  # 8KB max for shared secrets
        size = 8192

    # Read actual data
    data = process.ReadMemory(data_ptr, int(size), error)
    if error.Success():
        return data
    return b''
