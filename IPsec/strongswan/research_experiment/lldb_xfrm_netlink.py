#!/usr/bin/env python3
# lldb_xfrm_netlink.py
# Attach in LLDB to charon and log Netlink (NETLINK_XFRM) messages sent via sendto()
#
# Works without strongSwan debug symbols by hooking libc's sendto().
# On aarch64 (your Ubuntu ARM64 VM), sendto() args are:
#   x0=sockfd, x1=buf, x2=len, x3=flags, x4=dest_addr, x5=addrlen
# On x86_64 they are:
#   rdi=sockfd, rsi=buf, rdx=len, rcx=flags, r8=dest_addr, r9=addrlen
#
# Usage (from inside the target netns):
#   sudo ip netns exec left lldb -p $(pgrep -n charon)
#   (lldb) command script import /path/to/lldb_xfrm_netlink.py
#   (lldb) xfrmnetlink
#   (lldb) c
#
# You should then see lines like:
#   [NETLINK] type=0x10 (NEW?) len=... pid=0 seq=... (likely XFRM add)
#   [NETLINK] type=0x11 (DEL?) len=...
#
# NOTE: This only logs Netlink message header fields. For SPI, combine with
# the eBPF kernel tracer (xfrm_trace.bt).

import lldb
import struct

AF_NETLINK = 16  # Linux AF_NETLINK
# Netlink header is struct nlmsghdr (linux/netlink.h):
#   __u32 nlmsg_len;
#   __u16 nlmsg_type;
#   __u16 nlmsg_flags;
#   __u32 nlmsg_seq;
#   __u32 nlmsg_pid;
NLMSG_HDRLEN = 16

def _read_mem(proc, addr, size):
    err = lldb.SBError()
    data = proc.ReadMemory(addr, size, err)
    if not err.Success():
        raise RuntimeError(f"ReadMemory(0x{addr:x}, {size}) failed: {err}")
    return data

def _arch_regs(frame):
    """Return a dict with relevant arg regs depending on arch."""
    target = frame.GetThread().GetProcess().GetTarget()
    triple = target.GetTriple()
    regs = {}
    if "aarch64" in triple:
        regs["buf"]  = frame.FindRegister("x1").GetValueAsUnsigned()
        regs["len"]  = frame.FindRegister("x2").GetValueAsUnsigned()
        regs["to"]   = frame.FindRegister("x4").GetValueAsUnsigned()
        regs["tolen"]= frame.FindRegister("x5").GetValueAsUnsigned()
    else:
        # x86_64 fallback
        regs["buf"]  = frame.FindRegister("rsi").GetValueAsUnsigned()
        regs["len"]  = frame.FindRegister("rdx").GetValueAsUnsigned()
        regs["to"]   = frame.FindRegister("r8").GetValueAsUnsigned()
        regs["tolen"]= frame.FindRegister("r9").GetValueAsUnsigned()
    return regs

def _bp_callback(frame, bp_loc, _dict):
    proc = frame.GetThread().GetProcess()
    try:
        regs = _arch_regs(frame)
        to_addr = regs["to"]
        # read sockaddr_nl to confirm AF_NETLINK
        # struct sockaddr_nl { sa_family_t nl_family; unsigned short pad; __u32 nl_pid; __u32 nl_groups; }
        sockaddr = _read_mem(proc, to_addr, 12)
        (family, _pad, nl_pid, nl_groups) = struct.unpack("<HHII", sockaddr)
        if family != AF_NETLINK:
            return False  # not a netlink sendto, ignore

        buf = regs["buf"]
        n = min(regs["len"], 64)  # read enough for nlmsghdr and a bit more
        hdr = _read_mem(proc, buf, max(NLMSG_HDRLEN, n))
        (nlmsg_len, nlmsg_type, nlmsg_flags, nlmsg_seq, nlmsg_pid) = struct.unpack("<IHHII", hdr[:NLMSG_HDRLEN])

        print(f"[NETLINK] type=0x{nlmsg_type:x} len={nlmsg_len} flags=0x{nlmsg_flags:x} seq={nlmsg_seq} pid={nlmsg_pid} dstpid={nl_pid} groups=0x{nl_groups:x}")
    except Exception as e:
        print(f"[NETLINK] error: {e}")
    return False  # continue execution

def xfrmnetlink(debugger, command, result, _dict):
    """Set a breakpoint on libc sendto() and attach our callback to log Netlink msgs.
    Usage from LLDB:  xfrmnetlink
    """
    target = debugger.GetSelectedTarget()
    if not target:
        print("No target. Attach first (e.g., 'process attach -p <pid>')")
        return

    # Break on libc's sendto symbol
    bp = target.BreakpointCreateByName("sendto", None)
    if not bp or not bp.IsValid() or bp.num_locations == 0:
        print("Failed to create breakpoint on sendto. Is libc loaded?")
        return
    bp.SetScriptCallbackFunction(__name__ + "._bp_callback")
    print(f"Breakpoint {bp.GetID()} set on sendto(). Continue with 'c'.")

def __lldb_init_module(debugger, _dict):
    debugger.HandleCommand('command script add -f lldb_xfrm_netlink.xfrmnetlink xfrmnetlink')
    print("Loaded lldb_xfrm_netlink.py. Use 'xfrmnetlink' to hook libc sendto().")
