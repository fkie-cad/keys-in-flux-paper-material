#!/usr/bin/env python3
"""
Dump Linux XFRM (IPsec) objects from one or more network namespaces using drgn.

Features
--------
- Namespace selection:
    1) NETNS_INUM=<inum>          (best: exact kernel inum of the target netns)
    2) NETNS_FILE=/var/run/netns/left
    3) CHARON_PID="123 456"       (any PID(s) that live in the desired netns)
  If *none* of the above are provided, the script iterates **all** namespaces
  present in the kernel's global netns list (net_namespace_list).

- Dumps (per netns):
    * All xfrm_state SAs (via fast hashes if available, else list)
    * All xfrm_policy entries (via fast hashes if available, else list)
    * For each xfrm_state, the referenced algorithm/key blobs:
        - struct xfrm_algo_aead  (x->aead)  with alg_key[]
        - struct xfrm_algo       (x->ealg)  with alg_key[]
        - struct xfrm_algo_auth  (x->aalg)  with alg_key[]
      Key sizes are derived from alg_key_len (bits).

- Output layout:
    /tmp/xfrm-dump-<nsinum>-<ts>/
        xfrm_state_<addr>.bin
        xfrm_policy_<addr>.bin
        xfrm_key_<nsinum>_spi0x<spi>_<proto>_<daddr>_<kind>_<addr>.bin
      where <kind> ∈ {aead,ealg,aalg}.

Notes
-----
- Key material lives in the xfrm_algo* blobs referenced by xfrm_state
  (ealg/aalg/aead). See include/net/xfrm.h and include/uapi/linux/xfrm.h. [1][2]
- Network namespaces are linked via the global list 'net_namespace_list'. [3]

Refs
----
[1] include/net/xfrm.h (kernel xfrm_state with ealg/aalg/aead members)
[2] include/uapi/linux/xfrm.h (xfrm_algo*, flexible alg_key[], alg_key_len bits)
[3] net/core/net_namespace.c (global net_namespace_list & iteration semantics)
"""
import os, sys, time, stat as pystat, ipaddress
from typing import Optional
from drgn import Object
from drgn import FaultError
from drgn import program_from_kernel, set_default_prog, MissingDebugInfoError, KmodSearchMethod
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.list import hlist_for_each, list_for_each_entry

PAGE_SIZE = 4096
AF_INET  = 2   # from linux/include/linux/socket.h  ("#define AF_INET 2") :contentReference[oaicite:4]{index=4}
AF_INET6 = 10

# --- Keep the same interpreter (venv-safe) when elevating ---
if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

# --- Attach to live kernel; load only main kernel symbols (ignore module debuginfo noise) ---
prog = program_from_kernel()
prog.debug_info_options.try_kmod = KmodSearchMethod.NONE
try:
    prog.load_debug_info(main=True)
except MissingDebugInfoError as e:
    print(f"[warn] {e}")
set_default_prog(prog)

def _warn(msg): print(f"[!] {msg}", file=sys.stderr)
def _info(msg): print(f"[*] {msg}")
def _ok(msg): print(f"[✓] {msg}")

# -------- Small helpers --------
def tsize(t):
    """Safe size accessor for drgn.Type or anonymous types."""
    try:
        return t.size
    except AttributeError:
        return t.sizeof

def has_member(t, name: str) -> bool:
    """Return True if type 't' (drgn.Type of a struct) has field 'name'."""
    return any(m.name == name for m in t.members)

def member_offset(t, name: str) -> int:
    """Return byte offset of struct member 'name' inside type 't'."""
    for m in t.members:
        if m.name == name:
            return m.bit_offset // 8
    raise KeyError(f"{t} has no member '{name}'")

def array_length_of_member(container_type_name: str, member_name: str, fallback: int = 8) -> int:
    """Return static array length for member if available, else fallback."""
    ct = prog.type(container_type_name)
    for m in ct.members:
        if m.name == member_name:
            return getattr(m.type, "length", fallback)
    return fallback


def _is_probably_kernel_va(addr: int) -> bool:
    # Very rough: reject small/addrs below a page and userland-ish addrs.
    # On x86_64/arm64, kernel VAs are in a high range; drgn will still be the final arbiter.
    return addr >= PAGE_SIZE

def _safe_read(prog, addr: int, size: int) -> bytes | None:
    try:
        return prog.read(addr, size)
    except FaultError:
        return None

def _inet_addr_str(xfrm_addr) -> str:
    """Format xfrm_address_t into a human-friendly string (IPv4/IPv6)."""
    # xfrm_address_t is a union { __u32 a4; __u32 a6[4]; } exposed via .a4/.a6
    # We detect IPv4 vs IPv6 by whether high a6 words are nonzero when available.
    try:
        # Prefer v6 if any a6 words beyond a4 are set
        a6 = [int(xfrm_addr.a6[i]) for i in range(4)]
        if any(a6[1:]) or (a6[0] >> 16):  # heuristic
            return str(ipaddress.IPv6Address(int.from_bytes(
                b"".join(int(w).to_bytes(4, "big") for w in a6), "big")))
        # else fall back to IPv4
        a4 = int(xfrm_addr.a4)
        return str(ipaddress.IPv4Address(a4))
    except Exception:
        # Last-ditch: raw hex
        try:
            a4 = int(xfrm_addr.a4)
            return f"{(a4>>24)&0xff}.{(a4>>16)&0xff}.{(a4>>8)&0xff}.{a4&0xff}"
        except Exception:
            return "addr"

# -------- Resolve struct net (netns) targets --------
def _net_from_inum(target_inum: int):
    """Find struct net by ns.inum."""
    head = prog["net_namespace_list"]  # struct list_head (global head)
    for net in list_for_each_entry("struct net", head.address_of_(), "list"):
        if int(net.ns.inum) == target_inum:
            return net
    return None

def _net_from_netns_file(path: str):
    """Find struct net from a bind-mounted netns file path (inode)."""
    st = os.stat(path)
    if not pystat.S_ISREG(st.st_mode) and not pystat.S_ISLNK(st.st_mode):
        _warn(f"{path} doesn't look like a netns handle; trying anyway (inode={st.st_ino})")
    net = _net_from_inum(st.st_ino)
    if not net:
        raise SystemExit(f"Could not resolve struct net for inode {st.st_ino} from {path}")
    return net

def _net_from_pid(pid: int):
    """Resolve struct net from a PID (task->nsproxy->net_ns)."""
    task = find_task(prog, pid)
    nsproxy = task.nsproxy.read_()
    return nsproxy.net_ns

def _resolve_selected_nets():
    """
    Return a list of (struct net, inum) to process based on env selectors.
    If no selectors are given, iterate **all** namespaces from net_namespace_list.
    """
    env_inum = os.environ.get("NETNS_INUM")
    env_file = os.environ.get("NETNS_FILE")
    env_pids = os.environ.get("CHARON_PID")

    if env_inum:
        inum = int(env_inum)
        _info(f"Selecting net via NETNS_INUM={inum}")
        net = _net_from_inum(inum)
        if not net:
            raise SystemExit(f"No struct net found with ns.inum={inum}")
        return [(net, inum)]

    if env_file:
        _info(f"Selecting net via NETNS_FILE={env_file}")
        net = _net_from_netns_file(env_file)
        return [(net, int(net.ns.inum))]

    if env_pids:
        pids = [int(p) for p in env_pids.strip().split()]
        nets = {}
        for p in pids:
            try:
                n = _net_from_pid(p)
                inum = int(n.ns.inum)
                nets.setdefault(inum, n)
            except Exception as e:
                _warn(f"PID {p}: failed to resolve netns: {e}")
        if not nets:
            raise SystemExit("None of the provided PIDs could be resolved to a netns.")
        # Return all distinct net namespaces from the given PIDs
        out = []
        for inum, n in nets.items():
            _info(f"Selected ns.inum={inum} via PID(s)")
            out.append((n, inum))
        return out

    # --- Default: iterate ALL namespaces in the kernel ---
    _info("No selector env provided; iterating all namespaces from net_namespace_list")
    head = prog["net_namespace_list"]
    nets = []
    for net in list_for_each_entry("struct net", head.address_of_(), "list"):
        nets.append((net, int(net.ns.inum)))
    return nets

# -------- Generic dump helpers --------
def _mkdir_outdir(inum: int) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    outdir = f"/tmp/xfrm-dump-{inum}-{ts}"
    os.makedirs(outdir, exist_ok=True)
    return outdir

def dump_obj_bytes(outdir: str, addr: int, size: int, label: str):
    """Dump raw bytes from kernel memory [addr, addr+size) into outdir/label_addr.bin."""
    path = os.path.join(outdir, f"{label}_{addr:x}.bin")
    with open(path, "wb") as f:
        f.write(prog.read(addr, size))
    return path

# -------- XFRM dumping (states, policies, keys) --------
def dump_states(net, outdir: str):
    """
    Dump all struct xfrm_state blobs reachable from netns 'net'.
    Returns list of integer addresses of the dumped states.
    """
    dumped_addrs = []
    st = prog.type("struct xfrm_state")
    xfrm = net.xfrm

    # choose best link field available on this kernel for hash walks
    link = next((m for m in ("bydst", "byspi", "byhash") if has_member(st, m)), None)

    # try hash tables in order of preference
    for tbl in ("state_bydst", "state_byspi", "state_byhash"):
        if hasattr(xfrm, tbl) and link:
            try:
                buckets = getattr(xfrm, tbl)
                mask = int(getattr(xfrm, "state_hmask"))
                link_off = member_offset(st, link)
                _info(f"[ns {int(net.ns.inum)}] States via {tbl} (mask={mask}, link={link})")
                for i in range(mask + 1):
                    head = buckets[i]
                    for node in hlist_for_each(head.address_of_()):
                        addr = int(node) - link_off
                        dump_obj_bytes(outdir, addr, tsize(st), "xfrm_state")
                        dumped_addrs.append(addr)
                if dumped_addrs:
                    return dumped_addrs
            except AttributeError:
                pass  # mask or table missing; try next

    # fallback: walk the global list of all states
    if hasattr(xfrm, "state_all"):
        _info(f"[ns {int(net.ns.inum)}] States via list walk: xfrm.state_all")
        for s in list_for_each_entry("struct xfrm_state", xfrm.state_all.address_of_(), "all"):
            addr = int(s)
            dump_obj_bytes(outdir, addr, tsize(st), "xfrm_state")
            dumped_addrs.append(addr)
        return dumped_addrs

    raise SystemExit("Couldn't find states (no state_* hash and no state_all list).")

def dump_policies(net, outdir: str):
    """Dump all struct xfrm_policy blobs reachable from netns 'net'. Returns count."""
    dumped = 0
    pt = prog.type("struct xfrm_policy")
    xfrm = net.xfrm

    # A) by index (fastest)
    if hasattr(xfrm, "policy_byidx") and hasattr(xfrm, "policy_idx_hmask") and has_member(pt, "byidx"):
        buckets = xfrm.policy_byidx
        mask = int(xfrm.policy_idx_hmask)
        link_off = member_offset(pt, "byidx")
        _info(f"[ns {int(net.ns.inum)}] Policies via policy_byidx (mask={mask}, link=byidx)")
        for i in range(mask + 1):
            head = buckets[i]
            for node in hlist_for_each(head.address_of_()):
                addr = int(node) - link_off
                dump_obj_bytes(outdir, addr, tsize(pt), "xfrm_policy")
                dumped += 1
        return dumped

    # B) by destination hashes
    if hasattr(xfrm, "policy_bydst"):
        nslots = array_length_of_member("struct netns_xfrm", "policy_bydst", fallback=6)
        link = "bydst" if has_member(pt, "bydst") else ("byhash" if has_member(pt, "byhash") else None)
        if link:
            link_off = member_offset(pt, link)
            _info(f"[ns {int(net.ns.inum)}] Policies via policy_bydst[{nslots}] (link={link})")
            for s in range(nslots):
                h = xfrm.policy_bydst[s]
                try:
                    mask = int(h.hmask)
                    table = h.table  # pointer to array of hlist_head
                except Exception:
                    continue
                for i in range(mask + 1):
                    head = table[i]
                    for node in hlist_for_each(head.address_of_()):
                        addr = int(node) - link_off
                        dump_obj_bytes(outdir, addr, tsize(pt), "xfrm_policy")
                        dumped += 1
            if dumped:
                return dumped

    # C) policy_bysel (seen on some kernels)
    if hasattr(xfrm, "policy_bysel"):
        link = "byhash" if has_member(pt, "byhash") else ("bydst" if has_member(pt, "bydst") else None)
        if link and hasattr(xfrm, "policy_hmask"):
            mask = int(xfrm.policy_hmask)
            buckets = xfrm.policy_bysel
            link_off = member_offset(pt, link)
            _info(f"[ns {int(net.ns.inum)}] Policies via policy_bysel (mask={mask}, link={link})")
            for i in range(mask + 1):
                head = buckets[i]
                for node in hlist_for_each(head.address_of_()):
                    addr = int(node) - link_off
                    dump_obj_bytes(outdir, addr, tsize(pt), "xfrm_policy")
                    dumped += 1
            if dumped:
                return dumped

    # D) fallback: walk the global list (stable across kernels)
    if hasattr(xfrm, "policy_all"):
        _info(f"[ns {int(net.ns.inum)}] Policies via list walk: xfrm.policy_all")
        for pol in list_for_each_entry("struct xfrm_policy", xfrm.policy_all.address_of_(), "list"):
            dump_obj_bytes(outdir, int(pol), tsize(pt), "xfrm_policy")
            dumped += 1
        return dumped

    raise SystemExit("Couldn't find policies (no usable policy_* hashes and no policy_all list).")

def _read_c_string(char_array) -> str:
    """Read a C char array as a Python string (up to first NUL)."""
    try:
        ba = bytes(char_array)
        return ba.split(b'\x00', 1)[0].decode(errors="ignore")
    except Exception:
        return ""

# --- helpers for key blobs ----------------------------------------------------
def _read_cstring(addr: int, maxlen: int = 64) -> str:
    """Read up to maxlen bytes from kernel and strip at first NUL."""
    if addr == 0:
        return ""
    buf = prog.read(addr, maxlen)
    nul = buf.find(b"\x00")
    if nul != -1:
        buf = buf[:nul]
    return buf.decode(errors="ignore")

def _algo_header_size(typename: str) -> int:
    """Compute the offset of the flexible array member alg_key[]."""
    t = prog.type(typename)
    try:
        return member_offset(t, "alg_key")
    except Exception:
        # Very old DWARF sometimes omits the flexible array field.
        # Fall back to the offset right after the last fixed member.
        # This list matches UAPI layout for each struct.
        if typename == "struct xfrm_algo":
            return member_offset(t, "alg_key_len") + 4
        if typename == "struct xfrm_algo_auth":
            return member_offset(t, "alg_trunc_len") + 4
        if typename == "struct xfrm_algo_aead":
            return member_offset(t, "alg_icv_len") + 4
        raise

def _dump_algo_blob(kind: str, algo_ptr, outdir: str, ns_inum: int,
                    spi_hex: str, proto: int, daddr_str: str) -> bool:
    """
    Dump raw key bytes for one of: kind in {"ealg","aalg","aead"}.
    Returns True if a blob was written.
    """
    addr = int(algo_ptr)
    if addr == 0:
        return False

    if kind == "ealg":
        tname = "struct xfrm_algo"
    elif kind == "aalg":
        tname = "struct xfrm_algo_auth"
    else:
        tname = "struct xfrm_algo_aead"

    # Read fixed header fields using DWARF, then raw key bytes directly.
    algo = Object(prog, tname, address=addr).read_()
    # offsets and sizes
    hdr = _algo_header_size(tname)
    name = _read_cstring(int(algo.address_of_()) + member_offset(prog.type(tname), "alg_name"), 64)
    key_bits = int(getattr(algo, "alg_key_len"))
    key_len = (key_bits + 7) // 8
    if key_len <= 0 or key_len > (1 << 16):
        _warn(f"[key skip] {kind}: bad key_len={key_len} (name='{name}', addr=0x{addr:x})")
        return False

    key_addr = addr + hdr
    key_bytes = prog.read(key_addr, key_len)

    # Write file: xfrm_key_{ns}_{proto}_{spi}_{daddr}_{kind}_{name}.bin
    safe_name = name.replace("/", "_").replace("(", "_").replace(")", "_")
    fn = f"xfrm_key_ns{ns_inum}_{proto}_{spi_hex}_{daddr_str}_{kind}_{safe_name}.bin"
    with open(os.path.join(outdir, fn), "wb") as f:
        f.write(key_bytes)
    return True

def dump_state_keys(net, outdir: str, state_addrs: list[int]) -> None:
    """
    For each xfrm_state in 'state_addrs' dump any present key blobs:
      - ealg (ESP encryption), aalg (auth), aead (GCM/CCM)
    Also print a per-SA one-liner with what we found.
    """
    dumped_total = 0
    stype = prog.type("struct xfrm_state")
    for addr in state_addrs:
        s = Object(prog, stype, address=addr).read_()
        spi = int(s.id.spi) & 0xffffffff
        spi_hex = f"0x{spi:08x}"
        proto = int(s.id.proto)
        fam = int(s.props.family)
        # destination address for filename/context
        if fam == prog["AF_INET"]:
            daddr = bytes(s.id.daddr.a4).hex(".")
            daddr_str = ".".join(str(int(x,16)) for x in daddr.split("."))
        else:
            # readable IPv6
            from ipaddress import IPv6Address
            daddr_str = str(IPv6Address(bytes(s.id.daddr.a6)))
        ns = int(net.ns.inum)

        have = []
        for kind in ("aead", "ealg", "aalg"):
            ptr = getattr(s, kind, 0)
            try:
                if _dump_algo_blob(kind, ptr, outdir, ns, spi_hex, proto, daddr_str):
                    have.append(kind)
                    dumped_total += 1
            except FaultError as e:
                _warn(f"[key fault] addr=0x{int(ptr):x} ({kind}) for SA {spi_hex} proto={proto} daddr={daddr_str}: {e}")

        # Nice human log per SA
        if have:
            _ok(f"[ns {ns}] SA {spi_hex} proto={proto} daddr={daddr_str}: keys dumped -> {','.join(have)}")
        else:
            _warn(f"[ns {ns}] SA {spi_hex} proto={proto} daddr={daddr_str}: no key blobs present")

    if dumped_total:
        _ok(f"[ns {int(net.ns.inum)}] Key blobs dumped: {dumped_total} files (aead/ealg/aalg where present).")
    else:
        _warn(f"[ns {int(net.ns.inum)}] No key blobs dumped. See per-SA logs above.")

# -------- Run for all chosen namespaces --------
def main():
    targets = _resolve_selected_nets()
    if not targets:
        raise SystemExit("No target net namespaces resolved.")

    for net, inum in targets:
        _ok(f"Resolved struct net at {int(net.value_())} (ns.inum={inum})")
        outdir = _mkdir_outdir(inum)
        _info(f"[ns {inum}] Output dir: {outdir}")

        # Dump SAs and Policies
        state_addrs = dump_states(net, outdir)
        pol_count   = dump_policies(net, outdir)
        _ok(f"[ns {inum}] Dumped states={len(state_addrs)}, policies={pol_count}")

        # Dump key blobs referenced by each state
        dump_state_keys(net, outdir, state_addrs)
        _ok(f"[ns {inum}] Key blobs (aead/ealg/aalg) dumped where present.")

    _ok("All done.")

if __name__ == "__main__":
    main()