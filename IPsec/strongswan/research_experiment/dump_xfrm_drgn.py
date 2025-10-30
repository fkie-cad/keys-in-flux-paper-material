#!/usr/bin/env python3
"""
Dump Linux XFRM (IPsec) objects from one or more network namespaces using drgn.

What this dumps (per netns)
---------------------------
1) All Security Associations:         struct xfrm_state
2) All Security Policies:             struct xfrm_policy
3) The key blobs referenced by SAs:   struct xfrm_algo       (x->ealg  : encryption key)
                                       struct xfrm_algo_auth  (x->aalg  : auth key)
                                       struct xfrm_algo_aead  (x->aead  : AEAD key)

Why this is correct
-------------------
- The key *bytes* live in the xfrm_algo* blobs (flexible member alg_key[]). These are
  pointed to by xfrm_state->ealg/aalg/aead and are freed when the SA is destroyed.
  See kernel headers/sources.  [include/uapi/linux/xfrm.h, net/xfrm/xfrm_state.c]
- xfrm_state hash tables must be walked using the matching 'link' member:
    state_bydst -> xfrm_state.bydst   (in an anonymous union on modern kernels)
    state_byspi -> xfrm_state.byspi
    state_byhash -> xfrm_state.byhash (older kernels)
  Failing to match link <-> table yields wrong base addresses and bogus pointers.

Selection (pick one; if none given we iterate all namespaces)
-------------------------------------------------------------
  NETNS_INUM=<inum>          e.g. from: readlink /proc/<pid>/ns/net -> net:[INUM]
  NETNS_FILE=/var/run/netns/left
  CHARON_PID="123 456"       one or more PIDs; all should be in the same netns

Examples
--------
  sudo NETNS_FILE=/var/run/netns/left  "$(python3 -c 'import sys;print(sys.executable)')" ./dump_xfrm_drgn.py
  INO=$(stat -Lc %i /var/run/netns/left); sudo NETNS_INUM=$INO "$(python3 -c 'import sys;print(sys.executable)')" ./dump_xfrm_drgn.py
  PIDS="$(sudo ip netns exec left sh -lc 'pidof charon || pgrep -x charon')"
  sudo CHARON_PID="$PIDS"     "$(python3 -c 'import sys;print(sys.executable)')" ./dump_xfrm_drgn.py
"""

import os, sys, time, stat as pystat, ipaddress
from typing import Optional, List
from drgn import program_from_kernel, set_default_prog, MissingDebugInfoError, KmodSearchMethod, Object, FaultError
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.list import hlist_for_each, list_for_each_entry

# --- Keep same interpreter (venv-safe) when elevating ---
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

# --- Constants (avoid looking up macros like AF_INET in DWARF; they aren't symbols) ---
AF_INET  = 2   # from linux/include/linux/socket.h  ("#define AF_INET 2") :contentReference[oaicite:4]{index=4}
AF_INET6 = 10  # "#define AF_INET6 10" (same header)                                 :contentReference[oaicite:5]{index=5}
PAGE_SIZE = 4096
PTR_SIZE  = prog.type("void *").size

# -------- small helpers --------
def tsize(t):
    """Safe size accessor for drgn.Type or anonymous types."""
    try:
        return t.size
    except AttributeError:
        return t.sizeof

def has_member_recursive(t, name: str) -> bool:
    """Return True if type 't' (drgn.Type of a struct) has field 'name', recursing into anonymous unions/structs."""
    for m in t.members:
        if m.name == name:
            return True
        # Recurse into anonymous union/struct (no name) if present
        if (getattr(m, "name", None) in (None, "") and hasattr(m.type, "members")):
            if has_member_recursive(m.type, name):
                return True
    return False

def member_offset_recursive(t, name: str) -> int:
    """Return byte offset of struct member 'name' inside type 't', recursing into anonymous unions/structs."""
    for m in t.members:
        if m.name == name:
            return m.bit_offset // 8
        if (getattr(m, "name", None) in (None, "") and hasattr(m.type, "members")):
            try:
                inner = member_offset_recursive(m.type, name)
                return (m.bit_offset // 8) + inner
            except KeyError:
                pass
    raise KeyError(f"{t} has no member '{name}' (including anonymous unions)")

def array_length_of_member(container_type_name: str, member_name: str, fallback: int = 8) -> int:
    """Return static array length for member if available, else fallback."""
    ct = prog.type(container_type_name)
    for m in ct.members:
        if m.name == member_name:
            return getattr(m.type, "length", fallback)
    return fallback

def _is_probably_kernel_va(addr: int) -> bool:
    """Very rough filter to reject obvious garbage pointers (tiny / NULL)."""
    return addr >= PAGE_SIZE

def _safe_read(addr: int, size: int) -> Optional[bytes]:
    """Read raw kernel memory defensively."""
    try:
        return prog.read(addr, size)
    except FaultError:
        return None

# -------- resolve the target struct net (i.e., the netns) --------
def _net_from_inum(target_inum: int):
    head = prog["net_namespace_list"]  # struct list_head (global head)
    for net in list_for_each_entry("struct net", head.address_of_(), "list"):
        if int(net.ns.inum) == target_inum:
            return net
    return None

def _net_from_netns_file(path: str):
    st = os.stat(path)
    if not pystat.S_ISREG(st.st_mode) and not pystat.S_ISLNK(st.st_mode):
        _warn(f"{path} doesn't look like a netns handle; trying anyway (inode={st.st_ino})")
    net = _net_from_inum(st.st_ino)
    if not net:
        raise SystemExit(f"Could not resolve struct net for inode {st.st_ino} from {path}")
    return net

def _net_from_pid(pid: int):
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
        out = []
        for inum, n in nets.items():
            _info(f"Selected ns.inum={inum} via PID(s)")
            out.append((n, inum))
        return out

    # Default: iterate ALL namespaces in the kernel
    _info("No selector env provided; iterating all namespaces from net_namespace_list")
    head = prog["net_namespace_list"]
    nets = []
    for net in list_for_each_entry("struct net", head.address_of_(), "list"):
        nets.append((net, int(net.ns.inum)))
    return nets

# -------- output helpers --------
def _mkdir_outdir(inum: int) -> str:
    ts = time.strftime("%Y%m%d-%H%M%S")
    outdir = f"/tmp/xfrm-dump-{inum}-{ts}"
    os.makedirs(outdir, exist_ok=True)
    return outdir

def dump_obj_bytes(outdir: str, addr: int, size: int, label: str):
    """Dump raw bytes from kernel memory [addr, addr+size) into outdir/label_addr.bin."""
    path = os.path.join(outdir, f"{label}_{addr:x}.bin")
    data = _safe_read(addr, size)
    if data is not None:
        with open(path, "wb") as f:
            f.write(data)
    return path

# -------- address formatting --------
def _inet_addr_str(daddr_obj, family: int) -> str:
    """
    Render xfrm_address_t as human-readable string. We avoid relying on DWARF
    endianness and read raw bytes, then re-order to network byte order.
    """
    base = int(daddr_obj.address_of_())
    try:
        if family == AF_INET:
            raw = _safe_read(base, 4)
            if not raw:
                return "ipv4"
            # __be32 stored in host-endian memory; reverse per-host endianness
            raw_be = raw[::-1] if sys.byteorder == "little" else raw
            return str(ipaddress.IPv4Address(raw_be))
        elif family == AF_INET6:
            raw16 = _safe_read(base, 16)
            if not raw16:
                return "ipv6"
            # union uses a6[4] (__u32 words). Convert each word to big-endian.
            if sys.byteorder == "little":
                raw16 = b"".join(raw16[i:i+4][::-1] for i in range(0, 16, 4))
            return str(ipaddress.IPv6Address(raw16))
    except Exception:
        pass
    return "addr"

# -------- XFRM dumping (states, policies, keys) --------
def dump_states(net, outdir: str) -> List[int]:
    """
    Dump all struct xfrm_state blobs reachable from netns 'net'.
    Returns list of integer addresses of the dumped states.
    """
    dumped_addrs: List[int] = []
    st = prog.type("struct xfrm_state")
    xfrm = net.xfrm

    # table -> link actually used in that table
    tbl_link = [
        ("state_bydst",  "bydst"),
        ("state_byspi",  "byspi"),
        ("state_byhash", "byhash"),  # older kernels
    ]

    for tbl, link in tbl_link:
        if hasattr(xfrm, tbl):
            try:
                buckets = getattr(xfrm, tbl)
                mask = int(getattr(xfrm, "state_hmask"))
                link_off = member_offset_recursive(st, link)
                _info(f"[ns {int(net.ns.inum)}] States via {tbl} (mask={mask}, link={link})")
                for i in range(mask + 1):
                    head = buckets[i]
                    for node in hlist_for_each(head.address_of_()):
                        base = int(node) - link_off
                        dump_obj_bytes(outdir, base, tsize(st), "xfrm_state")
                        dumped_addrs.append(base)
                if dumped_addrs:
                    return dumped_addrs
            except (AttributeError, KeyError):
                continue

    # fallback: walk the global list of all states
    if hasattr(xfrm, "state_all"):
        _info(f"[ns {int(net.ns.inum)}] States via list walk: xfrm.state_all")
        for s in list_for_each_entry("struct xfrm_state", xfrm.state_all.address_of_(), "all"):
            base = int(s)
            dump_obj_bytes(outdir, base, tsize(st), "xfrm_state")
            dumped_addrs.append(base)
        return dumped_addrs

    raise SystemExit("Couldn't find states (no state_* hash and no state_all list).")

def dump_policies(net, outdir: str) -> int:
    """
    Dump all struct xfrm_policy blobs reachable from netns 'net'.
    Returns count of dumped policies.
    """
    dumped = 0
    pt = prog.type("struct xfrm_policy")
    xfrm = net.xfrm

    # A) by index
    if hasattr(xfrm, "policy_byidx") and hasattr(xfrm, "policy_idx_hmask") and has_member_recursive(pt, "byidx"):
        buckets = xfrm.policy_byidx
        mask = int(xfrm.policy_idx_hmask)
        link_off = member_offset_recursive(pt, "byidx")
        _info(f"[ns {int(net.ns.inum)}] Policies via policy_byidx (mask={mask}, link=byidx)")
        for i in range(mask + 1):
            head = buckets[i]
            for node in hlist_for_each(head.address_of_()):
                base = int(node) - link_off
                dump_obj_bytes(outdir, base, tsize(pt), "xfrm_policy")
                dumped += 1
        return dumped

    # B) by destination hashes
    if hasattr(xfrm, "policy_bydst"):
        nslots = array_length_of_member("struct netns_xfrm", "policy_bydst", fallback=6)
        link = "bydst" if has_member_recursive(pt, "bydst") else ("byhash" if has_member_recursive(pt, "byhash") else None)
        if link:
            link_off = member_offset_recursive(pt, link)
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
                        base = int(node) - link_off
                        dump_obj_bytes(outdir, base, tsize(pt), "xfrm_policy")
                        dumped += 1
            if dumped:
                return dumped

    # C) policy_bysel (some kernels)
    if hasattr(xfrm, "policy_bysel"):
        link = "byhash" if has_member_recursive(pt, "byhash") else ("bydst" if has_member_recursive(pt, "bydst") else None)
        if link and hasattr(xfrm, "policy_hmask"):
            mask = int(xfrm.policy_hmask)
            buckets = xfrm.policy_bysel
            link_off = member_offset_recursive(pt, link)
            _info(f"[ns {int(net.ns.inum)}] Policies via policy_bysel (mask={mask}, link={link})")
            for i in range(mask + 1):
                head = buckets[i]
                for node in hlist_for_each(head.address_of_()):
                    base = int(node) - link_off
                    dump_obj_bytes(outdir, base, tsize(pt), "xfrm_policy")
                    dumped += 1
            if dumped:
                return dumped

    # D) fallback: list walk
    if hasattr(xfrm, "policy_all"):
        _info(f"[ns {int(net.ns.inum)}] Policies via list walk: xfrm.policy_all")
        for pol in list_for_each_entry("struct xfrm_policy", xfrm.policy_all.address_of_(), "list"):
            dump_obj_bytes(outdir, int(pol), tsize(pt), "xfrm_policy")
            dumped += 1
        return dumped

    raise SystemExit("Couldn't find policies (no usable policy_* hashes and no policy_all list).")

# --- key-dump helpers ---------------------------------------------------------
def _algo_header_size(typename: str) -> int:
    """Compute the offset of the flexible array member alg_key[]."""
    t = prog.type(typename)
    try:
        return member_offset_recursive(t, "alg_key")
    except Exception:
        # Very old DWARF may omit the flexible array; infer from last fixed field.
        if typename == "struct xfrm_algo":
            return member_offset_recursive(t, "alg_key_len") + 4
        if typename == "struct xfrm_algo_auth":
            return member_offset_recursive(t, "alg_trunc_len") + 4
        if typename == "struct xfrm_algo_aead":
            return member_offset_recursive(t, "alg_icv_len") + 4
        raise

def _read_ptr(base: int, off: int) -> int:
    """Raw pointer read from base+off; avoids DWARF surprises."""
    raw = _safe_read(base + off, PTR_SIZE)
    if not raw:
        return 0
    return int.from_bytes(raw, byteorder=sys.byteorder, signed=False)

def _dump_algo_blob(kind: str, algo_addr: int, outdir: str, ns_inum: int,
                    spi: int, proto: int, daddr_str: str) -> bool:
    """
    Dump raw key bytes for one of: kind in {"ealg","aalg","aead"}.
    Returns True if a blob was written.
    """
    if algo_addr == 0 or not _is_probably_kernel_va(algo_addr):
        return False

    if kind == "ealg":
        tname = "struct xfrm_algo"
    elif kind == "aalg":
        tname = "struct xfrm_algo_auth"
    else:
        tname = "struct xfrm_algo_aead"

    # Read header (up to alg_key[]), then parse alg_key_len via DWARF
    hdr = _safe_read(algo_addr, _algo_header_size(tname))
    if hdr is None:
        return False

    try:
        algo = Object(prog, tname, address=algo_addr).read_()
        key_bits = int(getattr(algo, "alg_key_len"))
    except FaultError:
        return False

    if key_bits <= 0 or key_bits > 32768:
        return False
    key_len = (key_bits + 7) // 8

    blob = _safe_read(algo_addr, _algo_header_size(tname) + key_len)
    if blob is None:
        return False

    # File naming: ns/spi/proto/daddr/kind
    daddr_sanitized = daddr_str.replace(":", "_")
    fn = f"xfrm_key_{ns_inum}_spi0x{spi:08x}_p{proto}_{daddr_sanitized}_{kind}_{algo_addr:x}.bin"
    with open(os.path.join(outdir, fn), "wb") as f:
        f.write(blob)
    return True

def dump_state_keys(net, outdir: str, state_addrs: List[int]) -> None:
    """
    For each xfrm_state in 'state_addrs' dump any present key blobs:
      - ealg (ESP encryption), aalg (auth), aead (GCM/CCM)
    Also print a per-SA one-liner with what we found.
    """
    st = prog.type("struct xfrm_state")
    off_ealg = member_offset_recursive(st, "ealg")
    off_aalg = member_offset_recursive(st, "aalg")
    off_aead = member_offset_recursive(st, "aead")

    for base in state_addrs:
        try:
            s = Object(prog, st, address=base)  # no .read_() needed for field access
        except FaultError:
            continue

        spi = int(s.id.spi) & 0xffffffff
        proto = int(s.id.proto)
        fam = int(s.props.family)

        daddr_str = _inet_addr_str(s.id.daddr, fam)

        # Read pointers *raw* (helps catch DWARF hiccups)
        ptrs = {
            "aead": _read_ptr(base, off_aead),
            "ealg": _read_ptr(base, off_ealg),
            "aalg": _read_ptr(base, off_aalg),
        }

        dumped_kinds = []
        # Prefer AEAD if present, else ealg/aalg
        order = ("aead", "ealg", "aalg") if ptrs["aead"] else ("ealg", "aalg")
        for kind in order:
            p = ptrs[kind]
            if p and _dump_algo_blob(kind, p, outdir, int(net.ns.inum), spi, proto, daddr_str):
                dumped_kinds.append(kind)

        if dumped_kinds:
            _ok(f"[ns {int(net.ns.inum)}] SA 0x{spi:08x} proto={proto} daddr={daddr_str}: keys dumped -> {','.join(dumped_kinds)}")
        else:
            _warn(f"[ns {int(net.ns.inum)}] SA 0x{spi:08x} proto={proto} daddr={daddr_str}: no key blobs present")

# -------- run --------
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
