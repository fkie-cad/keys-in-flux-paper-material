#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Scan live kernel memory (with drgn) for IPsec XFRM keys.

Key sources:
  --from-file keymat_xfrm_info.txt --side LEFT|RIGHT   # parse mixed file containing [SIDE] XFRM block
  (or) live: -n left                                   # run `ip xfrm` in that netns

Kernel netns selection (where xfrm_state lives) via env (priority):
  NETNS_INUM=<inum> | NETNS_FILE=/var/run/netns/left | CHARON_PID="123 456"

Regions scanned:
  - xfrm_state objects (robust walker) ✓
  - Crypto API contexts (aead/skcipher/ahash) ✓
  - XFRM key blobs themselves (ealg/aalg/aead) ✓
  - SLUB/SLAB heaps (sampled) ✓
  - vmalloc areas (capped) ✓
  - module core memory ✓
  - (optional) small directmap windows

Output:
  - "KEYS (parsed)" table (kind/role/SPI/route/key-hex)
  - Hit tables per-kind with Region / VA / +Offset / Meta
  - `--debug` prints walker diagnostics and candidate members/tables.

Examples:
  sudo NETNS_FILE=/var/run/netns/left "$(python3 -c 'import sys;print(sys.executable)')" \
       ./scan_kernel_for_xfrm_keys.py --from-file keymat_xfrm_info.txt --side LEFT --debug

  sudo NETNS_FILE=/var/run/netns/left "$(python3 -c 'import sys;print(sys.executable)')" \
       ./scan_kernel_for_xfrm_keys.py -n left --slab-limit-pages 512 --vmalloc-max-bytes $((256<<20))
"""

import os, sys, re, ipaddress, subprocess
from dataclasses import dataclass
from typing import List, Optional, Tuple, Dict, Iterable, Set

from drgn import (program_from_kernel, set_default_prog, MissingDebugInfoError,
                  KmodSearchMethod, Object, FaultError)
from drgn.helpers.linux.pid import find_task
from drgn.helpers.linux.list import list_for_each_entry, hlist_for_each
from drgn.helpers.linux.mm import page_to_virt

try:
    from drgn.helpers.linux.percpu import per_cpu_ptr, for_each_possible_cpu
    HAVE_PERCPU = True
except Exception:
    HAVE_PERCPU = False

# --- keep same interpreter (venv-safe) when elevating ---
if os.geteuid() != 0:
    os.execvp("sudo", ["sudo", sys.executable] + sys.argv)

# --- attach to kernel (main debuginfo only) ---
prog = program_from_kernel()
prog.debug_info_options.try_kmod = KmodSearchMethod.NONE
try:
    prog.load_debug_info(main=True)
except MissingDebugInfoError as e:
    print(f"[warn] {e}")
set_default_prog(prog)

PAGE_SIZE = os.sysconf('SC_PAGE_SIZE')
PTR_SIZE  = prog.type("void *").size

# ---------- small type helpers ----------
def tsize(t):
    try: return t.size
    except AttributeError: return t.sizeof

def has_member_recursive(t, name: str) -> bool:
    for m in t.members:
        if m.name == name:
            return True
        if (getattr(m, "name", None) in (None, "") and hasattr(m.type, "members")):
            if has_member_recursive(m.type, name):
                return True
    return False

def member_offset_recursive(t, name: str) -> int:
    for m in t.members:
        if m.name == name:
            return m.bit_offset // 8
        if (getattr(m, "name", None) in (None, "") and hasattr(m.type, "members")):
            try:
                inner = member_offset_recursive(m.type, name)
                return (m.bit_offset // 8) + inner
            except KeyError:
                pass
    raise KeyError(f"{t} has no member '{name}' (incl. anon unions)")

def collect_member_offsets_by_tag(t, tag_name: str) -> List[int]:
    """Return byte offsets of all sub-objects whose type tag equals tag_name (recursive, includes anon unions)."""
    offs: List[int] = []
    def rec(tt, base_off):
        for m in getattr(tt, "members", []):
            mt = getattr(m, "type", None)
            if not mt: continue
            off = base_off + (m.bit_offset // 8)
            if getattr(mt, "kind", None) == "STRUCT" and getattr(mt, "tag", "") == tag_name:
                offs.append(off)
            if hasattr(mt, "members") and (m.name in (None, "")):  # anonymous
                rec(mt, off)
    rec(t, 0)
    return sorted(set(offs))

# ---------- shell helpers ----------
def run(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {' '.join(cmd)}", file=sys.stderr)
        print(e.output.decode("utf-8", "replace"), file=sys.stderr)
        return ""

def get_ipv4_in_netns(ns: str) -> List[str]:
    txt = run(["ip", "-n", ns, "-o", "-4", "addr", "show"])
    ips = []
    for line in txt.splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/\d+\b", line)
        if m:
            ips.append(m.group(1))
    return ips

# ---------- parse XFRM ----------
STATE_HDR_RE = re.compile(r"^\s*src\s+(\S+)\s+dst\s+(\S+)\s*$", re.M)
PROTO_RE     = re.compile(r"^\s*proto\s+(\S+)\s+spi\s+(\S+)\s+reqid\s+\S+\s+mode\s+(\S+)\s*$", re.M)
ENC_RE       = re.compile(r"^\s*enc\s+(\S+)\s+(0x)?([0-9A-Fa-f]+)\s*$", re.M)
AUTH_RE      = re.compile(r"^\s*auth(?:-trunc)?\s+(\S+)\s+(0x)?([0-9A-Fa-f]+)\b", re.M)

@dataclass
class SAKey:
    kind: str
    hexstr: str
    raw: bytes
    role: str
    spi: str
    route: str

def normalize_hex_key(s: str) -> str:
    s = s.strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    return re.sub(r"[^0-9a-fA-f]", "", s, flags=re.I).lower()

def hex_to_bytes(s: str) -> bytes:
    s = normalize_hex_key(s)
    if len(s) % 2 == 1: s = "0" + s
    return bytes.fromhex(s)

def extract_block(text: str, side: str) -> Optional[str]:
    pat = re.compile(rf"(?mi)^\[{re.escape(side)}\]\s*XFRM:\s*$")
    m = pat.search(text)
    if not m: return None
    start = m.end()
    m2 = re.search(r"(?m)^\[[^\]\n]+\][^\n]*$", text[start:])
    end = start + (m2.start() if m2 else len(text) - start)
    return text[start:end].strip()

def parse_xfrm_states(xfrm_text: str, left_ips: List[str]) -> List[SAKey]:
    parts = xfrm_text.splitlines()
    blank_idx = next((i for i,l in enumerate(parts) if l.strip() == ""), len(parts))
    state_lines = parts[:blank_idx] if blank_idx < len(parts) else parts
    left_set = set(left_ips)

    res: List[SAKey] = []
    i = 0
    cur_src = cur_dst = cur_spi = None
    while i < len(state_lines):
        line = state_lines[i]
        m = STATE_HDR_RE.match(line)
        if m:
            cur_src, cur_dst, cur_spi = m.group(1), m.group(2), None
            i += 1; continue
        m = PROTO_RE.match(line)
        if m:
            cur_spi = m.group(2).lower()
            i += 1; continue
        m = ENC_RE.match(line)
        if m and cur_src and cur_dst and cur_spi:
            hx = normalize_hex_key((m.group(2) or "") + m.group(3))
            role = "initiator" if cur_src.split("/")[0] in left_set else "responder"
            res.append(SAKey("enc", hx, hex_to_bytes(hx), role, cur_spi, f"{cur_src}->{cur_dst}"))
            i += 1; continue
        m = AUTH_RE.match(line)
        if m and cur_src and cur_dst and cur_spi:
            hx = normalize_hex_key((m.group(2) or "") + m.group(3))
            role = "initiator" if cur_src.split("/")[0] in left_set else "responder"
            res.append(SAKey("auth", hx, hex_to_bytes(hx), role, cur_spi, f"{cur_src}->{cur_dst}"))
            i += 1; continue
        i += 1
    return res

# ---------- resolve struct net ----------
def _net_from_inum(target_inum: int):
    head = prog["net_namespace_list"]
    for net in list_for_each_entry("struct net", head.address_of_(), "list"):
        if int(net.ns.inum) == target_inum:
            return net
    return None

def _net_from_netns_file(path: str):
    st = os.stat(path)
    net = _net_from_inum(st.st_ino)
    if not net:
        raise SystemExit(f"Could not resolve struct net for inode {st.st_ino} from {path}")
    return net

def _net_from_pid(pid: int):
    task = find_task(prog, pid)
    nsproxy = task.nsproxy.read_()
    return nsproxy.net_ns

def resolve_net():
    env_inum = os.environ.get("NETNS_INUM")
    env_file = os.environ.get("NETNS_FILE")
    env_pids = os.environ.get("CHARON_PID")

    if env_inum:
        inum = int(env_inum); net = _net_from_inum(inum)
        if not net: raise SystemExit(f"No struct net found with ns.inum={inum}")
        print(f"[*] net via NETNS_INUM={inum}")
        return net
    if env_file:
        print(f"[*] net via NETNS_FILE={env_file}")
        return _net_from_netns_file(env_file)
    if env_pids:
        pids = [int(p) for p in env_pids.strip().split()]
        nets = {}
        for p in pids:
            try:
                n = _net_from_pid(p); inum = int(n.ns.inum)
                nets.setdefault(inum, []).append((p, n))
            except Exception as e:
                print(f"[!] PID {p}: {e}", file=sys.stderr)
        if not nets: raise SystemExit("No PID resolved to a netns.")
        inum, lst = next(iter(nets.items()))
        print(f"[*] net via CHARON_PID (ns.inum={inum}, using PID {lst[0][0]})")
        return lst[0][1]
    print("[*] defaulting NETNS_FILE=/var/run/netns/left")
    return _net_from_netns_file("/var/run/netns/left")

# ---------- raw memory helpers ----------
def _safe_read(addr: int, size: int) -> Optional[bytes]:
    try:
        return prog.read(addr, size)
    except FaultError:
        return None

def _read_ptr(addr: int) -> int:
    raw = _safe_read(addr, PTR_SIZE)
    if not raw: return 0
    return int.from_bytes(raw, byteorder=sys.byteorder, signed=False)

# ---------- DWARF-first iterator, then inference fallback ----------
# --- raw ptr helpers ---
def _rd_ptr(addr: int) -> int:
    raw = _safe_read(addr, PTR_SIZE)
    if not raw:
        return 0
    return int.from_bytes(raw, byteorder=sys.byteorder, signed=False)

def _raw_list_iter(head_addr: int, debug=False, max_steps=1_000_000):
    """Walk a circular struct list_head via raw pointers; yield 'pos' (embedded list_head address)."""
    nxt = _rd_ptr(head_addr)  # head->next
    steps = 0
    seen = set()
    while nxt and nxt != head_addr and steps < max_steps:
        if nxt in seen:
            break
        seen.add(nxt)
        yield nxt
        nxt = _rd_ptr(nxt)  # pos->next (offset 0)
        steps += 1
    if debug:
        print(f"    raw list: steps={steps}, start=0x{head_addr:x}")

def _raw_hlist_iter(hhead_addr: int, debug=False, max_steps=1_000_000):
    """Walk a struct hlist_head via raw pointers; yield 'node' (struct hlist_node* address)."""
    node = _rd_ptr(hhead_addr)  # head->first
    steps = 0
    seen = set()
    while node and steps < max_steps:
        if node in seen:
            break
        seen.add(node)
        yield node
        node = _rd_ptr(node + 0)  # node->next at offset 0
        steps += 1
    if debug:
        print(f"    raw hlist: steps={steps}, head=0x{hhead_addr:x}")

def iter_xfrm_states(net, debug: bool = False):
    """
    Robust xfrm_state enumerator:
      1) Try DWARF hash walk (raw hlist traversal) using known link offsets if available.
      2) Try state_all (raw list traversal), brute-forcing the list_head offset if needed.
      3) Brute-force hashes (raw hlist), brute-forcing hlist_node offset if needed.
    Yields drgn Objects of type 'struct xfrm_state'.
    """
    xfrm = net.xfrm
    st_t = prog.type("struct xfrm_state")
    st_size = tsize(st_t)

    def validate_state(base: int):
        try:
            s = Object(prog, "struct xfrm_state", address=base)
            proto = int(s.id.proto)
            fam   = int(s.props.family)
            spi   = int(s.id.spi)
            if proto in (50, 51) and fam in (2, 10) and spi != 0:
                return s
        except Exception:
            pass
        return None

    yielded = 0

    # A) Hashes via raw hlist, using DWARF-known link offsets if present
    mask = int(getattr(xfrm, "state_hmask", 0))
    link_offsets = []
    for nm in ("bydst", "byspi", "byhash"):
        try:
            link_offsets.append((nm, member_offset_recursive(st_t, nm)))
        except Exception:
            pass
    tables = [nm for nm in ("state_bydst", "state_byspi", "state_byhash") if hasattr(xfrm, nm)]

    if debug:
        print(f"[*] walker(raw): links={[n for n,_ in link_offsets]} tables={tables} state_hmask={mask}")

    for link_name, link_off in link_offsets:
        for tbl in tables:
            try:
                tbl_ptr = int(getattr(xfrm, tbl))  # address of hlist_head array
                if not tbl_ptr:
                    continue
            except Exception:
                continue
            local = 0
            rng = range(mask + 1) if mask > 0 else range(1)
            for i in rng:
                head_addr = tbl_ptr + i * PTR_SIZE  # sizeof(struct hlist_head) == one pointer
                for node_addr in _raw_hlist_iter(head_addr, debug=False):
                    base = node_addr - link_off
                    s = validate_state(base)
                    if s is not None:
                        local += 1; yielded += 1; yield s
            if debug:
                print(f"    tried {tbl} via link={link_name} (raw) -> yielded={local}")
            if local:
                return

    # B) state_all via raw list (no member names needed)
    if hasattr(xfrm, "state_all"):
        try:
            head_addr = int(xfrm.state_all.address_of_())
            list_off_cache = [None]  # learned list_head offset

            def brute_container_from_pos(pos: int):
                if list_off_cache[0] is not None:
                    s = validate_state(pos - list_off_cache[0])
                    if s is not None:
                        return s
                limit = min(st_size - 16, 2048)
                for off in range(0, max(0, limit), 8):
                    s = validate_state(pos - off)
                    if s is not None:
                        list_off_cache[0] = off
                        return s
                return None

            local = 0
            for pos in _raw_list_iter(head_addr, debug=False):
                s = brute_container_from_pos(pos)
                if s is not None:
                    local += 1; yielded += 1; yield s
            if debug:
                print(f"[*] walker(raw): state_all brute walk -> yielded={local}, list_off={list_off_cache[0]}")
            if local:
                return
        except Exception as e:
            if debug:
                print(f"    state_all raw walk failed: {e}")

    if yielded:
        return

    # C) Fully brute hashes via raw hlist (no link names); learn hlist_node offset
    try:
        hnode_off_cache = [None]
        any_local = 0
        for tbl in ("state_bydst", "state_byspi", "state_byhash"):
            if not hasattr(xfrm, tbl): continue
            try:
                tbl_ptr = int(getattr(xfrm, tbl))
                if not tbl_ptr: continue
            except Exception:
                continue
            local = 0
            rng = range(mask + 1) if mask > 0 else range(1)
            for i in rng:
                head_addr = tbl_ptr + i * PTR_SIZE
                for node_addr in _raw_hlist_iter(head_addr, debug=False):
                    if hnode_off_cache[0] is not None:
                        s = validate_state(node_addr - hnode_off_cache[0])
                        if s is not None:
                            local += 1; yielded += 1; any_local += 1; yield s
                            continue
                    limit = min(st_size - 16, 2048)
                    for off in range(0, max(0, limit), 8):
                        s = validate_state(node_addr - off)
                        if s is not None:
                            hnode_off_cache[0] = off
                            local += 1; yielded += 1; any_local += 1; yield s
                            break
            if debug:
                print(f"    brute(raw): {tbl} yielded={local}, hnode_off={hnode_off_cache[0]}")
            if local:
                return
        if debug and any_local == 0:
            print("[!] brute(raw): no xfrm_state candidates validated in hashes")
    except Exception as e:
        if debug:
            print(f"    brute(raw): hash traversal failed: {e}")
    return


# ---------- targeted regions (states + crypto ctx + key blobs) ----------
@dataclass
class Region:
    start: int
    size: int
    label: str
    meta: str

def get_crypto_ctx_region(tfm_base) -> Optional[Tuple[int,int]]:
    if tfm_base is None: return None
    try:
        base_addr = int(tfm_base.value_())
    except Exception:
        return None
    try:
        tfm_t = prog.type("struct crypto_tfm")
        base_sz = tsize(tfm_t)
    except Exception:
        return None
    alg_field = None
    for m in tfm_t.members:
        try:
            if str(m.type).startswith("struct crypto_alg *"):
                alg_field = m.name; break
        except Exception:
            pass
    if not alg_field and hasattr(tfm_base, "__crt_alg"):
        alg_field = "__crt_alg"
    if not alg_field:
        return None
    try:
        alg = getattr(tfm_base, alg_field)
        ctxsz = int(alg.cra_ctxsize)
    except Exception:
        return None
    if ctxsz <= 0:
        return None
    return (base_addr + base_sz, ctxsz)

def state_route_and_spi(s) -> Tuple[str, str]:
    spi = "unknown"
    try:
        spi_val = int(s.id.spi)
        spi = f"0x{spi_val:08x}"
    except Exception:
        pass
    route = "?"
    try:
        fam = int(s.props.family)
        if fam == 2:
            def v4str(addr):
                a = addr.a4
                return f"{int(a[0])}.{int(a[1])}.{int(a[2])}.{int(a[3])}"
            src = v4str(s.props.saddr) if hasattr(s.props, "saddr") else "?.?.?.?"
            dst = v4str(s.id.daddr)
            route = f"{src}->{dst}"
        else:
            route = "v6-route"
    except Exception:
        pass
    return route, spi

def collect_xfrm_targeted_regions(net, include_keyblobs=True, debug=False) -> Tuple[List[Region], List[Dict]]:
    regs: List[Region] = []
    st_t = prog.type("struct xfrm_state")
    keyblob_index: List[Dict] = []

    # pointer offsets
    off_ealg = off_aalg = off_aead = None
    try: off_ealg = member_offset_recursive(st_t, "ealg")
    except Exception: pass
    try: off_aalg = member_offset_recursive(st_t, "aalg")
    except Exception: pass
    try: off_aead = member_offset_recursive(st_t, "aead")
    except Exception: pass

    count = 0
    for s in iter_xfrm_states(net, debug=debug):
        count += 1
        s_addr = int(s.address_of_())
        route, spi = state_route_and_spi(s)
        regs.append(Region(s_addr, tsize(st_t), "xfrm_state", f"spi={spi} {route}"))

        for label, base in (
            ("aead_ctx",     getattr(s.aead, "base", None) if hasattr(s, "aead") else None),
            ("skcipher_ctx", getattr(s.ealg, "base", None) if hasattr(s, "ealg") else None),
            ("ahash_ctx",    getattr(s.aalg, "base", None) if hasattr(s, "aalg") else None),
        ):
            r = get_crypto_ctx_region(base)
            if r:
                regs.append(Region(r[0], r[1], label, f"spi={spi} {route}"))

        if include_keyblobs:
            for kind, field_name in (("aead","aead"), ("ealg","ealg"), ("aalg","aalg")):
                try:
                    p = int(getattr(s, field_name))
                except Exception:
                    p = 0
                if not p:
                    continue
                # header size + key len
                if kind == "ealg":
                    tname = "struct xfrm_algo"; keylen_field = "alg_key_len"
                    try: hdr = member_offset_recursive(prog.type(tname), "alg_key")
                    except Exception: hdr = member_offset_recursive(prog.type(tname), "alg_key_len") + 4
                elif kind == "aalg":
                    tname = "struct xfrm_algo_auth"; keylen_field = "alg_key_len"
                    try: hdr = member_offset_recursive(prog.type(tname), "alg_key")
                    except Exception: hdr = member_offset_recursive(prog.type(tname), "alg_trunc_len") + 4
                else:
                    tname = "struct xfrm_algo_aead"; keylen_field = "alg_key_len"
                    try: hdr = member_offset_recursive(prog.type(tname), "alg_key")
                    except Exception: hdr = member_offset_recursive(prog.type(tname), "alg_icv_len") + 4

                try:
                    algo = Object(prog, tname, address=p).read_()
                    key_bits = int(getattr(algo, keylen_field))
                    key_len = (key_bits + 7) // 8
                    if 0 < key_len < 4096:
                        regs.append(Region(p, hdr + key_len, f"xfrm_keyblob:{kind}", f"spi={spi} {route}"))
                        kb = (_safe_read(p + hdr, key_len) or b"")
                        keyblob_index.append({"kind":kind, "spi":spi, "route":route,
                                              "addr":p, "key_hex":kb.hex()})
                except Exception:
                    continue

    if debug:
        print(f"[*] targeted: enumerated xfrm_state={count}, regions={len(regs)}")
    return regs, keyblob_index

# ---------- vmalloc / modules / slab ----------
@dataclass
class Region:
    start: int
    size: int
    label: str
    meta: str

def collect_vmalloc_regions(max_bytes: int) -> List[Region]:
    regs: List[Region] = []
    total = 0
    try:
        head = prog["vmap_area_list"]
    except Exception:
        return regs
    for va in list_for_each_entry("struct vmap_area", head.address_of_(), "list"):
        try:
            start = int(va.va_start); end = int(va.va_end)
        except Exception:
            continue
        if end <= start: continue
        size = end - start
        if total + size > max_bytes:
            size = max(0, max_bytes - total)
        if size <= 0: break
        regs.append(Region(start, size, "vmalloc", f"0x{start:x}-0x{end:x}"))
        total += size
        if total >= max_bytes: break
    return regs

def collect_module_regions() -> List[Region]:
    regs: List[Region] = []
    try:
        head = prog["modules"]
    except Exception:
        return regs
    for mod in list_for_each_entry("struct module", head.address_of_(), "list"):
        try:
            core = mod.core_layout
            start = int(core.base); size = int(core.size)
            if start and size:
                regs.append(Region(start, size, "module:core",
                                   f"{mod.name.string_().decode(errors='ignore')}"))
        except Exception:
            continue
    return regs

def allocator_mode() -> str:
    kmc = prog.type("struct kmem_cache")
    if has_member_recursive(kmc, "node"):     return "SLUB"
    if has_member_recursive(kmc, "nodelists"):return "SLAB"
    return "UNKNOWN"

def collect_slub_regions(limit_pages_per_cache: int, include_percpu=True) -> List[Region]:
    regs: List[Region] = []
    try:
        head = prog["slab_caches"]
    except Exception:
        return regs

    def add_page(pg, cname, suffix):
        try:
            vaddr = int(page_to_virt(pg))
            if vaddr:
                regs.append(Region(vaddr, PAGE_SIZE, f"kmem:slub:{cname}:{suffix}",
                   f"page@0x{int(pg.address_of_()):x}"))
        except Exception:
            pass

    for kmc in list_for_each_entry("struct kmem_cache", head.address_of_(), "list"):
        try: cname = kmc.name.string_().decode(errors="ignore")
        except Exception: cname = "unknown"
        added = 0
        try:
            nodep = kmc.node
            for nid in range(0, 8):
                try:
                    kn = nodep[nid]
                except Exception:
                    break
                if int(kn) == 0: continue
                try:
                    partial = kn.partial
                    for pg in list_for_each_entry("struct page", partial.address_of_(), "lru"):
                        add_page(pg, cname, f"node{nid}:partial")
                        added += 1
                        if added >= limit_pages_per_cache: break
                except Exception:
                    pass
                if added >= limit_pages_per_cache: break
        except Exception:
            pass
        if include_percpu and HAVE_PERCPU and hasattr(kmc, "cpu_slab"):
            try:
                for cpu in for_each_possible_cpu(prog):
                    try:
                        cslab = per_cpu_ptr(kmc.cpu_slab, cpu)
                        pg = cslab.page
                        if int(pg) != 0:
                            add_page(pg, cname, f"cpu{cpu}:current")
                    except Exception:
                        continue
            except Exception:
                pass
    return regs

def collect_slab_regions(limit_pages_per_cache: int) -> List[Region]:
    regs: List[Region] = []
    try:
        head = prog["slab_caches"]
    except Exception:
        return regs
    kmc_t = prog.type("struct kmem_cache")
    if not has_member_recursive(kmc_t, "nodelists"):
        return regs

    for kmc in list_for_each_entry("struct kmem_cache", head.address_of_(), "list"):
        try: cname = kmc.name.string_().decode(errors="ignore")
        except Exception: cname = "unknown"
        objsz = 0
        try: objsz = int(kmc.size)
        except Exception: pass

        pages_added = 0
        try:
            nl = kmc.nodelists
            for nid in range(0, 8):
                try: l3 = nl[nid]
                except Exception: break
                if int(l3) == 0: continue
                for lstname in ("slabs_full","slabs_partial","slabs_free"):
                    if not hasattr(l3, lstname): continue
                    lst = getattr(l3, lstname)
                    try:
                        for slab in list_for_each_entry("struct slab", lst.address_of_(), "list"):
                            try: start = int(slab.s_mem)
                            except Exception: continue
                            if not start: continue
                            size = PAGE_SIZE
                            try:
                                objects = int(slab.objects)
                                if objsz and objects:
                                    size = min(objects * objsz, 8 * PAGE_SIZE)
                            except Exception:
                                pass
                            regs.append(Region(start, size, f"kmem:slab:{cname}:{lstname}:node{nid}", f"slab@0x{int(slab.address_of_()):x}"))

                            pages_added += 1
                            if pages_added >= limit_pages_per_cache: break
                    except Exception:
                        continue
                if pages_added >= limit_pages_per_cache: break
        except Exception:
            continue
    return regs

# ---------- scanning ----------
def find_all(buf: bytes, needle: bytes, max_hits: int = 4096) -> List[int]:
    if not needle: return []
    hits, start = [], 0
    while True:
        idx = buf.find(needle, start)
        if idx == -1: break
        hits.append(idx)
        if len(hits) >= max_hits: break
        start = idx + 1
    return hits

@dataclass
class Hit:
    key_label: str
    region_label: str
    addr: int
    offset: int
    meta: str

def scan_regions_for_key(regs: List[Region], key_hex_lower: str, key_raw: bytes,
                         title_label: str, max_hits_per_region=128, scan_ascii=True) -> List[Hit]:
    hits: Dict[int, Hit] = {}
    a1 = key_hex_lower.encode("ascii")
    a2 = b"0x" + a1
    for r in regs:
        try:
            data = prog.read(r.start, r.size)
        except Exception:
            continue
        for off in find_all(data, key_raw, max_hits=max_hits_per_region):
            hits[r.start + off] = Hit(title_label, r.label, r.start + off, off, r.meta)
        if scan_ascii:
            for off in find_all(data, a1, max_hits=max_hits_per_region):
                hits[r.start + off] = Hit(title_label, r.label, r.start + off, off, r.meta)
            for off in find_all(data, a2, max_hits=max_hits_per_region):
                hits[r.start + off] = Hit(title_label, r.label, r.start + off, off, r.meta)
    return list(hits.values())

# ---------- CLI ----------
import argparse

def main():
    ap = argparse.ArgumentParser(description="Scan live kernel memory for XFRM keys using drgn.")
    ap.add_argument("-n","--netns", default="left", help="netns name for ip xfrm (default: left)")
    ap.add_argument("--from-file", help="mixed file containing [LEFT]/[RIGHT] XFRM blocks")
    ap.add_argument("--side", choices=["LEFT","RIGHT"], default="LEFT", help="which [SIDE] XFRM block to parse")
    ap.add_argument("--left-ip", action="append", default=[], help="explicit local IP(s)")
    ap.add_argument("--no-ascii", action="store_true", help="do not search ASCII-hex copies")
    ap.add_argument("--max-hits", type=int, default=128, help="max matches per region")
    ap.add_argument("--debug", action="store_true", help="verbose walker diagnostics")

    ap.add_argument("--slab-limit-pages", type=int, default=256, help="per-cache page sample cap")
    ap.add_argument("--no-slab", action="store_true", help="disable SLUB/SLAB scanning")
    ap.add_argument("--no-vmalloc", action="store_true", help="disable vmalloc scanning")
    ap.add_argument("--vmalloc-max-bytes", type=int, default=(256<<20), help="cap vmalloc bytes")
    ap.add_argument("--no-modules", action="store_true", help="disable module core scanning")
    args = ap.parse_args()

    # 1) netns
    net = resolve_net()
    ns_inum = int(net.ns.inum)
    print(f"[✓] scanning netns inum={ns_inum}")

    # 2) keys (from file or live)
    if args.from_file:
        with open(args.from_file, "r", encoding="utf-8", errors="replace") as fh:
            whole = fh.read()
        block = extract_block(whole, args.side)
        xfrm_txt = block if block else whole
        left_ips = args.left_ip or get_ipv4_in_netns(args.netns)
        if not left_ips:
            m = re.search(r"(?mi)^\[LEFT\]\s*SAs:", whole)
            if m:
                tail = whole[m.end():]
                m2 = re.search(r"(?m)^\[[^\]\n]+\][^\n]*$", tail)
                if m2: tail = tail[:m2.start()]
                left_ips = re.findall(r"\blocal\b.*?@\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", tail)
    else:
        xfrm_txt = run(["ip", "netns", "exec", args.netns, "bash", "-lc", "ip xfrm state; echo; ip xfrm policy"])
        left_ips = args.left_ip or get_ipv4_in_netns(args.netns)

    if not xfrm_txt.strip():
        print("[!] No XFRM text found; cannot obtain keys.", file=sys.stderr)
        sys.exit(2)
    keys = parse_xfrm_states(xfrm_txt, left_ips)
    if not keys:
        print("[!] No keys parsed from XFRM text.", file=sys.stderr)
        sys.exit(2)

    # 3) keys table
    print("\n=== KEYS (parsed) ===")
    print(f"{'Kind':<6} {'Role':<10} {'SPI':<10} {'Route':<23} {'Key (hex)':}")
    for k in keys:
        print(f"{k.kind:<6} {k.role:<10} {k.spi:<10} {k.route:<23} {k.hexstr}")

    # 4) regions (DWARF-first; inference fallback inside)
    regions: List[Region] = []
    targeted, keyblob_index = collect_xfrm_targeted_regions(net, include_keyblobs=True, debug=args.debug)
    if not targeted:
        print("[!] No xfrm_state objects found (walker couldn’t see them).", file=sys.stderr)
    else:
        print(f"[*] targeted regions: {len(targeted)} (states/ctxs/keyblobs)")
    regions += targeted

    # generic regions
    if not args.no_slab:
        mode = allocator_mode()
        if mode == "SLUB":
            slub_regs = collect_slub_regions(args.slab_limit_pages, include_percpu=True)
            print(f"[*] SLUB regions: {len(slub_regs)}")
            regions += slub_regs
        elif mode == "SLAB":
            slab_regs = collect_slab_regions(args.slab_limit_pages)
            print(f"[*] SLAB regions: {len(slab_regs)}")
            regions += slab_regs
        else:
            print("[!] Unknown allocator; skipping slab scan.")
    if not args.no_vmalloc:
        vm_regs = collect_vmalloc_regions(args.vmalloc_max_bytes)
        print(f"[*] vmalloc regions: {len(vm_regs)} (cap {args.vmalloc_max_bytes} bytes)")
        regions += vm_regs
    if not args.no_modules:
        mod_regs = collect_module_regions()
        print(f"[*] module regions: {len(mod_regs)}")
        regions += mod_regs

    if not regions:
        print("[!] No regions to scan.", file=sys.stderr)
        sys.exit(1)

    # 5) scan + report (with key8/mem8)
    def report(title: str, subset: List[SAKey]):
        print(f"\n=== {title} ===")
        any_hit = False
        for k in subset:
            title_label = f"{k.kind} ({k.role}) spi={k.spi} {k.route}"
            print(f"\n- {title_label} [{len(k.raw)} bytes]")
            print(f"  {'Region':<26} {'VA':<18} {'+Off':<10} {'key8':<19} {'mem8':<19} Meta")
            hits = scan_regions_for_key(regions, k.hexstr, k.raw, title_label,
                                        max_hits_per_region=args.max_hits, scan_ascii=(not args.no_ascii))
            if not hits:
                print("  (no occurrences)")
                continue
            any_hit = True
            key8 = k.raw[:8].hex()
            for h in sorted(hits, key=lambda x: (x.region_label, x.addr)):
                try:
                    mem8 = (prog.read(h.addr, min(8, len(k.raw))) or b"").hex()
                except Exception:
                    mem8 = ""
                print(f"  {h.region_label:<26} 0x{h.addr:016x}  +0x{h.offset:08x} {key8:<19} {mem8:<19} {h.meta}")
        return any_hit

    enc_keys  = [k for k in keys if k.kind == "enc"]
    auth_keys = [k for k in keys if k.kind == "auth"]

    h1 = report("ENC KEY OCCURRENCES (kernel)", enc_keys)
    h2 = report("AUTH KEY OCCURRENCES (kernel)", auth_keys)

    # 6) show any key blobs we dereferenced directly
    if keyblob_index:
        print("\n=== KEY BLOBS (from xfrm_state pointers) ===")
        print(f"{'Kind':<8} {'SPI':<10} {'Route':<23} {'Blob @':<18} {'Key (hex)':}")
        for kb in keyblob_index:
            print(f"{kb['kind']:<8} {kb['spi']:<10} {kb['route']:<23} 0x{kb['addr']:016x} {kb['key_hex']}")

    if not (h1 or h2):
        print("\n[!] No key occurrences found in scanned regions.", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
