#!/usr/bin/env python3
"""kernel2elf's kprobe list (kprobe_table, written as JSON in the non-alloc section .memlens.kprobes) against FAKE
volatility3 modules, a fake kernel (types with the Debian 13 / Linux 6.12 ISF's offsets) and a fake memory layer: no
Volatility and no memory image needed. Checks our logic only; the real run on the demo image is described in
docs/OUTPUT.md and was made with Volatility 2.28.2.

usage: python3 tests/test_kernel2elf_kprobes.py
"""
import hashlib, io, json, os, signal, struct, sys, types
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

# Just enough of volatility3 for vol_plugins/linux/kernel2elf.py to import (as in tests/test_kernel2elf_bpf.py).
fake = {name: types.ModuleType(name) for name in (
    "volatility3", "volatility3.framework", "volatility3.framework.configuration", "volatility3.framework.renderers",
    "volatility3.framework.symbols", "volatility3.framework.symbols.linux", "volatility3.framework.symbols.linux.utilities")}
framework = fake["volatility3.framework"]
framework.exceptions = types.SimpleNamespace(SymbolError=KeyError, InvalidAddressException=ValueError, VolatilityException=Exception)
framework.interfaces = types.SimpleNamespace(plugins=types.SimpleNamespace(PluginInterface=object))
framework.renderers = fake["volatility3.framework.renderers"]
framework.renderers.TreeGrid = lambda columns, rows: (columns, rows)
fake["volatility3.framework.renderers"].format_hints = types.SimpleNamespace(Hex=int)
fake["volatility3.framework.configuration"].requirements = types.SimpleNamespace()
fake["volatility3.framework.symbols.linux.utilities"].modules = types.SimpleNamespace(Modules=object)
fake["volatility3.framework.symbols.linux"].kallsyms = types.SimpleNamespace(Kallsyms=None)
sys.modules.update(fake)
sys.path.insert(0, os.path.join(HERE, "..", "vol_plugins", "linux"))
import kernel2elf as k  # noqa: E402
import patchscan as ps  # noqa: E402


class Type:
    """A fake Volatility type template: relative_child_offset raises IndexError for a missing member, as Volatility's does."""
    def __init__(self, size, fields):
        self.size, self.fields = size, fields

    def relative_child_offset(self, name):
        if name not in self.fields:
            raise IndexError("Member not present in template: %s" % name)
        return self.fields[name]

    def has_member(self, name):
        return name in self.fields


# Offsets from debian-6.12.115+deb13.1-amd64.json.xz (trace_event_call.name sits in an anonymous union, which Volatility
# flattens into the struct).
TYPES_612 = {
    "kprobe": Type(128, {"hlist": 0, "list": 16, "nmissed": 32, "addr": 40, "symbol_name": 48, "offset": 56, "pre_handler": 64,
                         "post_handler": 72, "flags": 120}),
    "hlist_head": Type(8, {"first": 0}), "hlist_node": Type(16, {"next": 0, "pprev": 8}), "list_head": Type(16, {"next": 0, "prev": 8}),
    "kretprobe": Type(168, {"kp": 0, "handler": 128}), "dyn_event": Type(24, {"list": 0, "ops": 16}),
    "trace_kprobe": Type(256, {"devent": 0, "rp": 24, "nhit": 192, "symbol": 200, "tp": 208}),
    "trace_probe": Type(48, {"list": 0, "event": 16, "size": 24}), "trace_probe_event": Type(248, {"flags": 0, "class": 8, "call": 80}),
    "trace_event_call": Type(120, {"list": 0, "class": 16, "name": 24, "tp": 24, "event": 32})}
SHIFT = 0x0d000000  # KASLR
TABLE, DISPATCHER, AGGR = 0xffffffff82100000, 0xffffffff81200000, 0xffffffff81200400
SYMBOLS = {"kprobe_table": TABLE, "kprobe_dispatcher": DISPATCHER, "aggr_pre_handler": AGGR}


class Kernel:
    def __init__(self, types_, symbols, count=64):
        self.types, self.symbols, self.count, self.offset = types_, symbols, count, SHIFT

    def get_type(self, name):
        if name not in self.types:
            raise KeyError(name)
        return self.types[name]

    def get_symbol(self, name):
        if name not in self.symbols:
            raise KeyError(name)
        kind = types.SimpleNamespace(vol=types.SimpleNamespace(count=self.count)) if name == "kprobe_table" else None
        return types.SimpleNamespace(address=self.symbols[name], type=kind)


class Memory:
    """A fake memory layer: pages that were written to are mapped, reading any other byte raises (as Volatility's
    InvalidAddressException, here ValueError)."""
    def __init__(self):
        self.pages = {}

    def put(self, address, data):
        for index, byte in enumerate(data):
            self.pages.setdefault((address + index) & ~0xfff, bytearray(0x1000))[(address + index) & 0xfff] = byte

    def read(self, address, length, pad=False):
        out = bytearray()
        for at in range(address, address + length):
            page = self.pages.get(at & ~0xfff)
            if page is None:
                raise ValueError("unmapped %#x" % at)
            out.append(page[at & 0xfff])
        return bytes(out)


def q(value):
    return struct.pack("<Q", value)


T = TYPES_612
DISPATCH, AGGR_K = DISPATCHER + SHIFT, AGGR + SHIFT
OPENAT2, VFS_READ, KILL = 0xffffffff8e642210, 0xffffffff8e650004, 0xffffffff8e3a0004
PRE, POST = 0xffffffffc0100100, 0xffffffffc0100200
HEAP = 0xffff888004a00000
mem = Memory()
mem.put(TABLE + SHIFT, b"\0" * 64 * 8)  # kprobe_table[64], all buckets empty for now


def string(address, text):
    mem.put(address, text.encode() + b"\0")
    return address


def kprobe(at, addr, pre, post=0, symbol=None, offset=0, bucket=None, after=None, flags=0):
    """A struct kprobe at at, linked first into kprobe_table[bucket] or after the kprobe 'after' (hlist)."""
    mem.put(at, b"\0" * 128)
    mem.put(at + 40, q(addr) + q(symbol or 0) + struct.pack("<I", offset) + b"\0" * 4 + q(pre) + q(post))
    mem.put(at + 120, struct.pack("<I", flags))  # kprobe.flags
    if bucket is not None:
        mem.put(TABLE + SHIFT + 8 * bucket, q(at))  # head.first -> kprobe.hlist (offset 0)
    if after is not None:
        mem.put(after, q(at))  # previous kprobe's hlist.next
    return at


def trace_kprobe(at, event, on_list=True, **probe):
    """A trace_kprobe at at (its kprobe at at + 24, rp.kp), with tp.event -> a trace_probe_event whose call.name is event;
    on_list: its devent.list is on the dyn_event list (a tracefs event), else empty (perf_event_open's local probe)."""
    mem.put(at, b"\0" * 256)
    mem.put(at, q(0xffffffff83000000 if on_list else at) + q(0xffffffff83000000 if on_list else at))  # devent.list
    tpe = at + 0x1000
    mem.put(tpe, b"\0" * 248)
    mem.put(at + 208 + 16, q(tpe))                           # tp.event
    mem.put(tpe + 80 + 24, q(string(at + 0x800, event)))      # call.name
    probe.setdefault("pre", DISPATCH)
    return kprobe(at + 24, **probe)


SYM1, SYM2, SYM3 = string(HEAP + 0x9000, "do_sys_openat2"), string(HEAP + 0x9100, "vfs_read"), string(HEAP + 0x9200, "__x64_sys_kill")
TK1 = HEAP + 0x10000
trace_kprobe(TK1, "memlens_kp", addr=OPENAT2, symbol=SYM1, bucket=5)
TK2 = HEAP + 0x20000
trace_kprobe(TK2, "p_vfs_read_0", on_list=False, addr=VFS_READ, symbol=SYM2, bucket=9, flags=2 | 8)  # DISABLED | FTRACE
MODPROBE = 0xffffffffc0102040  # a module's static struct kprobe, second in bucket 5
kprobe(MODPROBE, KILL, PRE, POST, symbol=SYM3, after=TK1 + 24, flags=8)
# Two probes on one address: the table holds the aggregate probe (pre_handler aggr_pre_handler), whose list holds both.
AGG, P1, P2 = HEAP + 0x30000, HEAP + 0x30200, HEAP + 0x30400
kprobe(AGG, 0xffffffff8e700004, AGGR_K, bucket=63)
kprobe(P1, 0xffffffff8e700004, PRE)
kprobe(P2, 0xffffffff8e700004, 0, POST, symbol=string(HEAP + 0x9300, "evil_target"), offset=4)
mem.put(AGG + 16, q(P1 + 16)); mem.put(P1 + 16, q(P2 + 16)); mem.put(P2 + 16, q(AGG + 16))  # list_head ring via kprobe.list

kernel = Kernel(T, SYMBOLS)
layout = k.kprobe_layout(kernel)
assert layout["table"] == TABLE + SHIFT and layout["count"] == 64 and layout["head"] == 8 and layout["first"] == 0, layout
assert (layout["dispatcher"], layout["aggregate"]) == (DISPATCH, AGGR_K), layout
assert layout["event"] == [-24 + 208 + 16, 80 + 24] and layout["tracefs"] == -24 + 0, layout  # container_of rp.kp, then tp.event
records = k.kprobe_list(mem, layout)
expected = [
    {"kprobe": TK1 + 24, "addr": OPENAT2, "symbol": "do_sys_openat2", "offset": 0, "pre_handler": DISPATCH, "post_handler": 0,
     "event": "memlens_kp", "tracefs": True, "flags": 0},
    {"kprobe": TK2 + 24, "addr": VFS_READ, "symbol": "vfs_read", "offset": 0, "pre_handler": DISPATCH, "post_handler": 0,
     "event": "p_vfs_read_0", "tracefs": False, "flags": 2 | 8},
    {"kprobe": MODPROBE, "addr": KILL, "symbol": "__x64_sys_kill", "offset": 0, "pre_handler": PRE, "post_handler": POST, "flags": 8},
    {"kprobe": P1, "addr": 0xffffffff8e700004, "symbol": None, "offset": 0, "pre_handler": PRE, "post_handler": 0, "flags": 0},
    {"kprobe": P2, "addr": 0xffffffff8e700004, "symbol": "evil_target", "offset": 4, "pre_handler": 0, "post_handler": POST, "flags": 0}]
assert sorted(records, key=lambda r: (r["addr"], r["kprobe"])) == sorted(expected, key=lambda r: (r["addr"], r["kprobe"])), records
assert records == sorted(records, key=lambda r: (r["addr"], r["kprobe"])), records  # written in a stable order

# The bucket read adds hlist_head.first's offset from the ISF (review s179 NIT 4): a layout whose first sits 8 bytes in,
# with the table 8 bytes lower, reads the same buckets.
assert k.kprobe_list(mem, dict(layout, table=layout["table"] - 8, first=8)) == records
assert k.kprobe_layout(Kernel(dict(T, hlist_head=Type(8, {})), SYMBOLS)) is None  # an ISF without hlist_head.first

# Linux before 5.4: struct trace_probe embeds its trace_event_call (no event pointer); before 5.0 trace_kprobe has a list
# instead of devent. The path to the name comes from the ISF either way.
old = dict(T, trace_probe=Type(200, {"list": 0, "class": 16, "call": 88}), trace_kprobe=Type(256, {"list": 0, "rp": 16, "tp": 200}))
del old["trace_probe_event"], old["dyn_event"]
old_layout = k.kprobe_layout(Kernel(old, SYMBOLS))
assert old_layout["event"] == [-16 + 200 + 88 + 24] and old_layout["tracefs"] == -16 + 0, old_layout
# No trace_kprobe in the ISF (CONFIG_KPROBE_EVENTS off): probes are still listed, without event names.
bare = dict(T); del bare["trace_kprobe"]
assert k.kprobe_layout(Kernel(bare, SYMBOLS))["event"] is None
assert [r.get("event") for r in k.kprobe_list(mem, k.kprobe_layout(Kernel(bare, SYMBOLS)))] == [None] * 5
# An ISF whose struct kprobe has no flags member: the records have no flags key (patchscan then counts them as enabled).
noflags = dict(T, kprobe=Type(128, {name: at for name, at in T["kprobe"].fields.items() if name != "flags"}))
assert k.kprobe_layout(Kernel(noflags, SYMBOLS))["flags"] is None
assert k.kprobe_list(mem, k.kprobe_layout(Kernel(noflags, SYMBOLS))) == [{key: value for key, value in record.items() if key != "flags"}
                                                                         for record in records]
# kretprobes (review s179 MINOR 1). Linux 6.12: register_kretprobe sets rp->kp.pre_handler = pre_handler_kretprobe
# (kernel/kprobes.c), and an 'r:' event sets tk->rp.handler = kretprobe_dispatcher (kernel/trace/trace_kprobe.c). The
# record gets ret_handler (kretprobe.handler, at kp + 128 here); with kretprobe_dispatcher, the event name as for a kprobe.
KRET_PRE, KRET_DISPATCH, RETH, VFS_WRITE = 0xffffffff81200800, 0xffffffff81200c00, 0xffffffffc0100300, 0xffffffff8e660004
KSYMBOLS = dict(SYMBOLS, pre_handler_kretprobe=KRET_PRE, kretprobe_dispatcher=KRET_DISPATCH)
rmem = Memory()
rmem.pages = {page: bytearray(data) for page, data in mem.pages.items()}
mem, saved = rmem, mem
TK3, MODRET = HEAP + 0x70000, 0xffffffffc0102200  # a tracefs 'r:' event; a module's static struct kretprobe
trace_kprobe(TK3, "r_vfs_write", addr=VFS_WRITE, symbol=string(HEAP + 0x9400, "vfs_write"), bucket=20, pre=KRET_PRE + SHIFT)
mem.put(TK3 + 24 + 128, q(KRET_DISPATCH + SHIFT))  # tk->rp.handler
kprobe(MODRET, VFS_WRITE + 0x100, KRET_PRE + SHIFT, bucket=21, flags=8)
mem.put(MODRET + 128, q(RETH))  # rp.handler: the module's function
mem = saved
rlayout = k.kprobe_layout(Kernel(T, KSYMBOLS))
assert (rlayout["kret_pre"], rlayout["kret_dispatcher"], rlayout["rp_handler"]) == (KRET_PRE + SHIFT, KRET_DISPATCH + SHIFT, 128), rlayout
rrecords = k.kprobe_list(rmem, rlayout)
assert [r for r in rrecords if r["kprobe"] in (TK3 + 24, MODRET)] == [
    {"kprobe": TK3 + 24, "addr": VFS_WRITE, "symbol": "vfs_write", "offset": 0, "pre_handler": KRET_PRE + SHIFT, "post_handler": 0,
     "flags": 0, "ret_handler": KRET_DISPATCH + SHIFT, "event": "r_vfs_write", "tracefs": True},
    {"kprobe": MODRET, "addr": VFS_WRITE + 0x100, "symbol": None, "offset": 0, "pre_handler": KRET_PRE + SHIFT, "post_handler": 0,
     "flags": 8, "ret_handler": RETH}], rrecords
assert [r for r in rrecords if r["kprobe"] not in (TK3 + 24, MODRET)] == records, rrecords  # the kprobes as before
read = ps.kprobe_records(json.dumps({"version": 1, "kprobes": rrecords}).encode())
assert (read[VFS_WRITE][0]["ret_handler"], read[VFS_WRITE + 0x100][0]["ret_handler"], read[OPENAT2][0]["ret_handler"]) == (
    KRET_DISPATCH + SHIFT, RETH, None), read
# An ISF without those symbols or without kretprobe.handler: no ret_handler and no event for a kretprobe, as before.
assert all("ret_handler" not in r and r.get("event") is None for r in k.kprobe_list(rmem, layout) if r["kprobe"] in (TK3 + 24, MODRET))
nohandler = k.kprobe_layout(Kernel(dict(T, kretprobe=Type(168, {"kp": 0})), KSYMBOLS))
assert nohandler["rp_handler"] is None and all("ret_handler" not in r for r in k.kprobe_list(rmem, nohandler)), nohandler
# A name that ends 8 bytes before an unmapped page is read: read_string reads up to the page end, not 512 bytes at once
# (review s179 NIT 1, mutant R3). Here as a trace_kprobe's event name.
emem = Memory()
emem.pages = {page: bytearray(data) for page, data in mem.pages.items()}
mem, saved = emem, mem
EDGE = HEAP + 0x80000 - 8  # HEAP + 0x80000 is not mapped
TK4 = HEAP + 0x7e000
trace_kprobe(TK4, "x", addr=VFS_READ + 0x400, bucket=22)
mem.put(EDGE, b"kp_edge\0")
mem.put(TK4 + 0x1000 + 80 + 24, q(EDGE))  # call.name -> the name at the page's end
mem = saved
assert k.read_string(emem, EDGE) == "kp_edge" and k.read_string(emem, EDGE + 8) is None
assert [r["event"] for r in k.kprobe_list(emem, layout) if r["kprobe"] == TK4 + 24] == ["kp_edge"]
# No kprobe_table or struct kprobe (CONFIG_KPROBES off): no list at all.
assert k.kprobe_layout(Kernel(T, {})) is None
assert k.kprobe_layout(Kernel({name: t for name, t in T.items() if name != "kprobe"}, SYMBOLS)) is None
assert k.kprobe_layout(Kernel(dict(T, kprobe=Type(128, {"hlist": 0})), SYMBOLS)) is None  # a member missing

# A torn capture: a bucket points at unmapped memory, a cycle, an unreadable name. The walk stops, and the export goes on.
torn = Memory()
torn.pages = {page: bytearray(data) for page, data in mem.pages.items()}
mem, saved = torn, mem
kprobe(HEAP + 0x40000, VFS_READ + 0x100, PRE, bucket=10)
mem.put(HEAP + 0x40000, q(HEAP + 0x40000))                # its hlist.next points at itself
mem.put(TABLE + SHIFT + 8 * 11, q(0xffff888100000000))     # bucket 11 -> unmapped
kprobe(HEAP + 0x50000, VFS_READ + 0x200, PRE, symbol=0xffff888100000000, bucket=12)  # symbol_name unreadable
mem.put(HEAP + 0x60000, b"bad\x01name\0")
kprobe(HEAP + 0x50400, VFS_READ + 0x300, PRE, symbol=HEAP + 0x60000, bucket=13)     # not printable
# The aggregate's ring is torn too: P2's list.next points back at P1, not at the aggregate's head, so the ring never
# returns to head (review s179 MINOR 4). The walk must end and list P1 and P2 once; an alarm turns a hang into a failure.
mem.put(P2 + 16, q(P1 + 16))


def hung(signum, frame):
    raise AssertionError("kprobe_list did not end on a torn aggregate ring")


signal.signal(signal.SIGALRM, hung)
signal.alarm(20)
trecords = k.kprobe_list(torn, layout)
signal.alarm(0)
assert [r["kprobe"] for r in trecords].count(P1) == 1 and [r["kprobe"] for r in trecords].count(P2) == 1, trecords
assert len(trecords) == 8 and [r["symbol"] for r in trecords if r["addr"] in (VFS_READ + 0x100, VFS_READ + 0x200, VFS_READ + 0x300)] == [
    None, None, None], trecords
mem = saved

# The section: written as non-alloc JSON after the ELF's other section headers; patchscan reads it back.
plugin = k.Kernel2Elf.__new__(k.Kernel2Elf)
elf = k.Elf()
elf.add_section(".text", 0xffffffff81000000, k.SHF_ALLOC | k.SHF_EXEC, b"\xcc" * 0x1000)
elf.add_symbol("_text", 0xffffffff81000000, 0x10, k.STT_FUNC)
rows = list(plugin._kprobes(kernel, mem, elf))
assert rows == [(0, ("kprobes", ps.KPROBES_SECTION, TABLE + SHIFT, 5))], rows
out = io.BytesIO()
elf.write(out)
blob = out.getvalue()
data = ps.section_data(blob, ps.KPROBES_SECTION)
assert json.loads(data) == {"version": 1, "kprobes": records}, data
assert data == json.dumps({"version": 1, "kprobes": records}, sort_keys=True, separators=(",", ":")).encode()
image = ps.Image(blob)
assert image.kprobes[OPENAT2][0]["event"] == "memlens_kp" and len(image.kprobes[0xffffffff8e700004]) == 2, image.kprobes
assert image.kprobes[VFS_READ][0]["flags"] == 2 | 8 and image.kprobes[KILL][0]["flags"] == 8, image.kprobes  # read back
assert image.segment(0xffffffff81000000) and len(image.segments) == 1 and image.by_name["_text"][0] == 0xffffffff81000000
assert ".memlens.kprobes" in ps.section_names(blob) and ".symtab" in ps.section_names(blob)
# Not loaded: no program header for it, and its section header has no SHF_ALLOC and address 0.
shoff, = struct.unpack_from("<Q", blob, 40)
phnum, shnum, shstrndx = struct.unpack_from("<H", blob, 56)[0], *struct.unpack_from("<HH", blob, 60)
assert (phnum, shnum, shstrndx) == (1, 6, 4), (phnum, shnum, shstrndx)
name, kind, flags, addr = struct.unpack_from("<IIQQ", blob, shoff + 64 * 5)
assert (kind, flags, addr) == (1, 0, 0), (kind, flags, addr)
# No kprobe types: no row and no section; and an ELF with no such section is byte for byte what the writer wrote before
# (this SHA-256 is the v0.3.28 writer's output for the same sections and symbols).
elf2 = k.Elf()
elf2.add_section(".text", 0xffffffff81000000, k.SHF_ALLOC | k.SHF_EXEC, b"\xcc" * 0x1000)
elf2.add_symbol("_text", 0xffffffff81000000, 0x10, k.STT_FUNC)
assert list(plugin._kprobes(Kernel(T, {}), mem, elf2)) == []
plain = io.BytesIO()
elf2.write(plain)
assert ps.section_data(plain.getvalue(), ps.KPROBES_SECTION) is None and ps.Image(plain.getvalue()).kprobes == {}
assert hashlib.sha256(plain.getvalue()).hexdigest() == "c772cd39866b9bd0e960b77547856be71b6df76ae6cbb39fedec0a0f7a116ac5", hashlib.sha256(plain.getvalue()).hexdigest()
# An empty kprobe_table still gets its (empty) list: the export says it looked.
empty = Memory(); empty.put(TABLE + SHIFT, b"\0" * 64 * 8)
elf3 = k.Elf()
elf3.add_section(".text", 0xffffffff81000000, k.SHF_ALLOC | k.SHF_EXEC, b"\xcc" * 0x1000)
assert list(plugin._kprobes(kernel, empty, elf3)) == [(0, ("kprobes", ps.KPROBES_SECTION, TABLE + SHIFT, 0))]
# review s180 NIT 1: a probe whose 4 flags bytes cannot be read is still listed (without flags), and its bucket's walk
# goes on to the next probe
torn = Memory(); torn.put(TABLE + SHIFT, b"\0" * 64 * 8)
EDGE, NEXT = HEAP + 0x40000 - 120, HEAP + 0x50000  # EDGE's flags (+120) fall on a page that is not mapped
for at, nxt in ((EDGE, NEXT), (NEXT, 0)):
    torn.put(at, q(nxt) + b"\0" * 112)  # hlist.next, then the rest up to flags
    torn.put(at + 40, q(OPENAT2) + q(0) + struct.pack("<I", 0) + b"\0" * 4 + q(PRE) + q(0))
torn.put(NEXT + 120, struct.pack("<I", 8) + b"\0" * 4)
torn.put(TABLE + SHIFT + 8 * 5, q(EDGE))
got = k.kprobe_list(torn, layout)
assert [r["kprobe"] for r in got] == [EDGE, NEXT] and "flags" not in got[0] and got[1]["flags"] == 8, got
print("kernel2elf kprobe test OK (fake volatility3 modules and memory layer: %d probes, the 6.12 and pre-5.4 layouts)" % len(records))
