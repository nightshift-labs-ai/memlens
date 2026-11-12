#!/usr/bin/env python3
"""Who owns a copied hook page (patchscan.page_owner), with no IDA: hand-made ELFs laid out like real x86 ftrace
trampolines, then real kernel.elf exports when given.

usage: python3 tests/test_owner.py [kernel.elf ...]
Pass the demo kernel.elf (memlens-demo-debian13.zip, demo-data release); an export of the Ubuntu 24.04 capture is known
too. Exports with other hooks or none are skipped with a note. Without files only the hand-made cases run.

An ftrace trampoline (arch/x86/kernel/ftrace.c, create_trampoline) is a copy of ftrace_caller or ftrace_regs_caller,
then its ret, then a pointer to the ftrace_ops it serves; its mov rdx, [rip+disp32] loads that pointer. ops->func is
the callback the ops registered, also when the trampoline calls ftrace_ops_assist_func instead of it.
"""
import os, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan as ps

FUNC, OBJECT = 0x12, 0x11  # st_info: global function, global object


def build(segments, symbols):
    """segments [(address, bytes, p_flags)], symbols [(name, address, size, st_info)] -> ELF bytes."""
    strtab, symtab = bytearray(b"\0"), bytearray(b"\0" * 24)
    for name, address, size, info in symbols:
        symtab += struct.pack("<IBBHQQ", len(strtab), info, 0, 1, address, size)
        strtab += name.encode() + b"\0"
    offset = 64 + 56 * len(segments)
    placed = []
    for address, data, flags in segments:
        placed.append((address, data, flags, offset))
        offset += len(data)
    sy = offset; st = sy + len(symtab); sh = st + len(strtab)
    out = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
    out += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, segments[0][0], 64, sh, 0, 64, 56, len(segments), 64, 3, 2)
    for address, data, flags, where in placed:
        out += struct.pack("<IIQQQQQQ", 1, flags, where, address, address, len(data), len(data), 4096)
    for _, data, _, _ in placed:
        out += data
    out += symtab + strtab
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    out += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sy, len(symtab), 2, 1, 8, 24)
    out += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, st, len(strtab), 0, 0, 1, 0)
    return bytes(out)


def rel32(site, target, op=0xE8):
    return bytes([op]) + struct.pack("<i", target - (site + 5))


KTEXT, KDATA = 0xffffffff81000000, 0xffffffff82000000          # kernel text and data
MTEXT, MDATA = 0xffffffffc0100000, 0xffffffffc0102000          # evilmod's text and data (.mod.evilmod.*)
HOOKS = 0xffffffffc0b00000                                     # copied hook pages, 0x400 apart
HEAP_OPS, HIDDEN_OPS = 0xffff888003c41a00, 0xffffffffc0400000  # not in the ELF: kmalloc'd, and module memory not exported
ktext, kdata = bytearray(b"\xcc" * 0x2000), bytearray(0x1000)
mtext, mdata = bytearray(b"\xcc" * 0x1000), bytearray(0x1000)
hooks = bytearray(b"\x90" * 0x4000)
FTRACE, ASSIST, KPROBE = KTEXT + 0x1000, KTEXT + 0x1100, KTEXT + 0x1200
GLOBAL_OPS, OTHER_OPS = KDATA + 0x100, KDATA + 0x200
THUNK, KILL = MTEXT + 0x100, MTEXT + 0x200
HOOK_ARRAY = MDATA + 0x40   # evilmod.hooks: struct ftrace_hook[], its ftrace_ops 0x20 into the first element


def put(buffer, base, address, data):
    buffer[address - base:address - base + len(data)] = data


def trampoline(page, handler, ops, ret=b"\xc3\xcc\x00\x00\x00", load=0x74, call=0x94, end=0xd8):
    """A copied ftrace trampoline: mov rdx, [rip+X] at +load, call handler at +call, ret at +end, ops pointer after it."""
    slot = page + end + len(ret)
    put(hooks, HOOKS, page + load, b"\x48\x8b\x15" + struct.pack("<i", slot - (page + load + 7)))
    put(hooks, HOOKS, page + call, rel32(page + call, handler))
    put(hooks, HOOKS, page + end, ret)
    put(hooks, HOOKS, slot, struct.pack("<Q", ops))
    return slot


PAGES = {name: HOOKS + 0x400 * index for index, name in enumerate(
    ("vfs_getattr", "__x64_sys_getdents64", "__x64_sys_kill", "__x64_sys_read", "__x64_sys_write", "far_load", "thunked",
     "direct_cb", "plumbing_only", "retthunk", "sls", "offset8", "noret"))}
SLOTS = {}
SLOTS["vfs_getattr"] = trampoline(PAGES["vfs_getattr"], FTRACE, GLOBAL_OPS)                        # tracefs function tracer
SLOTS["__x64_sys_getdents64"] = trampoline(PAGES["__x64_sys_getdents64"], ASSIST, HOOK_ARRAY + 0x20)  # ftrace-hook rootkit
SLOTS["__x64_sys_kill"] = trampoline(PAGES["__x64_sys_kill"], ASSIST, HEAP_OPS)                    # ops kmalloc'd
SLOTS["__x64_sys_read"] = trampoline(PAGES["__x64_sys_read"], ASSIST, HIDDEN_OPS)                  # ops in a hidden module
SLOTS["__x64_sys_write"] = trampoline(PAGES["__x64_sys_write"], ASSIST, HOOK_ARRAY + 0x20 + 0x60)  # second ftrace_hook
# far_load: a page whose mov rdx, [rip+X] reads a kernel global (no ret before it): not an ftrace_ops slot.
page = PAGES["far_load"]
put(hooks, HOOKS, page + 0x10, b"\x48\x8b\x15" + struct.pack("<i", OTHER_OPS - (page + 0x17)))
put(hooks, HOOKS, page + 0x40, rel32(page + 0x40, KILL))
SLOTS["thunked"] = trampoline(PAGES["thunked"], THUNK, HOOK_ARRAY + 0x20)                        # no RECURSION flag: direct call
page = PAGES["direct_cb"]
put(hooks, HOOKS, page + 0x40, rel32(page + 0x40, KILL))                                          # calls a module function, no ops
page = PAGES["plumbing_only"]
put(hooks, HOOKS, page + 0x40, rel32(page + 0x40, FTRACE))                                        # ftrace plumbing, no ops load
SLOTS["retthunk"] = trampoline(PAGES["retthunk"], FTRACE, GLOBAL_OPS, ret=rel32(PAGES["retthunk"] + 0xd8, KTEXT + 0x1300, 0xE9))
SLOTS["sls"] = trampoline(PAGES["sls"], FTRACE, GLOBAL_OPS, ret=b"\xc3\xcc")
SLOTS["offset8"] = trampoline(PAGES["offset8"], FTRACE, OTHER_OPS)
SLOTS["noret"] = trampoline(PAGES["noret"], FTRACE, GLOBAL_OPS, ret=b"\x90" * 5)  # slot in the page, no ret before it
put(kdata, KDATA, GLOBAL_OPS, struct.pack("<Q", FTRACE))
put(kdata, KDATA, OTHER_OPS, struct.pack("<QQ", 0xdead, KPROBE))  # read at offset 0: 0xdead; at offset 8: kprobe_ftrace_handler
put(mdata, MDATA, HOOK_ARRAY + 0x20, struct.pack("<Q", THUNK))
put(mdata, MDATA, HOOK_ARRAY + 0x80, struct.pack("<Q", KILL))
ENTRIES = {name: KTEXT + 0x40 * index for index, name in enumerate(PAGES)}
for name, entry in ENTRIES.items():
    put(ktext, KTEXT, entry, b"\xf3\x0f\x1e\xfa" + rel32(entry + 4, PAGES[name]))
symbols = [(name, entry, 0x40, FUNC) for name, entry in ENTRIES.items()]
symbols += [("function_trace_call", FTRACE, 0x100, FUNC), ("ftrace_ops_assist_func", ASSIST, 0x100, FUNC),
            ("kprobe_ftrace_handler", KPROBE, 0x100, FUNC), ("__x86_return_thunk", KTEXT + 0x1300, 0x10, FUNC),
            ("global_ops", GLOBAL_OPS, 0xd8, OBJECT), ("other_ops", OTHER_OPS, 0xd8, OBJECT), ("linux_banner", KDATA, 0x20, OBJECT),
            ("evilmod.fh_ftrace_thunk", THUNK, 0x80, FUNC), ("evilmod.fh_sys_kill", KILL, 0x80, FUNC),
            ("evilmod.hooks", HOOK_ARRAY, 0xc0, OBJECT)]
symbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0, FUNC) for page in PAGES.values()]
blob = build([(KTEXT, ktext, 5), (KDATA, kdata, 6), (MTEXT, mtext, 5), (MDATA, mdata, 6), (HOOKS, hooks, 5)], symbols)
image = ps.Image(blob)
findings = ps.scan(blob, image)
assert {row[1] for row in findings} == set(PAGES), findings
links = {link.function: link for link in ps.hook_links(image, findings)}
assert set(links) == set(PAGES) and all(link.page for link in links.values()), links
owners = {name: link.owner for name, link in links.items()}
D = "data"
# The function tracer: ops is a kernel global, its func the tracer callback (what CheckFtrace lists too).
assert owners["vfs_getattr"] == ps.Owner("function_trace_call (ftrace_ops global_ops)", FTRACE, "ftrace_ops",
                                         [(SLOTS["vfs_getattr"], GLOBAL_OPS, D), (GLOBAL_OPS, FTRACE, D)]), owners["vfs_getattr"]
# The rootkit pattern: the trampoline calls ftrace_ops_assist_func (Handler column), the ops sits in the module's data
# inside its ftrace_hook array, and ops->func is the module's callback.
assert links["__x64_sys_getdents64"].handler_name == "ftrace_ops_assist_func"
assert owners["__x64_sys_getdents64"] == ps.Owner("evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)", THUNK, "ftrace_ops",
                                                  [(SLOTS["__x64_sys_getdents64"], HOOK_ARRAY + 0x20, D), (HOOK_ARRAY + 0x20, THUNK, D)])
assert owners["__x64_sys_write"].text == "evilmod.fh_sys_kill (ftrace_ops evilmod.hooks+0x80)", owners["__x64_sys_write"]
# ops not in the ELF: said so, no address to jump to, no xref.
assert owners["__x64_sys_kill"] == ps.Owner("ftrace_ops at 0xffff888003c41a00 (no symbol: heap)", None, "ftrace_ops", []), owners
assert owners["__x64_sys_read"] == ps.Owner("ftrace_ops at 0xffffffffc0400000 (no symbol: module memory MemLens did not export)",
                                            None, "ftrace_ops", []), owners["__x64_sys_read"]
# A rip-relative load that is not the trampoline's slot (no ret right before it) is not an ftrace_ops; the page calls a
# module function, so that first named call is the owner, marked as such.
assert owners["far_load"] == ps.Owner("evilmod.fh_sys_kill (first named call)", KILL, "first named call", []), owners["far_load"]
assert owners["direct_cb"] == ps.Owner("evilmod.fh_sys_kill (first named call)", KILL, "first named call", []), owners["direct_cb"]
# An ops without the RECURSION flag: the trampoline calls the callback itself; the ops still names it.
assert owners["thunked"].text == "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)" and owners["thunked"].how == "ftrace_ops"
# Known plumbing and no ops: no owner (the Handler column already shows the plumbing).
assert owners["plumbing_only"] is None, owners["plumbing_only"]
assert owners["noret"] is None, owners["noret"]  # a pointer in the page but no ret before it: not the ops slot
# The ret before the slot may be a jmp to the return thunk (RET_SIZE 5) or ret; int3 (SLS).
assert owners["retthunk"].text == owners["sls"].text == "function_trace_call (ftrace_ops global_ops)", (owners["retthunk"], owners["sls"])
# The offset of func in struct ftrace_ops: 0 unless told otherwise (an ISF says so); here a layout with func at 8.
assert owners["offset8"].text == "0xdead (ftrace_ops other_ops)" and owners["offset8"].address is None, owners["offset8"]
assert ps.ftrace_ops_func_offset({"user_types": {"ftrace_ops": {"fields": {"func": {"offset": 8}}}}}) == 8
assert ps.ftrace_ops_func_offset({"user_types": {}}) is None and ps.ftrace_ops_func_offset({}) is None
image8 = ps.Image(blob)
image8.ftrace_ops_func = 8
owner8 = {link.function: link.owner for link in ps.hook_links(image8, findings)}["offset8"]
assert owner8 == ps.Owner("kprobe_ftrace_handler (ftrace_ops other_ops)", KPROBE, "ftrace_ops",
                          [(SLOTS["offset8"], OTHER_OPS, D), (OTHER_OPS + 8, KPROBE, D)]), owner8
assert ps.Image(blob).ftrace_ops_func == ps.FTRACE_OPS_FUNC == 0
print("owner tests OK (hand-made ELF: %d hooked entries, %d with an ftrace_ops owner)" % (
    len(links), sum(1 for owner in owners.values() if owner and owner.how == "ftrace_ops")))

# Real exports: the ftrace_ops each trampoline loads (CheckFtrace lists the same ops and callbacks on the demo image).
EXPECTED = {
    "vfs_getattr": ("function_trace_call (ftrace_ops global_ops)", "function_trace_call", 0xdd, "global_ops"),
    "do_sys_openat2": ("kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)", "kprobe_ftrace_handler", 0x162, "kprobe_ftrace_ops"),
}
for path in sys.argv[1:]:
    image = ps.Image(open(path, "rb").read())
    findings = ps.scan(None, image)
    links = ps.hook_links(image, findings)
    known = [link for link in links if link.function in EXPECTED]
    if not known:
        print("%s: SKIPPED, no ftrace hook with expected values (EXPECTED knows the demo's)" % path)
        continue
    for link in known:
        text, func, slot, ops = EXPECTED[link.function]
        owner = link.owner
        assert owner.text == text and owner.how == "ftrace_ops" and owner.address == image.by_name[func][0], (link, owner)
        assert owner.refs == [(link.target + slot, image.by_name[ops][0], "data"), (image.by_name[ops][0], owner.address, "data")], owner
        print("%s: %s -> %s" % (path, link.function, owner.text))
