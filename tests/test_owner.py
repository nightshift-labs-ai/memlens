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
import json, os, struct, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan as ps

FUNC, OBJECT = 0x12, 0x11  # st_info: global function, global object


def build(segments, symbols, sections=()):
    """segments [(address, bytes, p_flags)], symbols [(name, address, size, st_info)], sections [(name, bytes)] (non-alloc,
    as the exporter's .memlens.kprobes) -> ELF bytes."""
    strtab, symtab = bytearray(b"\0"), bytearray(b"\0" * 24)
    for name, address, size, info in symbols:
        symtab += struct.pack("<IBBHQQ", len(strtab), info, 0, 1, address, size)
        strtab += name.encode() + b"\0"
    named = []
    for name, data in sections:  # their names go into strtab, which is also the section name table here
        named.append((len(strtab), data))
        strtab += name.encode() + b"\0"
    offset = 64 + 56 * len(segments)
    placed = []
    for address, data, flags in segments:
        placed.append((address, data, flags, offset))
        offset += len(data)
    sy = offset; st = sy + len(symtab); extra = st + len(strtab)
    sh = extra + sum(len(data) for _, data in named)
    out = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
    out += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, segments[0][0], 64, sh, 0, 64, 56, len(segments), 64, 3 + len(named), 2)
    for address, data, flags, where in placed:
        out += struct.pack("<IIQQQQQQ", 1, flags, where, address, address, len(data), len(data), 4096)
    for _, data, _, _ in placed:
        out += data
    out += symtab + strtab
    for _, data in named:
        out += data
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    out += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sy, len(symtab), 2, 1, 8, 24)
    out += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, st, len(strtab), 0, 0, 1, 0)
    for name_at, data in named:
        out += struct.pack("<IIQQQQIIQQ", name_at, 1, 0, 0, extra, len(data), 0, 0, 1, 0)
        extra += len(data)
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
FTRACE, ASSIST, KPROBE, PRINTK, KLP = KTEXT + 0x1000, KTEXT + 0x1100, KTEXT + 0x1200, KTEXT + 0x1400, KTEXT + 0x1500
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
     "direct_cb", "plumbing_only", "retthunk", "sls", "offset8", "noret", "bare_ret", "printk_first", "livepatched"))}
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
page = PAGES["printk_first"]  # a hidden module's hook code: _printk first, then the module's function (judge s160 finding 5)
put(hooks, HOOKS, page + 0x40, rel32(page + 0x40, PRINTK))
put(hooks, HOOKS, page + 0x60, rel32(page + 0x60, KILL))
SLOTS["retthunk"] = trampoline(PAGES["retthunk"], FTRACE, GLOBAL_OPS, ret=rel32(PAGES["retthunk"] + 0xd8, KTEXT + 0x1300, 0xE9))
SLOTS["sls"] = trampoline(PAGES["sls"], FTRACE, GLOBAL_OPS, ret=b"\xc3\xcc")
SLOTS["livepatched"] = trampoline(PAGES["livepatched"], KLP, GLOBAL_OPS)  # an ftrace callback MemLens does not list (livepatch): still ftrace (claims s170 F1)
SLOTS["bare_ret"] = trampoline(PAGES["bare_ret"], FTRACE, GLOBAL_OPS, ret=b"\xc3")  # no RETPOLINE/SLS: RET_SIZE 1 (claims s165 N5)
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
            ("kprobe_ftrace_handler", KPROBE, 0x100, FUNC), ("__x86_return_thunk", KTEXT + 0x1300, 0x10, FUNC), ("_printk", PRINTK, 0x80, FUNC), ("klp_ftrace_handler", KLP, 0x80, FUNC),
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
# A rip-relative load that is not the trampoline's slot (no ret right before it) is not an ftrace_ops; the page's first
# named call is a module function, a module callback (judge s160 finding 5): the handler, and the owner under the same label.
assert owners["far_load"] == ps.Owner("evilmod.fh_sys_kill (module callback)", KILL, "module callback", []), owners["far_load"]
assert owners["direct_cb"] == ps.Owner("evilmod.fh_sys_kill (module callback)", KILL, "module callback", []), owners["direct_cb"]
assert {name: links[name].kind for name in ("far_load", "direct_cb", "thunked")} == dict.fromkeys(
    ("far_load", "direct_cb", "thunked"), "module callback"), links
# An ops without the RECURSION flag: the trampoline calls the callback itself; the ops still names it.
# The page is then a module callback (its first named call), and its owner still comes from the ftrace_ops.
assert owners["thunked"].text == "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)" and owners["thunked"].how == "ftrace_ops"
# Known plumbing and no ops: no owner (the Handler column already shows the plumbing).
assert owners["plumbing_only"] is None, owners["plumbing_only"]
assert owners["noret"] is None, owners["noret"]  # a pointer in the page but no ret before it: not the ops slot
# A first named call into the core kernel (_printk) is a helper the hook code uses: no kind, no owner (review s166 M1).
assert (links["printk_first"].handler_name, links["printk_first"].kind, owners["printk_first"]) == ("_printk", None, None), links
# The ret before the slot may be a jmp to the return thunk (RET_SIZE 5) or ret; int3 (SLS).
assert owners["retthunk"].text == owners["sls"].text == owners["bare_ret"].text == "function_trace_call (ftrace_ops global_ops)", (
    owners["retthunk"], owners["sls"], owners["bare_ret"])
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
lp = links["livepatched"]
assert (lp.handler_name, lp.kind) == ("klp_ftrace_handler", "ftrace") and owners["livepatched"].how == "ftrace_ops", (lp, owners["livepatched"])
assert owners["livepatched"].text.endswith("(ftrace_ops global_ops)"), owners["livepatched"]  # the owner is the ops' func, read from the ops
assert ps.role_names(image, [lp]) == {PAGES["livepatched"]: "ftrace_tramp_livepatched"}, ps.role_names(image, [lp])
print("owner tests OK (hand-made ELF: %d hooked entries, %d with an ftrace_ops owner)" % (
    len(links), sum(1 for owner in owners.values() if owner and owner.how == "ftrace_ops")))

# Where users see it: the list rows (owner text and address after the handler), the page comment, the xrefs that lead
# to the owner (each once), and patchscan.py --links, one "owner" line per copied page that has one.
rows = {row[1]: row for row in ps.list_rows(image, findings, list(links.values()), {})}
assert rows["__x64_sys_getdents64"][4:] == ("ftrace_ops_assist_func (ftrace)", ASSIST,
                                            "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)", THUNK), rows["__x64_sys_getdents64"]
assert rows["__x64_sys_kill"][6:] == ("ftrace_ops at 0xffff888003c41a00 (no symbol: heap)", None), rows["__x64_sys_kill"]
assert rows["direct_cb"][4:] == ("evilmod.fh_sys_kill (module callback)", KILL, "evilmod.fh_sys_kill (module callback)", KILL), rows
assert rows["plumbing_only"][6:] == ("", None), rows
# No known role: the Handler column says it is hook code and names the first call, with no handler address to jump to.
assert rows["printk_first"][4:] == ("(hook code; first call: _printk)", None, "", None), rows["printk_first"]
assert rows["thunked"][4:] == ("evilmod.fh_ftrace_thunk (module callback)", THUNK,
                               "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)", THUNK), rows["thunked"]
# Role names: the ftrace trampolines by their entry, and the module callback pages as module_hook_<entry>.
names = ps.role_names(image, list(links.values()))
assert {name: names.get(page) for name, page in PAGES.items() if name.startswith(("d", "f", "t", "p"))} == {
    "direct_cb": "module_hook_direct_cb", "far_load": "module_hook_far_load", "thunked": "module_hook_thunked",
    "plumbing_only": "ftrace_tramp_plumbing_only", "printk_first": None}, names
assert names[PAGES["__x64_sys_getdents64"]] == "ftrace_tramp___x64_sys_getdents64", names
comments = ps.page_comments(list(links.values()))
assert comments[PAGES["__x64_sys_getdents64"]].endswith(
    "first named call: ftrace_ops_assist_func (ftrace); owner: evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)"), comments
assert comments[PAGES["direct_cb"]].endswith("first named call: evilmod.fh_sys_kill (module callback)"), comments[PAGES["direct_cb"]]
assert "owner" not in comments[PAGES["direct_cb"]] and "owner" not in comments[PAGES["plumbing_only"]], comments
xrefs = ps.hook_xrefs(list(links.values()))
assert len(xrefs) == len(set(xrefs)) and xrefs.count((HOOK_ARRAY + 0x20, THUNK, "data")) == 1, xrefs  # two pages share that ops
assert {(SLOTS["__x64_sys_getdents64"], HOOK_ARRAY + 0x20, "data"), (SLOTS["vfs_getattr"], GLOBAL_OPS, "data"),
        (GLOBAL_OPS, FTRACE, "data")} <= set(xrefs), xrefs
assert not [x for x in xrefs if x[1] in (HEAP_OPS, HIDDEN_OPS)], xrefs  # nothing to point at outside the ELF
cli = [sys.executable, "-I", os.path.join(HERE, "..", "patchscan.py")]


def owner_lines(path, *options):
    run = subprocess.run(cli + list(options) + ["--links", path], capture_output=True, text=True)
    assert run.returncode == 0, run.stderr
    return [line.split("\t")[1:] for line in run.stdout.splitlines() if line.startswith("owner")], run.stdout


with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(blob)
    lines, out = owner_lines(path)
    expected = [["%#x" % link.target, "%#x" % link.owner.address if link.owner.address is not None else "-", link.owner.text]
                for link in sorted(links.values(), key=lambda link: link.target) if link.owner]
    assert lines == expected and len(lines) == 13, (lines, expected)
    assert "owner\t%#x\t-\tftrace_ops at 0xffff888003c41a00 (no symbol: heap)" % PAGES["__x64_sys_kill"] in out, out
    assert "xref\t%#x\t%#x\tdata\tevilmod.hooks+0x20 -> evilmod.fh_ftrace_thunk" % (HOOK_ARRAY + 0x20, THUNK) in out, out
    # --isf: the offset of ftrace_ops.func from the ISF (here 8, for the offset8 page).
    isf = os.path.join(work, "k.json")
    with open(isf, "w") as handle:
        json.dump({"user_types": {"ftrace_ops": {"kind": "struct", "size": 16, "fields": {"func": {"offset": 8}}}}}, handle)
    lines8, _ = owner_lines(path, "--isf", isf)
    assert ["%#x" % PAGES["offset8"], "%#x" % KPROBE, "kprobe_ftrace_handler (ftrace_ops other_ops)"] in lines8, lines8
    plain = subprocess.run(cli + [path], capture_output=True, text=True)
    assert plain.returncode == 0 and "owner" not in plain.stdout and "xref" not in plain.stdout, plain.stdout
    bad = subprocess.run(cli + ["--isf", os.path.join(work, "missing.json"), path], capture_output=True, text=True)
    assert bad.returncode != 0 and "missing.json" in bad.stderr, bad.stderr
    noisf = subprocess.run(cli + [path, "--isf"], capture_output=True, text=True)
    assert noisf.returncode != 0 and "usage" in noisf.stderr, noisf.stderr

# BPF trampolines (arch/x86/net/bpf_jit_comp.c, invoke_bpf_prog): after the call to __bpf_prog_enter* come
# mov rbx, rax; test rax, rax; je (a 2-byte NOP until patched); lea rdi, [rbp-N]; movabs rsi, insnsi (interpreter only);
# then the call that runs the program. The program is the owner.
ktext = bytearray(b"\xcc" * 0x2000)
jit = bytearray(b"\xcc" * 0x4000)
JIT = 0xffffffffc0004000
TRAMP_ENTER, PROG_ENTER, PROG_ENTER_RECUR, PROG_EXIT, PROG_RUN, ENTER_LSM_CG, RUN_LSM_CUR = (KTEXT + 0x1000 + 0x100 * i
                                                                                          for i in range(7))
PROG, NAMED_PROG, PROG2 = JIT + 0x664, JIT + 0x800, JIT + 0x900
UNEXPORTED_PROG = 0xffffffffc0700000


def bpf_trampoline(page, programs, je=b"\x74\x0d", lea=b"\x48\x8d\x7d\xe8", extra=b"", decoy=False):
    """A BPF trampoline page: __bpf_tramp_enter, then per program __bpf_prog_enter* and the program call. decoy: right
    after __bpf_tramp_enter, a lea rdi and a call that look like a program call but follow no __bpf_prog_enter*."""
    at = page + 0x23
    put(jit, JIT, at, rel32(at, TRAMP_ENTER))
    if decoy:
        put(jit, JIT, at + 5, b"\x48\x8d\x7d\xf0" + rel32(at + 9, PROG2))
    at += 0x20
    sites = []
    for enter, program in programs:
        put(jit, JIT, at, rel32(at, enter)); at += 5
        body = b"\x48\x89\xc3" + b"\x48\x85\xc0" + je + lea + extra
        put(jit, JIT, at, body); at += len(body)
        put(jit, JIT, at, rel32(at, program)); sites.append(at); at += 5
        put(jit, JIT, at, b"\x48\x89\x45\xf8"); at += 4
        put(jit, JIT, at, rel32(at, PROG_EXIT)); at += 0x10
    put(jit, JIT, at, b"\xc3")
    return sites


BPAGES = {name: JIT + 0x1000 + 0x200 * index for index, name in enumerate(
    ("bpf_lsm_file_open", "named", "interp", "two", "unpatched", "odd", "unexported", "decoy", "lsm_cgroup"))}
BSITES = {
    "bpf_lsm_file_open": bpf_trampoline(BPAGES["bpf_lsm_file_open"], [(PROG_ENTER, PROG)]),  # lea rdi, [rbp-0x18]: an e8 byte
    "named": bpf_trampoline(BPAGES["named"], [(PROG_ENTER_RECUR, NAMED_PROG)]),
    "interp": bpf_trampoline(BPAGES["interp"], [(PROG_ENTER, PROG_RUN)], lea=b"\x48\x8d\xbd" + struct.pack("<i", -0x118),
                             extra=b"\x48\xbe" + struct.pack("<Q", 0xffff8880e8e8e8e8)),
    "two": bpf_trampoline(BPAGES["two"], [(PROG_ENTER, PROG), (PROG_ENTER_RECUR, PROG2)]),
    "unpatched": bpf_trampoline(BPAGES["unpatched"], [(PROG_ENTER, PROG)], je=b"\x66\x90"),
    "odd": bpf_trampoline(BPAGES["odd"], [(PROG_ENTER, PROG)], extra=b"\x90"),  # an instruction invoke_bpf_prog does not emit
    "unexported": bpf_trampoline(BPAGES["unexported"], [(PROG_ENTER, UNEXPORTED_PROG)]),
    "decoy": bpf_trampoline(BPAGES["decoy"], [(PROG_ENTER, PROG)], decoy=True),
    # BPF_LSM_CGROUP (kernel/bpf/trampoline.c cgroup_shim_alloc): the trampoline runs a shim prog whose bpf_func is a kernel
    # function; the real programs hang off the cgroup's effective array. The shim is BPF_LSM_MAC and not JIT-compiled, so it
    # is entered through plain __bpf_prog_enter, with movabs rsi, insnsi (review s166 m1; claims s170 F1).
    "lsm_cgroup": bpf_trampoline(BPAGES["lsm_cgroup"], [(PROG_ENTER, RUN_LSM_CUR)],
                                 extra=b"\x48\xbe" + struct.pack("<Q", 0xffff8880e8e8e8e8)),
}
BENTRIES = {name: KTEXT + 0x40 * index for index, name in enumerate(BPAGES)}
for name, entry in BENTRIES.items():
    put(ktext, KTEXT, entry, b"\xf3\x0f\x1e\xfa" + rel32(entry + 4, BPAGES[name]))
bsymbols = [(name, entry, 0x40, FUNC) for name, entry in BENTRIES.items()]
bsymbols += [("__bpf_tramp_enter", TRAMP_ENTER, 0x80, FUNC), ("__bpf_prog_enter", PROG_ENTER, 0x80, FUNC),
             ("__bpf_prog_enter_recur", PROG_ENTER_RECUR, 0x80, FUNC), ("__bpf_prog_exit", PROG_EXIT, 0x80, FUNC),
             ("__bpf_prog_run32", PROG_RUN, 0x80, FUNC), ("linux_banner", KDATA, 0x20, OBJECT),
             ("__bpf_prog_enter_lsm_cgroup", ENTER_LSM_CG, 0x80, FUNC), ("__cgroup_bpf_run_lsm_current", RUN_LSM_CUR, 0x80, FUNC),
             ("bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems", NAMED_PROG, 0x100, FUNC)]
bsymbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0, FUNC) for page in BPAGES.values()]
bblob = build([(KTEXT, ktext, 5), (KDATA, bytearray(0x100), 6), (JIT, jit, 5)], bsymbols)
bimage = ps.Image(bblob)
blinks = {link.function: link for link in ps.hook_links(bimage, ps.scan(bblob, bimage))}
assert set(blinks) == set(BPAGES) and all(link.kind == "BPF trampoline" for link in blinks.values()), blinks
bowners = {name: link.owner for name, link in blinks.items()}
C, B = "call", "BPF program"
assert bowners["bpf_lsm_file_open"] == ps.Owner("BPF program at %#x" % PROG, PROG, B, [(BSITES["bpf_lsm_file_open"][0], PROG, C)]), bowners
assert bowners["named"] == ps.Owner("bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)", NAMED_PROG, B,
                                    [(BSITES["named"][0], NAMED_PROG, C)]), bowners["named"]
# A kernel function in the program's place is not a BPF program (review s166 m1): the interpreter runs a program that is
# not JIT-compiled, and a cgroup LSM trampoline runs the kernel's shim, whose programs are per cgroup.
assert bowners["interp"] == ps.Owner("__bpf_prog_run32 (BPF interpreter: the program is not JIT-compiled)", PROG_RUN, B,
                                     [(BSITES["interp"][0], PROG_RUN, C)]), bowners["interp"]
assert bowners["lsm_cgroup"] == ps.Owner("__cgroup_bpf_run_lsm_current (cgroup LSM shim: runs each cgroup's programs, not named here)",
                                         RUN_LSM_CUR, B, [(BSITES["lsm_cgroup"][0], RUN_LSM_CUR, C)]), bowners["lsm_cgroup"]
assert ps.bpf_program_label("bpf_prog_e8932b6bae2b9745_restrict_filesystems", NAMED_PROG, "__bpf_prog_enter") == (
    "bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)")  # a kernel BPF name without the export's "bpf."
assert ps.bpf_program_label("evilmod.cb", PROG, "__bpf_prog_enter") == "evilmod.cb (called by the BPF trampoline)"
assert ps.bpf_program_label("bpf.bpf_prog_0123456789abcdef", PROG, "__bpf_prog_enter").endswith("(BPF program)")  # no name
assert ps.bpf_program_label("bpf.restrict_filesy", PROG, "__bpf_prog_enter").endswith("(BPF program)")  # 5.5-5.7 export name
assert bowners["two"] == ps.Owner("BPF program at %#x, BPF program at %#x" % (PROG, PROG2), PROG, B,
                                  [(BSITES["two"][0], PROG, C), (BSITES["two"][1], PROG2, C)]), bowners["two"]
assert bowners["unpatched"] == bowners["bpf_lsm_file_open"]._replace(refs=[(BSITES["unpatched"][0], PROG, C)]), bowners
assert bowners["odd"] is None, bowners["odd"]  # not the sequence invoke_bpf_prog emits: no guess
assert bowners["decoy"] == ps.Owner("BPF program at %#x" % PROG, PROG, B, [(BSITES["decoy"][0], PROG, C)]), bowners["decoy"]
assert bowners["unexported"] == ps.Owner("BPF program at %#x" % UNEXPORTED_PROG, None, B, []), bowners["unexported"]
print("BPF owner tests OK (hand-made ELF: %d BPF trampolines, %d with a program)" % (
    len(blinks), sum(1 for owner in bowners.values() if owner)))

# kprobes (judge s178 item 5): an ftrace-based kprobe's trampoline calls kprobe_ftrace_handler through kprobe_ftrace_ops,
# the same for every probe, so the ftrace_ops owner cannot say whose probe it is. An export made with this version holds
# the kernel's kprobe list (kprobe_table) as JSON in the non-alloc section .memlens.kprobes; a probe registered at the
# patched instruction (kprobe.addr is the ftrace site) is then the owner: a tracefs event by its name (pre_handler
# kprobe_dispatcher: the exporter read the trace_kprobe), else the module function its pre_handler is. Hand-made ELFs:
# none of our captures has a module's kprobe.
ktext, kdata, mtext = bytearray(b"\xcc" * 0x2000), bytearray(0x1000), bytearray(b"\xcc" * 0x1000)
hooks = bytearray(b"\x90" * 0x2000)
KHANDLER, DISPATCH = KTEXT + 0x1200, KTEXT + 0x1600
KOPS = KDATA + 0x300
PRE, POST = MTEXT + 0x100, MTEXT + 0x200
KPAGES = {name: HOOKS + 0x400 * index for index, name in enumerate(("traced", "modprobe", "perfprobe", "unlisted", "hidden", "postonly"))}
KPAGES["shared_a"] = KPAGES["shared_b"] = HOOKS + 0x1800  # shared_a first: its entry comes first
KSLOTS = {name: trampoline(page, KHANDLER, KOPS) for name, page in KPAGES.items()}
KENTRIES = {name: KTEXT + 0x40 * index for index, name in enumerate(KPAGES)}
KSITES = {}
for name, entry in KENTRIES.items():
    endbr = b"" if name == "traced" else b"\xf3\x0f\x1e\xfa"  # do_sys_openat2 on the demo has no endbr64: call at the entry
    put(ktext, KTEXT, entry, endbr + rel32(entry + len(endbr), KPAGES[name]))
    KSITES[name] = entry + len(endbr)  # the ftrace site: kprobe.addr of a probe on that function
put(kdata, KDATA, KOPS, struct.pack("<Q", KHANDLER))
ksymbols = [(name, entry, 0x40, FUNC) for name, entry in KENTRIES.items()]
ksymbols += [("kprobe_ftrace_handler", KHANDLER, 0x100, FUNC), ("kprobe_dispatcher", DISPATCH, 0x100, FUNC),
             ("kprobe_ftrace_ops", KOPS, 0xd8, OBJECT), ("linux_banner", KDATA, 0x20, OBJECT),
             ("evilmod.kp_pre", PRE, 0x80, FUNC), ("evilmod.kp_post", POST, 0x80, FUNC)]
ksymbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0, FUNC) for page in sorted(set(KPAGES.values()))]


def probe(name, pre, post=0, **extra):
    record = {"kprobe": 0xffff888004a1c000 + 0x100 * len(name), "addr": KSITES[name], "symbol": name, "offset": 0,
              "pre_handler": pre, "post_handler": post}
    record.update(extra)
    return record


probes = [probe("traced", DISPATCH, event="memlens_kp", tracefs=True), probe("modprobe", PRE, POST),
          probe("perfprobe", DISPATCH, event="perfprobe", tracefs=False), probe("hidden", 0xffffffffc0400000),
          probe("postonly", 0, POST), probe("shared_a", DISPATCH, event="kp_a", tracefs=True),
          probe("shared_b", DISPATCH, event="kp_b", tracefs=True)]
probes.append(dict(probe("traced", PRE), kprobe=0xffff888004a1d000))  # a second probe on the same address (aggregated)
segments = [(KTEXT, ktext, 5), (KDATA, kdata, 6), (MTEXT, mtext, 5), (HOOKS, hooks, 5)]
section = json.dumps({"version": 1, "kprobes": probes}, sort_keys=True, separators=(",", ":")).encode()
kblob = build(segments, ksymbols, [(ps.KPROBES_SECTION, section)])
kimage = ps.Image(kblob)
klinks = {link.function: link for link in ps.hook_links(kimage, ps.scan(kblob, kimage))}
assert set(klinks) == set(KPAGES) and all(link.kind == "kprobe via ftrace" for link in klinks.values()), klinks
kowners = {name: link.owner for name, link in klinks.items()}
KREFS = lambda name: [(KSLOTS[name], KOPS, D), (KOPS, KHANDLER, D)]  # the trampoline's ftrace_ops path stays
assert kowners["traced"] == ps.Owner("kprobe memlens_kp on traced (tracefs kprobe event; pre_handler kprobe_dispatcher), "
                                     "evilmod.kp_pre (kprobe pre_handler)", DISPATCH, "kprobe", KREFS("traced")), kowners["traced"]
assert kowners["modprobe"] == ps.Owner("evilmod.kp_pre (kprobe pre_handler)", PRE, "kprobe", KREFS("modprobe")), kowners["modprobe"]
assert kowners["perfprobe"] == ps.Owner("kprobe perfprobe on perfprobe (made by perf_event_open, not a tracefs event; "
                                        "pre_handler kprobe_dispatcher)", DISPATCH, "kprobe", KREFS("perfprobe")), kowners["perfprobe"]
assert kowners["hidden"] == ps.Owner("kprobe pre_handler at 0xffffffffc0400000 (no symbol)", None, "kprobe", KREFS("hidden")), kowners
assert kowners["postonly"] == ps.Owner("evilmod.kp_post (kprobe post_handler)", POST, "kprobe", KREFS("postonly")), kowners["postonly"]
# No probe recorded at that site (a probe registered after the capture's list was read, or a section without it): the
# ftrace_ops owner, as before.
assert kowners["unlisted"] == ps.Owner("kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)", KHANDLER, "ftrace_ops",
                                       KREFS("unlisted")), kowners["unlisted"]
# One trampoline serves every function only kprobe_ftrace_ops hooks: each entry gets its own probe; the page lists both.
assert kowners["shared_a"].text.startswith("kprobe kp_a on shared_a") and kowners["shared_b"].text.startswith("kprobe kp_b on shared_b")
shared = KPAGES["shared_a"]
assert ps.page_owners(list(klinks.values()))[shared].text == "%s; %s" % (kowners["shared_a"].text, kowners["shared_b"].text)
assert ps.page_comments(list(klinks.values()))[shared].endswith("; owner: %s; %s" % (kowners["shared_a"].text, kowners["shared_b"].text))
krows = {row[1]: row for row in ps.list_rows(kimage, ps.scan(kblob, kimage), list(klinks.values()), {})}
assert krows["traced"][4:] == ("kprobe_ftrace_handler (kprobe via ftrace)", KHANDLER, kowners["traced"].text, DISPATCH), krows["traced"]
assert krows["shared_b"][6:] == (kowners["shared_b"].text, DISPATCH), krows["shared_b"]
# Old exports (no section) and a section that cannot be read: exactly the owners from before.
for blob_without in (build(segments, ksymbols), build(segments, ksymbols, [(ps.KPROBES_SECTION, b"{not json")]),
                     build(segments, ksymbols, [(ps.KPROBES_SECTION, b'{"kprobes": [{"addr": "x"}, 7]}')])):
    oimage = ps.Image(blob_without)
    olinks = ps.hook_links(oimage, ps.scan(blob_without, oimage))
    assert len(olinks) == len(KPAGES) and all(link.owner == ps.Owner("kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)",
               KHANDLER, "ftrace_ops", KREFS(link.function)) for link in olinks), olinks
    assert oimage.kprobes == {}, oimage.kprobes
# A probe counts only at its own site and only on a kprobe page: on a page of another kind the page's owner stays.
assert ps.kprobe_owner(kimage, KSITES["traced"] + 1, None) is None
handler = ps.page_handler(kimage, KPAGES["traced"])[:3]
assert ps.entry_owner(kimage, KSITES["traced"], KPAGES["traced"], *handler, "ftrace") == ps.page_owner(
    kimage, KPAGES["traced"], *handler, "ftrace") == kowners["unlisted"]._replace(refs=KREFS("traced")), handler
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(kblob)
    lines, out = owner_lines(path)
    assert ["%#x" % KPAGES["traced"], "%#x" % DISPATCH, kowners["traced"].text] in lines, lines
    assert len([line for line in out.splitlines() if line.startswith("xref")]) == len(ps.hook_xrefs(list(klinks.values()))), out
print("kprobe owner tests OK (hand-made ELF: %d probes in .memlens.kprobes, %d kprobe pages)" % (len(probes), len(set(KPAGES.values()))))

# Real exports: the ftrace_ops each trampoline loads (CheckFtrace lists the same ops and callbacks on the demo image).
EXPECTED = {
    "vfs_getattr": ("function_trace_call (ftrace_ops global_ops)", "function_trace_call", 0xdd, "global_ops"),
    "do_sys_openat2": ("kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)", "kprobe_ftrace_handler", 0x162, "kprobe_ftrace_ops"),
}
# An export with the kernel's kprobe list (.memlens.kprobes, exports made with v0.3.29 or later) names the probe instead:
# tests/vm/scenario_ftrace_d13.sh made it with 'p:memlens_kp do_sys_openat2'. The ftrace_ops references stay.
EXPECTED_KPROBE = {"do_sys_openat2": ("kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)",
                                      "kprobe_dispatcher")}
# BPF trampolines: the program call's offset in the page, the kernel's name for the program (an export with BPF names
# has it as bpf.<name>), and the program's address in the exports without BPF names that we know (page -> program):
# the demo kernel.elf and the Ubuntu 24.04 export.
EXPECTED_BPF = {"bpf_lsm_file_open": (0x53, "bpf_prog_e8932b6bae2b9745_restrict_filesystems", {0xffffffffc0004940: 0xffffffffc0004664}),
                "__hid_bpf_tail_call": (0x53, "bpf_prog_7cc47bbf07148bfe_hid_tail_call", {0xffffffffc0043a00: 0xffffffffc0043958})}
for path in sys.argv[1:]:
    image = ps.Image(open(path, "rb").read())
    findings = ps.scan(None, image)
    links = ps.hook_links(image, findings)
    known = [link for link in links if link.function in EXPECTED]
    for link in links:
        if link.function in EXPECTED_BPF:
            site, kernel_name, programs = EXPECTED_BPF[link.function]
            assert link.owner and len(link.owner.refs) == 1 and link.owner.refs[0][0] == link.target + site, link
            program = link.owner.refs[0][1]
            name = ps.symbol_start(image, program)
            if name:
                assert name == "bpf." + kernel_name, (name, link)
            elif link.target in programs:
                assert program == programs[link.target], link
            else:
                print("%s: %s: program address not checked (no BPF names, unknown capture)" % (path, link.function))
            text = "%s (BPF program)" % name if name else "BPF program at %#x" % program
            assert link.owner == ps.Owner(text, program, "BPF program", [(link.target + site, program, "call")]), link
            print("%s: %s -> %s" % (path, link.function, link.owner.text))
    if not known and not any(link.function in EXPECTED_BPF for link in links):
        print("%s: SKIPPED, no hook with expected values (EXPECTED knows the demo's and Ubuntu 24.04's)" % path)
        continue
    lines, _ = owner_lines(path)
    assert lines == [["%#x" % link.target, "%#x" % link.owner.address if link.owner.address is not None else "-", link.owner.text]
                     for link in sorted(links, key=lambda link: link.target) if link.owner], lines
    for link in known:
        text, func, slot, ops = EXPECTED[link.function]
        owner, how = link.owner, "ftrace_ops"
        if link.site in image.kprobes and link.function in EXPECTED_KPROBE:
            (text, func), how = EXPECTED_KPROBE[link.function], "kprobe"
        assert owner.text == text and owner.how == how and owner.address == image.by_name[func][0], (link, owner)
        assert owner.refs == [(link.target + slot, image.by_name[ops][0], "data"), (image.by_name[ops][0], owner.address, "data")], owner
        print("%s: %s -> %s" % (path, link.function, owner.text))
