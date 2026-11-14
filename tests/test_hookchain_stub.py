#!/usr/bin/env python3
"""Show patched kernel functions: the hook chain applied to the database, against FAKE ida_* modules (the ones of
tests/test_plugin_stub.py, which record every add_cref, set_name and comment). Checks our logic only; this is not a
test in real IDA.

usage: python3 tests/test_hookchain_stub.py [kernel.elf]
A hand-made kernel ELF always; with the demo kernel.elf (or another MemLens export) also that file, where the
recorded calls are counted. The fake database starts with the ELF's memlens_target_ labels as its names.
"""
import contextlib, io, json, os, runpy, struct, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan as ps

with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
    builder = runpy.run_path(os.path.join(HERE, "test_patchscan.py"))
m, calls, nalt, names, blobs, comments = g["m"], g["calls"], g["nalt"], g["names"], g["blobs"], g["comments"]
dummy_names, netnode, xref, iname = g["dummy_names"], g["netnode"], g["xref"], g["iname"]
elf, call, BASE, TEXT = builder["elf"], builder["call"], builder["BASE"], builder["TEXT"]
CALL, JUMP = 17 | 32, 19 | 32  # fl_CN | XREF_USER, fl_JN | XREF_USER
RENAME = 256 | 64  # SN_NOWARN | SN_NON_AUTO: a user name, so IDA does not replace it as it may an auto name


def run():
    """One activation of the menu action; returns (crefs, set_name calls, Output window text)."""
    m._open_list = None
    del calls[:]
    assert m.FindPatches().activate(None) == 1, calls
    crefs = sorted(c[1:] for c in calls if c[0] == "cref")
    renames = sorted(c[1:] for c in calls if c[0] == "setname")
    return crefs, renames, "".join(c[1] for c in calls if c[0] == "msg")


def database(blob):
    """The fake database's names: the ELF's memlens_target_ labels (IDA's loader is expected to keep them)."""
    names.clear()
    names.update({s[2]: s[0] for s in ps.Image(blob).symbols if s[2].startswith(ps.TARGET_PREFIX)})
    blobs.clear()
    comments.clear()


code = bytearray(b"\x90" * TEXT)
def put(offset, data): code[offset:offset + len(data)] = data
FTRACE, KPROBE, BPF = BASE + 0x1000, BASE + 0x1100, BASE + 0x1200
F, K, B = BASE + 0x2000, BASE + 0x2200, BASE + 0x2400
for page, handler in ((F, FTRACE), (K, KPROBE), (B, BPF)):
    put(page - BASE + 0x40, call(page + 0x40, handler))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, F))                             # traced_a -> F
put(0x100, call(BASE + 0x100, F))                                               # traced_b -> F (shared)
put(0x200, call(BASE + 0x200, K))                                               # probed -> K
put(0x300, b"\x48\xb8" + struct.pack("<Q", B) + b"\xff\xe0")                     # movjmp: movabs rax, B; jmp rax
put(0x400, b"\xcc\x89\xe5")                                                     # int3: a row without a handler
symbols = [("traced_a", BASE, 0x100), ("traced_b", BASE + 0x100, 0x100), ("probed", BASE + 0x200, 0x100), ("movjmp", BASE + 0x300, 0x100),
           ("kprobe_me", BASE + 0x400, 0x100), ("function_trace_call", FTRACE, 0x100), ("kprobe_ftrace_handler", KPROBE, 0x100),
           ("__bpf_tramp_enter", BPF, 0x100), ("linux_banner", BASE + TEXT, 0x20), ("sys_call_table", BASE + TEXT + 0x20, 8)]
symbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page in (F, K, B)]
blob = elf(code, symbols, b"Linux version 6.12\0".ljust(0x20, b"\0") + struct.pack("<Q", K))  # sys_call_table[0] -> page K
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(blob)
    nalt.get_input_file_path = lambda: path
    database(blob)
    crefs, renames, out = run()
    # Each hooking instruction to its page (call -> fl_CN, jmp -> fl_JN), each page's handler call to the handler, all XREF_USER.
    assert crefs == sorted([(BASE + 4, F, CALL), (BASE + 0x100, F, CALL), (BASE + 0x200, K, CALL), (BASE + 0x30a, B, JUMP),
                            (F + 0x40, FTRACE, CALL), (K + 0x40, KPROBE, CALL), (B + 0x40, BPF, CALL)]), crefs
    assert renames == sorted([(F, "ftrace_tramp_%x" % F, RENAME), (K, "kprobe_ftrace_tramp_probed", RENAME), (B, "bpf_tramp_movjmp", RENAME)]), renames
    assert "7 code xrefs added; 3 hook pages renamed by role\n" in out, out
    assert "4 patched entries lead into this database, 4 to a hook page MemLens copied" in out, out
    # The exporter's label stays findable in a comment at the page; the entries keep their own comment.
    assert comments[F].startswith("MemLens: hook page no module owns, copied from memory (exporter label memlens_target_%x); "
                                  "reached from traced_a, traced_b" % F), comments
    assert comments[BASE + 4 - 4].startswith("MemLens: call to memory with no symbol memlens_target_%x" % F), comments
    # The list: Handler and Owner columns; Enter goes to the entry, Ctrl+E ("Jump to handler") to the handler.
    table = m._open_list
    assert [c[0] for c in table.cols] == ["Address", "Where", "What", "Target", "Handler", "Owner"], table.cols
    lines = {line[1]: line for line in (table.OnGetLine(n) for n in range(table.OnGetSize()))}
    assert lines["traced_a"][3:5] == ["ftrace_tramp_%x" % F, "function_trace_call (ftrace)"], lines
    assert lines["probed"][3:5] == ["kprobe_ftrace_tramp_probed", "kprobe_ftrace_handler (kprobe via ftrace)"], lines
    assert lines["kprobe_me"][3:] == ["", "", ""], lines
    assert all(line[5] == "" for line in lines.values()), lines  # plumbing only, no ftrace_ops slot here: no owner
    # The syscall slot that points at page K: not linked, but it shows the page's new name and its handler.
    assert lines["sys_call_table[0]"][3:5] == ["kprobe_ftrace_tramp_probed", "kprobe_ftrace_handler (kprobe via ftrace)"], lines
    table.OnEditLine(list(lines).index("sys_call_table[0]")); assert calls[-1] == ("jump", KPROBE), calls[-1]
    index = [table.OnGetLine(n)[1] for n in range(table.OnGetSize())]
    table.OnSelectLine(index.index("movjmp")); assert calls[-1] == ("jump", BASE + 0x300), calls[-1]
    table.OnEditLine(index.index("movjmp")); assert calls[-1] == ("jump", BPF), calls[-1]
    table.OnEditLine(index.index("kprobe_me")); assert calls[-1][0] == "msg" and "no handler" in calls[-1][1], calls[-1]
    # Insert ("Jump to owner"): no owner is known on these pages, so it says so instead of jumping.
    table.OnInsertLine(index.index("traced_a")); assert calls[-1][0] == "msg" and "no owner" in calls[-1][1], calls[-1]
    table.OnInsertLine(-1); assert calls[-1][0] == "msg", calls[-1]  # nothing selected

    # Second run: nothing added or renamed twice; comments unchanged.
    before = dict(comments)
    crefs, renames, out = run()
    assert crefs == [] and renames == [], (crefs, renames)
    assert "0 code xrefs added (7 already added by an earlier run); 0 hook pages renamed by role, 3 already named by an earlier run" in out, out
    assert comments == before, comments
    assert m._open_list.OnGetLine(0)[3:] == table.OnGetLine(0)[3:]

    # The user renamed a page since: it is left alone.
    del names["kprobe_ftrace_tramp_probed"]; names["my_kprobe"] = K
    crefs, renames, out = run()
    assert crefs == [] and renames == [] and "2 already named by an earlier run, 1 left alone, they have another name now" in out, out
    assert {line[1]: line[3] for line in (m._open_list.OnGetLine(n) for n in range(3))}["probed"] == "my_kprobe"
    # ... or removed the name MemLens gave (IDA shows a dummy name): not named again either.
    del names["my_kprobe"]; names["sub_%X" % K] = K; dummy_names.add(K)
    crefs, renames, out = run()
    assert crefs == [] and renames == [] and "1 left alone" in out, out
    dummy_names.clear(); del names["sub_%X" % K]

    # A fresh database where the planned name is already used elsewhere (IDA refuses it), a page that has no name and
    # one with only a name IDA made up: those two are renamed.
    database(blob)
    names["bpf_tramp_movjmp"] = BASE + 0x3000
    del names["%s%x" % (ps.TARGET_PREFIX, F)]
    del names["%s%x" % (ps.TARGET_PREFIX, K)]; names["sub_%X" % K] = K; dummy_names.add(K)
    crefs, renames, out = run()
    assert len(crefs) == 7 and sorted(renames) == sorted([(B, "bpf_tramp_movjmp", RENAME), (F, "ftrace_tramp_%x" % F, RENAME),
                                                          (K, "kprobe_ftrace_tramp_probed", RENAME)]), (crefs, renames)
    assert "2 hook pages renamed by role, 1 refused by IDA" in out, out
    # The refused name is not recorded, so the next run tries it again (and IDA refuses it again).
    crefs, renames, out = run()
    assert crefs == [] and renames == [(B, "bpf_tramp_movjmp", RENAME)], (crefs, renames)
    assert "0 hook pages renamed by role, 2 already named by an earlier run, 1 refused by IDA" in out, out
    dummy_names.clear()
    # A damaged record is read as empty (everything added again), not a crash.
    blobs[next(iter(blobs))] = b"{not json"
    crefs, renames, out = run()
    assert len(crefs) == 7, crefs
    # An xref IDA refuses is counted, not recorded, and tried again on the next run.
    database(blob)
    refuse, good_add_cref = {(BASE + 0x200, K)}, xref.add_cref
    xref.add_cref = lambda frm, to, kind: calls.append(("cref", frm, to, kind)) or (frm, to) not in refuse
    try:
        crefs, renames, out = run()
        assert len(crefs) == 7 and "6 code xrefs added (1 refused by IDA)" in out, (crefs, out)
        assert [BASE + 0x200, K, "call"] not in json.loads(next(iter(blobs.values())))["xrefs"], blobs
        refuse.clear()
        crefs, renames, out = run()
        assert crefs == [(BASE + 0x200, K, CALL)] and "1 code xrefs added (6 already added by an earlier run)" in out, (crefs, out)
    finally:
        xref.add_cref = good_add_cref
    # A page the database shows with no name at all: the Target column falls back to the ELF's label, never "".
    database(blob)
    good_get_name = iname.get_name
    iname.get_name = lambda ea: "" if ea == B else good_get_name(ea)
    try:
        run()
    finally:
        iname.get_name = good_get_name
    lines = {line[1]: line for line in (m._open_list.OnGetLine(n) for n in range(m._open_list.OnGetSize()))}
    assert lines["movjmp"][3] == "memlens_target_%x" % B, lines["movjmp"]
    # If linking itself fails (here the netnode read raises), the list is still shown (nothing renamed; the handlers are
    # read from the ELF) and the traceback goes to the Output window.
    database(blob)
    good_getblob = netnode.getblob
    def broken(self, start, tag): raise TypeError("getblob broke")
    netnode.getblob = broken
    try:
        crefs, renames, out = run()
    finally:
        netnode.getblob = good_getblob
    assert crefs == [] and renames == [] and "getblob broke" in out and "hook chain stopped by this error" in out, out
    lines = {line[1]: line for line in (m._open_list.OnGetLine(n) for n in range(m._open_list.OnGetSize()))}
    assert lines["traced_a"][3:5] == ["memlens_target_%x" % F, "function_trace_call (ftrace)"] and len(lines) == 6, lines
    # A late failure (the record cannot be saved) after xrefs and names were added: the Output window must not claim
    # that nothing was added.
    database(blob)
    good_setblob = netnode.setblob
    def broken_set(self, data, start, tag): raise TypeError("setblob broke")
    netnode.setblob = broken_set
    try:
        crefs, renames, out = run()
    finally:
        netnode.setblob = good_setblob
    assert len(crefs) == 7 and len(renames) == 3 and "setblob broke" in out, (crefs, renames, out)
    assert "hook chain stopped by this error (xrefs or names added before it are not recorded" in out, out
    assert "no xrefs or renames" not in out, out
    # The input file is missing and the user picks a kernel.elf: if its SHA-256 is not the database's, MemLens asks
    # before writing anything (default No); the same file goes ahead without a question.
    import hashlib
    kw = g["kw"]
    database(blob)
    asked = []
    picked = os.path.join(work, "k%s.elf")  # a "%" in the name must reach ask_yn (printf-style) as "%%"
    with open(picked, "wb") as handle:
        handle.write(blob)
    kw.ask_file = lambda *a: picked
    kw.ask_yn = lambda default, text: asked.append((default, text)) or kw.ASKBTN_NO
    nalt.get_input_file_path = lambda: "/nonexistent/kernel.elf"
    nalt.retrieve_input_file_sha256 = lambda: hashlib.sha256(b"another file").digest()
    del calls[:]
    assert m.FindPatches().activate(None) == 0 and not [c for c in calls if c[0] in ("cref", "setname", "cmt")], calls
    assert len(asked) == 1 and asked[0][0] == kw.ASKBTN_NO and "SHA-256" in asked[0][1] and "k%%s.elf" in asked[0][1], asked
    # Esc on the question (real ask_yn returns ASKBTN_CANCEL, -1) also writes nothing.
    kw.ASKBTN_CANCEL = -1
    kw.ask_yn = lambda default, text: asked.append((default, text)) or kw.ASKBTN_CANCEL
    asked.clear()
    del calls[:]
    assert m.FindPatches().activate(None) == 0 and not [c for c in calls if c[0] in ("cref", "setname", "cmt")], calls
    assert len(asked) == 1, asked
    kw.ask_yn = lambda default, text: asked.append((default, text)) or kw.ASKBTN_NO
    nalt.retrieve_input_file_sha256 = lambda: hashlib.sha256(blob).digest()
    crefs, renames, out = run()
    assert len(asked) == 1 and len(crefs) == 7, (asked, crefs)
    # A picked file on a database with no stored SHA-256: nothing to compare with, so it goes ahead without a question.
    database(blob)
    nalt.retrieve_input_file_sha256 = lambda: None
    asked.clear()
    crefs, renames, out = run()
    assert asked == [] and len(crefs) == 7, (asked, crefs)
    nalt.get_input_file_path = lambda: path

# An ftrace trampoline whose ftrace_ops sits in a module's data (the ftrace-hook rootkit pattern; tests/test_owner.py has
# the layout): data xrefs slot -> ops -> callback (dr_O, user), the Owner column, Insert jumps to the callback, the page
# comment names it, a second run adds nothing. With an ISF offset recorded by Apply kernel types, ops->func is read there.
DATA = 1 | 32  # dr_O | XREF_USER
code = bytearray(b"\x90" * TEXT)
ASSIST, THUNK, OPS, PAGE = BASE + 0x1000, BASE + 0x1100, BASE + TEXT + 0x40, BASE + 0x2000
put(PAGE - BASE + 0x74, b"\x48\x8b\x15" + struct.pack("<i", (PAGE + 0xdd) - (PAGE + 0x7b)))  # mov rdx, [rip+X]: the ops slot
put(PAGE - BASE + 0x94, call(PAGE + 0x94, ASSIST))
put(PAGE - BASE + 0xd8, b"\xc3\xcc\x00\x00\x00" + struct.pack("<Q", OPS))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, PAGE))
rodata = b"Linux version 6.12\0".ljust(0x40, b"\0") + struct.pack("<QQ", THUNK, ASSIST)  # ops: func, then a decoy at +8
symbols = [("__x64_sys_getdents64", BASE, 0x100), ("ftrace_ops_assist_func", ASSIST, 0x100), ("evilmod.fh_ftrace_thunk", THUNK, 0x100),
           ("linux_banner", BASE + TEXT, 0x20), ("evilmod.hooks", OPS - 0x20, 0x80), ("%s%x" % (ps.TARGET_PREFIX, PAGE), PAGE, 0)]
blob = elf(code, symbols, rodata)
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(blob)
    nalt.get_input_file_path = lambda: path
    database(blob)
    crefs, renames, out = run()
    drefs = sorted(c[1:] for c in calls if c[0] == "dref")
    assert drefs == [(PAGE + 0xdd, OPS, DATA), (OPS, THUNK, DATA)], drefs
    assert crefs == [(BASE + 4, PAGE, CALL), (PAGE + 0x94, ASSIST, CALL)], crefs
    assert renames == [(PAGE, "ftrace_tramp___x64_sys_getdents64", RENAME)], renames  # ftrace_ops_assist_func: an ftrace role
    assert "2 code xrefs added; 2 data xrefs added; 1 hook pages renamed by role" in out, out
    table = m._open_list
    line = table.OnGetLine(0)
    assert line[3:] == ["ftrace_tramp___x64_sys_getdents64", "ftrace_ops_assist_func (ftrace)",
                        "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)"], line
    table.OnInsertLine(0); assert calls[-1] == ("jump", THUNK), calls[-1]
    table.OnEditLine(0); assert calls[-1] == ("jump", ASSIST), calls[-1]
    assert comments[PAGE].endswith("; owner: evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)"), comments[PAGE]
    crefs, renames, out = run()
    assert crefs == [] and not [c for c in calls if c[0] == "dref"], calls
    assert "0 code xrefs added (2 already added by an earlier run); 0 data xrefs added (2 already added by an earlier run)" in out, out
    # The ISF that Apply kernel types imported said func is at offset 8: the decoy there is read instead.
    database(blob)
    m.save_layout({"ftrace_ops.func": 8})
    crefs, renames, out = run()
    assert m._open_list.OnGetLine(0)[5] == "ftrace_ops_assist_func (ftrace_ops evilmod.hooks+0x20)", m._open_list.OnGetLine(0)
    assert sorted(c[1:] for c in calls if c[0] == "dref") == [(PAGE + 0xdd, OPS, DATA), (OPS + 8, ASSIST, DATA)], calls
    nalt.get_input_file_path = lambda: ""

# Hook pages with no ftrace, kprobe or BPF role (judge s160 finding 5). Page MP's first named call is a module's function,
# a module callback: MP is renamed module_hook_<entry>, the Handler and Owner columns name the callback and Ctrl+E jumps
# there. Page HP (a hidden module's hook code) calls _printk first: the Handler column says it is hook code and names that
# call, Ctrl+E does not jump into _printk (it says why), HP keeps its label; the xref of that real call is still added.
code = bytearray(b"\x90" * TEXT)
MODCB, PRINTK, MP, HP = BASE + 0x1000, BASE + 0x1100, BASE + 0x2000, BASE + 0x2200
put(MP - BASE + 0x40, call(MP + 0x40, MODCB))
put(HP - BASE + 0x40, call(HP + 0x40, PRINTK))
put(HP - BASE + 0x60, call(HP + 0x60, MODCB))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, MP))                              # __x64_sys_kill: endbr64; call MP
put(0x100, b"\x68" + struct.pack("<i", HP - (1 << 64)) + b"\xc3")                 # vfs_read: push HP; ret
symbols = [("__x64_sys_kill", BASE, 0x100), ("vfs_read", BASE + 0x100, 0x100), ("evilmod.fh_sys_kill", MODCB, 0x100),
           ("_printk", PRINTK, 0x100), ("linux_banner", BASE + TEXT, 0x20)]
symbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page in (MP, HP)]
blob = elf(code, symbols, b"Linux version 6.12\0".ljust(0x20, b"\0"))
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(blob)
    nalt.get_input_file_path = lambda: path
    database(blob)
    crefs, renames, out = run()
    assert crefs == sorted([(BASE + 4, MP, CALL), (BASE + 0x105, HP, JUMP), (MP + 0x40, MODCB, CALL), (HP + 0x40, PRINTK, CALL)]), crefs
    assert renames == [(MP, "module_hook___x64_sys_kill", RENAME)], renames
    assert "4 code xrefs added; 1 hook pages renamed by role\n" in out, out
    table = m._open_list
    rows = [table.OnGetLine(n) for n in range(table.OnGetSize())]
    lines = {line[1]: line for line in rows}
    assert lines["__x64_sys_kill"][3:] == ["module_hook___x64_sys_kill", "evilmod.fh_sys_kill (module callback)",
                                           "evilmod.fh_sys_kill (module callback)"], lines
    assert lines["vfs_read"][3:] == ["memlens_target_%x" % HP, "(hook code; first call: _printk)", ""], lines
    index = [line[1] for line in rows]
    table.OnEditLine(index.index("__x64_sys_kill")); assert calls[-1] == ("jump", MODCB), calls[-1]
    table.OnInsertLine(index.index("__x64_sys_kill")); assert calls[-1] == ("jump", MODCB), calls[-1]
    del calls[:]
    table.OnEditLine(index.index("vfs_read"))
    assert calls[-1][0] == "msg" and "no handler is known for vfs_read (hook code; first call: _printk)" in calls[-1][1], calls
    assert not [c for c in calls if c[0] == "jump"], calls
    table.OnInsertLine(index.index("vfs_read")); assert calls[-1][0] == "msg" and "module callback" in calls[-1][1], calls[-1]
    assert comments[MP].endswith("reached from __x64_sys_kill; first named call: evilmod.fh_sys_kill (module callback)"), comments[MP]
    assert comments[HP].endswith("reached from vfs_read; first named call: _printk"), comments[HP]
    nalt.get_input_file_path = lambda: ""
print("hook chain stub test OK (hand-made ELFs; fake IDA modules)")

for path in sys.argv[1:2]:
    blob = open(path, "rb").read()
    nalt.get_input_file_path = lambda: path
    database(blob)
    crefs, renames, out = run()
    drefs = [c for c in calls if c[0] == "dref"]
    assert crefs and all(kind == CALL for _, _, kind in crefs) and all(c[3] == DATA for c in drefs), (crefs, drefs)
    second = run()
    assert second[:2] == ([], []) and not [c for c in calls if c[0] == "dref"], second
    print("%s: first run %d add_cref, %d add_dref, %d set_name (%s); second run %d add_cref, %d set_name" % (
        path, len(crefs), len(drefs), len(renames), ", ".join(r[1] for r in renames), len(second[0]), len(second[1])))
    for line in out.splitlines():
        print("  " + line)
    table = m._open_list
    for n in range(table.OnGetSize()):
        print("  row: " + " | ".join(table.OnGetLine(n)))
    # Jump to owner (the list's Insert command) on a real export: each row with an owner jumps to the owner's address
    # (review s191: the hand-made MODCB case above was the only check of OnInsertLine).
    image = ps.Image(blob)
    owners = {link.function: link.owner.address for link in ps.hook_links(image, ps.scan(None, image))
              if link.owner and link.owner.address is not None}
    jumped = 0
    for n in range(table.OnGetSize()):
        where = table.OnGetLine(n)[1]
        if where in owners:
            del calls[:]
            table.OnInsertLine(n)
            assert calls and calls[-1] == ("jump", owners[where]), (where, calls)
            jumped += 1
    print("  Jump to owner: %d of %d rows jump to their owner" % (jumped, table.OnGetSize()))
