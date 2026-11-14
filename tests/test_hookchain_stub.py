#!/usr/bin/env python3
"""Show patched kernel functions: the hook chain applied to the database, against FAKE ida_* modules (the ones of
tests/test_plugin_stub.py, which record every add_cref, set_name and comment). Checks our logic only; this is not a
test in real IDA.

usage: python3 tests/test_hookchain_stub.py [kernel.elf ...]
A hand-made kernel ELF always; with the demo kernel.elf (or other MemLens exports, such as the second sample's) also
each of those, where the recorded calls are counted and the rows printed: first with no layout recorded and no type
imported (as before Apply kernel types), then on a fresh database with the layout Apply kernel types records (from the
ISF in MEMLENS_ISF, else ftrace_ops.func = 0), which must give the same rows. With that kernel's ISF (MEMLENS_ISF, else
the *.json.xz next to the kernel.elf) also the full layout (ftrace_ops.flags and the FTRACE_OPS_FL_* values) and struct
ftrace_ops in the database: the same rows, the ftrace_ops flags comments and the module ops' type (on the two public
samples exactly the expected ones), nothing added by a second run, and no flags comment without the enum. The fake
database starts with the ELF's memlens_target_ labels as its names.
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

# ftrace_ops flags (judge s192 item 5): the comment texts, the small ISFs the hand-made cases take their layout from, and
# the database's types (the fake tinfo_t knows struct ftrace_ops only while known_types has it, as after Apply kernel types).
NO_IPMODIFY = ("no IPMODIFY: the callback did not declare that it may change where the hooked function continues (a "
               "declaration, not a guarantee: read the callback to be sure)")
IPMODIFY_TEXT = ("IPMODIFY: the callback declared that it may change where the hooked function continues (as livepatch and "
                 "ftrace hooks that replace a function do)")
FL_6_12 = ["ENABLED", "DYNAMIC", "SAVE_REGS", "SAVE_REGS_IF_SUPPORTED", "RECURSION", "STUB", "INITIALIZED", "DELETED", "ADDING",
           "REMOVING", "MODIFYING", "ALLOC_TRAMP", "IPMODIFY", "PID", "RCU", "TRACE_ARRAY", "PERMANENT", "DIRECT", "SUBOP"]
def flags_isf(names, flags_field=True):
    """A small ISF: struct ftrace_ops (func at 0, flags at 16) and an anonymous enum with FTRACE_OPS_FL_<name> = bit n."""
    fields = {"func": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}}
    if flags_field:
        fields["flags"] = {"offset": 16, "type": {"kind": "base", "name": "unsigned long"}}
    constants = {"FTRACE_OPS_FL_" + name: 1 << bit for bit, name in enumerate(names)}
    return {"base_types": {"unsigned long": {"size": 8, "signed": False, "kind": "int"}},
            "user_types": {"ftrace_ops": {"kind": "struct", "size": 24, "fields": fields}},
            "enums": {"unnamed_3584957e6fdd2840": {"size": 4, "base": "unsigned int", "constants": constants},
                      "trace_flag_type": {"size": 4, "base": "unsigned int", "constants": {"TRACE_FLAG_IRQS_OFF": 1}}},
            "symbols": {}}
FLAGS_ISF = flags_isf(FL_6_12)
known_types = set()
good_get_named_type = g["ti"].tinfo_t.get_named_type
def get_named_type(self, til, name):
    if name in known_types:
        self.size = 216
        return True
    return good_get_named_type(self, til, name)
g["ti"].tinfo_t.get_named_type = get_named_type


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
rodata = b"Linux version 6.12\0".ljust(0x40, b"\0") + struct.pack("<QQQ", THUNK, ASSIST, 0)  # ops: func, a decoy at +8, flags 0
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
    # With the flags layout and struct ftrace_ops in the database: the flags (0 here) are decoded at the page and the
    # ops, but an ops inside a bigger module object (evilmod.hooks+0x20, the ftrace_hook array) is not retyped.
    database(blob)
    known_types.add("ftrace_ops")
    m.save_layout(m.isf_layout(FLAGS_ISF))
    run()
    assert not [c for c in calls if c[0] == "settype"], calls
    assert comments[OPS] == "MemLens: ftrace_ops flags 0x0 = none; " + NO_IPMODIFY, comments
    known_types.clear()
    nalt.get_input_file_path = lambda: ""

# ftrace_ops flags (judge s192 item 5): Apply kernel types records the offset of ftrace_ops.flags and the FTRACE_OPS_FL_*
# values, read by name from the ISF's (anonymous) enum. For each ftrace trampoline whose Owner comes from its ftrace_ops,
# the page and the ops get a comment that decodes the ops' flags, and an ops a module symbol starts at is typed as
# struct ftrace_ops once (when the database has that struct). kprobe pages get nothing: a pre_handler can change
# regs->ip and no flag says so. Without the layout, or without the enum's IPMODIFY, nothing is said.
code = bytearray(b"\x90" * TEXT)
ASSIST, THUNK, KPROBE_H, PAGE, KPAGE = BASE + 0x1000, BASE + 0x1100, BASE + 0x1200, BASE + 0x2000, BASE + 0x2400
OPS, KOPS = BASE + TEXT + 0x40, BASE + TEXT + 0x80
def trampoline(page, handler, ops):
    put(page - BASE + 0x74, b"\x48\x8b\x15" + struct.pack("<i", (page + 0xdd) - (page + 0x7b)))
    put(page - BASE + 0x94, call(page + 0x94, handler))
    put(page - BASE + 0xd8, b"\xc3\xcc\x00\x00\x00" + struct.pack("<Q", ops))
trampoline(PAGE, ASSIST, OPS)
trampoline(KPAGE, KPROBE_H, KOPS)
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, PAGE))                          # __x64_sys_kill -> the module's trampoline
put(0x100, b"\xf3\x0f\x1e\xfa" + call(BASE + 0x104, KPAGE))                     # do_sys_openat2 -> a kprobe trampoline
symbols = [("__x64_sys_kill", BASE, 0x100), ("do_sys_openat2", BASE + 0x100, 0x100), ("ftrace_ops_assist_func", ASSIST, 0x100),
           ("evilmod.fh_kill", THUNK, 0x100), ("kprobe_ftrace_handler", KPROBE_H, 0x100), ("linux_banner", BASE + TEXT, 0x20),
           ("evilmod.fh_ops", OPS, 0x40), ("kprobe_ipmodify_ops", KOPS, 0x40)]
symbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page in (PAGE, KPAGE)]
def flags_blob(flags, kprobe_flags=0x1845, symbols=symbols):
    """The ELF with these ftrace_ops flags at offset 16 of the module's ops (and of the kprobe layer's ops)."""
    rodata = (b"Linux version 6.12\0".ljust(0x40, b"\0") + struct.pack("<QQQ", THUNK, 0, flags).ljust(0x40, b"\0")
              + struct.pack("<QQQ", KPROBE_H, 0, kprobe_flags).ljust(0x40, b"\0"))
    return elf(code, symbols, rodata)
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    nalt.get_input_file_path = lambda: path
    def flags_run(flags, layout, types=("ftrace_ops",), kprobe_flags=0x1845, fresh=True):
        """A fresh database (fresh=False: the same one) of the ELF with these flags, the layout and the types given;
        returns (settype calls, out)."""
        blob = flags_blob(flags, kprobe_flags)
        with open(path, "wb") as handle:
            handle.write(blob)
        if fresh:
            database(blob)
        known_types.clear(); known_types.update(types)
        if layout is not None:
            m.save_layout(layout)
        _, _, out = run()
        return [c[1:] for c in calls if c[0] == "settype"], out
    def flag_lines():
        return {ea: [line for line in text.split("\n") if "ftrace_ops flags" in line] for ea, text in comments.items()
                if "ftrace_ops flags" in text}
    # What Apply kernel types records: the offsets and the values by name (the other enum is not taken).
    layout = m.isf_layout(FLAGS_ISF)
    assert layout == {"ftrace_ops.func": 0, "ftrace_ops.flags": 16,
                      "FTRACE_OPS_FL": {"FTRACE_OPS_FL_" + name: 1 << bit for bit, name in enumerate(FL_6_12)}}, layout
    assert layout["FTRACE_OPS_FL"]["FTRACE_OPS_FL_IPMODIFY"] == 0x1000, layout
    # IPMODIFY set, plus a bit the enum does not name (shown as a number, not dropped; above bit 31: flags is an
    # unsigned long, read as 8 bytes).
    settype, out = flags_run(0x10000001007, layout)
    text = "MemLens: ftrace_ops flags 0x10000001007 = ENABLED|DYNAMIC|SAVE_REGS|IPMODIFY|0x10000000000; " + IPMODIFY_TEXT
    assert flag_lines() == {PAGE: [text], OPS: [text]}, flag_lines()
    assert comments[OPS] == text and comments[PAGE].split("\n")[0].startswith("MemLens: hook page no module owns"), comments
    assert settype == [(OPS, "struct ftrace_ops;")], settype
    assert out.endswith("; 1 module ftrace_ops typed as struct ftrace_ops\n"), out
    table = m._open_list
    assert table.OnGetLine(0)[1] == "__x64_sys_kill" and table.OnGetLine(0)[5] == "evilmod.fh_kill (ftrace_ops evilmod.fh_ops)", table.OnGetLine(0)
    # kprobe page: its ops (here with IPMODIFY set) gets no flags comment and is not typed, its Owner is unchanged.
    assert table.OnGetLine(1)[5] == "kprobe_ftrace_handler (ftrace_ops kprobe_ipmodify_ops)" and KOPS not in comments, (table.OnGetLine(1), comments)
    # Second run: no type applied again, no comment line added.
    before = dict(comments)
    crefs, renames, out = run()
    assert crefs == [] and renames == [] and not [c for c in calls if c[0] in ("settype", "cmt")], calls
    assert comments == before and out.endswith("; 0 module ftrace_ops typed as struct ftrace_ops (1 already typed by an earlier run)\n"), out
    # No IPMODIFY: the 6.12 values of th_kill_ops in the second sample.
    settype, out = flags_run(0x857, layout)
    text = "MemLens: ftrace_ops flags 0x857 = ENABLED|DYNAMIC|SAVE_REGS|RECURSION|INITIALIZED|ALLOC_TRAMP; " + NO_IPMODIFY
    assert flag_lines() == {PAGE: [text], OPS: [text]} and settype == [(OPS, "struct ftrace_ops;")], (flag_lines(), settype)
    # The values are read by name: with an older numbering (a CONTROL flag at bit 2 shifts the rest, IPMODIFY = 0x2000) the
    # same 0x1000 bit is ALLOC_TRAMP, not IPMODIFY.
    old = m.isf_layout(flags_isf(["ENABLED", "DYNAMIC", "CONTROL", "SAVE_REGS", "SAVE_REGS_IF_SUPPORTED", "RECURSION_SAFE", "STUB",
                                  "INITIALIZED", "DELETED", "ADDING", "REMOVING", "MODIFYING", "ALLOC_TRAMP", "IPMODIFY", "PID"]))
    assert old["FTRACE_OPS_FL"]["FTRACE_OPS_FL_IPMODIFY"] == 0x2000, old
    flags_run(0x10000001007, old)
    text = "MemLens: ftrace_ops flags 0x10000001007 = ENABLED|DYNAMIC|CONTROL|ALLOC_TRAMP|0x10000000000; " + NO_IPMODIFY
    assert flag_lines() == {PAGE: [text], OPS: [text]}, flag_lines()
    # Then, on the same database, Apply kernel types with the right ISF and the list again (review s193 MINOR): the flags
    # line the other ISF decoded is replaced, not kept next to the new one; the other lines stay; a third run changes nothing.
    settype, out = flags_run(0x10000001007, layout, fresh=False)
    text = "MemLens: ftrace_ops flags 0x10000001007 = ENABLED|DYNAMIC|SAVE_REGS|IPMODIFY|0x10000000000; " + IPMODIFY_TEXT
    assert flag_lines() == {PAGE: [text], OPS: [text]} and settype == [], (flag_lines(), settype)
    assert comments[OPS] == text and comments[PAGE].split("\n")[0].startswith("MemLens: hook page no module owns"), comments
    before = dict(comments)
    run()
    assert not [c for c in calls if c[0] in ("settype", "cmt")] and comments == before, calls
    # struct ftrace_ops not in the database (types not imported): the flags are decoded, nothing is typed.
    settype, out = flags_run(0x101007, layout, types=())
    assert settype == [] and len(flag_lines()) == 2 and "typed as struct ftrace_ops" not in out, (settype, out)
    # Nothing is said without the layout, without the enum, without its IPMODIFY or without the flags field.
    for no_flags in (None, m.isf_layout(dict(FLAGS_ISF, enums={})), m.isf_layout(flags_isf([n for n in FL_6_12 if n != "IPMODIFY"])),
                     m.isf_layout(flags_isf(FL_6_12, flags_field=False))):
        flags_run(0x101007, no_flags)
        assert flag_lines() == {}, (no_flags, comments)
    assert "FTRACE_OPS_FL" not in m.isf_layout(dict(FLAGS_ISF, enums={})), m.isf_layout(dict(FLAGS_ISF, enums={}))
    assert "ftrace_ops.flags" not in m.isf_layout(flags_isf(FL_6_12, flags_field=False))
    # A damaged layout record (a flags offset that is not a number, values that are not a table): nothing said, no crash.
    for broken in ({"ftrace_ops.flags": "16", "FTRACE_OPS_FL": layout["FTRACE_OPS_FL"]}, {"ftrace_ops.flags": 16, "FTRACE_OPS_FL": [1, 2]},
                   {"ftrace_ops.flags": 16, "FTRACE_OPS_FL": {"FTRACE_OPS_FL_IPMODIFY": "0x1000"}}):
        flags_run(0x101007, broken)
        assert flag_lines() == {}, (broken, comments)
    # A kprobe trampoline as kernels before 5.11 build it (review s193 MAJOR): kprobe_ftrace_ops and kprobe_ipmodify_ops
    # have no RECURSION_SAFE there, so the page calls ftrace_ops_assist_func, not kprobe_ftrace_handler. Its kind is then
    # "ftrace" and its Owner comes from the ops, whose func is kprobe_ftrace_handler: still no flags comment and no type,
    # with IPMODIFY set (kprobe_ipmodify_ops, live) or not (kprobe_ftrace_ops); the module's trampoline keeps its comment.
    trampoline(KPAGE, ASSIST, KOPS)
    text = "MemLens: ftrace_ops flags 0x857 = ENABLED|DYNAMIC|SAVE_REGS|RECURSION|INITIALIZED|ALLOC_TRAMP; " + NO_IPMODIFY
    for kprobe_flags in (0x1845, 0x845):
        settype, out = flags_run(0x857, layout, kprobe_flags=kprobe_flags)
        assert flag_lines() == {PAGE: [text], OPS: [text]} and settype == [(OPS, "struct ftrace_ops;")], (kprobe_flags, flag_lines(), settype)
        assert KOPS not in comments and "ftrace_ops flags" not in comments.get(KPAGE, ""), (kprobe_flags, comments)
        assert m._open_list.OnGetLine(1)[4:] == ["ftrace_ops_assist_func (ftrace)", "kprobe_ftrace_handler (ftrace_ops kprobe_ipmodify_ops)"], m._open_list.OnGetLine(1)
    # The same page when kprobe_ftrace_handler has no symbol in the ELF: only the export's kprobe list (a probe recorded at
    # the patched instruction) says that it is a kprobe's; without the list it reads as an ftrace page.
    image = ps.Image(flags_blob(0x857, 0x1845, [s for s in symbols if s[0] != "kprobe_ftrace_handler"]))
    links = ps.hook_links(image, ps.scan(None, image))
    assert ps.ftrace_ops_pages(image, links) == {PAGE: OPS, KPAGE: KOPS}, ps.ftrace_ops_pages(image, links)
    image.kprobes = {BASE + 0x104: [{"addr": BASE + 0x104, "pre_handler": THUNK, "post_handler": 0, "offset": 0, "symbol": "do_sys_openat2",
                                     "event": None, "tracefs": None, "flags": 0, "ret_handler": None, "ret_entry": None}]}
    assert ps.ftrace_ops_pages(image, links) == {PAGE: OPS} and ps.module_ops(image, links) == [OPS], ps.ftrace_ops_pages(image, links)
    trampoline(KPAGE, KPROBE_H, KOPS)
    nalt.get_input_file_path = lambda: ""
known_types.clear()

# Apply kernel types records that layout in the database: a second ISF without the enum drops the old values (they
# would be another kernel's), and keys it does not set stay; an ISF without struct ftrace_ops leaves the record alone.
with tempfile.TemporaryDirectory() as work:
    blobs.clear()
    m.save_layout({"other.key": 1})
    for isf, expected in ((FLAGS_ISF, dict(m.isf_layout(FLAGS_ISF), **{"other.key": 1})),
                          (dict(FLAGS_ISF, enums={}), {"ftrace_ops.func": 0, "ftrace_ops.flags": 16, "other.key": 1}),
                          (FLAGS_ISF, dict(m.isf_layout(FLAGS_ISF), **{"other.key": 1})),
                          (dict(FLAGS_ISF, user_types={}, enums={}), dict(m.isf_layout(FLAGS_ISF), **{"other.key": 1}))):
        isf_path = os.path.join(work, "isf.json")
        with open(isf_path, "w") as handle:
            json.dump(isf, handle)
        assert m.apply_types(isf_path) is not None
        assert m.load_layout() == expected, m.load_layout()

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

# The list needs neither the kernel types nor finished auto-analysis (README Try it, step 2): the action never waits for
# auto-analysis (no ida_auto call on its path), reads kernel.elf from disk and the ELF's own symbol table, imports no
# type, and without the layout Apply kernel types records it reads ftrace_ops.func at offset 0 (patchscan.FTRACE_OPS_FUNC).
import inspect
for function in (m.FindPatches.activate, m.scan_current_input, m.link_hooks, m.load_layout):
    assert "ida_auto" not in inspect.getsource(function), function
import glob, hashlib, isf2c
loaded_isfs = {}
def load_isf(isf_path):
    if isf_path not in loaded_isfs:
        loaded_isfs.clear()  # one at a time: a kernel's ISF takes about 300 MB once loaded
        loaded_isfs[isf_path] = isf2c.load_isf(isf_path)
    return loaded_isfs[isf_path]
layout_offset, layout_source = ps.FTRACE_OPS_FUNC, "patchscan.FTRACE_OPS_FUNC, no ISF given"
if os.path.isfile(os.environ.get("MEMLENS_ISF", "")):  # what Apply kernel types records for that ISF
    layout_offset = ps.ftrace_ops_func_offset(load_isf(os.environ["MEMLENS_ISF"]))
    layout_source = os.path.basename(os.environ["MEMLENS_ISF"])
# The flags comments and types on the two public samples, after Apply kernel types with their ISF (both: the Debian 13
# 6.12.115 kernel; values read from memory, judge s192): demo kernel.elf, the function tracer's global_ops 0x2841 on the
# trampoline of vfs_getattr (a kernel global, typed by Apply kernel types itself); second sample, the test module's
# th_kill_ops 0x857 on the trampoline of __x64_sys_kill (a module symbol: typed here). Neither has IPMODIFY; the kprobe
# pages (do_sys_openat2, __x64_sys_getdents64, ops kprobe_ftrace_ops 0x845) get no flags comment.
FLAGS_2841 = "MemLens: ftrace_ops flags 0x2841 = ENABLED|INITIALIZED|ALLOC_TRAMP|PID; " + NO_IPMODIFY
FLAGS_857 = "MemLens: ftrace_ops flags 0x857 = ENABLED|DYNAMIC|SAVE_REGS|RECURSION|INITIALIZED|ALLOC_TRAMP; " + NO_IPMODIFY
REAL_FLAGS = {  # kernel.elf SHA-256: ({address: [flags comment line]}, SetType calls)
    "1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5":
        ({0xffffffffc0b2b000: [FLAGS_2841], 0xffffffff8ff42660: [FLAGS_2841]}, []),
    "8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9":
        ({0xffffffffc0cd0000: [FLAGS_857], 0xffffffffc0cc80a0: [FLAGS_857]}, [(0xffffffffc0cc80a0, "struct ftrace_ops;")]),
}
def flag_comments():
    """{address: [comment lines with ftrace_ops flags]} in the fake database."""
    return {ea: [line for line in text.split("\n") if "ftrace_ops flags" in line] for ea, text in comments.items()
            if "ftrace_ops flags" in text}

for path in sys.argv[1:]:
    blob = open(path, "rb").read()
    nalt.get_input_file_path = lambda: path
    database(blob)
    assert m.load_layout() == {}, m.load_layout()  # as before Apply kernel types: no layout recorded
    crefs, renames, out = run()
    assert not [c for c in calls if c[0] in ("parse", "settype")], calls  # no type imported or applied
    assert flag_comments() == {}, flag_comments()  # no layout: nothing said about ftrace_ops flags
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
    # The same list after Apply kernel types (a fresh database with the layout it records): the same rows.
    rows = [table.OnGetLine(n) for n in range(table.OnGetSize())]
    database(blob)
    m.save_layout({"ftrace_ops.func": layout_offset})
    run()
    typed = [m._open_list.OnGetLine(n) for n in range(m._open_list.OnGetSize())]
    assert typed == rows, (typed, rows)
    print("  with the layout Apply kernel types records (ftrace_ops.func = %d, from %s): the same %d rows"
          % (layout_offset, layout_source, len(rows)))
    assert flag_comments() == {} and not [c for c in calls if c[0] == "settype"], calls  # no flags layout, no struct
    # After Apply kernel types with this kernel's ISF (MEMLENS_ISF, else the *.json.xz next to kernel.elf): the layout it
    # records (offsets of ftrace_ops.func and .flags, the FTRACE_OPS_FL_* values by name) and struct ftrace_ops in the
    # database. The same rows (the Owner column does not change); the flags comments and the module ops' type; a second
    # run adds nothing; an ISF without the FTRACE_OPS_FL_ enum gives no flags comment.
    sha = hashlib.sha256(blob).hexdigest()
    isf_path = os.environ.get("MEMLENS_ISF", "")
    if not os.path.isfile(isf_path):
        isf_path = (sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(path)), "*.json.xz"))) or [""])[0]
    if not isf_path:
        print("SKIP: ftrace_ops flags of %s: no ISF (set MEMLENS_ISF, or put the kernel's *.json.xz next to it)" % path)
        continue
    isf = load_isf(isf_path)
    isf_banner = m.isf_linux_banner(isf)
    elf_banner = image.read(image.by_name["linux_banner"][0], len(isf_banner)) if isf_banner and "linux_banner" in image.by_name else None
    if isf_banner is None or elf_banner != isf_banner:
        print("SKIP: ftrace_ops flags of %s: %s is not this kernel's ISF (its linux_banner differs)" % (path, os.path.basename(isf_path)))
        continue
    layout = m.isf_layout(isf)
    assert isinstance(layout.get("ftrace_ops.flags"), int) and layout["FTRACE_OPS_FL"].get("FTRACE_OPS_FL_IPMODIFY"), layout
    database(blob)
    known_types.add("ftrace_ops")
    m.save_layout(layout)
    _, _, flags_out = run()
    settype = [c[1:] for c in calls if c[0] == "settype"]
    assert [m._open_list.OnGetLine(n) for n in range(m._open_list.OnGetSize())] == rows
    flagged = flag_comments()
    if sha in REAL_FLAGS:
        assert (flagged, settype) == REAL_FLAGS[sha], (flagged, settype)
    assert all(len(lines) == 1 and lines[0].startswith("MemLens: ftrace_ops flags 0x") for lines in flagged.values()), flagged
    links = ps.hook_links(image, ps.scan(None, image))
    assert not [link for link in links if link.kind == ps.KPROBE_KIND and link.target in flagged], flagged  # no kprobe page
    before = dict(comments)
    second = run()
    assert second[:2] == ([], []) and not [c for c in calls if c[0] in ("settype", "cmt", "dref")] and comments == before, calls
    print("  after Apply kernel types with %s (ftrace_ops.flags = %d, %d FTRACE_OPS_FL_* values by name, IPMODIFY = %#x): the same %d rows"
          % (os.path.basename(isf_path), layout["ftrace_ops.flags"], len(layout["FTRACE_OPS_FL"]),
             layout["FTRACE_OPS_FL"]["FTRACE_OPS_FL_IPMODIFY"], len(rows)))
    print("    " + next(line for line in flags_out.splitlines() if "hook chain:" in line))
    for ea, lines in sorted(flagged.items()):
        print("    comment at %#x (%s): %s" % (ea, iname.get_name(ea) or ps.at(image, ea), lines[0]))
    for ea, declaration in settype:
        print("    SetType(%#x (%s), %r)" % (ea, iname.get_name(ea) or ps.at(image, ea), declaration))
    print("    %d SetType; second run: 0 SetType, 0 comments changed%s" % (
        len(settype), "; as expected for this public sample" if sha in REAL_FLAGS else ""))
    # The same ISF without its FTRACE_OPS_FL_ enum: no flags comment (no guessed values); the struct is still there.
    enums = {name: enum for name, enum in isf["enums"].items()
             if not any(key.startswith("FTRACE_OPS_FL_") for key in (enum.get("constants") or {}))}
    database(blob)
    m.save_layout(m.isf_layout(dict(isf, enums=enums)))
    run()
    assert flag_comments() == {} and [c[1:] for c in calls if c[0] == "settype"] == settype, (comments, calls)
    print("    with that ISF's FTRACE_OPS_FL_ enum removed: no flags comment, the same %d SetType" % len(settype))
    known_types.clear()
