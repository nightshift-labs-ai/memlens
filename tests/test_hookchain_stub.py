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
    # The list: a Handler column; Enter goes to the entry, Ctrl+E ("Jump to handler") to the handler.
    table = m._open_list
    assert [c[0] for c in table.cols] == ["Address", "Where", "What", "Target", "Handler"], table.cols
    lines = {line[1]: line for line in (table.OnGetLine(n) for n in range(table.OnGetSize()))}
    assert lines["traced_a"][3:] == ["ftrace_tramp_%x" % F, "function_trace_call (ftrace)"], lines
    assert lines["probed"][3:] == ["kprobe_ftrace_tramp_probed", "kprobe_ftrace_handler (kprobe via ftrace)"], lines
    assert lines["kprobe_me"][3:] == ["", ""], lines
    # The syscall slot that points at page K: not linked, but it shows the page's new name and its handler.
    assert lines["sys_call_table[0]"][3:] == ["kprobe_ftrace_tramp_probed", "kprobe_ftrace_handler (kprobe via ftrace)"], lines
    table.OnEditLine(list(lines).index("sys_call_table[0]")); assert calls[-1] == ("jump", KPROBE), calls[-1]
    index = [table.OnGetLine(n)[1] for n in range(table.OnGetSize())]
    table.OnSelectLine(index.index("movjmp")); assert calls[-1] == ("jump", BASE + 0x300), calls[-1]
    table.OnEditLine(index.index("movjmp")); assert calls[-1] == ("jump", BPF), calls[-1]
    table.OnEditLine(index.index("kprobe_me")); assert calls[-1][0] == "msg" and "no handler" in calls[-1][1], calls[-1]

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
    assert crefs == [] and renames == [] and "getblob broke" in out and "hook chain not added" in out, out
    lines = {line[1]: line for line in (m._open_list.OnGetLine(n) for n in range(m._open_list.OnGetSize()))}
    assert lines["traced_a"][3:] == ["memlens_target_%x" % F, "function_trace_call (ftrace)"] and len(lines) == 6, lines
print("hook chain stub test OK (hand-made ELF; fake IDA modules)")

for path in sys.argv[1:2]:
    blob = open(path, "rb").read()
    nalt.get_input_file_path = lambda: path
    database(blob)
    crefs, renames, out = run()
    assert crefs and all(kind == CALL for _, _, kind in crefs), crefs
    second = run()
    assert second[:2] == ([], []), second
    print("%s: first run %d add_cref, %d set_name (%s); second run %d add_cref, %d set_name" % (
        path, len(crefs), len(renames), ", ".join(r[1] for r in renames), len(second[0]), len(second[1])))
    for line in out.splitlines():
        print("  " + line)
    table = m._open_list
    for n in range(table.OnGetSize()):
        print("  row: " + " | ".join(table.OnGetLine(n)))
