#!/usr/bin/env python3
"""Add Volatility hook findings (JSON): Volatility 3 2.28.2's `vol -r json` output of six hook plugins added to the
MemLens list, against FAKE ida_* modules (the ones of tests/test_plugin_stub.py). Checks our logic only; this is not a
test in real IDA.

usage: python3 tests/test_volfind_stub.py [demo kernel.elf] [second sample's kernel.elf]
Always: volfind.py on hand-made JSON (Volatility's 48-bit addresses sign-extended, the plugin a file comes from told by
its 2.28.2 field names, unknown fields, unknown plugins, files that are not JSON, a plugin read twice, nested rows) and
the action on a hand-made kernel ELF whose ftrace trampoline loads an ftrace_ops: an ftrace row with that ops is merged
into the MemLens row (no row repeats it), the other findings become rows with a Source column, Enter and Jump to owner
go to the sign-extended callback, a file of an unknown plugin gives one warning line and the rest still load.
With the two public samples' kernel.elf files (told apart by SHA-256; any other kernel.elf is skipped), also the action
on the JSON recorded from their memory images (tests/fixtures/vol-2.28.2/findings/<sample>, see its README.txt): the
tracepoint, IDT and netfilter rows at the sign-extended addresses, each address at the kernel.elf symbol Volatility
names, netfilter's "Is Hooked" verbatim, the MemLens rows unchanged, and no Volatility row that repeats a MemLens row
(an ftrace row whose ftrace_ops a MemLens row's hook page loads is merged into that row).
Then two mutants, no sign extension and no merge of ftrace rows by ops address, must fail the same checks.
"""
import contextlib, hashlib, io, json, os, runpy, shutil, struct, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan as ps

with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
    builder = runpy.run_path(os.path.join(HERE, "test_patchscan.py"))
m, calls, nalt, names, blobs, comments, kw = g["m"], g["calls"], g["nalt"], g["names"], g["blobs"], g["comments"], g["kw"]
elf, call, BASE, TEXT = builder["elf"], builder["call"], builder["BASE"], builder["TEXT"]
import volfind  # noqa: E402  (memlens_entry put the repository folder on sys.path)

FIXTURES = os.path.join(HERE, "fixtures", "vol-2.28.2", "findings")
FILES = ("tracepoints", "keyboard_notifiers", "check_idt", "check_afinfo", "netfilter", "ftrace-flags")
COLUMNS = ["Address", "Where", "What", "Target", "Handler", "Owner"]
TITLE = "MemLens: patched kernel functions and Volatility findings"
MASK48 = (1 << 48) - 1
DEMO_SHA = "1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5"  # memlens-demo-debian13.zip's kernel.elf
TESTHOOK_SHA = "8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9"  # memlens-demo-testhook.zip's kernel.elf
# What the recorded JSON gives on each public sample (measured): MemLens rows, Volatility rows per plugin, and the MemLens
# rows an ftrace_ops row of Volatility's is merged into (their hook page loads that ops).
EXPECT = {
    "demo": {"memlens": 3, "linux.tracing.tracepoints": 3, "linux.malware.check_idt": 21, "linux.malware.netfilter": 2,
             "linux.tracing.ftrace": 1, "merged": ["do_sys_openat2", "vfs_getattr"]},
    "testhook": {"memlens": 3, "linux.tracing.tracepoints": 0, "linux.malware.check_idt": 21, "linux.malware.netfilter": 2,
                 "linux.tracing.ftrace": 1, "merged": ["__x64_sys_getdents64", "__x64_sys_kill"]},
}
SAMPLES = {DEMO_SHA: "demo", TESTHOOK_SHA: "testhook"}


def sign(value):
    """The test's own sign extension of a 48-bit address (not volfind's, which the mutant changes)."""
    return value | 0xffff000000000000 if value >> 47 & 1 else value


def database(blob, path):
    names.clear()
    names.update({s[2]: s[0] for s in ps.Image(blob).symbols if s[2].startswith(ps.TARGET_PREFIX)})
    blobs.clear()
    comments.clear()
    nalt.get_input_file_path = lambda: path


def lines_of(table):
    return [table.OnGetLine(n) for n in range(table.OnGetSize())]


def show_plain():
    """The rows of Show patched kernel functions (6 columns)."""
    m._open_list = None
    del calls[:]
    assert m.FindPatches().activate(None) == 1, calls
    assert [c[0] for c in m._open_list.cols] == COLUMNS, m._open_list.cols
    return lines_of(m._open_list)


def add_findings(pick):
    """One activation of Add Volatility hook findings with `pick` chosen in the file dialog: (return value, list, Output)."""
    m._open_list = None
    del calls[:]
    kw.ask_file = lambda *a: pick
    result = m.AddVolatilityFindings().activate(None)
    return result, m._open_list, "".join(c[1] for c in calls if c[0] == "msg")


def write(folder, name, data):
    with open(os.path.join(folder, name), "w") as handle:
        handle.write(data if isinstance(data, str) else json.dumps(data, indent=2))


def warnings(out):
    return [line for line in out.splitlines() if line.startswith("[MemLens] warning: ")]


@contextlib.contextmanager
def mutant(name, replacement):
    good = getattr(volfind, name)
    setattr(volfind, name, replacement)
    try:
        yield
    finally:
        setattr(volfind, name, good)


MUTANTS = (("no sign extension", "sign_extend", lambda value: value if isinstance(value, int) and not isinstance(value, bool) else None),
           ("no merge of ftrace rows by ops address", "repeats", lambda finding, by_ops: []))

# --- volfind.py alone -------------------------------------------------------------------------------------------------
assert volfind.VOLATILITY == "2.28.2"
assert volfind.sign_extend(281473643531984) == 0xffffffffb0894ed0  # judge s194: JSON 281473643531984 = 0xffffb0894ed0
assert volfind.sign_extend(0x7fffffffffff) == 0x7fffffffffff  # bit 47 clear: not a kernel address, left as it is
assert volfind.sign_extend(0xffffffff81000000) == 0xffffffff81000000  # already 64 bits
for bad in (None, True, "0xffff8e433cb0", -1, 1 << 64, 1.5):
    assert volfind.sign_extend(bad) is None, bad
with tempfile.TemporaryDirectory() as work:
    keyboard = [{"Address": 0xffffc0001000, "Module": "evilmod", "Symbol": None, "__children": []}]
    idt = [{"Index": 128, "Address": 0xffff8f0012b0, "Module": "__kernel__", "Symbol": "asm_int80_emulation", "__children": []}]
    nested = [{"Symbol Name": "tcp4_seq_afinfo", "Member": "show", "Handler Address": 0xffffc0002000,
               "__children": [{"Symbol Name": "udp4_seq_afinfo", "Member": "show", "Handler Address": 0xffffc0002100, "__children": []}]}]
    write(work, "kb.json", keyboard)
    write(work, "idt.json", idt)
    write(work, "afinfo.json", nested)
    write(work, "empty.json", "\n[]\n")
    loaded = volfind.load([os.path.join(work, name) for name in ("kb.json", "idt.json", "afinfo.json", "empty.json")])
    assert loaded.warnings == [], loaded.warnings
    assert [(name, plugin, count) for name, plugin, count in loaded.read] == [
        ("kb.json", "linux.malware.keyboard_notifiers", 1), ("idt.json", "linux.malware.check_idt", 1),
        ("afinfo.json", "linux.malware.check_afinfo", 2), ("empty.json", None, 0)], loaded.read
    by_plugin = {}
    for finding in loaded.findings:
        by_plugin.setdefault(finding.plugin, []).append(finding)
    assert [(f.address, f.where, f.owner) for f in by_plugin["linux.malware.keyboard_notifiers"]] == [
        (0xffffffffc0001000, "keyboard notifier", "evilmod")], by_plugin
    assert [(f.address, f.where, f.what) for f in by_plugin["linux.malware.check_idt"]] == [
        (0xffffffff8f0012b0, "IDT 0x80", "handler asm_int80_emulation")], by_plugin
    assert [(f.address, f.where) for f in by_plugin["linux.malware.check_afinfo"]] == [
        (0xffffffffc0002000, "afinfo tcp4_seq_afinfo.show"), (0xffffffffc0002100, "afinfo udp4_seq_afinfo.show")], by_plugin
    # Problems: each file gets one warning line at most, and the others still load.
    write(work, "ebpf.json", [{"Address": 1, "Name": "restrict_filesy", "Tag": "e8932b6bae2b9745", "Type": "BPF_PROG_TYPE_LSM", "__children": []}])
    write(work, "broken.json", "Volatility 3 Framework 2.28.2\n[")
    write(work, "object.json", {"Address": 1})
    write(work, "kb-again.json", keyboard)
    write(work, "newer.json", [dict(idt[0], Index=3, Gate="interrupt")])
    loaded = volfind.load([os.path.join(work, name) for name in ("kb.json", "ebpf.json", "broken.json", "object.json", "kb-again.json")])
    assert len(loaded.warnings) == 4 and [w.split(":")[0] for w in loaded.warnings] == ["ebpf.json", "broken.json", "object.json", "kb-again.json"], loaded.warnings
    assert "Volatility 2.28.2" in loaded.warnings[0] and "kb.json" in loaded.warnings[3], loaded.warnings
    assert [(name, plugin, count) for name, plugin, count in loaded.read] == [("kb.json", "linux.malware.keyboard_notifiers", 1)], loaded.read
    loaded = volfind.load([os.path.join(work, "newer.json")])  # a field 2.28.2 does not write: ignored, the row is read
    assert len(loaded.warnings) == 1 and "Gate" in loaded.warnings[0], loaded.warnings
    assert [(f.plugin, f.where) for f in loaded.findings] == [("linux.malware.check_idt", "IDT 0x3")], loaded.findings
    # A folder: every .json file in it, in name order, whatever file was picked; a file too big for findings is skipped.
    write(work, "notes.txt", "not read")
    good_size = volfind.MAX_SIZE
    volfind.MAX_SIZE = 1000
    try:
        write(work, "big.json", [dict(idt[0], Index=n) for n in range(20)])
        loaded = volfind.load_folder(os.path.join(work, "notes.txt"))
    finally:
        volfind.MAX_SIZE = good_size
    assert [name for name, _, _ in loaded.read] == ["afinfo.json", "empty.json", "idt.json", "kb-again.json"], loaded.read
    assert [w.split(":")[0] for w in loaded.warnings] == ["big.json", "broken.json", "ebpf.json", "kb.json", "newer.json", "object.json"], loaded.warnings
    assert "kb-again.json" in loaded.warnings[3] and "idt.json" in loaded.warnings[4], loaded.warnings  # read twice: the first one counts
    assert "notes.txt" not in str(loaded), loaded

# --- the action on a hand-made kernel ELF ----------------------------------------------------------------------------
# An ftrace trampoline whose ftrace_ops sits in a module's data (as in tests/test_hookchain_stub.py), a tracepoint probe
# and a keyboard notifier in the module.
code = bytearray(b"\x90" * TEXT)
def put(offset, data): code[offset:offset + len(data)] = data
ASSIST, THUNK, PROBE, NOTIFIER, OPS, PAGE = BASE + 0x1000, BASE + 0x1100, BASE + 0x1200, BASE + 0x1300, BASE + TEXT + 0x40, BASE + 0x2000
put(PAGE - BASE + 0x74, b"\x48\x8b\x15" + struct.pack("<i", (PAGE + 0xdd) - (PAGE + 0x7b)))  # mov rdx, [rip+X]: the ops slot
put(PAGE - BASE + 0x94, call(PAGE + 0x94, ASSIST))
put(PAGE - BASE + 0xd8, b"\xc3\xcc\x00\x00\x00" + struct.pack("<Q", OPS))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, PAGE))
rodata = b"Linux version 6.12\0".ljust(0x40, b"\0") + struct.pack("<QQQ", THUNK, ASSIST, 1)
symbols = [("__x64_sys_getdents64", BASE, 0x100), ("ftrace_ops_assist_func", ASSIST, 0x100), ("evilmod.fh_ftrace_thunk", THUNK, 0x100),
           ("evilmod.probe_sched_switch", PROBE, 0x100), ("evilmod.kb_notify", NOTIFIER, 0x100),
           ("linux_banner", BASE + TEXT, 0x20), ("evilmod.hooks", OPS - 0x20, 0x80), ("%s%x" % (ps.TARGET_PREFIX, PAGE), PAGE, 0)]
blob = elf(code, symbols, rodata)
HEAP_OPS = 0xffff88fd495fcb00
FTRACE = [{"ftrace_ops address": OPS & MASK48, "Callback": None, "Callback address": THUNK & MASK48, "Hooked symbols": None,
           "Module": "evilmod", "Module address": BASE & MASK48, "__children": []},
          {"ftrace_ops address": HEAP_OPS & MASK48, "Callback": "call_direct_funcs", "Callback address": ASSIST & MASK48,
           "Hooked symbols": None, "Module": "__kernel__", "Module address": BASE & MASK48, "__children": []}]
TRACEPOINTS = [{"tracepoint": "sched_switch", "tracepoint address": (BASE + TEXT) & MASK48, "Probe": "probe_sched_switch",
                "Probe address": PROBE & MASK48, "Probe priority": 10, "Module": "evilmod", "Module address": BASE & MASK48,
                "__children": []}]
KEYBOARD = [{"Address": NOTIFIER & MASK48, "Module": "evilmod", "Symbol": None, "__children": []}]


def check_handmade(work):
    """Errors of the hand-made case (empty when right)."""
    errors = []
    result, table, out = add_findings(os.path.join(work, "tracepoints.json"))
    if result != 1 or table is None:
        return ["the action did not show the list (%r):\n%s" % (result, out)]
    if [c[0] for c in table.cols] != COLUMNS + ["Source"] or table.title != TITLE:
        errors.append("columns %s, title %r" % (table.cols, table.title))
    rows = lines_of(table)
    want = [["%X" % BASE, "__x64_sys_getdents64", "call to memory with no symbol", "ftrace_tramp___x64_sys_getdents64",
             "ftrace_ops_assist_func (ftrace)", "evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)",
             "MemLens; Volatility linux.tracing.ftrace: same ftrace_ops"],
            ["%X" % (ASSIST), "ftrace_ops %#x" % HEAP_OPS, "callback call_direct_funcs, hooked symbols -", "ftrace_ops_assist_func",
             "", "__kernel__", "Volatility linux.tracing.ftrace"],
            ["%X" % NOTIFIER, "keyboard notifier", "notifier_call -", "evilmod.kb_notify", "", "evilmod",
             "Volatility linux.malware.keyboard_notifiers"],
            ["%X" % PROBE, "tracepoint sched_switch", "probe probe_sched_switch, priority 10", "evilmod.probe_sched_switch", "",
             "evilmod", "Volatility linux.tracing.tracepoints"]]
    if sorted(rows) != sorted(want):
        errors.append("rows:\n  %s\nwant:\n  %s" % ("\n  ".join(map(str, rows)), "\n  ".join(map(str, want))))
    if len(warnings(out)) != 1 or "ebpf.json" not in warnings(out)[0]:
        errors.append("want one warning line, for ebpf.json: %s" % warnings(out))
    for n, row in enumerate(rows):
        if row[6].startswith("Volatility"):
            del calls[:]
            table.OnSelectLine(n)
            table.OnInsertLine(n)  # Jump to owner: the callback, which is the module's (Owner column)
            if calls != [("jump", int(row[0], 16))] * 2:
                errors.append("Enter / Jump to owner on %s: %s" % (row[1], calls))
    return errors


with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(blob)
    findings = os.path.join(work, "vol")
    os.mkdir(findings)
    write(findings, "ftrace.json", FTRACE)
    write(findings, "tracepoints.json", TRACEPOINTS)
    write(findings, "keyboard_notifiers.json", KEYBOARD)
    write(findings, "check_afinfo.json", "[]")
    write(findings, "ebpf.json", [{"Address": 1, "Name": "x", "Tag": "t", "Type": "BPF_PROG_TYPE_LSM", "__children": []}])
    database(blob, path)
    plain = show_plain()
    errors = check_handmade(findings)
    assert not errors, "\n".join(errors)
    assert show_plain() == plain  # the plain list is unchanged afterwards (6 columns, no Volatility row)
    for name, attribute, replacement in MUTANTS:
        with mutant(attribute, replacement):
            database(blob, path)
            assert check_handmade(findings), "mutant %r passed the hand-made checks" % name
    # Nothing read at all (every file skipped): a warning, no list.
    empty = os.path.join(work, "nothing")
    os.mkdir(empty)
    write(empty, "ebpf.json", [{"Name": "x", "__children": []}])
    result, table, out = add_findings(os.path.join(empty, "ebpf.json"))
    assert result == 0 and table is None and [c for c in calls if c[0] == "ui"], (result, calls)
    # Cancel in the file dialog: nothing happens.
    result, table, out = add_findings("")
    assert result == 0 and table is None and calls == [], calls
    print("hand-made: 4 rows with a Source column (1 MemLens row with Volatility's ftrace_ops merged into it, 3 Volatility "
          "rows), one warning line for the unknown file; %d mutants fail" % len(MUTANTS))


# --- the two public samples ------------------------------------------------------------------------------------------
def memlens_ops(image):
    """{ftrace_ops address: the MemLens rows (function names) whose hook page loads it}."""
    found = {}
    for _, function, _, _, target in ps.scan(None, image):
        slot = ps.ftrace_ops_slot(image, target) if target and ps.copied_page(image, target) else None
        if slot:
            found.setdefault(slot[1], []).append(function)
    return found


def check_sample(sample, image, plain):
    """Errors of the list the action shows for this sample's recorded JSON (empty when right)."""
    errors = []
    folder = os.path.join(FIXTURES, sample)
    result, table, out = add_findings(os.path.join(folder, "tracepoints.json"))
    if result != 1 or table is None:
        return ["the action did not show the list (%r):\n%s" % (result, out)]
    if [c[0] for c in table.cols] != COLUMNS + ["Source"]:
        errors.append("columns %s" % table.cols)
    if warnings(out) or not all("%s.json" % name in out for name in FILES):
        errors.append("want the six files read and no warning:\n%s" % out)
    rows = lines_of(table)
    expect = EXPECT[sample]
    data = {}
    for name in FILES:
        with open(os.path.join(folder, name + ".json")) as handle:
            data[name] = json.load(handle)
    mine = [row for row in rows if row[6].startswith("MemLens")]
    theirs = [row for row in rows if row[6].startswith("Volatility ")]
    if [row[:6] for row in mine] != plain or len(mine) != expect["memlens"] or len(mine) + len(theirs) != len(rows):
        errors.append("the MemLens rows are not those of Show patched kernel functions")
    by_plugin = {}
    for row in theirs:
        by_plugin.setdefault(row[6][len("Volatility "):], []).append(row)
    counts = {plugin: len(by_plugin.get(plugin, [])) for plugin in expect if plugin.startswith("linux.")}
    if counts != {plugin: count for plugin, count in expect.items() if plugin.startswith("linux.")} or \
            set(by_plugin) - set(counts):
        errors.append("Volatility rows per plugin %s, measured %s" % ({p: len(r) for p, r in by_plugin.items()}, expect))
    # Each tracepoint probe, IDT handler and netfilter hook at the sign-extended address, which is the kernel.elf symbol
    # Volatility names (Target is kernel.elf's own name for the address).
    for plugin, name, address, symbol in (("linux.tracing.tracepoints", "tracepoints", "Probe address", "Probe"),
                                          ("linux.malware.check_idt", "check_idt", "Address", "Symbol"),
                                          ("linux.malware.netfilter", "netfilter", "Handler", "Symbol")):
        got = [(int(row[0], 16), row[3]) for row in by_plugin.get(plugin, [])]
        want = [(sign(record[address]), record[symbol]) for record in data[name]]
        if got != want:
            errors.append("%s rows (address, kernel.elf name) %s, Volatility printed %s (sign-extended)"
                          % (plugin, [(hex(a), n) for a, n in got], [(hex(a), n) for a, n in want]))
        if any(image.symbol_at(sign(record[address])) != record[symbol] for record in data[name]):
            errors.append("%s: an address is not at the symbol Volatility names in this kernel.elf" % plugin)
    hooked = [row[2].rsplit("; ", 1)[-1] for row in by_plugin.get("linux.malware.netfilter", [])]
    if hooked != ["Is Hooked: %s" % record["Is Hooked"] for record in data["netfilter"]] or \
            any(record["Is Hooked"] != "False" for record in data["netfilter"]):
        errors.append("netfilter rows do not say Volatility's Is Hooked verbatim: %s" % hooked)
    # No row repeats a MemLens row: an ftrace row whose ops a MemLens row's hook page loads is merged into that row.
    ops = memlens_ops(image)
    own = [int(row[1].split()[1], 16) for row in by_plugin.get("linux.tracing.ftrace", [])]
    merged = sorted(row[1] for row in mine if "Volatility linux.tracing.ftrace" in row[6])
    printed = [sign(record["ftrace_ops address"]) for record in data["ftrace-flags"]]
    if [o for o in own if o in ops]:
        errors.append("Volatility ftrace rows repeat MemLens rows: ops %s" % [hex(o) for o in own if o in ops])
    if merged != expect["merged"] or merged != sorted(f for o in printed if o in ops for f in ops[o]):
        errors.append("MemLens rows with Volatility's ftrace_ops merged in: %s, measured %s" % (merged, expect["merged"]))
    if sorted(own) != sorted(o for o in printed if o not in ops):
        errors.append("ftrace rows of their own %s; Volatility printed %s" % ([hex(o) for o in own], [hex(o) for o in printed]))
    callbacks = {sign(record["ftrace_ops address"]): record["Callback"] for record in data["ftrace-flags"]}
    if any(row[3] != callbacks.get(int(row[1].split()[1], 16)) for row in by_plugin.get("linux.tracing.ftrace", [])):
        errors.append("an ftrace row's callback is not at the kernel.elf symbol Volatility names")
    if {(row[0], row[1]) for row in theirs} & {(row[0], row[1]) for row in mine}:
        errors.append("a Volatility row has the Address and Where of a MemLens row")
    for n, row in enumerate(rows):
        if row[6].startswith("Volatility linux.tracing.tracepoints"):
            del calls[:]
            table.OnSelectLine(n)
            if calls != [("jump", int(row[0], 16))]:
                errors.append("Enter on %s: %s" % (row[1], calls))
    return errors


for path in sys.argv[1:]:
    with open(path, "rb") as handle:
        blob = handle.read()
    sample = SAMPLES.get(hashlib.sha256(blob).hexdigest())
    if sample is None:
        print("SKIP: %s is neither public sample's kernel.elf (by SHA-256): no recorded Volatility JSON for it" % path)
        continue
    image = ps.Image(blob)
    database(blob, path)
    plain = show_plain()
    errors = check_sample(sample, image, plain)
    assert not errors, "%s:\n  %s" % (sample, "\n  ".join(errors))
    database(blob, path)
    result, table, out = add_findings(os.path.join(FIXTURES, sample, "tracepoints.json"))  # again, for its Output lines
    print("%s (%s): %d rows: %d MemLens, %s; MemLens rows with Volatility's ftrace_ops merged in: %s" % (
        sample, path, table.OnGetSize(), EXPECT[sample]["memlens"],
        ", ".join("%d %s" % (count, plugin) for plugin, count in EXPECT[sample].items() if plugin.startswith("linux.")),
        ", ".join(EXPECT[sample]["merged"])))
    for line in out.splitlines():
        if "Volatility" in line:
            print("  " + line)
    for row in lines_of(table):
        if not row[1].startswith("IDT "):
            print("  row: " + " | ".join(row))
    print("  (and %d IDT rows)" % sum(row[1].startswith("IDT ") for row in lines_of(table)))
    for name, attribute, replacement in MUTANTS:
        with mutant(attribute, replacement):
            database(blob, path)
            assert check_sample(sample, image, plain), "mutant %r passed the %s checks" % (name, sample)
    print("  %d mutants fail the %s checks" % (len(MUTANTS), sample))
print("volfind stub tests OK")
