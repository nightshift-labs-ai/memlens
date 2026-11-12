#!/usr/bin/env python3
"""Runs the plugin against FAKE ida_* modules. Checks our logic only; this is not a test in real IDA."""
import json, os, sys, tempfile, types
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)
calls = []
kw = types.ModuleType("ida_kernwin")
class handler: pass
kw.action_handler_t = handler; kw.action_desc_t = lambda *a: a; kw.SETMENU_APP = 1; kw.AST_ENABLE_ALWAYS = 1
kw.register_action = lambda d: calls.append(("reg", d[0])) or True
kw.attach_action_to_menu = lambda m, a, f: calls.append(("menu", m, a)) or True
kw.unregister_action = lambda a: calls.append(("unreg", a)) or True
kw.msg = lambda s: calls.append(("msg", s)); kw.info = kw.warning = lambda s: calls.append(("ui", s))
kw.show_wait_box = kw.replace_wait_box = lambda s: None; kw.hide_wait_box = lambda: None; kw.user_cancelled = lambda: False
class chooser:
    CHCOL_HEX = 1 << 24; NOTHING_CHANGED = 0; CH_CAN_EDIT = 1024; CH_CAN_INS = 256
    def __init__(self, title, cols, flags=0, popup_names=None):
        self.title, self.cols, self.flags, self.popup_names = title, cols, flags, popup_names
    def Show(self): calls.append(("show", self.title))
kw.Choose = chooser; kw.jumpto = lambda ea: calls.append(("jump", ea))
ti = types.ModuleType("ida_typeinf"); ti.get_idati = lambda: "til"
class tinfo:
    size = 0
    def get_named_type(self, til, name):
        self.size = {"demo": 8, "shrunk": 2}.get(name, 0); return bool(self.size)
    def get_size(self): return self.size
ti.tinfo_t = tinfo
api = types.ModuleType("ida_idaapi"); api.plugin_t = object; api.PLUGIN_KEEP = 2; api.PLUGIN_HIDE = 0x10
idc = types.ModuleType("idc"); idc.PT_SIL = 1; idc.PT_PAK1 = 0x10
def parse(text, flags):
    calls.append(("parse", text, flags)); return text.count("BADTOKEN")
idc.parse_decls = parse
idc.BADADDR = -1
idc.SEGATTR_PERM = 5
code_eas = set()
idc.get_segm_attr = lambda ea, attr: 5 if ea in code_eas else 6  # 5 = read+exec, 6 = read+write
names = {}
def set_names(table):
    """The database's names: both the one-by-one lookup and idautils.Names() read this table."""
    names.clear(); names.update(table)
idc.get_name_ea_simple = lambda n: names.get(n, idc.BADADDR)
autils = types.ModuleType("idautils"); autils.Names = lambda: [(ea, n) for n, ea in names.items()]
set_names({"demo_var": 0x1000})
idc.get_first_seg = lambda: idc.BADADDR  # no per-CPU sections unless a case adds them
idc.get_next_seg = lambda ea: idc.BADADDR
idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
nalt = types.ModuleType("ida_nalt"); nalt.get_input_file_path = lambda: ""
nalt.retrieve_input_file_sha256 = lambda: None  # no stored hash: nothing to compare a picked file with
# Hook chain: xrefs and names are recorded; flag values as in the IDA 9.1-9.4 stubs (ida_xref.pyi, ida_name.pyi).
xref = types.ModuleType("ida_xref"); xref.fl_CN, xref.fl_JN, xref.XREF_USER, xref.dr_O = 17, 19, 32, 1
xref.add_cref = lambda frm, to, kind: calls.append(("cref", frm, to, kind)) or True
xref.add_dref = lambda frm, to, kind: calls.append(("dref", frm, to, kind)) or True
iname = types.ModuleType("ida_name"); iname.SN_NOWARN, iname.SN_NON_AUTO = 256, 64
iname.get_name = lambda ea: next((n for n, a in names.items() if a == ea), "")
def set_name(ea, name, flags):
    calls.append(("setname", ea, name, flags))
    if names.get(name, ea) != ea:
        return False  # used at another address: IDA refuses without SN_FORCE
    for old in [n for n, a in names.items() if a == ea]:
        del names[old]
    names[name] = ea
    return True
iname.set_name = set_name
blobs = {}
nnode = types.ModuleType("ida_netnode")
class netnode:
    def __init__(self, name, namelen=0, create=False): self.name = name
    def getblob(self, start, tag): return blobs.get((self.name, start, tag))
    def setblob(self, data, start, tag): blobs[(self.name, start, tag)] = bytes(data); return True
nnode.netnode = netnode
comments = {}
idc.set_cmt = lambda ea, c, r: calls.append(("cmt", ea, c)) or comments.__setitem__(ea, c)
idc.get_cmt = lambda ea, r: comments.get(ea)
dbytes = types.ModuleType("ida_bytes"); dbytes.get_bytes = lambda ea, size: b"Linux version 1.0"[:size]
dummy_names = set()  # addresses whose name IDA made up (sub_..., loc_...): not a real name
dbytes.get_flags = lambda ea: ea  # the fake flags are the address, for has_user_name below
dbytes.has_user_name = lambda flags: bool(iname.get_name(flags)) and flags not in dummy_names
kw.ASKBTN_NO, kw.ASKBTN_YES = 0, 1
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_typeinf=ti, ida_nalt=nalt, idc=idc, ida_bytes=dbytes, idautils=autils,
                   ida_xref=xref, ida_name=iname, ida_netnode=nnode)
import memlens_entry as m
isf = {"base_types": {"unsigned int": {"size": 4, "signed": False, "kind": "int"}},
       "enums": {}, "symbols": {"demo_var": {"address": 1, "type": {"kind": "struct", "name": "demo"}}, "absent": {"address": 2, "type": {"kind": "struct", "name": "demo"}}, "fn": {"address": 3, "type": {"kind": "base", "name": "void"}}}, "user_types": {"demo": {"kind": "struct", "size": 8, "fields": {"a": {"offset": 4, "type": {"kind": "base", "name": "unsigned int"}}, "private": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}}}, "shrunk": {"kind": "struct", "size": 4, "fields": {"a": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}}}, "gone": {"kind": "struct", "size": 4, "fields": {"a": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}}}}}
with tempfile.TemporaryDirectory() as t:
    p = os.path.join(t, "x.json"); json.dump(isf, open(p, "w"))
    kw.ask_file = lambda *a: p
    plugin = m.PLUGIN_ENTRY(); assert plugin.init() == api.PLUGIN_KEEP
    assert m.ApplyTypes().activate(None) == 1
    parsed = "\n".join(c[1] for c in calls if c[0] == "parse")
    assert all(c[2] == idc.PT_SIL | idc.PT_PAK1 for c in calls if c[0] == "parse")
    assert "struct demo {" in parsed and "__pad_" not in parsed and "unsigned int private_;" in parsed, parsed
    result = m.apply_types(p)
    assert result["rejected"] == [] and result["missing"] == ["gone"] and result["wrong_size"] == ["shrunk"], result
    assert "differing from the ISF: 1" in m.report(result)
    st = result["stats"]
    assert (st["globals_declared"], st["globals_typed"], st["globals_failed"], st["globals_not_in_database"]) == (2, 1, 0, 1), st
    assert "typed 1 of the 2 globals the ISF declares, plus 0 per-CPU variables in every CPU's copy; 0 failed; 1 have no symbol in this database" in m.report(result)
    assert "CANCELLED" not in m.report(result) and "cancelled" not in result
    big = dict(result, stats=dict(st, globals_typed=33500, globals_declared=79316, percpu_typed=1388, globals_failed=1234,
                                  globals_not_in_database=45350, globals_skipped_code=1078))
    assert "typed 33,500 of the 79,316 globals" in m.report(big) and "45,350 have no symbol" in m.report(big), m.report(big)
    assert "plus 1,388 per-CPU" in m.report(big) and "1,234 failed" in m.report(big), m.report(big)
    assert "left 1,078 names alone" in m.report(big), m.report(big)
    kw.user_cancelled = lambda: True  # Cancel during the type import: nothing typed, the report says so
    r = m.apply_types(p)
    assert r["cancelled"].startswith("while importing types, after 0 of") and "globals_typed" not in r["stats"], r
    assert m.report(r).startswith("[MemLens] CANCELLED while importing types"), m.report(r)
    answers_c = iter([False, True])  # Cancel at the first globals checkpoint
    kw.user_cancelled = lambda: next(answers_c)
    r = m.apply_types(p)
    assert r["cancelled"] == "while typing globals, after 0 of 2" and r["stats"]["globals_typed"] == 0, r
    kw.user_cancelled = lambda: False
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; m.apply_types(p)
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "struct demo demo_var;")], calls
    # A per-CPU variable: no plain symbol, one copy per CPU named cpu<N>.<name> by the exporter.
    set_names({"demo_var": 0x1000, "cpu0.absent": 0x2000, "cpu1.absent": 0x2100})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert (st["globals_typed"], st["percpu_typed"], st["globals_not_in_database"]) == (1, 1, 0), st
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x2000, "struct demo absent;"), (0x2100, "struct demo absent;"), (0x1000, "struct demo demo_var;")], calls
    # If IDA stored '.' as '_', cpu<N>_<name> is taken, but only inside that CPU's per-CPU section.
    idc.get_segm_name = lambda ea: {0x2000: ".percpu.cpu0", 0x2100: "_percpu_cpu1", 0x4000: ".data"}.get(ea, "")
    set_names({"demo_var": 0x1000, "cpu0_absent": 0x2000, "cpu1_absent": 0x2100})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert (st["globals_typed"], st["percpu_typed"], st["globals_not_in_database"]) == (1, 1, 0), st
    set_names({"demo_var": 0x1000, "cpu0_absent": 0x4000})  # a real symbol elsewhere
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert (st["percpu_typed"], st["globals_not_in_database"]) == (0, 1), st
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;")], calls
    # A name the ISF declares as a variable but which is code here (schedule, strlen): never retyped.
    set_names({"demo_var": 0x1000})
    code_eas.add(0x1000)
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; result = m.apply_types(p); st = result["stats"]
    assert (st["globals_typed"], st["globals_skipped_code"]) == (0, 1) and not [c for c in calls if c[0] == "settype"], (st, calls)
    assert "left 1 names alone" in m.report(result)
    code_eas.clear()
    # Linux 7.0 style: a plain symbol for the boot template plus one copy per CPU; all of them are typed.
    set_names({"demo_var": 0x1000, "cpu0.demo_var": 0x3000, "cpu1.demo_var": 0x3100})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert (st["globals_typed"], st["percpu_typed"], st["globals_failed"], st["globals_not_in_database"]) == (1, 1, 0, 1), st
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3000, "struct demo demo_var;"), (0x3100, "struct demo demo_var;")], calls
    # A CPU whose per-CPU area was not in the image has no section (the exporter keeps real CPU numbers): CPU 2 is still typed.
    segs = {0x1000: ".data", 0x3000: ".percpu.cpu0", 0x3200: "_percpu_cpu2"}
    idc.get_first_seg = lambda: min(segs)
    idc.get_next_seg = lambda ea: min([s for s in segs if s > ea], default=idc.BADADDR)
    idc.get_segm_name = lambda ea: segs.get(ea, "")
    assert m.percpu_cpus() == [0, 2]
    set_names({"demo_var": 0x1000, "cpu0.demo_var": 0x3000, "cpu2.demo_var": 0x3200})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert st["percpu_typed"] == 1, st
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3000, "struct demo demo_var;"), (0x3200, "struct demo demo_var;")], calls
    # A partly mapped per-CPU area is split by the exporter into .percpu.cpu<N>.<k> sections: that CPU is still typed.
    segs = {0x1000: ".data", 0x3000: ".percpu.cpu0", 0x3100: ".percpu.cpu1.0", 0x3180: "_percpu_cpu1_1", 0x3200: ".percpu.cpu2", 0x3300: ".percpu.cpu10"}
    assert m.percpu_cpus() == [0, 1, 2, 10]
    assert [m.segment_cpu(n) for n in (".percpu.cpu1x", ".percpu.cpu", "percpu.cpu3.", ".data.percpu", None)] == [None] * 5
    set_names({"demo_var": 0x1000, "cpu0.demo_var": 0x3000, "cpu1_demo_var": 0x3180, "cpu2.demo_var": 0x3200})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert st["percpu_typed"] == 1, st
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3000, "struct demo demo_var;"), (0x3180, "struct demo demo_var;"), (0x3200, "struct demo demo_var;")], calls
    # A listed CPU without a copy of this variable is skipped; later CPUs are still typed.
    segs = {0x1000: ".data", 0x3000: ".percpu.cpu0", 0x3100: ".percpu.cpu1", 0x3200: ".percpu.cpu2"}
    set_names({"demo_var": 0x1000, "cpu0.demo_var": 0x3000, "cpu2.demo_var": 0x3200})
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3000, "struct demo demo_var;"), (0x3200, "struct demo demo_var;")], calls
    # The per-CPU copies come from one pass over the names (percpu_index): '.' beats '_' in either order, a '_'
    # copy outside its CPU's section and a zero-padded or unlisted CPU number are never taken.
    # (the fake get_segm_name knows section starts only, so the '_' copy sits at the start of CPU 1's second piece)
    segs = {0x1000: ".data", 0x3000: ".percpu.cpu0", 0x3100: ".percpu.cpu1", 0x3108: ".percpu.cpu1.1", 0x3200: ".percpu.cpu2", 0x4000: ".data"}
    assert m.segment_cpu(segs[0x3108]) == 1
    for table in ({"cpu1_demo_var": 0x3108, "cpu1.demo_var": 0x3100}, {"cpu1.demo_var": 0x3100, "cpu1_demo_var": 0x3108}):
        set_names(dict(table, demo_var=0x1000, **{"cpu0_demo_var": 0x4000, "cpu02.demo_var": 0x3208, "cpu3.demo_var": 0x3300}))
        assert m.percpu_index(m.percpu_cpus()) == {"demo_var": {1: 0x3100}}, m.percpu_index(m.percpu_cpus())
        calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
        assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3100, "struct demo demo_var;")], calls
    # A name list without the per-CPU copies (IDA can keep names out of it): the copies are looked up one by one.
    set_names({"demo_var": 0x1000, "cpu1.demo_var": 0x3100})
    autils.Names = lambda: [(0x1000, "demo_var")]
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3100, "struct demo demo_var;")], calls
    autils.Names = lambda: [(ea, n) for n, ea in names.items()]
    # Only one copy kept out of the name list (hide_name, SN_NOLIST): the listed CPU missing from the index is looked up.
    set_names({"demo_var": 0x1000, "cpu0.demo_var": 0x3000, "cpu1.demo_var": 0x3100})
    autils.Names = lambda: [(0x1000, "demo_var"), (0x3000, "cpu0.demo_var")]
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3000, "struct demo demo_var;"), (0x3100, "struct demo demo_var;")], calls
    # A name list holding only a rejected cpu<N>_<name> (outside its section) still counts as "no copy listed".
    set_names({"demo_var": 0x1000, "cpu0_demo_var": 0x4000, "cpu1.demo_var": 0x3100})
    autils.Names = lambda: [(0x1000, "demo_var"), (0x4000, "cpu0_demo_var")]
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; st = m.apply_types(p)["stats"]
    assert [c[1:] for c in calls if c[0] == "settype"] == [(0x1000, "struct demo demo_var;"), (0x3100, "struct demo demo_var;")], calls
    autils.Names = lambda: [(ea, n) for n, ea in names.items()]
    # The index gives exactly what the one-by-one lookup gives, on random databases (both read the same names).
    import random
    rng = random.Random(146)
    for _ in range(3000):
        segs = {0x1000: ".data", 0x9000: ".text"}
        segs.update({0x10000 * (c + 1): rng.choice([".percpu.cpu%d", "_percpu_cpu%d", ".percpu.cpu%d.0"]) % c for c in rng.sample(range(12), rng.randint(1, 5))})
        cpus = m.percpu_cpus()
        table = {}
        for _ in range(rng.randint(0, 12)):
            cpu, var = rng.randint(0, 12), rng.choice(["a", "b", "a_b", "b.c"])
            symbol = rng.choice(["cpu%d.%s", "cpu%d_%s", "cpu0%d.%s", "xcpu%d.%s", "mod.cpu%d_%s"]) % (cpu, var)
            table[symbol] = rng.choice([0x10000 * (cpu + 1) + 8 * rng.randint(0, 3), 0x1000, 0x10000 * rng.randint(1, 13)])
        set_names(table)
        index = m.percpu_index(cpus)
        for var in ("a", "b", "a_b", "b.c", "c"):
            assert list(m.percpu_copies(var, cpus, index)) == list(m.percpu_copies(var, cpus)), (segs, table, var)
    idc.get_first_seg = lambda: idc.BADADDR
    set_names({"demo_var": 0x1000})
    assert sum(c[0] == "reg" for c in calls) == 3 and sum(c[0] == "menu" for c in calls) == 3
    cmd = m.export_command("/bin/vol", "/x/m.lime", "/out", "/sym")
    assert cmd[-1] == "linux.kernel2elf.Kernel2Elf" and "/x/m.lime" in cmd and "/sym" in cmd
    decls = ["a;", "BADTOKEN;", "b;", "c;", "BADTOKEN2;"]
    seen = []
    assert m.isf2c.import_in_batches(decls, lambda t: seen.append(t) or t.count("BADTOKEN"), batch=4) == ["BADTOKEN;", "BADTOKEN2;"]
    assert sum("c;" in t.split() for t in seen) >= 1
    with tempfile.TemporaryDirectory() as f:
        assert os.path.isfile(os.path.join(m.symbols_folder(p, f), "linux", "x.json"))
    code, out, err = m.run_cancellable([sys.executable, "-c", "import sys; print('written\\tkernel-1.elf\\t0x0\\t5'); sys.stderr.write('boom'); sys.exit(3)"])
    assert code == 3 and err == b"boom" and m.written_file(out) == "kernel-1.elf", (code, out, err)
    assert m.written_file(b"") == "kernel.elf"
    # IDA 9.5 sets PYTHONHOME to its own Python's prefix; Volatility (another Python) must not inherit it.
    os.environ["PYTHONHOME"] = os.path.join(tempfile.gettempdir(), "no-such-ida-python-prefix")
    try:
        code2, out2, err2 = m.run_cancellable([sys.executable, "-c", "print('ok')"])
    finally:
        del os.environ["PYTHONHOME"]
    assert code2 == 0 and out2.strip() == b"ok", err2
    # Export failure text: Volatility's own explanation (stdout) is shown, plus a hint for the missing-symbols case
    vol_out = b"A symbol table requirement was not fulfilled.  Please verify that:\n\tYou have the correct symbol file\n"
    vol_err = b"Unable to validate the plugin requirements: ['plugins.Kernel2Elf.kernel.symbol_table_name']\n"
    ftext = m.export_failure_text(vol_out, vol_err, False)
    assert "a fresh pip install has none" in ftext and "A symbol table requirement" in ftext and "symbol_table_name" in ftext, ftext
    ftext = m.export_failure_text(vol_out, vol_err, True)
    assert "built for another kernel" in ftext and "fresh pip install" not in ftext, ftext
    ftext = m.export_failure_text(b"", b"Traceback ... OSError: disk full", True)
    assert "no symbols" not in ftext and "disk full" in ftext, ftext
    # Volatility's quoted output starts at a whole line (it began with "2.28.2", the rest of a cut-off line).
    assert m.tail("Volatility 3 Framework 2.28.2\n\nUnsatisfied requirement x\n", 30) == "Unsatisfied requirement x"
    assert m.tail("x" * 50, 10) == "x" * 10 and m.tail("ab\ncd", 10) == "ab\ncd"
    assert m.tail("aaaa\nbbbb\ncccc", 9) == "bbbb\ncccc" and m.tail("aaaa\nbbbb\ncccc", 8) == "cccc"  # cut at a line start
    assert m.tail("aaaa\n\nbbbb", 5) == "bbbb" and m.tail("aaaa\nbbbb\ncccc", 10) == "bbbb\ncccc"
    # An old Volatility (seen with 2.11.0) cannot load the exporter: argparse says "invalid choice" and lists the rest.
    old_out = b"Volatility 3 Framework 2.11.0\n"
    old_err = (b"usage: vol [-h] ... plugin ...\nvol: error: argument plugin: invalid choice linux.kernel2elf.Kernel2Elf "
               b"(choose from banners.Banners, ..., windows.registry.hivescan.HiveScan)\n")
    ftext = m.export_failure_text(old_out, old_err, True)
    assert "This Volatility (2.11.0) could not load MemLens' exporter" in ftext and "volatility3==2.28.2" in ftext, ftext
    assert "built for another kernel" not in ftext, ftext
    ftext = m.export_failure_text(b"", old_err, False)
    assert "This Volatility could not load" in ftext and "fresh pip install" not in ftext, ftext
    # Real Volatility 2.28.2 (recorded: empty stdout, argparse usage + "invalid choice" on stderr, exit 2) prints no
    # version before the plugin-name check, so the text must cover both cases rather than assume an old one.
    recorded = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "invalid_choice_vol2.28.2.stderr"), "rb").read()
    ftext = m.export_failure_text(b"", recorded, True)
    assert "vol -h" in ftext and "-vvv" in ftext and "volatility3==2.28.2" in ftext and "(2." not in ftext.split("Volatility said")[0], ftext
    # The same error from the tested version or a newer one is not the old-API case: no install-2.28.2 advice.
    for newer in (b"2.28.2", b"2.30.0", b"3.0"):
        ftext = m.export_failure_text(b"Volatility 3 Framework " + newer + b"\n", old_err, True)
        assert "not older than 2.28.2" in ftext and "volatility3==2.28.2" not in ftext, (newer, ftext)
    ftext = m.export_failure_text(b"Volatility 3 Framework 2.28.1\n", old_err, True)
    assert "volatility3==2.28.2" in ftext and "not older" not in ftext, ftext
    # Export "succeeded" on a kernel file from disk: recorded Volatility 2.28.2 output for the demo kernel.elf given as
    # the image (fixtures/export_from_kernel_file.txt) -> 0 bytes of .text -> not reported as a usable export.
    fixture = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "export_from_kernel_file.txt"), "rb").read()
    probs = m.export_problems(fixture)
    assert len(probs) == 1 and ".text: 0 bytes" in probs[0] and "use Apply kernel types" in probs[0], probs
    good = (b"Volatility 3 Framework 2.28.2\n\nItem\tName\tAddress\tCount\n\nsection\t.text\t0xffffffff8e200000\t16777216\n"
            b"percpu\tcpu0\t0xffff88807dc00000\t776\npercpu\tcpu1\t0xffff88807dd00000\t776\nwritten\tkernel.elf\t0x0\t5\n")
    assert m.export_problems(good) == [], m.export_problems(good)
    same = good.replace(b"0xffff88807dd00000", b"0xffff88807dc00000")
    probs = m.export_problems(same)
    assert len(probs) == 1 and "same address" in probs[0] and "All 2 per-CPU" in probs[0], probs
    assert m.export_problems(b"") == [], "no rows at all (unknown output) must not be called a failure"
    rep = m.report({"stats": {"structs": 9734, "unions": 1715, "enums": 2149, "bitfields_as_storage": 0, "skipped": 2,
                              "globals_declared": 79, "globals_typed": 33500, "globals_failed": 0, "globals_not_in_database": 1},
                    "rejected": [], "missing": [], "wrong_size": []})
    assert "declarations generated from the ISF: 9,734 structs, 1,715 unions, 2,149 enums, 2 skipped\n" in rep, rep
    assert "{" not in rep and "globals_typed" not in rep, rep
    table = m.PatchList([(0x10, "fn", "what", "tgt", "handler_fn (ftrace)", 0x30, "evil.cb (ftrace_ops evil.ops)", 0x50),
                         (0x40, "sys_call_table[1]", "odd", "x", "", None, "", None),
                         (0x60, "gn", "what", "tgt", "assist (ftrace)", 0x70, "ftrace_ops at 0xffff888000001000 (no symbol: heap)", None)])
    assert [c[0] for c in table.cols] == ["Address", "Where", "What", "Target", "Handler", "Owner"], table.cols
    assert table.flags & kw.Choose.CH_CAN_EDIT and table.popup_names[2] == "Jump to handler", (table.flags, table.popup_names)
    assert table.flags & kw.Choose.CH_CAN_INS and table.popup_names[0] == "Jump to owner", (table.flags, table.popup_names)
    assert table.OnGetSize() == 3 and table.OnGetLine(0) == ["10", "fn", "what", "tgt", "handler_fn (ftrace)", "evil.cb (ftrace_ops evil.ops)"]
    assert table.OnSelectLine(0) == (0,) and calls[-1] == ("jump", 0x10)
    assert table.OnEditLine(0) == (0,) and calls[-1] == ("jump", 0x30)  # Ctrl+E: the handler
    assert table.OnEditLine(1) == (0,) and calls[-1][0] == "msg" and "no handler is known for sys_call_table[1] (only hook pages that MemLens copied have one)" in calls[-1][1], calls[-1]  # code review s170 n-3 e07
    assert table.OnInsertLine(0) == (0,) and calls[-1] == ("jump", 0x50)  # Insert: the owner
    assert table.OnInsertLine(1) == (0,) and calls[-1][0] == "msg" and "no owner is known for sys_call_table[1]" in calls[-1][1], calls[-1]
    assert table.OnInsertLine(2) == (0,) and calls[-1][0] == "msg" and "(no symbol: heap)" in calls[-1][1] and "not in this database" in calls[-1][1], calls[-1]
    assert table.OnInsertLine(-1) == (0,) and calls[-1][0] == "msg", calls[-1]  # nothing selected
    # A hook page with no known role: its first named call is not the handler, so Ctrl+E says so and jumps nowhere.
    hook_code = m.PatchList([(0x80, "vfs_read", "push+ret to memory with no symbol", "memlens_target_ffffffffc0b00000",
                              "(hook code; first call: _printk)", None, "", None)])
    del calls[:]
    assert hook_code.OnEditLine(0) == (0,) and len(calls) == 1 and calls[-1][0] == "msg", calls
    assert "no handler is known for vfs_read (hook code; first call: _printk)" in calls[-1][1], calls[-1]
    # Apply kernel types keeps the ISF's offset of ftrace_ops.func for the patch list (Show patched kernel functions).
    layout_isf = dict(isf, user_types=dict(isf["user_types"], ftrace_ops={"kind": "struct", "size": 16, "fields": {
        "func": {"offset": 8, "type": {"kind": "base", "name": "unsigned int"}}}}))
    lp = os.path.join(t, "layout.json"); json.dump(layout_isf, open(lp, "w"))
    blobs.clear()
    assert m.load_layout() == {} and m.apply_types(p) is not None and m.load_layout() == {}  # no ftrace_ops in that ISF
    assert m.apply_types(lp) is not None and m.load_layout() == {"ftrace_ops.func": 8}, m.load_layout()
    blobs.clear()
    import base64
    def banner_isf(text):
        data = dict(isf); data["symbols"] = dict(isf["symbols"], linux_banner={"address": 9, "constant_data": base64.b64encode(text + b"\0").decode()})
        q = os.path.join(t, "banner.json"); json.dump(data, open(q, "w")); return q
    set_names({"demo_var": 0x1000, "linux_banner": 0x3000})
    asked = []
    same = banner_isf(b"Linux version 1.0")
    assert m.apply_types(same, lambda e, a: asked.append(e) or False) is not None and asked == []
    other = banner_isf(b"Linux version 2.0")
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]
    assert m.apply_types(other, lambda e, a: asked.append((e, a)) or False) is None
    assert asked == [(b"Linux version 2.0", b"Linux version 1.0")] and not [c for c in calls if c[0] == "parse"]
    assert m.apply_types(other, lambda e, a: True) is not None
    answers = []
    kw.ask_yn = lambda d, text: answers.append(text) or kw.ASKBTN_NO
    assert m.confirm_other_kernel(b"Linux 100% A", b"Linux B") is False and "100%%" in answers[0]
    set_names({"demo_var": 0x1000})
    assert m.banner_mismatch({"symbols": {"linux_banner": {"constant_data": "YQ=="}}}) == (b"a", b"")  # no such symbol in the database
    assert m.banner_mismatch({"symbols": {}}) is None  # the ISF has no banner to compare
    answers[:] = []
    assert m.confirm_other_kernel(b"Linux A", b"") is False and "no linux_banner symbol" in answers[0]
    comments[0x10] = "analyst note"
    m.add_comment(0x10, "MemLens: hook"); m.add_comment(0x10, "MemLens: hook"); m.add_comment(0x20, "MemLens: hook")
    assert comments == {0x10: "analyst note\nMemLens: hook", 0x20: "MemLens: hook"}, comments
    # code review s170 m-1: a line an older build wrote, which the new text only extends (a kind added), is replaced, not kept twice
    comments[0x30] = "analyst note\nMemLens: call to sys_kill (calls evilmod.fh_sys_kill)"
    m.add_comment(0x30, "MemLens: call to sys_kill (calls evilmod.fh_sys_kill, module callback)")
    assert comments[0x30] == "analyst note\nMemLens: call to sys_kill (calls evilmod.fh_sys_kill, module callback)", comments[0x30]
    comments[0x40] = "MemLens: hook page for sys_kill"
    m.add_comment(0x40, "MemLens: hook page for sys_kill (module callback)")
    assert comments[0x40] == "MemLens: hook page for sys_kill (module callback)", comments[0x40]
    # ... but a different line that merely shares a prefix is kept (calls a vs calls ab)
    comments[0x50] = "MemLens: call to sys_kill (calls a)"
    m.add_comment(0x50, "MemLens: call to sys_kill (calls ab, module callback)")
    assert comments[0x50] == "MemLens: call to sys_kill (calls a)\nMemLens: call to sys_kill (calls ab, module callback)", comments[0x50]
    # claims check s171: empty lines in an analyst's existing comment are kept (the m-1 replace must not drop them)
    comments[0x60] = "para one\n\npara two"
    m.add_comment(0x60, "MemLens: hook")
    assert comments[0x60] == "para one\n\npara two\nMemLens: hook", repr(comments[0x60])
    comments[0x61] = "note\n\nMemLens: call to f (calls m.g)"
    m.add_comment(0x61, "MemLens: call to f (calls m.g, module callback)")
    assert comments[0x61] == "note\n\nMemLens: call to f (calls m.g, module callback)", repr(comments[0x61])
    # builder s171: a v0.3.27 page line that already ended with a role and now only gains "; owner: ..." is replaced too
    comments[0x62] = "MemLens: hook page; first named call: function_trace_call (ftrace)"
    m.add_comment(0x62, "MemLens: hook page; first named call: function_trace_call (ftrace); owner: function_trace_call (ftrace_ops global_ops)")
    assert comments[0x62] == "MemLens: hook page; first named call: function_trace_call (ftrace); owner: function_trace_call (ftrace_ops global_ops)", repr(comments[0x62])
    # code review s170 n-2: a folder listing that fails is unknown (None), never an empty folder, so nothing is removed on it
    missing = os.path.join(tempfile.mkdtemp(), "no-such-folder")
    assert m.elf_files(missing) is None
    assert "left it in place" in m.remove_unusable(missing, "kernel.elf", None)
    keep_dir = tempfile.mkdtemp(); open(os.path.join(keep_dir, "kernel.elf"), "wb").close()
    assert "left it in place" in m.remove_unusable(keep_dir, "kernel.elf", None) and os.path.exists(os.path.join(keep_dir, "kernel.elf"))
    assert m.written_file(b"", missing, None) == "kernel.elf" and m.written_file(b"", missing, set()) == "kernel.elf"
    # code review s170 n-3 e03/e04: removing the new export fails (its name is a directory: IsADirectoryError, an OSError) -> the dialog says so
    odd_dir = tempfile.mkdtemp(); before_odd = m.elf_files(odd_dir); os.mkdir(os.path.join(odd_dir, "kernel.elf"))
    said = m.remove_unusable(odd_dir, "kernel.elf", before_odd)
    assert said.startswith("MemLens could not remove it (") and said.endswith("); do not open it.") and os.path.isdir(os.path.join(odd_dir, "kernel.elf")), said
    plugin.term(); assert sum(c[0] == "unreg" for c in calls) == 3
print("stub test OK (fake IDA modules)")
