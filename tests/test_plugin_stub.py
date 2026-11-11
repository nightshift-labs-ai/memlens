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
    CHCOL_HEX = 1 << 24; NOTHING_CHANGED = 0
    def __init__(self, title, cols): self.title = title
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
comments = {}
idc.set_cmt = lambda ea, c, r: calls.append(("cmt", ea, c)) or comments.__setitem__(ea, c)
idc.get_cmt = lambda ea, r: comments.get(ea)
dbytes = types.ModuleType("ida_bytes"); dbytes.get_bytes = lambda ea, size: b"Linux version 1.0"[:size]
kw.ASKBTN_NO, kw.ASKBTN_YES = 0, 1
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_typeinf=ti, ida_nalt=nalt, idc=idc, ida_bytes=dbytes, idautils=autils)
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
    table = m.PatchList([(0x10, "fn", "what", "tgt", 0x20)])
    assert table.OnGetSize() == 1 and table.OnGetLine(0) == ["10", "fn", "what", "tgt"]
    assert table.OnSelectLine(0) == (0,) and ("jump", 0x10) in calls
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
    assert m.banner_mismatch({"symbols": {"linux_banner": {"constant_data": "YQ=="}}}) is None  # no such symbol in the database
    comments[0x10] = "analyst note"
    m.add_comment(0x10, "MemLens: hook"); m.add_comment(0x10, "MemLens: hook"); m.add_comment(0x20, "MemLens: hook")
    assert comments == {0x10: "analyst note\nMemLens: hook", 0x20: "MemLens: hook"}, comments
    plugin.term(); assert sum(c[0] == "unreg" for c in calls) == 3
print("stub test OK (fake IDA modules)")
