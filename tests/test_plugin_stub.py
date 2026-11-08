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
    CHCOL_EA = 1 << 24; NOTHING_CHANGED = 0
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
api = types.ModuleType("ida_idaapi"); api.plugin_t = object; api.PLUGIN_KEEP = 2
idc = types.ModuleType("idc"); idc.PT_SIL = 1; idc.PT_PAK1 = 0x10
def parse(text, flags):
    calls.append(("parse", text, flags)); return text.count("BADTOKEN")
idc.parse_decls = parse
idc.BADADDR = -1
idc.get_name_ea_simple = lambda n: 0x1000 if n == "demo_var" else idc.BADADDR
idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
nalt = types.ModuleType("ida_nalt"); nalt.get_input_file_path = lambda: ""
idc.set_cmt = lambda ea, c, r: calls.append(("cmt", ea, c))
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_typeinf=ti, ida_nalt=nalt, idc=idc)
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
    calls[:] = [c for c in calls if c[0] in ("reg", "menu")]; m.apply_types(p)
    assert [c for c in calls if c[0] == "settype"] == [("settype", 0x1000, "struct demo demo_var;")], calls
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
    assert table.OnGetSize() == 1 and table.OnGetLine(0) == ["0x10", "fn", "what", "tgt"]
    assert table.OnSelectLine(0) == (0,) and ("jump", 0x10) in calls
    plugin.term(); assert sum(c[0] == "unreg" for c in calls) == 3
print("stub test OK (fake IDA modules)")
