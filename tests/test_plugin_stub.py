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
api = types.ModuleType("ida_idaapi"); api.plugin_t = object; api.PLUGIN_KEEP = 2
idc = types.ModuleType("idc"); idc.PT_FILE = 1
def parse(path, flags):
    calls.append(("parse", open(path).read(), flags)); return 0
idc.parse_decls = parse
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, idc=idc)
import memlens_entry as m
isf = {"base_types": {"unsigned int": {"size": 4, "signed": False, "kind": "int"}},
       "enums": {}, "user_types": {"demo": {"kind": "struct", "size": 8, "fields": {"a": {"offset": 4, "type": {"kind": "base", "name": "unsigned int"}}}}}}
with tempfile.TemporaryDirectory() as t:
    p = os.path.join(t, "x.json"); json.dump(isf, open(p, "w"))
    kw.ask_file = lambda *a: p
    plugin = m.PLUGIN_ENTRY(); assert plugin.init() == api.PLUGIN_KEEP
    assert m.ApplyTypes().activate(None) == 1
    parsed = [c for c in calls if c[0] == "parse"][0]
    assert parsed[2] == idc.PT_FILE and "struct demo" in parsed[1] and "__pad_0[4]" in parsed[1], parsed[1]
    assert sum(c[0] == "reg" for c in calls) == 2 and sum(c[0] == "menu" for c in calls) == 2
    cmd = m.export_command("/bin/vol", "/x/m.lime", "/out", "/sym")
    assert cmd[-1] == "linux.kernel2elf.Kernel2Elf" and "/x/m.lime" in cmd and "/sym" in cmd
    plugin.term(); assert sum(c[0] == "unreg" for c in calls) == 2
print("stub test OK (fake IDA modules)")
