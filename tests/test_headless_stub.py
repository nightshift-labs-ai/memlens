#!/usr/bin/env python3
"""tools/memlens_headless.py against a FAKE idapro and FAKE ida_* modules. Checks the orchestration only
(open, types, comments, close + save, exit codes); this is not a test with a real idalib."""
import contextlib, io
import json, os, subprocess, sys, tempfile, types
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "tools"))
calls = []
kw = types.ModuleType("ida_kernwin")
class handler: pass
kw.action_handler_t = handler; kw.AST_ENABLE_ALWAYS = 1; kw.ASKBTN_NO, kw.ASKBTN_YES = 0, 1
kw.msg = kw.info = kw.warning = lambda s: None
kw.show_wait_box = kw.replace_wait_box = lambda s: None; kw.hide_wait_box = lambda: None; kw.user_cancelled = lambda: False
class chooser:
    CHCOL_HEX = 1 << 24; NOTHING_CHANGED = 0
    def __init__(self, title, cols): pass
kw.Choose = chooser
ti = types.ModuleType("ida_typeinf"); ti.get_idati = lambda: "til"
class tinfo:
    def get_named_type(self, til, name): return name == "demo"
    def get_size(self): return 8
ti.tinfo_t = tinfo
api = types.ModuleType("ida_idaapi"); api.plugin_t = object; api.PLUGIN_KEEP = 2; api.PLUGIN_HIDE = 0x10
idc = types.ModuleType("idc"); idc.PT_SIL = 1; idc.PT_PAK1 = 0x10; idc.BADADDR = -1
idc.SEGATTR_PERM = 5; idc.get_segm_attr = lambda ea, attr: 6
segments = {0x1000: ".data", 0x2000: ".percpu.cpu0", 0x2100: ".percpu.cpu1"}  # start -> name, as the exporter writes them
idc.get_first_seg = lambda: min(segments)
idc.get_next_seg = lambda ea: min([s for s in segments if s > ea], default=idc.BADADDR)
idc.get_segm_name = lambda ea: segments.get(ea, "")
idc.parse_decls = lambda text, flags: 0
names = {"demo_var": 0x1000, "cpu0.pcpu_var": 0x2000, "cpu1.pcpu_var": 0x2100, "linux_banner": 0x3000}
idc.get_name_ea_simple = lambda n: names.get(n, idc.BADADDR)
autils = types.ModuleType("idautils"); autils.Names = lambda: [(ea, n) for n, ea in names.items()]
idc.SetType = lambda ea, d: calls.append(("settype", ea, d)) or True
comments = {}
idc.set_cmt = lambda ea, c, r: comments.__setitem__(ea, c)
idc.get_cmt = lambda ea, r: comments.get(ea)
nalt = types.ModuleType("ida_nalt"); nalt.get_input_file_path = lambda: ""
banner = [b"Linux version 1.0"]
dbytes = types.ModuleType("ida_bytes"); dbytes.get_bytes = lambda ea, size: banner[0][:size]
idapro = types.ModuleType("idapro")
idapro.open_database = lambda path, analysis: calls.append(("open", os.path.basename(path), analysis)) or 0
idapro.close_database = lambda save: calls.append(("close", save))
xref = types.ModuleType("ida_xref"); xref.fl_CN, xref.fl_JN, xref.XREF_USER = 17, 19, 32
iname = types.ModuleType("ida_name"); iname.SN_NOWARN = 256
nnode = types.ModuleType("ida_netnode")
funcs = types.ModuleType("ida_funcs")
sys.modules.update(ida_kernwin=kw, ida_idaapi=api, ida_typeinf=ti, ida_nalt=nalt, idc=idc, ida_bytes=dbytes, idapro=idapro, idautils=autils,
                   ida_xref=xref, ida_name=iname, ida_netnode=nnode, ida_funcs=funcs)
import memlens_headless as h
import memlens_entry as m
isf = {"base_types": {"unsigned int": {"size": 4, "signed": False, "kind": "int"}}, "enums": {},
       "symbols": {"demo_var": {"address": 1, "type": {"kind": "struct", "name": "demo"}},
                   "pcpu_var": {"address": 0x2000, "type": {"kind": "struct", "name": "demo"}},
                   "linux_banner": {"address": 5, "constant_data": "TGludXggdmVyc2lvbiAxLjA="}},
       "user_types": {"demo": {"kind": "struct", "size": 8, "fields": {"a": {"offset": 0, "type": {"kind": "base", "name": "unsigned int"}}}}}}
findings = [(0x1000, "vfs_getattr", "call to memory with no symbol", "memlens_target_ffffffffc0b2b000 (calls function_trace_call, ftrace)", None)]
m.patchscan.on_disk_kernel = lambda blob: False
m.patchscan.Image = lambda blob: ("image", blob)
not_kernel = [None]
m.patchscan.nothing_to_check = lambda image: not_kernel[0]
m.patchscan.scan = lambda blob, image=None: findings
# The hook chain itself is tested in test_hookchain_stub.py; here only that the runner applies it to the scanned image.
m.link_hooks = lambda image, found: calls.append(("link", image, found)) or ([], dict.fromkeys(
    ("xrefs", "xrefs_before", "xrefs_failed", "renamed", "named_before", "kept", "rename_failed"), 0))
with tempfile.TemporaryDirectory() as t:
    elf, p = os.path.join(t, "kernel.elf"), os.path.join(t, "x.json")
    open(elf, "wb").write(b"\x7fELF"); json.dump(isf, open(p, "w"))
    assert h.main([elf, p, "--no-analysis"]) == 0
    assert calls[0] == ("open", "kernel.elf", False) and calls[-1] == ("close", True), calls
    assert ("settype", 0x1000, "struct demo demo_var;") in calls and ("settype", 0x2100, "struct demo pcpu_var;") in calls, calls
    assert comments[0x1000].startswith("MemLens: call to memory with no symbol memlens_target_ffffffffc0b2b000"), comments
    assert ("link", ("image", b"\x7fELF"), findings) in calls and calls.index(("link", ("image", b"\x7fELF"), findings)) < len(calls) - 1, calls
    calls[:] = []; assert h.main([elf, p]) == 0 and calls[0] == ("open", "kernel.elf", True)
    # Different kernel: nothing imported without --any-kernel, database still closed.
    banner[0] = b"Linux version 2.0"; calls[:] = []
    assert h.main([elf, p]) == 3 and not [c for c in calls if c[0] == "settype"] and calls[-1] == ("close", True), calls
    calls[:] = []; assert h.main([elf, p, "--any-kernel"]) == 0 and [c for c in calls if c[0] == "settype"], calls
    # Not a kernel.elf (e.g. a user program, imported with --any-kernel): no empty "0 patched entries" that reads clean.
    not_kernel[0] = "no linux_banner symbol (not a kernel.elf exported by MemLens)"; comments.clear(); calls[:] = []
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert h.main([elf, p, "--any-kernel"]) == 0
    assert "patch list skipped: kernel.elf has no linux_banner symbol" in out.getvalue() and "patched entries" not in out.getvalue(), out.getvalue()
    assert not comments and calls[-1] == ("close", True), (comments, calls)
    not_kernel[0] = None
    # IDA cannot open the file.
    idapro.open_database = lambda path, analysis: 1; calls[:] = []
    assert h.main([elf, p]) == 1 and calls == [], calls
    # No idalib at all: a clear message and exit 2 (run in a fresh process without the fake idapro).
    run = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "memlens_headless.py"), elf, p], capture_output=True, text=True)
    assert run.returncode == 2 and "idalib is not available" in run.stderr, (run.returncode, run.stderr)
print("headless stub test OK (fake idapro and ida_* modules)")
