#!/usr/bin/env python3
"""The plugin on a Python built without _lzma (simulated by blocking the module). Fake IDA modules, not real IDA."""
import os, runpy, subprocess, sys
sys.modules["lzma"] = None  # "import lzma" now raises ImportError, as on a Python built without _lzma
HERE = os.path.dirname(os.path.abspath(__file__))

# The whole stub test passes without lzma: the plugin loads and a plain .json ISF is applied.
g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
m, kw, calls = g["m"], g["kw"], g["calls"]

# A .json.xz ISF gives one clear warning, not a traceback.
kw.ask_file = lambda *a: "/nonexistent/x.json.xz"
assert m.ApplyTypes().activate(None) == 0
ui = [c[1] for c in calls if c[0] == "ui"]
assert ui and "no lzma module" in ui[-1] and "xz -dk x.json.xz" in ui[-1], ui[-1:]
assert not any(c[0] == "msg" and "unexpected error" in c[1] for c in calls)

# The command line prints one line and exits 1.
code = ("import sys; sys.modules['lzma'] = None; sys.path.insert(0, %r); import isf2c; "
        "sys.exit(isf2c.main(['/nonexistent/x.json.xz', '/dev/null']))" % os.path.join(HERE, ".."))
r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
assert r.returncode == 1 and r.stderr.startswith("isf2c: this Python has no lzma module"), (r.returncode, r.stderr)
assert "Traceback" not in r.stderr
print("no-lzma test OK (plugin loads, .json ISF works, .xz gives one clear message)")
