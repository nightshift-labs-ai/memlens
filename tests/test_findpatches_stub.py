#!/usr/bin/env python3
"""Show patched kernel functions on a database whose input file has no function symbols (here /bin/ls, or the
file given as argv[1]): one warning and no list, instead of an empty list that looks clean. Fake IDA modules."""
import os, runpy, sys
HERE = os.path.dirname(os.path.abspath(__file__))
target = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
if not os.path.isfile(target):
    print("SKIP: %s not found (pass an ELF without function symbols)" % target)
    sys.exit(0)

g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
m, calls, nalt = g["m"], g["calls"], g["nalt"]
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan
blob = open(target, "rb").read()
assert not any(s[3] == patchscan.STT_FUNC for s in patchscan.Image(blob).symbols), "%s has function symbols" % target

nalt.get_input_file_path = lambda: target
m._open_list = None
del calls[:]
assert m.FindPatches().activate(None) == 0
ui = [c[1] for c in calls if c[0] == "ui"]
assert len(ui) == 1 and "checked nothing" in ui[0] and "no function symbols" in ui[0], ui
assert m._open_list is None, "a patch list was opened"
assert not any(c[0] == "msg" and "patched entries" in c[1] for c in calls), calls
print("FindPatches stub test OK (%s: no function symbols -> one warning, no list)" % os.path.basename(target))
