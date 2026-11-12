#!/usr/bin/env python3
"""Show patched kernel functions on a database whose input file is not a kernel: one warning and no list, instead of an
empty list that looks clean. Two inputs: a file without function symbols (/bin/ls, or argv[1]) and, when a C compiler
is installed, a small unstripped program (function symbols but no linux_banner). Also the same warning from
patchscan.py on the command line. Fake IDA modules."""
import os, runpy, shutil, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan

g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
m, calls, nalt = g["m"], g["calls"], g["nalt"]


def check(target, reason):
    image = patchscan.Image(open(target, "rb").read())
    assert patchscan.nothing_to_check(image) == reason, (target, patchscan.nothing_to_check(image))
    nalt.get_input_file_path = lambda: target
    m._open_list = None
    del calls[:]
    assert m.FindPatches().activate(None) == 0
    ui = [c[1] for c in calls if c[0] == "ui"]
    assert len(ui) == 1 and "checked nothing" in ui[0] and reason in ui[0], ui
    assert m._open_list is None, "a patch list was opened"
    assert not any(c[0] == "msg" and "patched entries" in c[1] for c in calls), calls
    cli = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "patchscan.py"), target],
                         capture_output=True, text=True)
    assert cli.returncode == 0 and ("warning: %s, so nothing was checked" % reason) in cli.stderr, cli.stderr
    assert cli.stdout == "", cli.stdout
    print("FindPatches stub test OK (%s: %s -> one warning, no list; command line warns too)"
          % (os.path.basename(target), reason))


ran = 0
stripped = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
if not os.path.isfile(stripped):
    print("SKIP: %s not found (pass an ELF without function symbols)" % stripped)
elif any(s[3] == patchscan.STT_FUNC for s in patchscan.Image(open(stripped, "rb").read()).symbols):
    print("SKIP: %s has function symbols here (pass a stripped ELF as argv[1])" % stripped)
else:
    check(stripped, "no function symbols")
    ran += 1

cc = shutil.which("cc") or shutil.which("gcc")
if not cc:
    print("SKIP: no C compiler, so the unstripped-program case was not run")
else:
    with tempfile.TemporaryDirectory() as work:
        source, program = os.path.join(work, "hello.c"), os.path.join(work, "hello")
        with open(source, "w") as handle:
            handle.write("#include <stdio.h>\nint helper(int x) { return x * 2; }\n"
                         "int main(void) { printf(\"%d\\n\", helper(21)); return 0; }\n")
        subprocess.run([cc, "-O1", "-o", program, source], check=True)
        check(program, "no linux_banner symbol, so it is not a Linux kernel")
        ran += 1

# The real exported kernel.elf must still be scanned (it has linux_banner).
demo = os.environ.get("MEMLENS_KERNEL_ELF", "/home/agent/tools/memlens-demo/x/kernel.elf")
if os.path.isfile(demo):
    assert patchscan.nothing_to_check(patchscan.Image(open(demo, "rb").read())) is None
    print("kernel.elf %s: checkable" % demo)
print("ran %d of 2 non-kernel cases" % ran)
