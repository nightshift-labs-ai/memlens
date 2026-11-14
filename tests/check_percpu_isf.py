#!/usr/bin/env python3
"""tests/test_demo_percpu_index.py and its ISF (release check 4 of review s192). The test takes the ISF from its second
argument, else MEMLENS_ISF, else a *.json* file next to kernel.elf; with none it must say SKIPPED and why, and exit 0,
not stop with an ISFError traceback. Not named test_*.py, so tests/run_all.py does not run it. No IDA, no network.

usage: python3 tests/check_percpu_isf.py [path/to/test_demo_percpu_index.py]
Without the demo it checks the SKIP cases on a dummy kernel.elf. With MEMLENS_DEMO_ELF and an ISF (MEMLENS_ISF, else the
*.json.xz next to the demo kernel.elf) it also links the demo kernel.elf into a folder with no ISF, as an export folder
is, and checks that the test then passes with MEMLENS_ISF (or the ISF as second argument) and SKIPs without it.
"""
import glob
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
script = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "test_demo_percpu_index.py")
OK = "demo per-CPU index test OK"


def run(args, isf=None):
    """(exit status, output, last line) of the test with MEMLENS_ISF unset (isf None) or set to isf."""
    env = {k: v for k, v in os.environ.items() if k not in ("MEMLENS_ISF", "MEMLENS_DEMO_ELF")}
    if isf is not None:
        env["MEMLENS_ISF"] = isf
    done = subprocess.run([sys.executable, "-I", script] + args, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=300)
    out = done.stdout.decode("utf-8", errors="replace")
    return done.returncode, out, (out.strip().splitlines() or [""])[-1]


def skipped(result, reason):
    rc, out, last = result
    return rc == 0 and "SKIPPED" in last and reason in last


with tempfile.TemporaryDirectory() as tmp:
    dummy = os.path.join(tmp, "kernel.elf")
    with open(dummy, "wb") as handle:
        handle.write(b"\x7fELF" + b"\0" * 60)  # never parsed when the ISF is missing: the test looks for it first
    # Nothing next to kernel.elf and no MEMLENS_ISF; run_all sets MEMLENS_ISF to "" when the demo folder has no ISF.
    for isf in (None, ""):
        result = run([dummy], isf)
        assert skipped(result, "no ISF next to kernel.elf; set MEMLENS_ISF"), (isf, result)
    # MEMLENS_ISF, or the second argument, names a file that is not there.
    missing = os.path.join(tmp, "missing.json.xz")
    result = run([dummy], missing)
    assert skipped(result, "no ISF at " + missing), result
    result = run([dummy, missing])
    assert skipped(result, "no ISF at " + missing), result
    checked = "4 SKIP cases"

    demo = os.environ.get("MEMLENS_DEMO_ELF", "")
    isf = os.environ.get("MEMLENS_ISF") or (sorted(glob.glob(os.path.join(os.path.dirname(demo), "*.json.xz"))) or [""])[0]
    if demo and os.path.isfile(demo) and isf and os.path.isfile(isf):
        folder = os.path.join(tmp, "out")
        os.mkdir(folder)
        link = os.path.join(folder, "kernel.elf")
        os.symlink(os.path.abspath(demo), link)
        isf = os.path.abspath(isf)
        result = run([link], isf)
        assert result[0] == 0 and result[2] == OK, result
        result = run([link, isf], missing)  # the second argument comes before MEMLENS_ISF
        assert result[0] == 0 and result[2] == OK, result
        result = run([link])
        assert skipped(result, "no ISF next to kernel.elf; set MEMLENS_ISF"), result
        checked += "; the demo kernel.elf in a folder with no ISF: passes with MEMLENS_ISF or the ISF argument, SKIPs without"
    else:
        print("SKIP: no demo kernel.elf and ISF (MEMLENS_DEMO_ELF, MEMLENS_ISF): only the SKIP cases checked")
print("percpu ISF check OK (%s)" % checked)
