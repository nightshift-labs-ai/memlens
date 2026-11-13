#!/usr/bin/env python3
"""tests/run_all.py itself (not named test_*.py, so run_all does not run it): unknown arguments give the usage and exit
2; a test that hangs is stopped after the per-test timeout and counted as FAIL; with a demo kernel.elf and no MEMLENS_ISF,
the children get the demo zip's *.json.xz next to it. No IDA, no network."""
import contextlib
import importlib.util
import io
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("run_all", os.path.join(HERE, "run_all.py"))
run_all = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run_all)


def call(argv, env=None):
    buf = io.StringIO()
    old = dict(os.environ)
    os.environ.clear()
    os.environ.update(env if env is not None else old)
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = run_all.main(argv)
    finally:
        os.environ.clear()
        os.environ.update(old)
    return rc, buf.getvalue()


for argv in (["--bogus"], ["kernel.elf"], ["--ida-stubs=x"]):
    rc, out = call(argv)
    assert rc == 2 and "usage" in out, (argv, rc, out)

with tempfile.TemporaryDirectory() as tmp:
    tests = os.path.join(tmp, "tests")
    os.makedirs(tests)
    with open(os.path.join(tests, "test_hang.py"), "w") as handle:
        handle.write("import time\ntime.sleep(30)\n")
    with open(os.path.join(tests, "test_env.py"), "w") as handle:
        handle.write("import os\nprint('isf=' + os.environ.get('MEMLENS_ISF', ''))\n")
    demo = os.path.join(tmp, "kernel.elf")
    isf = os.path.join(tmp, "debian-6.12.115+deb13.1-amd64.json.xz")
    for path in (demo, isf):
        open(path, "wb").close()
    run_all.HERE, run_all.TIMEOUT = tests, 2
    env = {k: v for k, v in os.environ.items() if k != "MEMLENS_ISF"}
    env["MEMLENS_DEMO_ELF"] = demo
    rc, out = call([], env)
    assert rc == 1, (rc, out)
    assert any(line.startswith("FAIL") and "test_hang.py" in line for line in out.splitlines()), out
    assert "isf=" + isf in out, out
    env["MEMLENS_ISF"] = "/elsewhere.json.xz"
    rc, out = call([], env)
    assert "isf=/elsewhere.json.xz" in out, out
print("run_all check OK (usage on unknown arguments, per-test timeout, MEMLENS_ISF from the demo folder)")
