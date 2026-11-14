#!/usr/bin/env python3
"""Run every MemLens test, one after another, and print a pass / skip / fail table.

    python3 tests/run_all.py                                  # everything that needs no demo kernel
    MEMLENS_DEMO_ELF=kernel.elf python3 tests/run_all.py      # also the parts that check the demo export
    MEMLENS_TESTHOOK_ELF=<testhook kernel.elf> ...           # also the second sample (memlens-demo-testhook.zip)
    python3 tests/run_all.py --ida-stubs <folder with ida_*.pyi>   # also tests/check_ida_names.py (IDA's stubs)
    python3 tests/run_all.py --ida-sdk <SDK src/plugins/idapython>  # also tests/check_ida_api.py (api_contents.brief)

The demo kernel.elf is in the demo-data release (see the README's Try it); with it, MEMLENS_ISF defaults to the demo
zip's *.json.xz in the same folder. Needs Python 3.8+; a few tests use cc when it is installed and say SKIP when not.
Each test gets TIMEOUT seconds (a hung test is a FAIL). Exit status 1 when any test fails, 2 on a usage error.
"""
import glob
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TIMEOUT = 600  # seconds per test
USAGE = ("usage: python3 tests/run_all.py [--ida-stubs <folder with ida_*.pyi>] [--ida-sdk <IDA SDK src/plugins/idapython>]"
         " (the demo kernel.elf goes in MEMLENS_DEMO_ELF)")
# tests that take the demo kernel.elf as their first argument (without it they skip the demo part)
KERNEL_TESTS = {"test_demo_injection.py", "test_demo_percpu_index.py", "test_hookchain.py", "test_hookchain_stub.py",
                "test_owner.py"}
# tests that also check the second sample's kernel.elf (a hook set by a module), passed after the demo
TESTHOOK_TESTS = {"test_hookchain.py", "test_hookchain_stub.py", "test_owner.py"}


def status(rc, out):
    """FAIL (exit status not 0), SKIP (the whole test skipped: its last line says SKIPPED) or PASS, with the number of
    optional parts it skipped (its 'SKIP: ...' lines)."""
    if rc != 0:
        return "FAIL", 0
    lines = out.strip().splitlines() or [""]
    return ("SKIP" if "SKIPPED" in lines[-1] else "PASS"), sum(1 for line in lines if line.startswith("SKIP: "))


def main(argv):
    folders, i = {}, 0
    while i < len(argv):  # only the two flags, each with an existing folder (anything else: usage, exit 2)
        if argv[i] not in ("--ida-stubs", "--ida-sdk") or i + 1 >= len(argv) or not os.path.isdir(argv[i + 1]):
            print(USAGE, file=sys.stderr)
            return 2
        folders[argv[i]], i = argv[i + 1], i + 2
    demo = os.environ.get("MEMLENS_DEMO_ELF", "")
    demo = os.path.abspath(demo) if demo else ""  # the tests run from the repository folder (review s179 MAJOR 2)
    if demo and not os.path.isfile(demo):
        print("MEMLENS_DEMO_ELF=%s: no such file" % demo, file=sys.stderr)
        return 2
    testhook = os.environ.get("MEMLENS_TESTHOOK_ELF", "")
    testhook = os.path.abspath(testhook) if testhook else ""
    if testhook and not os.path.isfile(testhook):
        print("MEMLENS_TESTHOOK_ELF=%s: no such file" % testhook, file=sys.stderr)
        return 2
    runs = []
    for name in sorted(n for n in os.listdir(HERE) if n.startswith("test_") and n.endswith(".py")):
        extra = [demo] if demo and name in KERNEL_TESTS else []
        if testhook and name in TESTHOOK_TESTS:
            extra = extra + [testhook]
        if demo and name == "test_findpatches_stub.py":
            extra = ["/bin/ls", demo]  # a stripped program (the test SKIPs it when missing), then the demo export
        runs.append((name, [name] + extra))
    if "--ida-sdk" in folders:
        runs.append(("check_ida_api.py", ["check_ida_api.py", folders["--ida-sdk"]]))
    if "--ida-stubs" in folders:
        runs.append(("check_ida_names.py", ["check_ida_names.py", folders["--ida-stubs"]]))
    env = dict(os.environ, MEMLENS_DEMO_ELF=demo, MEMLENS_TESTHOOK_ELF=testhook)  # absolute: the tests run from the repository
    if demo and not env.get("MEMLENS_ISF"):  # the demo zip's ISF next to kernel.elf (test_export_failure_stub uses it)
        env["MEMLENS_ISF"] = (sorted(glob.glob(os.path.join(os.path.dirname(demo), "*.json.xz"))) or [""])[0]
    rows, failed = [], []
    for name, args in runs:
        start = time.time()
        try:
            run = subprocess.run([sys.executable, "-I", os.path.join(HERE, args[0])] + args[1:], cwd=os.path.dirname(HERE),
                                 env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=TIMEOUT)
            code, output = run.returncode, run.stdout
        except subprocess.TimeoutExpired as expired:
            code, output = -1, (expired.output or b"") + b"\nstopped after %d s (TIMEOUT)" % TIMEOUT
        output = output.decode("utf-8", errors="replace")
        result, parts = status(code, output)
        last = (output.strip().splitlines() or [""])[-1]
        note = " (%d optional part%s skipped)" % (parts, "s" if parts > 1 else "") if parts and result == "PASS" else ""
        rows.append((result, name, time.time() - start, last))
        print("%-4s %-28s %6.1f s  %s%s" % (result, name, time.time() - start, last[:90], note), flush=True)
        if result == "FAIL":
            failed.append((name, output))
    for name, out in failed:
        print("\n== %s output (last 30 lines)\n%s" % (name, "\n".join(out.splitlines()[-30:])))
    counts = {k: sum(1 for r in rows if r[0] == k) for k in ("PASS", "SKIP", "FAIL")}
    print("\n%d passed, %d skipped, %d failed%s" % (counts["PASS"], counts["SKIP"], counts["FAIL"],
                                                   "" if demo else " (MEMLENS_DEMO_ELF not set: demo parts skipped)"))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
