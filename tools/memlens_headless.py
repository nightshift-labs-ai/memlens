#!/usr/bin/env python3
"""MemLens without the IDA window, through idalib (IDA 9.0 or newer).

    python3 tools/memlens_headless.py kernel.elf <isf.json.xz> [--no-analysis] [--any-kernel]

Opens kernel.elf as an IDA database, imports the ISF's types and types the globals (per-CPU copies too), adds
a comment at every patched entry, prints the same report and patch list as the plugin, and saves the database.
It calls the plugin's own functions (memlens_entry.apply_types, report, add_comment and patchscan.scan), so
the result should match the menu actions. Not yet run with a real idalib: we have no IDA licence.

idalib setup (from Hex-Rays): install the idapro wheel shipped in <IDA>/idalib/python and run its
py-activate-idalib.py once, or set IDADIR to your IDA folder.
"""
import argparse
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Apply MemLens to kernel.elf with idalib (no IDA window).")
    parser.add_argument("elf", help="kernel.elf written by MemLens / linux.kernel2elf")
    parser.add_argument("isf", help="Volatility ISF for the same kernel (.json or .json.xz)")
    parser.add_argument("--no-analysis", action="store_true", help="skip IDA's auto-analysis (faster; types and comments are still applied)")
    parser.add_argument("--any-kernel", action="store_true", help="import even if the ISF's kernel banner differs from the one in kernel.elf, or kernel.elf has none")
    args = parser.parse_args(argv)
    for path in (args.elf, args.isf):
        if not os.path.isfile(path):
            parser.error("no such file: %s" % path)
    with open(args.elf, "rb") as handle:
        blob = handle.read()

    try:
        import idapro  # must be imported before any ida_* module
    except ImportError as error:
        print("memlens_headless: idalib is not available (%s). It needs IDA 9.0 or newer; see the top of this file." % error, file=sys.stderr)
        return 2
    if idapro.open_database(args.elf, not args.no_analysis) != 0:
        print("memlens_headless: IDA could not open %s" % args.elf, file=sys.stderr)
        return 1
    try:
        import memlens_entry
        result = memlens_entry.apply_types(args.isf, confirm=lambda expected, actual: args.any_kernel)
        if result is None:
            print("memlens_headless: the ISF was built for a different kernel than kernel.elf, or the database has no "
                  "linux_banner; nothing imported (use --any-kernel to import anyway)", file=sys.stderr)
            return 3
        sys.stdout.write(memlens_entry.report(result))
        patchscan = memlens_entry.patchscan
        try:
            if patchscan.on_disk_kernel(blob):
                print("[MemLens] patch list skipped: this is a kernel file from disk, whose entry bytes are not what ran")
                return 0
            findings = patchscan.scan(blob)
        except patchscan.BAD_ELF as error:
            print("memlens_headless: patch list needs the kernel.elf MemLens exported: %s" % error, file=sys.stderr)
            return 1
        for address, name, what, target, _ in findings:
            memlens_entry.add_comment(address, "MemLens: %s %s" % (what, target))
            print("0x%x\t%s\t%s\t%s" % (address, name, what, target))
        print("[MemLens] %d patched entries or odd syscall slots" % len(findings))
        return 0
    finally:
        idapro.close_database(True)


if __name__ == "__main__":
    sys.exit(main())
