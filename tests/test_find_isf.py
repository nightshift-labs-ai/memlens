#!/usr/bin/env python3
"""tools/find_isf.py on a 5-entry index and a hand-made image: a hit, a miss (the dwarf2json hint), two banners in one
image (the more frequent first), a journal copy of a banner counted with it, a format string skipped, a banner given
as text, no banner at all. No network."""
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "tools", "find_isf.py")
UBUNTU = ("Linux version 6.8.0-147-generic (buildd@lcy02-amd64-081) (x86_64-linux-gnu-gcc-13 (Ubuntu 13.3.0-6ubuntu2~24.04.1)"
          " 13.3.0, GNU ld (GNU Binutils for Ubuntu) 2.42) #147-Ubuntu SMP PREEMPT_DYNAMIC Thu Sep 24 11:33:16 UTC 2026 "
          "(Ubuntu 6.8.0-147.147-generic 6.8.12)")
DEBIAN = ("Linux version 6.12.115+deb13.1-amd64 (debian-kernel@lists.debian.org) (x86_64-linux-gnu-gcc-14 (Debian 14.2.0-19)"
          " 14.2.0, GNU ld (GNU Binutils for Debian) 2.44) #1 SMP PREEMPT_DYNAMIC Debian 6.12.115-1 (2026-10-20)")
URL = "https://github.com/Abyss-W4tcher/volatility3-symbols/releases/download/isf-Ubuntu-amd64-6.8.0/Ubuntu_6.8.0-147.json.xz"


def run(*args):
    out = subprocess.run([sys.executable, "-I", TOOL] + list(args), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         universal_newlines=True)
    return out.returncode, out.stdout


with tempfile.TemporaryDirectory() as tmp:
    index = os.path.join(tmp, "banners_plain.json")
    entries = {UBUNTU: [URL]}
    for n in range(4):
        entries["Linux version 5.%d.0-1-amd64 (x) (gcc) #1 SMP" % n] = ["https://example.invalid/%d.json.xz" % n]
    with open(index, "w") as handle:
        json.dump(entries, handle)
    image = os.path.join(tmp, "image.raw")
    with open(image, "wb") as handle:
        handle.write(b"\0" * 4096 + DEBIAN.encode() + b"\n\0" + b"\xff" * 100 + b"Linux version %s (%s@%s) (%s) %s\n\0"
                     + b"<6>[    0.000000] " + UBUNTU.encode() + b"\n" + b"\0" * 64 + UBUNTU.encode() + b"\n\0")
    rc, out = run(image, "--index", index)
    lines = out.splitlines()
    assert rc == 0, (rc, out)
    assert lines[0] == "banner: " + UBUNTU, "the banner seen twice (kernel + journal copy) comes first: %s" % out
    assert lines[1] == "ISF: " + URL and lines[2] == "  curl -LO " + URL, out
    assert lines[3] == "banner: " + DEBIAN and "linux-image-6.12.115+deb13.1-amd64-dbg" in lines[4], out
    assert lines[5] == "  dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.12.115+deb13.1-amd64 | xz > " \
                       "6.12.115+deb13.1-amd64.json.xz", out
    assert "%s" not in out and len([l for l in lines if l.startswith("banner: ")]) == 2, out
    rc, out = run(DEBIAN, "--index", index)  # a banner given as text: a miss -> exit 1, the Debian hint
    assert rc == 1 and "linux-image-6.12.115+deb13.1-amd64-dbg" in out, (rc, out)
    rc, out = run(UBUNTU.replace("Debian", ""), "--index", index)
    assert rc == 0 and "ISF: " + URL in out, (rc, out)
    rc, out = run(UBUNTU.replace("#147-Ubuntu", "#148-Ubuntu"), "--index", index)  # another build: a miss, Ubuntu hint
    assert rc == 1 and "linux-image-unsigned-6.8.0-147-generic-dbgsym" in out, (rc, out)
    empty = os.path.join(tmp, "empty.raw")
    with open(empty, "wb") as handle:
        handle.write(b"\0" * 1000)
    rc, out = run(empty, "--index", index)
    assert rc == 1 and "no 'Linux version ...' banner" in out, (rc, out)
    rc, out = run(os.path.join(tmp, "missing.raw"), "--index", index)
    assert rc == 2, (rc, out)
print("find_isf test OK (5-entry index: hit, miss with the dwarf2json hint, two banners, journal copy, format string)")
