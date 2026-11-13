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
    with open(index, "w") as handle:  # values that are not lists of URLs: a miss, no crash, no "ISF: h"
        json.dump({UBUNTU: "https://example.invalid/x.json.xz", DEBIAN: {"a": 1}}, handle)
    rc, out = run(UBUNTU, "--index", index)
    assert rc == 1 and "ISF: " not in out and "dwarf2json" in out, (rc, out)
    rc, out = run(DEBIAN, "--index", index)
    assert rc == 1 and "Traceback" not in out, (rc, out)
    empty = os.path.join(tmp, "empty.raw")
    with open(empty, "wb") as handle:
        handle.write(b"\0" * 1000)
    rc, out = run(empty, "--index", index)
    assert rc == 1 and "no 'Linux version ...' banner" in out, (rc, out)
    import lzma, gzip  # noqa: E401 (compressed images: say so instead of "no banner", review s179 MINOR 5)
    for name, data, tool in (("image.raw.xz", lzma.compress(b"x" * 100), "xz"), ("image.raw.gz", gzip.compress(b"x" * 100), "gzip"),
                             ("image.raw.bz2", b"BZh91AY&SY" + bytes(50), "bzip2")):
        packed = os.path.join(tmp, name)
        with open(packed, "wb") as handle:
            handle.write(data)
        rc, out = run(packed, "--index", index)
        assert rc == 2 and "%s-compressed" % tool in out and "decompress" in out, (name, rc, out)
    rc, out = run(os.path.join(tmp, "missing.raw"), "--index", index)
    assert rc == 2, (rc, out)
    # review s179 MINOR 7: only "Linux version <digits>.<digits>.<digits>" is a banner (Volatility's rule), so prose and
    # the kernel's own format string are not printed
    prose = os.path.join(tmp, "prose.raw")
    with open(prose, "wb") as handle:
        handle.write(b"\0" * 64 + b"Linux version of the popular PasswordSafe (x) manager\n\0" + UBUNTU.encode() + b"\n\0")
    with open(index, "w") as handle:
        json.dump(entries, handle)
    rc, out = run(prose, "--index", index)
    assert rc == 0 and "PasswordSafe" not in out and out.count("banner: ") == 1, (rc, out)
    # review s179 MINOR 6: errors exit 2 with a message (never a traceback, never 1 = "a miss")
    for bad, why in ((os.path.join(tmp, "no-such-index.json"), "missing"), (image, "not JSON"), (None, "a JSON list")):
        if bad is None:
            bad = os.path.join(tmp, "list.json")
            with open(bad, "w") as handle:
                json.dump([UBUNTU], handle)
        rc, out = run(UBUNTU, "--index", bad)
        assert rc == 2 and "Traceback" not in out and "cannot read the index" in out, (why, rc, out)
    for argv in ((UBUNTU, "--index"), (UBUNTU, "--index", "--download"), (UBUNTU, "--bogus")):
        rc, out = run(*argv)
        assert rc == 2 and "Traceback" not in out, (argv, rc, out)
    rc, out = run("--help")
    assert rc == 0 and "find_isf.py" in out, (rc, out)
    # --download: a network error or an interrupted download leaves no cache file (it downloads to .part first)
    import importlib.util
    import urllib.error
    spec = importlib.util.spec_from_file_location("find_isf", TOOL)
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    tool.CACHE = os.path.join(tmp, "cache", "banners_plain.json")

    def no_network(*_args, **_kwargs):
        raise urllib.error.URLError("no network in the test")

    class Torn:  # a response that breaks after the first bytes
        def __enter__(self):
            return self

        def __exit__(self, *_exc):
            return False

        def __init__(self):
            self.calls = 0

        def read(self, *_args):
            self.calls += 1
            if self.calls > 1:
                raise OSError("connection reset")
            return b'{"Linux version 6'

    class Good(Torn):
        def read(self, *_args):
            self.calls += 1
            return json.dumps(entries).encode() if self.calls == 1 else b""

    import contextlib
    import io
    for opener, want_rc, want_cache in ((no_network, 2, False), (lambda *a, **k: Torn(), 2, False),
                                        (lambda *a, **k: Good(), 0, True)):
        tool.urllib.request.urlopen = opener
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rc = tool.main([UBUNTU, "--download"])
        assert rc == want_rc, (opener, rc, buf.getvalue())
        assert os.path.isfile(tool.CACHE) == want_cache, (opener, buf.getvalue())
        assert not os.path.exists(tool.CACHE + ".part"), opener
        if want_cache:
            assert "ISF: " + URL in buf.getvalue(), buf.getvalue()
print("find_isf test OK (5-entry index: hit, miss with the dwarf2json hint, two banners, journal copy, format string)")
