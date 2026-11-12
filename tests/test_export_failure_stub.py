#!/usr/bin/env python3
"""A failed export names the image's kernel. Drives Export kernel from memory image on FAKE ida_* modules with a fake
`vol` that replays real Volatility 2.28.2 output recorded in tests/fixtures/vol-2.28.2 (see its README.txt), through
the plugin's own run_cancellable. Checks our logic only; this is not a test in real IDA or with a real Volatility run."""
import base64, json, os, runpy, stat, struct, sys, tempfile, time
HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures", "vol-2.28.2")

g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
m, calls, kw = g["m"], g["calls"], g["kw"]


def fixture(name):
    with open(os.path.join(FIX, name), "rb") as handle:
        return handle.read()


# The ISFs' linux_banner constants, copied from the real Debian 13 (demo) and Debian 12 ISFs.
D13 = ("TGludXggdmVyc2lvbiA2LjEyLjExNStkZWIxMy4xLWFtZDY0IChkZWJpYW4ta2VybmVsQGxpc3RzLmRlYmlhbi5vcmcpICh4ODZfNjQtbGludXgtZ251"
       "LWdjYy0xNCAoRGViaWFuIDE0LjIuMC0xOSkgMTQuMi4wLCBHTlUgbGQgKEdOVSBCaW51dGlscyBmb3IgRGViaWFuKSAyLjQ0KSAjMSBTTVAgUFJFRU1Q"
       "VF9EWU5BTUlDIERlYmlhbiA2LjEyLjExNS0yICgyMDI2LTExLTAxKQoA")
D12 = ("TGludXggdmVyc2lvbiA2LjEuMC01NC1hbWQ2NCAoZGViaWFuLWtlcm5lbEBsaXN0cy5kZWJpYW4ub3JnKSAoZ2NjLTEyIChEZWJpYW4gMTIuMi4w"
       "LTE0K2RlYjEydTEpIDEyLjIuMCwgR05VIGxkIChHTlUgQmludXRpbHMgZm9yIERlYmlhbikgMi40MCkgIzEgU01QIFBSRUVNUFRfRFlOQU1JQyBEZWJp"
       "YW4gNi4xLjE5MC0xICgyMDI2LTEwLTE2KQoA")
D13_LINE = base64.b64decode(D13).split(b"\0")[0].decode().strip()
D12_LINE = base64.b64decode(D12).split(b"\0")[0].decode().strip()
assert D13_LINE.startswith("Linux version 6.12.115+deb13.1-amd64 ") and D12_LINE.startswith("Linux version 6.1.0-54-amd64 ")

# --- What the recordings show -------------------------------------------------------------------------------------
# Volatility's text is the same for a wrong ISF, no ISF and a file that is not a memory image: only banners can tell.
failed = ["export_trace_wrong_isf", "export_kernel_file_wrong_isf", "export_random_isf", "export_trace_no_isf",
          "export_random_no_isf", "export_journal_copy_wrong_isf", "export_truncated_isf"]
for name in failed:
    assert fixture(name + ".stdout") == fixture(failed[0] + ".stdout"), name
    assert fixture(name + ".stderr") == fixture(failed[0] + ".stderr"), name
    assert m.kernel_check_wanted(fixture(name + ".stdout"), fixture(name + ".stderr")), name
avml_out, avml_err = fixture("export_avml_header_isf.stdout"), fixture("export_avml_header_isf.stderr")
assert m.kernel_not_found(avml_out.decode(), avml_err.decode()) and not m.kernel_check_wanted(avml_out, avml_err)
# Random bytes holding only the ISF's banner: Volatility exits 0 with an empty ELF (already warned about, not a failure).
assert any(".text: 0 bytes" in p for p in m.export_problems(fixture("export_random_with_banner_isf.stdout")))

trace = m.image_banners(fixture("banners_trace.stdout"))
assert len(trace) == 3 and trace[0] == D13_LINE, trace  # 4 rows, 3 distinct; the ISF's line is found twice
assert [b for b in trace[1:] if b.endswith(") # SMP PREEMPT_DYNAMIC Debian 6.12.115-2 (2026-11-01)")]
assert [b for b in trace[1:] if b.endswith("(2026-11-01)1)")]
kernel_file = m.image_banners(fixture("banners_kernel_file.stdout"))
assert len(kernel_file) == 3 and set(kernel_file) == set(trace), kernel_file
assert m.image_banners(fixture("banners_random.stdout")) == [] and m.image_banners(fixture("banners_avml_header.stdout")) == []
assert m.image_banners(b"0x10\tDarwin Kernel Version 1.2.3\n0x20\tLinux version\n") == []
assert m.banner_command("/v/vol", "/x/img") == ["/v/vol", "-q", "-f", "/x/img", "banners.Banners"]

lines = m.banner_lines(["Linux version %d.0.0" % n for n in range(5)])
assert lines.count("Image: ") == 3 and "... and 2 more" in lines and "5 different" in lines, lines
lines = m.banner_lines(["Linux version %d.0.0" % n for n in range(5)], "Linux version 4.0.0", " (mark)")
assert lines.count("Image: ") == 4 and "\nImage: Linux version 4.0.0 (mark)\n... and 1 more\n" in lines, lines

# The exact-bytes check (what Volatility matches): across chunk boundaries, compressed files, Cancel.
D12_EXACT = base64.b64decode(D12)
assert D12_EXACT.endswith(b"\n\0")
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "img")
    for at in range(0, 70):
        with open(path, "wb") as handle:
            handle.write(b"\0" * at + D12_EXACT + b"\0" * 9)
        for chunk in (7, 64, 1 << 24):
            assert m.holds_bytes(path, D12_EXACT, chunk) == (True, None), (at, chunk)
    with open(path, "wb") as handle:
        handle.write(b"MESSAGE=" + D12_EXACT[:-2] + b"\0" * 300)  # a journal copy: no "\n\0" after the line
    assert m.holds_bytes(path, D12_EXACT, 64) == (False, None)
    for magic in (b"\xfd7zXZ\x00", b"\x1f\x8b\x08", b"BZh9", b"AVML\x02\0\0\0", b"PK\x03\x04"):
        with open(path, "wb") as handle:
            handle.write(magic + D12_EXACT)
        assert m.holds_bytes(path, D12_EXACT) == (None, "the file is compressed"), magic
    with open(path, "wb") as handle:
        handle.write(b"\0" * 1000 + D12_EXACT)
    kw.user_cancelled = lambda: True
    assert m.holds_bytes(path, D12_EXACT, 256) == (None, "you cancelled that check")
    kw.user_cancelled = lambda: False
    found, why = m.holds_bytes(os.path.join(work, "missing"), D12_EXACT)
    assert found is None and why.startswith("the file could not be read"), why

# A cut image: banners.Banners missed the real linux_banner in the first 125 MB of trace.elf (recorded), so the size the
# file's own ELF or LiME headers describe is checked first. Small hand-made files with the same layout here.
truncated = m.image_banners(fixture("banners_truncated.stdout"))
assert len(truncated) == 1 and D13_LINE not in truncated and truncated[0].endswith(" # SMP PREEMPT_DYNAMIC Debian "
                                                                                    "6.12.115-2 (2026-11-01)"), truncated


def elf_core(loads, ident=b"\x7fELF\x02\x01\x01", phentsize=56, e_type=4):
    """A 64-bit ELF core: header, one PT_NOTE, then a PT_LOAD per (size) in loads, data right after the headers."""
    phnum = 1 + len(loads)
    offset = 64 + phentsize * phnum
    table = struct.pack("<IIQQQQQQ", 4, 0, 0, 0, 0, 0, 0, 0).ljust(phentsize, b"\0")
    for size in loads:
        table += struct.pack("<IIQQQQQQ", 1, 7, offset, 0, 0, size, size, 0).ljust(phentsize, b"\0")
        offset += size
    head = ident.ljust(16, b"\0") + struct.pack("<HHIQQQIHHHHHH", e_type, 62, 1, 0, 64, 0, 0, 64, phentsize, phnum, 64, 0, 0)
    return head + table + b"\x5a" * (offset - 64 - phentsize * phnum)


def lime(sizes):
    return b"".join(struct.pack("<IIQQ8x", 0x4C694D45, 1, 0x1000 * n, 0x1000 * n + size - 1) + b"\x5a" * size
                    for n, size in enumerate(sizes))


with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "img")

    def short(data):
        with open(path, "wb") as handle:
            handle.write(data)
        return m.short_file(path)
    core, cut = elf_core([0x30, 0x2000]), elf_core([0x30, 0x2000])[:-0x100]
    assert short(core) is None and short(core + b"tail") is None, short(core)
    assert short(cut) == (len(cut), len(core), "ELF") and short(core[:-1]) == (len(core) - 1, len(core), "ELF")
    assert short(core[:64 + 56]) == (64 + 56, 64 + 56 * 3, "ELF")  # cut inside the program header table
    assert short(elf_core([0x30], ident=b"\x7fELF\x01\x01\x01")[:80]) is None  # 32-bit: not read by Volatility
    full = lime([0x40, 0x3000, 0x80])
    assert short(full) is None and short(full + b"\0" * 5) is None, short(full)
    assert short(full[:-1]) == (len(full) - 1, len(full), "LiME") and short(full[:200]) == (200, 32 + 0x40 + 32 + 0x3000, "LiME")
    assert short(full[:32 + 0x40 + 10]) == (32 + 0x40 + 10, 32 + 0x40 + 32, "LiME")  # cut inside the second header
    assert short(struct.pack("<IIQQ8x", 0x4C694D45, 1, 0x2000, 0x1000) + b"\0" * 64) is None  # end before start
    assert short(b"\0" * 100) is None and short(b"") is None and m.short_file(os.path.join(work, "missing")) is None
one = m.banner_lines([D13_LINE])
assert one == "Image: " + D13_LINE, one

# --- The plugin, end to end, with a fake vol ---------------------------------------------------------------------
FAKE_VOL = '''#!%s
import json, os, sys, time
here = os.path.dirname(os.path.abspath(__file__))
plan = json.load(open(os.path.join(here, "plan.json")))
kind = "banners" if "banners.Banners" in sys.argv else "export"
with open(os.path.join(here, "calls.log"), "a") as log:
    log.write(json.dumps([kind] + sys.argv[1:]) + "\\n")
step = plan[kind]
time.sleep(step.get("sleep", 0))
sys.stdout.buffer.write(open(step["path"] + ".stdout", "rb").read())
sys.stderr.buffer.write(open(step["path"] + ".stderr", "rb").read())
sys.exit(step["exit"])
''' % sys.executable

with tempfile.TemporaryDirectory() as work:
    bindir = os.path.join(work, "bin")
    os.mkdir(bindir)
    vol = os.path.join(bindir, "vol")
    with open(vol, "w") as handle:
        handle.write(FAKE_VOL)
    os.chmod(vol, os.stat(vol).st_mode | stat.S_IXUSR)
    os.environ["PATH"] = bindir + os.pathsep + os.environ.get("PATH", "")
    image = os.path.join(work, "trace.elf")
    open(image, "wb").close()

    def isf_file(name, banner=None, text=None):
        path = os.path.join(work, name)
        data = {"base_types": {}, "user_types": {}, "enums": {}, "symbols": {}}
        if banner:
            data["symbols"]["linux_banner"] = {"address": 1, "constant_data": banner}
        with open(path, "w") as handle:
            handle.write(text if text is not None else json.dumps(data))
        return path

    d13, d12 = isf_file("d13.json", D13), isf_file("d12.json", D12)
    no_banner, not_isf = isf_file("plain.json"), isf_file("notes.json", text="not an ISF")
    waits, started, boxes, box_errors = [], [], [], []  # boxes: the wait boxes up now (IDA stacks show_wait_box)

    def show_wait_box(text):
        waits.append(text)
        if boxes:
            box_errors.append("show_wait_box over the wait box %r: %s" % (boxes[-1], text))
        boxes.append(text)

    def replace_wait_box(text):
        waits.append(text)
        if not boxes:
            box_errors.append("replace_wait_box with no wait box up: " + text)
        boxes[-1:] = [text]

    def hide_wait_box():
        if not boxes:
            box_errors.append("hide_wait_box with no wait box up")
        del boxes[-1:]

    def dialog(text):
        calls.append(("ui", text))
        if boxes:
            box_errors.append("dialog under the wait box %r" % boxes[-1])
    kw.show_wait_box, kw.replace_wait_box, kw.hide_wait_box = show_wait_box, replace_wait_box, hide_wait_box
    kw.warning = kw.info = dialog
    real_run_cancellable = m.run_cancellable
    m.run_cancellable = lambda command: started.append(command) or real_run_cancellable(command)

    def run(export, banners=None, isf=None, cancel=lambda: False, export_sleep=0, banners_sleep=0, banners_exit=0,
            image_bytes=b""):
        """Export with the recorded export output, then (if the plugin asks) the recorded banners output. The image
        file holds image_bytes (the plugin reads it only to look for the ISF's exact kernel version line)."""
        with open(image, "wb") as handle:
            handle.write(image_bytes)
        plan = {"export": {"path": os.path.join(FIX, export), "exit": 1, "sleep": export_sleep},
                "banners": {"path": os.path.join(FIX, banners or "banners_random"), "exit": banners_exit,
                            "sleep": banners_sleep}}
        with open(os.path.join(bindir, "plan.json"), "w") as handle:
            json.dump(plan, handle)
        if os.path.exists(os.path.join(bindir, "calls.log")):
            os.remove(os.path.join(bindir, "calls.log"))
        kw.ask_file = lambda save, default, prompt: image if prompt == "Linux memory image" else isf
        kw.user_cancelled = cancel
        del calls[:], waits[:], started[:], boxes[:], box_errors[:]
        t0 = time.time()
        assert m.ExportKernel().activate(None) == 0
        # Every wait box shown is hidden again, none is stacked on another, and no dialog appears under one.
        assert box_errors == [] and boxes == [], (box_errors, boxes)
        log = [json.loads(line) for line in open(os.path.join(bindir, "calls.log"))] if os.path.exists(
            os.path.join(bindir, "calls.log")) else []
        dialogs = [c[1] for c in calls if c[0] == "ui"]
        return dialogs, log, time.time() - t0

    def ran_banners(log):
        """The banner scans the plugin started (also checked against what the fake vol logged when it got that far)."""
        scans = [command[1:] for command in started if "banners.Banners" in command]
        assert [entry[1:] for entry in log if entry[0] == "banners"] in ([], scans), (log, scans)
        return [["banners"] + scan for scan in scans]

    # A Debian 12 ISF on the Debian 13 image (the judge's case): the ISF is named as another kernel, both lines shown.
    dialogs, log, _ = run("export_trace_wrong_isf", "banners_trace", d12)
    assert len(dialogs) == 1, dialogs
    text = dialogs[0]
    assert ran_banners(log) == [["banners", "-q", "-f", image, "banners.Banners"]], log
    assert "The ISF you chose was built for another kernel" in text and "\nISF: " + D12_LINE + "\n" in text, text
    assert "\nImage: " + D13_LINE + "\n" in text and text.count("\nImage: ") == 3 and "3 different" in text, text
    assert text.index("ISF: ") < text.index("Image: ") and "An ISF for your own image" in text, text
    assert "(the ISF's)" not in text and "is the running kernel" not in text, text
    assert "\nUnsatisfied requirement" in text and "\n2.28.2" not in text, text  # Volatility's tail from a line start
    assert any("looking for the image's kernel version" in w for w in waits), waits
    assert any(c[0] == "msg" and c[1].startswith("[MemLens] banners.Banners (exit 0):") and D13_LINE in c[1] for c in calls)
    # The demo kernel.elf (ELF type EXEC) given as the image with the wrong ISF (recorded): not a memory image, said
    # before any banner scan (banners.Banners finds the kernel's lines in it); also a module, a program, a cut one.
    for e_type, kind in ((2, "executable (ELF type EXEC)"), (1, "relocatable file (ELF type REL)"),
                         (3, "shared object or PIE program (ELF type DYN)"), (0, "file of no type"), (9, "file of type 9")):
        for data in (elf_core([0x30, 0x200], e_type=e_type), elf_core([0x30, 0x200], e_type=e_type)[:-0x100]):
            dialogs, log, _ = run("export_kernel_file_wrong_isf", "banners_kernel_file", d12, image_bytes=data)
            text = dialogs[0]
            assert ran_banners(log) == [] and "This file is not a memory image: it is an ELF " + kind in text, text
            assert "open that file in IDA directly and use Apply kernel types" in text and "Image:" not in text, text
            assert "another kernel" not in text and "incomplete copy" not in text, text
    big_endian = elf_core([0x30], e_type=2)
    big_endian = big_endian[:5] + b"\x02" + big_endian[6:16] + b"\x00\x02" + big_endian[18:]
    text = run("export_kernel_file_wrong_isf", "banners_kernel_file", d12, image_bytes=big_endian)[0][0]
    assert "it is an ELF executable (ELF type EXEC)" in text, text
    # A core dump, a 9-byte stub of an ELF header, a file that is not ELF: the banner scan decides, as before.
    for data in (elf_core([0x30, 0x200]), b"\x7fELF\x02\x01\x01\0\0", b"\0" * 64):
        dialogs, log, _ = run("export_kernel_file_wrong_isf", "banners_kernel_file", d12, image_bytes=data)
        assert len(ran_banners(log)) == 1 and "built for another kernel" in dialogs[0], dialogs[0]
        assert dialogs[0].count("\nImage: ") == 3 and "not a memory image" not in dialogs[0], dialogs[0]

    # Random bytes with the right ISF (the judge's case): no kernel in the file, the ISF is not blamed.
    for isf in (d13, None):
        dialogs, log, _ = run("export_random_isf" if isf else "export_random_no_isf", "banners_random", isf)
        text = dialogs[0]
        assert len(ran_banners(log)) == 1, log
        assert "Volatility found no Linux kernel in this file" in text and "LiME" in text and "AVML" in text, text
        assert "and xz, gzip or bzip2 compressed copies of these (named .xz, .gz or .bz2);" in text, text
        assert "VMware .vmem (read as a raw image; its .vmss or .vmsn file next to it is needed for the right" in text, text
        assert "another kernel" not in text and "Image:" not in text and "ISF:" not in text, text
        assert "fresh pip install" not in text, text

    # No ISF (Volatility's own symbol folders): the image's lines, so the user knows which ISF to get.
    text = run("export_trace_no_isf", "banners_trace", None)[0][0]
    assert "fresh pip install has none" in text and "An ISF for your own image" in text, text
    assert text.count("\nImage: ") == 3 and "\nImage: " + D13_LINE + "\n" in text and "ISF:" not in text, text
    assert "is the running kernel" not in text, text

    # The ISF's line is in the image yet Volatility failed (not recorded: the real export with this ISF succeeds).
    D13_EXACT = base64.b64decode(D13)
    text = run("export_trace_wrong_isf", "banners_trace", d13, image_bytes=b"\0" * 64 + D13_EXACT)[0][0]
    assert "holds the ISF's kernel version line as the kernel stores it" in text and "another kernel" not in text, text
    assert "\nImage: " + D13_LINE + " (the ISF's)\n" in text and text.count("(the ISF's)") == 1, text
    assert any("exact kernel version line" in w for w in waits), waits

    # The review's planted journal copy of the Debian 12 line (real banners.Banners output, tests/fixtures): listed by
    # banners.Banners (last of 4 different lines) but not as the kernel stores it, so Volatility never matches it.
    copy = b"\0" * 64 + b"MESSAGE=" + D12_LINE.encode() + b"\0" * 8 + D13_EXACT
    journal = m.image_banners(fixture("banners_journal_copy.stdout"))
    assert len(journal) == 4 and journal[0] == D13_LINE and journal[-1] == D12_LINE, journal
    text = run("export_journal_copy_wrong_isf", "banners_journal_copy", d12, image_bytes=copy)[0][0]
    assert "The ISF you chose was built for another kernel: its kernel version line is in this image only as a copy" \
        in text and "fits" not in text and "An ISF for your own image" in text, text
    assert "\nISF: " + D12_LINE + "\n" in text and "\nImage: " + D12_LINE + " (the ISF's, only a copy)\n" in text, text
    assert text.count("\nImage: ") == 4 and "4 different" in text and "... and" not in text, text
    # The same image holding the Debian 12 line as a kernel stores it: the ISF fits (whatever its rank in the list).
    text = run("export_journal_copy_wrong_isf", "banners_journal_copy", d12, image_bytes=copy + D12_EXACT)[0][0]
    assert "holds the ISF's kernel version line as the kernel stores it" in text and "another kernel" not in text, text
    assert "\nImage: " + D12_LINE + " (the ISF's)\n" in text, text
    # A compressed image, or Cancel during that check: no verdict either way, both causes named.
    for image_bytes, cancel, why in ((b"\xfd7zXZ\x00" + copy, lambda: False, "the file is compressed"),
                                     (copy, lambda: bool(waits) and "exact" in waits[-1], "you cancelled that check")):
        text = run("export_journal_copy_wrong_isf", "banners_journal_copy", d12, cancel=cancel,
                   image_bytes=image_bytes)[0][0]
        assert "could not check whether it is there as the kernel stores it" in text and ": %s. So" % why in text, text
        assert "or the line is only a copy" in text and "Volatility failed for another reason" in text, text
        assert "\nImage: " + D12_LINE + " (the ISF's)\n" in text, text
    # A wrong ISF whose line is not in the image: no need to read the image (banners.Banners already says so).
    reads = []
    real_holds_bytes = m.holds_bytes
    m.holds_bytes = lambda *a: reads.append(a) or real_holds_bytes(*a)
    text = run("export_trace_wrong_isf", "banners_trace", d12, image_bytes=copy)[0][0]
    m.holds_bytes = real_holds_bytes
    assert reads == [] and "The ISF you chose was built for another kernel: its kernel version line (linux_banner) is " \
        "not in this image" in text, (reads, text)
    # An ISF without linux_banner, and a file that is not an ISF: said so, the image's lines still shown.
    text = run("export_trace_wrong_isf", "banners_trace", no_banner)[0][0]
    assert "cannot be compared with the image: it has no linux_banner" in text and "\nImage: " + D13_LINE in text, text
    text = run("export_trace_wrong_isf", "banners_trace", not_isf)[0][0]
    assert "cannot be compared with the image: notes.json is not a readable Volatility ISF" in text, text
    for damaged in ("!!!x", 7):  # not base64, not text: said so instead of an unexpected error
        line, exact, problem = m.isf_banner(isf_file("damaged.json", damaged))
        assert line is None is exact and problem.startswith("its linux_banner is not readable"), problem

    # AVML without libsnappy: Volatility's own warning names it; no banner scan of compressed bytes.
    dialogs, log, _ = run("export_avml_header_isf", "banners_avml_header", d13)
    assert ran_banners(log) == [] and "This is an AVML image" in dialogs[0] and "libsnappy.so.1" in dialogs[0], (log, dialogs)
    assert "another kernel" not in dialogs[0], dialogs[0]

    # Cancel during the export: no banner scan, no dialog.
    dialogs, log, took = run("export_trace_wrong_isf", "banners_trace", d12, cancel=lambda: True, export_sleep=5)
    assert dialogs == [] and ran_banners(log) == [] and took < 4, (dialogs, log, took)
    assert not any("kernel version" in w for w in waits), waits
    # Cancel during the banner scan: it is killed, and the dialog says the check was cancelled (no guess either way).
    dialogs, log, took = run("export_trace_wrong_isf", "banners_trace", d12, banners_sleep=5,
                             cancel=lambda: bool(waits) and "kernel version" in waits[-1])
    text = dialogs[0]
    assert len(ran_banners(log)) == 1 and took < 4, (log, took)
    assert "You cancelled the check" in text and "Image:" not in text and "ISF:" not in text, text
    assert "either the ISF you chose was built for another kernel" in text and "not a Linux memory image" in text, text
    # The banner scan fails too: said so, and no claim about the kernel.
    text = run("export_trace_no_isf", "banners_trace", None, banners_exit=1)[0][0]
    assert "banners.Banners exited with 1" in text and "Image:" not in text and "fresh pip install" in text, text

    # A cut image with the right ISF (recorded): said so, before any banner-based verdict, and no banner scan.
    for data, kind in ((elf_core([0x30, 0x2000])[:-0x100], "ELF"), (lime([0x40, 0x3000])[:500], "LiME")):
        dialogs, log, _ = run("export_truncated_isf", "banners_truncated", d13, image_bytes=data)
        text = dialogs[0]
        assert ran_banners(log) == [] and "The image file is shorter than its own %s headers say" % kind in text, text
        assert "probably an incomplete copy" in text and "Copy or download the image again" in text, text
        assert "another kernel" not in text and "no Linux kernel" not in text and "Image:" not in text, text
    text = run("export_truncated_isf", "banners_truncated", d13, image_bytes=b"\0" * 64 + D13_EXACT)[0][0]
    assert "another kernel" in text and "Image: " in text, text  # a plain file: only the banner scan to go by

    # Not a kernel-not-found failure (an old Volatility without the exporter): no banner scan.
    old = os.path.join(work, "old_volatility")  # the message shape seen with 2.11.0 (an absolute path wins in join)
    open(old + ".stdout", "wb").write(b"Volatility 3 Framework 2.11.0\n")
    open(old + ".stderr", "wb").write(b"vol: error: argument plugin: invalid choice linux.kernel2elf.Kernel2Elf "
                                      b"(choose from banners.Banners)\n")
    dialogs, log, _ = run(old, "banners_trace", d12)
    assert ran_banners(log) == [] and "could not load MemLens' exporter" in dialogs[0], (log, dialogs)

# The real demo ISF, when present, carries exactly the line the recorded scan of trace.elf put first.
demo_isf = os.environ.get("MEMLENS_ISF", "/home/agent/tools/memlens-demo/x/debian-6.12.115+deb13.1-amd64.json.xz")
if os.path.isfile(demo_isf):
    assert m.isf_banner(demo_isf) == (D13_LINE, base64.b64decode(D13), None), m.isf_banner(demo_isf)
    print("demo ISF %s: its linux_banner is the recorded image's first line" % demo_isf)
else:
    print("SKIP: demo ISF not found (set MEMLENS_ISF)")
print("export failure stub test OK (fake IDA modules, recorded Volatility 2.28.2 output)")
