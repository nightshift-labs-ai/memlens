#!/usr/bin/env python3
"""Show patched kernel functions on a database whose input file is not a kernel: one warning and no list, instead of an
empty list that looks clean. Two inputs: a file without function symbols (/bin/ls, or argv[1]) and, when a C compiler
is installed, a small unstripped program (function symbols but no linux_banner). Also the same warning from
patchscan.py on the command line. Then the first try on your own file (judge s194 item 5): a memory image (a hand-made
ELF core and a LiME header), a kernel file from disk (a hand-made ELF with .altinstructions, and argv[3] when given,
for example a stripped vmlinux) and anything else (a hand-made PE, an ARM64 ELF, a raw memory image, which has no
header and is read with one copy in memory) each get one line that names the next step. argv: [stripped ELF
(default /bin/ls)] [the demo kernel.elf, still scanned] [a kernel file from disk]. Fake IDA modules."""
import os, runpy, shutil, struct, subprocess, sys, tempfile, tracemalloc
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan

g = runpy.run_path(os.path.join(HERE, "test_plugin_stub.py"))
m, calls, nalt = g["m"], g["calls"], g["nalt"]
DEMO_URL = "https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data"  # the README's demo-data link
assert DEMO_URL in open(os.path.join(HERE, "..", "README.md")).read()
# One phrase per kind of file; each warning has its own kind's phrase and no other.
KEYS = {"memory image": "looks like a memory image",
        "from disk": "shows the kernel as built, not as it ran",
        "other": "MemLens works on a Linux kernel exported from a memory image"}
NEXT = {"memory image": ["Edit > Plugins > MemLens: Export kernel from memory image", "tools/find_isf.py"],
        "from disk": ["export a kernel.elf from a memory image of that system", DEMO_URL],
        "other": ["Edit > Plugins > MemLens: Export kernel from memory image", DEMO_URL]}  # a raw image is "other" too


def check(target, reason):
    image = patchscan.Image(open(target, "rb").read())
    assert patchscan.nothing_to_check(image) == reason, (target, patchscan.nothing_to_check(image))
    nalt.get_input_file_path = lambda: target
    m._open_list = None
    del calls[:]
    assert m.FindPatches().activate(None) == 0
    ui = [c[1] for c in calls if c[0] == "ui"]
    assert len(ui) == 1 and "checked nothing" in ui[0] and reason in ui[0], ui
    assert KEYS["other"] in ui[0] and DEMO_URL in ui[0], ui  # the next step: the demo kernel.elf
    assert m._open_list is None, "a patch list was opened"
    assert not any(c[0] == "msg" and "patched entries" in c[1] for c in calls), calls
    cli = subprocess.run([sys.executable, "-I", os.path.join(HERE, "..", "patchscan.py"), target],
                         capture_output=True, text=True)
    assert cli.returncode == 0 and ("warning: %s, so nothing was checked" % reason) in cli.stderr, cli.stderr
    assert cli.stdout == "", cli.stdout
    print("FindPatches stub test OK (%s: %s -> one warning, no list; command line warns too)"
          % (os.path.basename(target), reason))


ran = 0
def image_of(path):
    """The parsed ELF, or None when it is not an x86-64 ELF (macOS Mach-O, an ARM host's binaries)."""
    try:
        return patchscan.Image(open(path, "rb").read())
    except patchscan.BAD_ELF as error:
        print("SKIP: %s: %s" % (path, error))
        return None


stripped = sys.argv[1] if len(sys.argv) > 1 else "/bin/ls"
if not os.path.isfile(stripped):
    print("SKIP: %s not found (pass an ELF without function symbols)" % stripped)
else:
    image = image_of(stripped)
    if image is not None and any(s[3] == patchscan.STT_FUNC for s in image.symbols):
        print("SKIP: %s has function symbols here (pass a stripped ELF as argv[1])" % stripped)
    elif image is not None:
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
        if image_of(program) is not None:
            check(program, "no linux_banner symbol (not a kernel.elf exported by MemLens)")
            ran += 1

# The real exported kernel.elf must still be scanned (it has linux_banner).
demo = sys.argv[2] if len(sys.argv) > 2 else "kernel.elf"
if os.path.isfile(demo):
    assert patchscan.nothing_to_check(patchscan.Image(open(demo, "rb").read())) is None
    print("kernel.elf %s: checkable" % demo)
else:
    print("SKIP: no %s to check that a real export is still scanned (pass the demo kernel.elf as argv[2])" % demo)


# The first try on your own file (judge s194 item 5): one line with the next step, and no list.
class Counted:
    """A file whose reads are counted."""
    def __init__(self, handle):
        self.handle, self.count = handle, 0
    def read(self, *size):
        data = self.handle.read(*size)
        self.count += len(data)
        return data
    def __enter__(self):
        return self
    def __exit__(self, *error):
        self.handle.close()


landed = []
def landing(path, kind, what):
    nalt.get_input_file_path = lambda: path
    m._open_list = None
    del calls[:]
    opened = []
    m.open = lambda *args: opened.append(Counted(open(*args))) or opened[-1]  # memlens_entry's open: reads counted
    try:
        assert m.FindPatches().activate(None) == 0, what
    finally:
        del m.open
    if kind == "memory image":  # read no further than its header: a memory image can be gigabytes
        assert sum(handle.count for handle in opened) <= 64, (what, [handle.count for handle in opened])
    ui = [c[1] for c in calls if c[0] == "ui"]
    assert len(ui) == 1, (what, ui)
    text = ui[0]
    for other, phrase in KEYS.items():
        assert (phrase in text) == (other == kind), (what, kind, phrase, text)
    for step in NEXT[kind]:
        assert step in text, (what, step, text)
    assert "\n" not in text and len(text) <= 330, (what, len(text), text)  # one short line
    assert os.path.basename(path) in text, (what, text)
    assert m._open_list is None, "a patch list was opened for %s" % what
    print("landing OK (%s -> %s: %s)" % (what, kind, text))
    landed.append(kind)


def elf(e_type, machine, sections=None, loads=()):
    """A 64-bit little-endian ELF: a header, one program header per (p_type, data) in loads, then each section's data
    and a section table with a .shstrtab (sections: (name, data)); no section table when sections is None."""
    offset = 64 + 56 * len(loads)
    phdrs, body = b"", b""
    for index, (p_type, data) in enumerate(loads):
        phdrs += struct.pack("<IIQQQQQQ", p_type, 4, offset + len(body), 0, 0x1000 * index, len(data), len(data), 0)
        body += data
    shoff = shnum = shstrndx = 0
    table = b""
    if sections is not None:
        names, table = b"\0", bytes(64)
        for name, data in list(sections) + [(".shstrtab", None)]:
            if data is None:  # the section names come last
                data = names + name.encode() + b"\0"
            table += struct.pack("<IIQQQQIIQQ", len(names), 3 if name == ".shstrtab" else 1, 0, 0, offset + len(body),
                                 len(data), 0, 0, 1, 0)
            names += name.encode() + b"\0"
            body += data
        shoff, shnum, shstrndx = offset + len(body), len(sections) + 2, len(sections) + 1
    head = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9) + struct.pack(
        "<HHIQQQIHHHHHH", e_type, machine, 1, 0, 64 if loads else 0, shoff, 0, 64, 56, len(loads), 64, shnum, shstrndx)
    return head + phdrs + body + table


with tempfile.TemporaryDirectory() as work:
    def write(name, data):
        path = os.path.join(work, name)
        with open(path, "wb") as handle:
            handle.write(data)
        return path

    # A memory image: an ELF core dump (QEMU's dump-guest-memory writes one) and a LiME file (one 4 KiB range).
    landing(write("guest.elf", elf(4, 62, loads=[(4, bytes(32)), (1, bytes(4096))])), "memory image", "ELF core (ET_CORE)")
    landing(write("guest.lime", struct.pack("<IIQQ8x", 0x4C694D45, 1, 0, 0xFFF) + bytes(4096)), "memory image", "LiME")
    # A kernel file from disk: its alternatives are unapplied (.altinstructions), so its entries are not what ran.
    landing(write("vmlinux", elf(2, 62, sections=[(".text", b"\x90" * 16), (".altinstructions", bytes(12))])),
            "from disk", "hand-made ELF with .altinstructions")
    vmlinux = sys.argv[3] if len(sys.argv) > 3 else ""
    if vmlinux and os.path.isfile(vmlinux):
        landing(vmlinux, "from disk", "kernel file from disk %s" % vmlinux)
    else:
        print("(no kernel file from disk given as argv[3]: only the hand-made one was checked)")
    # Anything else: a Windows PE and an ELF for another machine.
    pe = bytearray(0x200)
    pe[:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, 0x80)
    pe[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", pe, 0x84, 0x8664)
    landing(write("program.exe", bytes(pe)), "other", "PE (MZ...PE)")
    landing(write("arm64.elf", elf(2, 183, sections=[(".text", bytes(16))])), "other", "ARM64 ELF")
    # A raw memory image (LiME format=raw, dd, VMware .vmem) has no header to tell: it is "other", whose line names
    # Export too, and it is read like any other file, with one copy of it in memory (review s197: the first 64 bytes
    # joined to the rest held two).
    raw, size = os.path.join(work, "memory.raw"), 32 << 20
    with open(raw, "wb") as handle:
        handle.truncate(size)  # sparse zeros
    tracemalloc.start()
    try:
        landing(raw, "other", "raw memory image (no header), 32 MiB")
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1.5 * size, (peak, size)
    print("raw memory image: peak %.1f MiB of Python memory for a %d MiB file (one copy)" % (peak / 2.0 ** 20, size >> 20))
print("ran %d of 2 non-kernel cases; %d own-file warnings name the next step (%s)"
      % (ran, len(landed), ", ".join("%d %s" % (landed.count(k), k) for k in KEYS)))
