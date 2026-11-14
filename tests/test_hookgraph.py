#!/usr/bin/env python3
"""tools/hookgraph.py and the picture it drew (docs/img/hookchain.svg and .png), with no IDA.

usage: python3 tests/test_hookgraph.py [<demo kernel.elf> [<testhook kernel.elf>]]
Without arguments it takes MEMLENS_DEMO_ELF and MEMLENS_TESTHOOK_ELF from the environment (tests/run_all.py passes
both on), in that order.

Always:
- docs/img/hookchain.svg parses with xml.etree, uses only the generic monospace font, and has no script, style, image,
  link or event attribute (GitHub sanitises SVG). Every text node in its panel i is a substring of the --links output of
  sample i (docs/img/expected-hook-chain.demo.txt and .testhook.txt, byte copies of the two demo zips'
  expected-hook-chain.txt), each bold text a piece of an 'owner' line, one lane per patched entry, each with its owner
  in bold. Mutants fail that check: an owner renamed, an edge label changed, a hand-typed label, a line kind ('owner')
  or two fields as a label, a text outside the panels, a site made bold, the panels swapped.
- docs/img/hookchain.png is as wide and as tall as the SVG (about 900 px) and under 300 KB.
- docs/img/README.md has the README snippet with the caption and the image path.
- A hand-made kernel.elf (ftrace, module callback and unknown-role pages): the tool's SVG for it passes the same check
  against a fresh `patchscan.py --links` of it, the CLI and the function give the same bytes, and the exit codes.
With the demo kernel.elf files: `patchscan.py --links` on each prints its sample's expected text; the tool's SVG for
each alone passes the check; both together give docs/img/hookchain.svg byte for byte, twice (and through the CLI).
"""
import contextlib
import io
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import patchscan as ps  # noqa: E402
import hookgraph  # noqa: E402

IMG = os.path.join(ROOT, "docs", "img")
SVG_PATH, PNG_PATH = os.path.join(IMG, "hookchain.svg"), os.path.join(IMG, "hookchain.png")
SAMPLES = [("demo", os.path.join(IMG, "expected-hook-chain.demo.txt")),
           ("testhook", os.path.join(IMG, "expected-hook-chain.testhook.txt"))]
NS = "{http://www.w3.org/2000/svg}"
TOOL = [sys.executable, "-I", os.path.join(ROOT, "tools", "hookgraph.py")]
PATCHSCAN = [sys.executable, "-I", os.path.join(ROOT, "patchscan.py")]
CAPTION = "Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot"
SCANNED = re.compile(r"^\d+ function symbols scanned$")  # patchscan's stderr line, in the testhook zip's file too


def read(path, mode="r"):
    with open(path, mode) as handle:
        return handle.read()


def stdout_lines(text):
    """The lines of an expected-hook-chain text that patchscan prints on stdout (without its stderr line)."""
    return [line for line in text.splitlines() if not SCANNED.match(line)]


def fields(text):
    """The tab-separated fields of a --links text, without the line kinds (xref, rename, owner): a label must be a piece
    of one field, so a word that only the line kinds hold ('owner') or that spans two fields is not from the output."""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        out += parts[1:] if parts[0] in ("xref", "rename", "owner") else parts
    return out


def owner_texts(text):
    return [line.split("\t", 3)[3] for line in text.splitlines() if line.startswith("owner\t")]


def problems(svg_text, expected):
    """What is wrong with an SVG drawn from len(expected) kernel.elf files, panel i from the --links output expected[i]:
    [] when every text node in panel i is a substring of expected[i], and of one of its fields (fields), each bold text a
    piece of one of its owner lines, no text is outside a panel, and there are as many panels as texts."""
    root = ET.fromstring(svg_text)
    found = []
    panels = [g for g in root.iter(NS + "g") if g.get("class") == "panel"]
    if len(panels) != len(expected):
        found.append("%d panels for %d samples" % (len(panels), len(expected)))
    inside = set()
    for panel, text in zip(panels, expected):
        owners, pieces = owner_texts(text), fields(text)
        for element in panel.iter():
            if element.text and element.text.strip():
                inside.add(element)
                if element.text not in text:
                    found.append("not in the --links output: %r" % element.text)
                elif not any(element.text in piece for piece in pieces):
                    found.append("not in one field of the --links output: %r" % element.text)
                if element.get("font-weight") == "bold" and not any(element.text in owner for owner in owners):
                    found.append("bold but not an owner: %r" % element.text)
    for element in root.iter():
        if element.text and element.text.strip() and element not in inside:
            found.append("text outside the panels: %r" % element.text)
        if element.tail and element.tail.strip():
            found.append("text between elements: %r" % element.tail)
    return found


def safe(svg_text):
    """What GitHub's sanitiser or an offline viewer would trip on: [] when there is none."""
    root = ET.fromstring(svg_text)
    found = []
    if root.tag != NS + "svg" or root.get("font-family") != "monospace":
        found.append("root %s, font-family %r" % (root.tag, root.get("font-family")))
    for element in root.iter():
        tag = element.tag[len(NS):] if element.tag.startswith(NS) else element.tag
        if tag in ("script", "style", "image", "foreignObject", "a", "use", "font", "font-face"):
            found.append("element %s" % tag)
        for name, value in element.attrib.items():
            if name.lower().startswith("on") or name.endswith("href") or "url(" in value:
                found.append("attribute %s=%r" % (name, value))
        if element.get("font-family") not in (None, "monospace"):
            found.append("font-family %r" % element.get("font-family"))
    return found


def lanes_of(svg_text):
    """[[lane element, ...] per panel]."""
    root = ET.fromstring(svg_text)
    return [[lane for lane in panel.iter(NS + "g") if lane.get("class") == "lane"]
            for panel in root.iter(NS + "g") if panel.get("class") == "panel"]


def bold(element):
    return [node.text for node in element.iter() if node.get("font-weight") == "bold"]


# 1. The committed picture against the committed --links texts.
texts = [read(path) for _, path in SAMPLES]
svg_text = read(SVG_PATH)
assert safe(svg_text) == [], safe(svg_text)
assert problems(svg_text, texts) == [], problems(svg_text, texts)
panels = lanes_of(svg_text)
entries = [sum(1 for line in stdout_lines(text) if line.startswith("0x")) for text in texts]
assert [len(panel) for panel in panels] == entries, ([len(panel) for panel in panels], entries)  # one lane per patched entry
for panel, text in zip(panels, texts):
    for lane in panel:
        names = bold(lane)
        assert len(names) == 1 and any(owner.startswith(names[0]) for owner in owner_texts(text)), names  # the owner, in bold
root = ET.fromstring(svg_text)
width, height = int(root.get("width")), int(root.get("height"))
assert root.get("viewBox") == "0 0 %d %d" % (width, height) and 880 <= width <= 1000, (width, height)

# Mutants: each must fail.
mutants = {
    "owner renamed": svg_text.replace(">memlens_testhook.th_kill_callback<", ">memlens_testhook.th_kill_handler<"),
    "edge label": svg_text.replace(">call<", ">jump<", 1),
    "hand-typed label": svg_text.replace('<g class="lane">', '<g class="lane">\n<text x="0" y="0">hook page</text>', 1),
    "a line kind as a label": svg_text.replace(">ftrace_ops<", ">owner<", 1),
    "two fields as one label": svg_text.replace(">call<", ">call\tbpf_lsm_file_open+0x4<", 1),
    "text outside the panels": svg_text.replace('<g class="panel">', '<text x="0" y="0">call</text>\n<g class="panel">', 1),
    "site made bold": re.sub(r'(<text class="site"[^>]*?) fill=', r'\1 font-weight="bold" fill=', svg_text, count=1),
}
for name, mutant in mutants.items():
    assert mutant != svg_text, name
    assert problems(mutant, texts), name
assert problems(svg_text, texts[::-1]), "panels swapped"
assert problems(svg_text, texts[:1]), "a panel too many"
assert safe(svg_text.replace("<rect ", '<rect onclick="x" ', 1)) and safe(svg_text.replace('font-family="monospace"', 'font-family="Fira Code"'))

# 2. The PNG and the README snippet.
png = read(PNG_PATH, "rb")
assert png[:8] == b"\x89PNG\r\n\x1a\n" and png[12:16] == b"IHDR", png[:16]
assert struct.unpack(">II", png[16:24]) == (width, height), (struct.unpack(">II", png[16:24]), width, height)
assert len(png) < 300 * 1024, len(png)
notes = read(os.path.join(IMG, "README.md"))
assert CAPTION in notes and "docs/img/hookchain.png" in notes and "tools/hookgraph.py" in notes, notes[:300]
print("committed picture OK (%dx%d px; %s lanes; %d mutants fail; PNG %d bytes)" % (
    width, height, "+".join(str(len(panel)) for panel in panels), len(mutants) + 2, len(png)))

# 3. A hand-made kernel.elf: an ftrace page with no owner, a module callback (owner), a page whose role is unknown.
with contextlib.redirect_stdout(io.StringIO()):  # reuse test_patchscan's ELF builder; its own checks run silently
    builder = runpy.run_path(os.path.join(HERE, "test_patchscan.py"))
elf, call, BASE, TEXT = builder["elf"], builder["call"], builder["BASE"], builder["TEXT"]
code = bytearray(b"\x90" * TEXT)


def put(offset, data):
    code[offset:offset + len(data)] = data


FTRACE, OTHER, MODCB = BASE + 0x1000, BASE + 0x1100, BASE + 0x1900
PAGES = {"F": (BASE + 0x2000, FTRACE), "M": (BASE + 0x2200, MODCB), "U": (BASE + 0x2400, OTHER)}
for page, handler in PAGES.values():
    put(page - BASE + 0x40, call(page + 0x40, handler))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, PAGES["F"][0]))                     # traced_a: endbr64; call page F
put(0x100, call(BASE + 0x100, PAGES["M"][0]))                                       # modhook: call page M
put(0x200, b"\x68" + struct.pack("<i", PAGES["U"][0] - (1 << 64)) + b"\xc3")        # pushret: push page U; ret
symbols = [("traced_a", BASE, 0x100), ("modhook", BASE + 0x100, 0x100), ("pushret", BASE + 0x200, 0x100),
           ("function_trace_call", FTRACE, 0x100), ("some_helper", OTHER, 0x100), ("evilmod.fh_cb", MODCB, 0x100),
           ("linux_banner", BASE + 0xf00, 0x10)] + [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page, _ in PAGES.values()]
with tempfile.TemporaryDirectory() as work:
    path, out = os.path.join(work, "kernel.elf"), os.path.join(work, "out.svg")
    with open(path, "wb") as handle:
        handle.write(elf(code, symbols))
    linked = subprocess.run(PATCHSCAN + ["--links", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert linked.returncode == 0, linked.stderr
    made = hookgraph.svg([hookgraph.lanes(path)])
    assert made == hookgraph.svg([hookgraph.lanes(path)])
    cli = subprocess.run(TOOL + [path, "-o", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert cli.returncode == 0 and read(out, "rb") == made.encode("utf-8"), (cli.returncode, cli.stderr)
    assert safe(made) == [] and problems(made, [linked.stdout]) == [], (safe(made), problems(made, [linked.stdout]))
    lanes = lanes_of(made)[0]
    assert len(lanes) == 3 and [bold(lane) for lane in lanes] == [[], ["evilmod.fh_cb"], []], [bold(lane) for lane in lanes]
    assert "ftrace_tramp_traced_a" in made and "module_hook_modhook" in made and ">some_helper<" in made, made
    assert problems(made.replace(">evilmod.fh_cb<", ">evilmod.fh_cbx<"), [linked.stdout])
    assert ">module callback<" in made and problems(made.replace(">module callback<", ">owner<"), [linked.stdout])  # only a line kind
    codes = {}
    for name, argv in (("no -o", [path]), ("no file", ["-o", out]), ("-o without a path", [path, "-o"]),
                       ("unknown option", [path, "--isf", "x", "-o", out]), ("missing", [path + ".no", "-o", out]),
                       ("not an ELF", [SVG_PATH, "-o", out]), ("not a kernel export", [path + ".bin", "-o", out])):
        if name == "not a kernel export":
            with open(path + ".bin", "wb") as handle:
                handle.write(elf(code, [("traced_a", BASE, 0x100)]))  # no linux_banner: patchscan checks nothing
        codes[name] = subprocess.run(TOOL + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode
    assert codes == {"no -o": 2, "no file": 2, "-o without a path": 2, "unknown option": 2, "missing": 2, "not an ELF": 2,
                     "not a kernel export": 1}, codes
print("hand-made kernel.elf OK (3 lanes, 1 owner; CLI and function give the same bytes; exit codes)")

# 4. The demo kernel.elf files.
given = sys.argv[1:] or [os.environ.get(name, "") for name in ("MEMLENS_DEMO_ELF", "MEMLENS_TESTHOOK_ELF")]
given = [path for path in given if path]
matched = {}
for path in given:
    run = subprocess.run(PATCHSCAN + ["--links", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert run.returncode == 0, (path, run.stderr)
    sample = [name for (name, _), text in zip(SAMPLES, texts) if stdout_lines(text) == run.stdout.splitlines()]
    alone = hookgraph.svg([hookgraph.lanes(path)])
    if not sample:
        print("SKIP: %s: its --links output is neither sample's (docs/img/expected-hook-chain.*.txt); checked against itself only" % path)
        assert problems(alone, [run.stdout]) == [], problems(alone, [run.stdout])
        continue
    text = texts[[name for name, _ in SAMPLES].index(sample[0])]
    assert problems(alone, [text]) == [], problems(alone, [text])
    beside = os.path.join(os.path.dirname(os.path.abspath(path)), "expected-hook-chain.txt")
    if os.path.isfile(beside):  # the zip's own copy, when kernel.elf is where the zip put it
        assert read(beside) == text, beside
    matched[sample[0]] = path
    print("%s: the %s sample (%d lanes, every label in its expected-hook-chain.txt)" % (path, sample[0], len(lanes_of(alone)[0])))
if set(matched) == {"demo", "testhook"}:
    both = [matched["demo"], matched["testhook"]]
    first = hookgraph.svg([hookgraph.lanes(path) for path in both])
    second = hookgraph.svg([hookgraph.lanes(path) for path in both])
    assert first == second, "two runs differ"
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, "hookchain.svg")
        cli = subprocess.run(TOOL + both + ["-o", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert cli.returncode == 0, cli.stderr
        made = read(out, "rb")
    assert made == first.encode("utf-8") == read(SVG_PATH, "rb"), "docs/img/hookchain.svg is not what tools/hookgraph.py draws now"
    print("docs/img/hookchain.svg is what tools/hookgraph.py draws from the two demo kernel.elf files, byte for byte (twice, and the CLI)")
else:
    print("SKIP: regenerating docs/img/hookchain.svg needs both demo kernel.elf files (MEMLENS_DEMO_ELF, MEMLENS_TESTHOOK_ELF)")
print("hookgraph tests OK (%s)" % ("both demo kernel.elf files" if len(matched) == 2 else "%d demo kernel.elf file(s)" % len(matched)))
