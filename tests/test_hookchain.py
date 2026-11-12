#!/usr/bin/env python3
"""The hook chain decisions in patchscan (which instruction hooks an entry, which page and handler it leads to, what
the page is renamed to), with no IDA: hand-made ELFs, then real kernel.elf exports when given.

usage: python3 tests/test_hookchain.py [kernel.elf ...]
Pass the demo kernel.elf (memlens-demo-debian13.zip, demo-data release) and/or the export of the Debian 13 hooks
capture: both hold the same three hooks (ftrace on vfs_getattr, a kprobe on do_sys_openat2, a BPF trampoline on
bpf_lsm_file_open) at different KASLR addresses. An export of the Ubuntu 24.04 capture (BPF trampoline on
__hid_bpf_tail_call) is known too. Without files only the hand-made cases run.
"""
import contextlib, io, os, runpy, struct, subprocess, sys, tempfile
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
import patchscan as ps

with contextlib.redirect_stdout(io.StringIO()):  # reuse its ELF builder; its own checks run silently
    builder = runpy.run_path(os.path.join(HERE, "test_patchscan.py"))
elf, call, BASE, TEXT = builder["elf"], builder["call"], builder["BASE"], builder["TEXT"]

code = bytearray(b"\x90" * TEXT)
def put(offset, data): code[offset:offset + len(data)] = data
ENDBR, NOP = b"\xf3\x0f\x1e\xfa", ps.FENTRY_NOP
FTRACE, KPROBE, BPF, OTHER = BASE + 0x1000, BASE + 0x1100, BASE + 0x1200, BASE + 0x1300  # handlers
P = {key: BASE + offset for key, offset in (("F", 0x2000), ("K", 0x2200), ("B", 0x2400), ("U", 0x2600), ("X", 0x2800), ("F2", 0x2a00),
                                            ("C", 0x2c00), ("D1", 0x2e00), ("D2", 0x3000), ("L", 0x3200), ("F3", 0x3400), ("A", 0x3600))}
handler_of = {"F": FTRACE, "K": KPROBE, "B": BPF, "U": OTHER, "X": FTRACE, "F2": FTRACE, "C": FTRACE, "D1": FTRACE, "D2": FTRACE,
              "L": FTRACE, "F3": FTRACE, "A": FTRACE}
for key, page in P.items():
    put(page - BASE + 0x40, call(page + 0x40, handler_of[key]))                 # each page calls its handler at +0x40
put(P["F"] - BASE + 0x10, call(P["F"] + 0x10, P["K"]))                          # a call to another copied page is not the handler
LONG = "l" * 210
put(0x000, ENDBR + call(BASE + 4, P["F"]))                                      # traced_a: endbr64; call page F
put(0x100, call(BASE + 0x100, P["F"]))                                          # traced_b: call page F (shared)
put(0x200, ENDBR + call(BASE + 0x204, P["K"]))                                  # probed.isra.0
put(0x300, ENDBR + b"\x48\xb8" + struct.pack("<Q", P["B"]) + b"\xff\xe0")        # movjmp: movabs rax; jmp rax
put(0x400, b"\x68" + struct.pack("<i", P["U"] - (1 << 64)) + b"\xc3")            # pushret: push imm32; ret
put(0x500, b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", P["X"]))              # ripjmp: jmp [rip+0] to a page with a real symbol
put(0x600, b"\xff\x15" + struct.pack("<i", BASE + TEXT - (BASE + 0x606)))       # rippage: call [rip+X], pointer -> page F2
put(0x700, ENDBR + NOP + call(BASE + 0x709, P["C"], 0xE9))                      # nop_then: endbr; ftrace NOP; jmp page C
put(0x800, b"\xcc\x89\xe5")                                                     # int3_fn: no target
put(0x900, call(BASE + 0x900, 0xffffffffc0001000))                              # far: target not in the ELF
put(0xa00, call(BASE + 0xa00, P["D1"]))                                         # dup.x
put(0xb00, call(BASE + 0xb00, P["D2"]))                                         # dup_x: same name once made IDA-safe
put(0xc00, call(BASE + 0xc00, P["L"]))                                          # a 210-character name
put(0xd00, b"\x48\xb8" + struct.pack("<Q", P["F3"]) + b"\xff\xd0")               # movcall: movabs rax; call rax
put(0xe00, call(BASE + 0xe00, P["A"]))                                          # alias_a and alias_b: one entry, two names
symbols = [("traced_a", BASE, 0x100), ("traced_b", BASE + 0x100, 0x100), ("probed.isra.0", BASE + 0x200, 0x100),
           ("movjmp", BASE + 0x300, 0x100), ("pushret", BASE + 0x400, 0x100), ("ripjmp", BASE + 0x500, 0x100),
           ("rippage", BASE + 0x600, 0x100), ("nop_then", BASE + 0x700, 0x100), ("int3_fn", BASE + 0x800, 0x100),
           ("far", BASE + 0x900, 0x100), ("dup.x", BASE + 0xa00, 0x100), ("dup_x", BASE + 0xb00, 0x100), (LONG, BASE + 0xc00, 0x100),
           ("movcall", BASE + 0xd00, 0x100), ("alias_b", BASE + 0xe00, 0x100), ("alias_a", BASE + 0xe00, 0x100),
           ("function_trace_call", FTRACE, 0x100), ("kprobe_ftrace_handler", KPROBE, 0x100), ("__bpf_tramp_enter", BPF, 0x100),
           ("some_helper", OTHER, 0x100),
           ("ftrace_tramp_nop_then", BASE + 0x1400, 0x10), ("ftrace_tramp_%x" % P["L"], BASE + 0x1410, 0x10),  # names already taken
           ("real_tramp", P["X"], 0), ("sys_call_table", BASE + TEXT + 8, 0x8)]
symbols += [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page in P.values()]
rodata = struct.pack("<QQ", P["F2"], P["F"])  # rippage's pointer; sys_call_table[0] -> page F (data, never linked)
image = ps.Image(elf(code, symbols, rodata))
findings = ps.scan(None, image)
assert {row[1] for row in findings} == {"traced_a", "traced_b", "probed.isra.0", "movjmp", "pushret", "ripjmp", "rippage", "nop_then",
                                        "int3_fn", "far", "dup.x", "dup_x", LONG, "movcall", "alias_a", "alias_b", "sys_call_table[0]"}, findings

links = {link.function: link for link in ps.hook_links(image, findings)}
assert set(links) == {"traced_a", "traced_b", "probed.isra.0", "movjmp", "pushret", "ripjmp", "rippage", "nop_then", "dup.x", "dup_x",
                      LONG, "movcall", "alias_a", "alias_b"}, sorted(links)  # not int3_fn, far (not in the ELF), the syscall slot
# Where the hooking instruction is and what it is: after endbr64, the jmp/call of a movabs hook 10 bytes in, a
# push+ret at its ret, after the ftrace NOP.
sites = {name: (link.site - link.entry, link.flow, link.target) for name, link in links.items()}
assert sites == {"traced_a": (4, "call", P["F"]), "traced_b": (0, "call", P["F"]), "probed.isra.0": (4, "call", P["K"]),
                 "movjmp": (14, "jmp", P["B"]), "pushret": (5, "jmp", P["U"]), "ripjmp": (0, "jmp", P["X"]),
                 "rippage": (0, "call", P["F2"]), "nop_then": (9, "jmp", P["C"]), "dup.x": (0, "call", P["D1"]),
                 "dup_x": (0, "call", P["D2"]), LONG: (0, "call", P["L"]), "movcall": (10, "call", P["F3"]),
                 "alias_a": (0, "call", P["A"]), "alias_b": (0, "call", P["A"])}, sites
# Handler: the first named call in a copied page (the call to page K at +0x10 is skipped); none behind a real symbol.
assert links["traced_a"].handler_site == P["F"] + 0x40 and links["traced_a"].handler == FTRACE, links["traced_a"]
assert (links["traced_a"].handler_name, links["traced_a"].kind) == ("function_trace_call", "ftrace")
assert (links["probed.isra.0"].handler_name, links["probed.isra.0"].kind) == ("kprobe_ftrace_handler", "kprobe via ftrace")
assert (links["movjmp"].handler_name, links["movjmp"].kind) == ("__bpf_tramp_enter", "BPF trampoline")
assert (links["pushret"].handler_name, links["pushret"].kind) == ("some_helper", None)
assert not links["ripjmp"].page and links["ripjmp"].handler is None and links["ripjmp"].handler_name is None
assert all(link.page for name, link in links.items() if name != "ripjmp")

xrefs = ps.hook_xrefs(list(links.values()))
expected = {(link.site, link.target, link.flow) for link in links.values()}
expected |= {(P[key] + 0x40, handler_of[key], "call") for key in P if key != "X"}
assert sorted(expected) == xrefs and len(xrefs) == len(set(xrefs)), xrefs  # page F's handler call once, for two entries

names = ps.role_names(image, list(links.values()))
assert names == {P["F"]: "ftrace_tramp_%x" % P["F"],                 # shared by traced_a and traced_b: role and address
                 P["K"]: "kprobe_ftrace_tramp_probed_isra_0",       # one user: role and function, '.' made '_'
                 P["B"]: "bpf_tramp_movjmp", P["F2"]: "ftrace_tramp_rippage", P["F3"]: "ftrace_tramp_movcall",
                 P["C"]: "ftrace_tramp_%x" % P["C"],                 # ftrace_tramp_nop_then is a symbol already
                 P["D1"]: "ftrace_tramp_dup_x", P["D2"]: "ftrace_tramp_%x" % P["D2"],  # dup.x took it first
                 P["A"]: "ftrace_tramp_alias_a"}, names               # one entry with two names: the smaller one
# Not renamed: page U (unknown role), page X (it has a real symbol), page L (too long, and its address form is taken).
assert all(ps.ida_safe(name) == name and not name[0].isdigit() for name in names.values())
assert len(set(names.values())) == len(names) and not set(names.values()) & set(image.by_name)
assert ps.ida_safe("nf_tables.nft_do_chain") == "nf_tables_nft_do_chain" and ps.ida_safe("a-b$cé") == "a_b_c_"
assert not ps.copied_page(image, P["X"]) and ps.copied_page(image, P["U"]) and not ps.copied_page(image, FTRACE)
assert not ps.copied_page(image, P["F"] + 1)  # no symbol at that address at all

comments = ps.page_comments(list(links.values()))
assert set(comments) == set(P.values()) - {P["X"]}, comments
assert comments[P["F"]] == ("MemLens: hook page no module owns, copied from memory (exporter label memlens_target_%x); reached from "
                            "traced_a, traced_b; first named call: function_trace_call (ftrace)" % P["F"]), comments[P["F"]]
assert comments[P["U"]].endswith("reached from pushret; first named call: some_helper"), comments[P["U"]]
many = [ps.Link(BASE + 0x10 * i, "fn%d" % i, BASE + 0x10 * i, "call", P["F"], True, None, None, None, None) for i in range(7)]
assert ps.page_comments(many)[P["F"]].endswith("reached from fn0, fn1, fn2, fn3, fn4 and 2 more"), ps.page_comments(many)

rows = {row[1]: row for row in ps.list_rows(image, findings, list(links.values()), names)}
assert rows["traced_a"][3:] == ("ftrace_tramp_%x" % P["F"], "function_trace_call (ftrace)", FTRACE), rows["traced_a"]
assert rows["pushret"][3:] == ("memlens_target_%x" % P["U"], "some_helper", OTHER), rows["pushret"]
assert rows["ripjmp"][3:] == ("real_tramp", "", None), rows["ripjmp"]
# A syscall slot is never linked, but its target page F was renamed: the row shows the page's name now and its handler.
assert rows["sys_call_table[0]"][3:] == ("ftrace_tramp_%x" % P["F"], "function_trace_call (ftrace)", FTRACE), rows["sys_call_table[0]"]
assert ps.copied_targets(image, findings) == {link.target for link in links.values() if link.page}, ps.copied_targets(image, findings)
assert rows["int3_fn"][3:] == ("", "", None) and rows["far"][3] == "0xffffffffc0001000 (no symbol)", (rows["int3_fn"], rows["far"])
assert [row[0] for row in ps.list_rows(image, findings, [], {})] == [row[0] for row in findings]
# The command line prints the same chain with --links (and only then): one line per xref, one per rename.
with tempfile.TemporaryDirectory() as work:
    path = os.path.join(work, "kernel.elf")
    with open(path, "wb") as handle:
        handle.write(elf(code, symbols, rodata))
    cli = [sys.executable, "-I", os.path.join(HERE, "..", "patchscan.py")]
    plain = subprocess.run(cli + [path], capture_output=True, text=True)
    linked = subprocess.run(cli + ["--links", path], capture_output=True, text=True)
assert plain.returncode == 0 and linked.returncode == 0, (plain.stderr, linked.stderr)
extra = linked.stdout[len(plain.stdout):].splitlines()
assert linked.stdout.startswith(plain.stdout) and not any(line.startswith(("xref", "rename")) for line in plain.stdout.splitlines())
assert [line.split("\t")[1:4] for line in extra if line.startswith("xref")] == [["%#x" % a, "%#x" % b, f] for a, b, f in xrefs], extra
assert [line.split("\t")[1:] for line in extra if line.startswith("rename")] == [
    ["%#x" % page, "%s%x" % (ps.TARGET_PREFIX, page), name] for page, name in sorted(names.items())], extra
assert len(extra) == len(xrefs) + len(names), extra
assert "xref\t%#x\t%#x\tcall\ttraced_a+0x4 -> memlens_target_%x" % (BASE + 4, P["F"], P["F"]) in extra, extra
assert "xref\t%#x\t%#x\tcall\tmemlens_target_%x+0x40 -> function_trace_call" % (P["F"] + 0x40, FTRACE, P["F"]) in extra, extra

# Two trampolines packed into one copied region (BPF prog_pack, execmem caches): P1's own call goes to memory with no
# symbol (a hidden module's callback), P2 at +0x100 is an ordinary ftrace trampoline. P1's handler search stops at P2's
# label, so P1 does not get P2's handler, role, xref or name.
packed = bytearray(b"\x90" * TEXT)
P1, P2, HIDDEN = BASE + 0x2000, BASE + 0x2100, BASE + 0x3800
packed[P1 - BASE + 0x94:P1 - BASE + 0x99] = call(P1 + 0x94, HIDDEN)
packed[P2 - BASE + 0x94:P2 - BASE + 0x99] = call(P2 + 0x94, FTRACE)
packed[0x000:0x005] = call(BASE, P1)
packed[0x100:0x105] = call(BASE + 0x100, P2)
pimage = ps.Image(elf(packed, [("evil_target", BASE, 0x100), ("traced", BASE + 0x100, 0x100), ("function_trace_call", FTRACE, 0x100)]
                      + [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page in (P1, P2)]))
plinks = {link.function: link for link in ps.hook_links(pimage, ps.scan(None, pimage))}
assert (plinks["evil_target"].handler_site, plinks["evil_target"].handler_name) == (None, None), plinks["evil_target"]
assert (plinks["traced"].handler_site, plinks["traced"].kind) == (P2 + 0x94, "ftrace"), plinks["traced"]
assert ps.role_names(pimage, list(plinks.values())) == {P2: "ftrace_tramp_traced"}
assert (P1 + 0x94, FTRACE, "call") not in ps.hook_xrefs(list(plinks.values()))
assert ps.handler_call(pimage, P2) == (P2 + 0x94, FTRACE, "function_trace_call")  # the last symbol: up to span or segment end
print("hook chain tests OK (hand-made ELFs: %d links, %d xrefs, %d pages renamed; packed trampolines; patchscan.py --links)" % (
    len(links), len(xrefs), len(names)))

# Real exports. Offsets from the entry and from the page, as seen in objdump on the demo (README "What you get").
EXPECTED = {
    "vfs_getattr": (4, 0x94, "function_trace_call", "ftrace", "ftrace_tramp_vfs_getattr"),
    "do_sys_openat2": (0, 0xd9, "kprobe_ftrace_handler", "kprobe via ftrace", "kprobe_ftrace_tramp_do_sys_openat2"),
    "bpf_lsm_file_open": (4, 0x23, "__bpf_tramp_enter", "BPF trampoline", "bpf_tramp_bpf_lsm_file_open"),
    "__hid_bpf_tail_call": (0, 0x23, "__bpf_tramp_enter", "BPF trampoline", "bpf_tramp___hid_bpf_tail_call"),
}
for path in sys.argv[1:]:
    image = ps.Image(open(path, "rb").read())
    findings = ps.scan(None, image)
    links = ps.hook_links(image, findings)
    names = ps.role_names(image, links)
    assert links and len(links) == len(findings), (path, findings)
    for link in links:
        site, handler_offset, handler, kind, name = EXPECTED[link.function]
        assert (link.site - link.entry, link.flow, link.page) == (site, "call", True), link
        assert (link.handler_site - link.target, link.handler_name, link.kind) == (handler_offset, handler, kind), link
        assert image.by_name[handler][0] == link.handler, link
        assert names[link.target] == name, (names, link)
        assert ps.describe(image, link.target) == "%s%x" % (ps.TARGET_PREFIX, link.target)
    xrefs = ps.hook_xrefs(links)
    assert len(xrefs) == 2 * len(links), xrefs
    print("%s: %d patched entries, %d linked to a copied hook page, %d xrefs, %d pages renamed (%s)" % (
        path, len(findings), sum(link.page for link in links), len(xrefs), len(names), ", ".join(sorted(names.values()))))
if len(sys.argv) < 2:
    print("real kernel.elf files SKIPPED (none given)")
