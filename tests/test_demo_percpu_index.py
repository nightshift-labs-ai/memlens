#!/usr/bin/env python3
"""Per-CPU copies on the real demo export: the one-pass index must give what the one-by-one lookup gives.

usage: python3 tests/test_demo_percpu_index.py [path/to/demo/kernel.elf [path/to/isf.json.xz]]
The demo is in memlens-demo-debian13.zip (demo-data release). Without it the test is skipped.
IDA is faked: names come from the ELF's .symtab and segments from its allocated sections, so this checks
our logic on a real kernel2elf export, not IDA itself. Run twice: with the exporter's cpu<N>.<name> names,
and with '.' stored as '_' (cpu<N>_<name>, sections _percpu_cpu<N>), in case IDA's loader does that.
"""
import bisect, glob, os, struct, sys, types

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
elf_path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MEMLENS_DEMO_ELF", "")
if not elf_path or not os.path.isfile(elf_path):
    print("demo per-CPU index test SKIPPED (no demo kernel.elf given)")
    sys.exit(0)
isf_path = sys.argv[2] if len(sys.argv) > 2 else (glob.glob(os.path.join(os.path.dirname(elf_path), "*.json*")) or [""])[0]
data = open(elf_path, "rb").read()


def cstr(offset):
    return data[offset:data.index(b"\0", offset)].decode()


shoff, = struct.unpack_from("<Q", data, 0x28)
shentsize, shnum, shstrndx = struct.unpack_from("<HHH", data, 0x3A)
sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
shstr_off = sections[shstrndx][4]
symtab = next(s for s in sections if s[1] == 2)  # SHT_SYMTAB
strtab_off = sections[symtab[6]][4]
symbols = {}
for i in range(symtab[5] // 24):
    st_name, _, _, _, st_value, _ = struct.unpack_from("<IBBHQQ", data, symtab[4] + i * 24)
    if st_name:
        symbols.setdefault(cstr(strtab_off + st_name), st_value)
allocated = sorted((s[3], s[3] + s[5], cstr(shstr_off + s[0])) for s in sections if s[2] & 2 and s[5])  # SHF_ALLOC

idc = types.ModuleType("idc"); idc.BADADDR = -1
autils = types.ModuleType("idautils")
for module in ("ida_kernwin", "ida_typeinf", "ida_nalt", "ida_bytes"):
    sys.modules[module] = types.ModuleType(module)
api = types.ModuleType("ida_idaapi"); api.plugin_t = object; api.PLUGIN_KEEP = 2; api.PLUGIN_HIDE = 0x10
sys.modules["ida_kernwin"].action_handler_t = object; sys.modules["ida_kernwin"].Choose = object
sys.modules.update(idc=idc, idautils=autils, ida_idaapi=api)
sys.path.insert(0, ROOT)
import isf2c  # noqa: E402
import memlens_entry as m  # noqa: E402

isf = isf2c.load_isf(isf_path)
generator = isf2c.Generator(isf)
list(generator.declarations())  # as apply_types does before it lists the globals
decls = [name for name, _ in isf2c.global_decls(generator, isf)]

for underscore in (False, True):
    names = {(n.replace(".", "_", 1) if underscore and n.startswith("cpu") else n): ea for n, ea in symbols.items()}
    segments = [(a, b, n.replace(".", "_") if underscore else n) for a, b, n in allocated]
    starts = [a for a, _, _ in segments]

    def segment_name(ea, segments=segments, starts=starts):
        i = bisect.bisect_right(starts, ea) - 1
        return segments[i][2] if i >= 0 and ea < segments[i][1] else ""

    idc.get_name_ea_simple = lambda n, names=names: names.get(n, idc.BADADDR)
    idc.get_segm_name = segment_name
    idc.get_first_seg = lambda starts=starts: starts[0]
    idc.get_next_seg = lambda ea, starts=starts: next((a for a in starts if a > ea), idc.BADADDR)
    autils.Names = lambda names=names: list((ea, n) for n, ea in names.items())
    cpus = m.percpu_cpus()
    index = m.percpu_index(cpus)
    old = {n: list(m.percpu_copies(n, cpus)) for n in decls}
    new = {n: list(m.percpu_copies(n, cpus, index)) for n in decls}
    differ = [n for n in decls if old[n] != new[n]]
    assert not differ, differ[:10]
    with_copies = sum(1 for n in decls if new[n])
    assert cpus and with_copies, (cpus, with_copies)
    print("%s names: CPUs %s, %d globals, %d per-CPU variables, %d copies, index = one-by-one lookup"
          % ("'_'" if underscore else "'.'", cpus, len(decls), with_copies, sum(len(v) for v in new.values())))
print("demo per-CPU index test OK")
