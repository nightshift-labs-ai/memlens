#!/usr/bin/env python3
"""kernel2elf's BPF part (names from Volatility's Kallsyms.get_bpf_symbols, and the BPF JIT pages), against FAKE
volatility3 modules and a fake memory layer: no Volatility and no memory image needed. Checks our logic only; the real
run is described in README ("What you get") and was made with Volatility 2.28.2.

usage: python3 tests/test_kernel2elf_bpf.py
"""
import collections, io, os, struct, sys, types
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))

# Just enough of volatility3 for vol_plugins/linux/kernel2elf.py to import.
fake = {name: types.ModuleType(name) for name in (
    "volatility3", "volatility3.framework", "volatility3.framework.configuration", "volatility3.framework.renderers",
    "volatility3.framework.symbols", "volatility3.framework.symbols.linux", "volatility3.framework.symbols.linux.utilities")}
framework = fake["volatility3.framework"]
framework.exceptions = types.SimpleNamespace(SymbolError=KeyError, InvalidAddressException=ValueError, VolatilityException=Exception)
framework.interfaces = types.SimpleNamespace(plugins=types.SimpleNamespace(PluginInterface=object))
framework.renderers = fake["volatility3.framework.renderers"]
framework.renderers.TreeGrid = lambda columns, rows: (columns, rows)
fake["volatility3.framework.renderers"].format_hints = types.SimpleNamespace(Hex=int)
fake["volatility3.framework.configuration"].requirements = types.SimpleNamespace()
fake["volatility3.framework.symbols.linux.utilities"].modules = types.SimpleNamespace(Modules=object)
fake["volatility3.framework.symbols.linux"].kallsyms = types.SimpleNamespace(Kallsyms=None)
sys.modules.update(fake)
sys.path.insert(0, os.path.join(HERE, "..", "vol_plugins", "linux"))
import kernel2elf as k  # noqa: E402
import patchscan as ps  # noqa: E402

KAS = collections.namedtuple("KAS", "name type address size module_name")  # the fields of Volatility's KASSymbol we read
MASK = (1 << 48) - 1  # Kallsyms masks BPF addresses to the layer's 48 bits (kallsyms.py: sym_addr &= layer.address_mask)
PROG, TRAMP, DISPATCH, PROG2 = 0xffffffffc0004664, 0xffffffffc0004940, 0xffffffffc0009000, 0xffffffffc000b000
ksyms = [KAS("bpf_prog_e8932b6bae2b9745_restrict_filesystems", "t", PROG & MASK, 306, "bpf"),
         KAS("bpf_trampoline_6442509381", "t", TRAMP & MASK, 238, "bpf"),
         KAS("bpf_dispatcher_xdp", "t", DISPATCH & MASK, 0x10, "bpf"),
         KAS("bpf_prog_0123456789abcdef_big", "t", PROG2 & MASK, 0x1800, "bpf")]

# Names: 'bpf.' + the kernel's name at the sign-extended address; none at a hook target (MemLens' label stays there, so
# the page is still the copied hook page whose handler, role name and owner MemLens works out).
named = k.bpf_symbols(ksyms, {TRAMP})
assert named == [("bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems", PROG, 306), ("bpf.bpf_dispatcher_xdp", DISPATCH, 0x10),
                 ("bpf.bpf_prog_0123456789abcdef_big", PROG2, 0x1800)], named
assert k.bpf_symbols([KAS("bpf_prog_x", "t", 0x7fffc0004000, 8, "bpf")], set()) == [("bpf.bpf_prog_x", 0x7fffc0004000, 8)]
# Pages: every page any BPF symbol touches, merged into runs, minus pages already in the ELF.
assert k.page_runs([(PROG, PROG + 306), (TRAMP, TRAMP + 238), (DISPATCH, DISPATCH + 0x10), (PROG2, PROG2 + 0x1800)],
                   lambda page: False) == [(0xffffffffc0004000, 0xffffffffc0005000), (0xffffffffc0009000, 0xffffffffc000a000),
                                           (0xffffffffc000b000, 0xffffffffc000d000)]
assert k.page_runs([(PROG, PROG + 306), (DISPATCH, DISPATCH + 0x10)], lambda page: page == 0xffffffffc0004000) == [
    (0xffffffffc0009000, 0xffffffffc000a000)]
assert k.page_runs([(0xffffffffc0001000, 0xffffffffc0001000)], lambda page: False) == [(0xffffffffc0001000, 0xffffffffc0002000)]


class Layer:
    """A fake memory layer: the pages in self.pages are mapped (bytes 0xcc), everything else is not."""
    def __init__(self, pages):
        self.pages = pages

    def mapping(self, start, length, ignore_errors=False):
        for page in range(start & ~0xfff, start + length, 0x1000):
            if page in self.pages:
                low, high = max(page, start), min(page + 0x1000, start + length)
                yield low, high - low, low, high - low, "memory"

    def read(self, start, length, pad=False):
        return b"\xcc" * length


# The plugin step: the hook page (copied before, as .hook.<target>) keeps its label; the BPF pages not yet in the ELF
# are copied as .bpf.<start>; the symbols are written; an unmapped page is skipped.
plugin = k.Kernel2Elf.__new__(k.Kernel2Elf)
elf = k.Elf()
elf.add_section(".hook.%x" % TRAMP, 0xffffffffc0004000, k.SHF_ALLOC | k.SHF_EXEC, b"\xcc" * 0x2000)
elf.add_symbol("%s%x" % (ps.TARGET_PREFIX, TRAMP), TRAMP, 0, k.STT_FUNC)
layer = Layer({0xffffffffc0004000, 0xffffffffc0005000, 0xffffffffc0009000, 0xffffffffc000b000})  # PROG2's 2nd page unmapped
rows = list(plugin._bpf(elf, layer, ksyms, {TRAMP}))
assert rows == [(0, ("bpf pages", ".bpf.ffffffffc0009000", 0xffffffffc0009000, 0x1000)),
                (0, ("bpf pages", ".bpf.ffffffffc000b000", 0xffffffffc000b000, 0x1000)),
                (0, ("bpf symbols", "bpf", 0, 3))], rows
out = io.BytesIO()
elf.write(out)
image = ps.Image(out.getvalue())
assert ps.symbol_start(image, PROG) == "bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems", ps.symbol_start(image, PROG)
assert ps.symbol_start(image, TRAMP) is None and ps.copied_page(image, TRAMP), image.symbol_at(TRAMP)  # only the label there
assert image.segment(DISPATCH) and image.segment(PROG2) and not image.segment(PROG2 + 0x1000)
assert image.segment(DISPATCH)[3] and image.segment(PROG2)[3], "BPF pages must be executable"
# No BPF symbols (no Kallsyms API, or a kernel without them): nothing added, one row that says 0.
assert list(plugin._bpf(k.Elf(), layer, [], set())) == [(0, ("bpf symbols", "bpf", 0, 0))]
print("kernel2elf BPF test OK (fake volatility3 modules and memory layer)")
