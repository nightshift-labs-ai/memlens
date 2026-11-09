"""linux.kernel2elf: write a Linux kernel found in a memory image as an ordinary ELF file.

The ELF holds the virtual memory of the kernel image and of loaded modules, at their real
(KASLR-adjusted) addresses, with a full symbol table. Disassemblers open it with no custom loader.
"""
import bisect
import io
import logging
import os
import struct
import sys
from typing import Iterator, List, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.symbols.linux.utilities import modules as linux_utilities_modules

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
import patchscan  # noqa: E402  (lives in the plugin's root folder)

vollog = logging.getLogger(__name__)

PAGE = 0x1000
SHF_WRITE, SHF_ALLOC, SHF_EXEC = 1, 2, 4
STT_OBJECT, STT_FUNC = 1, 2
GLOBAL = 1


def canonical(address: int) -> int:
    """Volatility layers mask addresses to 48 bits; kernel pointers in memory are sign-extended."""
    address &= 0xFFFFFFFFFFFFFFFF
    return address | 0xFFFF000000000000 if address & (1 << 47) else address


class Elf:
    """Minimal ELF64 little-endian x86-64 writer: loadable sections plus a symbol table."""

    def __init__(self):
        self.sections: List[Tuple[str, int, int, bytes]] = []
        self.symbols: List[Tuple[str, int, int, int]] = []

    def add_section(self, name, addr, flags, data):
        self.sections.append((name, canonical(addr), flags, data))

    def add_symbol(self, name, addr, size, kind):
        self.symbols.append((name, canonical(addr), size, kind))

    def section_index(self, addr):
        for index, (_, start, _, data) in enumerate(self.sections):
            if start <= addr < start + len(data):
                return index + 1
        return 0

    def write(self, out):
        # Loaders expect PT_LOAD segments to be disjoint and ascending: a later region gives up
        # whatever an earlier one already covers.
        sections, covered = [], None
        for name, start, flags, data in sorted(self.sections, key=lambda item: item[1]):
            if covered is not None and start < covered:
                data = data[covered - start:]
                start = covered
            if data:
                sections.append((name, start, flags, data))
                covered = start + len(data)
        self.sections = sections
        shnames, name_offsets = bytearray(b"\0"), {}
        for name in [s[0] for s in sections] + [".symtab", ".strtab", ".shstrtab"]:
            name_offsets[name] = len(shnames)
            shnames += name.encode() + b"\0"

        strtab, symtab = bytearray(b"\0"), bytearray(b"\0" * 24)
        starts = [s[1] for s in sections]
        for name, addr, size, kind in sorted(self.symbols, key=lambda item: item[1]):
            index = bisect.bisect_right(starts, addr) - 1
            if index < 0 or addr >= starts[index] + len(sections[index][3]):
                continue
            offset = len(strtab)
            strtab += name.encode("ascii", "replace") + b"\0"
            symtab += struct.pack("<IBBHQQ", offset, (GLOBAL << 4) | kind, 0, index + 1, addr, size)

        count = len(sections)
        cursor = 64 + 56 * count
        layout = []
        for _, addr, _, data in sections:
            # A segment's file offset and address must agree modulo the page size.
            cursor += (addr - cursor) % PAGE
            layout.append(cursor)
            cursor += len(data)
        symoff, stroff = cursor, cursor + len(symtab)
        shstroff = stroff + len(strtab)
        shoff = shstroff + len(shnames)
        shoff += -shoff % 8

        entry = sections[0][1] if sections else 0
        out.write(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
        out.write(struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, entry, 64, shoff, 0, 64, 56, count, 64, count + 4, count + 3))
        for (name, addr, flags, data), offset in zip(sections, layout):
            pflags = 4 | (2 if flags & SHF_WRITE else 0) | (1 if flags & SHF_EXEC else 0)
            out.write(struct.pack("<IIQQQQQQ", 1, pflags, offset, addr, addr, len(data), len(data), PAGE))
        position = 64 + 56 * count
        for (_, _, _, data), offset in zip(sections, layout):
            out.write(b"\0" * (offset - position))
            out.write(data)
            position = offset + len(data)
        out.write(bytes(symtab))
        out.write(bytes(strtab))
        out.write(bytes(shnames))
        out.write(b"\0" * (shoff - (shstroff + len(shnames))))

        def header(name, kind, flags, addr, offset, size, link=0, info=0, align=1, entsize=0):
            out.write(struct.pack("<IIQQQQIIQQ", name, kind, flags, addr, offset, size, link, info, align, entsize))

        header(0, 0, 0, 0, 0, 0, align=0)
        for (name, addr, flags, data), offset in zip(sections, layout):
            header(name_offsets[name], 1, flags, addr, offset, len(data), align=16)
        header(name_offsets[".symtab"], 2, 0, 0, symoff, len(symtab), count + 2, 1, 8, 24)
        header(name_offsets[".strtab"], 3, 0, 0, stroff, len(strtab))
        header(name_offsets[".shstrtab"], 3, 0, 0, shstroff, len(shnames))


class Kernel2Elf(interfaces.plugins.PluginInterface):
    """Writes the kernel and its modules from a memory image as a symbolled ELF for disassemblers."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [
            requirements.ModuleRequirement(name="kernel", description="Linux kernel", architectures=["Intel64"]),
            requirements.VersionRequirement(
                name="linux_utilities_modules", component=linux_utilities_modules.Modules, version=(3, 0, 0)
            ),
            requirements.BooleanRequirement(name="no-modules", description="Kernel image only", default=False, optional=True),
        ]

    def _runs(self, layer, start, end) -> List[Tuple[int, int]]:
        """Mapped virtual ranges inside [start, end), merged where contiguous."""
        runs: List[Tuple[int, int]] = []
        for vaddr, vlen, _, _, _ in layer.mapping(start, end - start, ignore_errors=True):
            if runs and runs[-1][1] == vaddr:
                runs[-1] = (runs[-1][0], vaddr + vlen)
            else:
                runs.append((vaddr, vaddr + vlen))
        return runs

    def _add_range(self, elf, layer, start, end, name, flags) -> int:
        total = 0
        runs = self._runs(layer, start, end)
        for number, (run_start, run_end) in enumerate(runs):
            data = layer.read(run_start, run_end - run_start, pad=True)
            label = name if len(runs) == 1 else "%s.%d" % (name, number)
            elf.add_section(label, run_start, flags, data)
            total += len(data)
        return total

    def _generator(self) -> Iterator:
        kernel = self.context.modules[self.config["kernel"]]
        layer = self.context.layers[kernel.layer_name]
        table = self.context.symbol_space[kernel.symbol_table_name]

        def address(symbol):
            return kernel.get_symbol(symbol).address + kernel.offset

        elf = Elf()
        boundaries = [(address("_text"), address("_etext"), ".text", SHF_ALLOC | SHF_EXEC)]
        data_start = address("_etext")
        try:
            rodata_end = address("__end_rodata")
            boundaries.append((data_start, rodata_end, ".rodata", SHF_ALLOC))
            data_start = rodata_end
        except exceptions.SymbolError:
            pass
        boundaries.append((data_start, address("_end"), ".data", SHF_ALLOC | SHF_WRITE))
        for start, end, name, flags in boundaries:
            if start < end:
                yield (0, ("section", name, format_hints.Hex(start), self._add_range(elf, layer, start, end, name, flags)))

        text_start, text_end = boundaries[0][0], boundaries[0][1]
        addresses = []
        for name in table.symbols:
            try:
                value = kernel.get_symbol(name).address + kernel.offset
            except exceptions.SymbolError:
                continue
            addresses.append((value, name))
        addresses.sort()
        ordered = [item[0] for item in addresses]
        for value, name in addresses:
            following = bisect.bisect_right(ordered, value)
            size = ordered[following] - value if following < len(ordered) else 0
            kind = STT_FUNC if text_start <= value < text_end else STT_OBJECT
            elf.add_symbol(name, value, size, kind)
        yield (0, ("symbols", "kernel", format_hints.Hex(text_start), len(addresses)))

        if not self.config.get("no-modules"):
            for module in linux_utilities_modules.Modules.list_modules(self.context, self.config["kernel"]):
                try:
                    name, base = module.get_name(), module.get_module_base()
                    regions = self._module_regions(module)
                except exceptions.InvalidAddressException:
                    continue
                written = sum(self._add_range(elf, layer, start, end, ".mod.%s.%s" % (name, label), flags) for label, start, end, flags in regions)
                symbols = 0
                try:
                    for symbol in module.get_symbols():
                        symbol_name = symbol.get_name()
                        if symbol_name:
                            elf.add_symbol("%s.%s" % (name, symbol_name), int(symbol.st_value), int(symbol.st_size), STT_FUNC if (int(symbol.st_info) & 15) == STT_FUNC else STT_OBJECT)
                            symbols += 1
                except exceptions.InvalidAddressException:
                    vollog.info("symbols of %s are partly unreadable", name)
                yield (0, ("module", name, format_hints.Hex(base), symbols if written else 0))

        for target in self._hook_targets(elf):
            copied = self._add_range(elf, layer, target & ~(PAGE - 1), (target & ~(PAGE - 1)) + 2 * PAGE, ".hook.%x" % target, SHF_ALLOC | SHF_EXEC)
            if copied:
                elf.add_symbol("%s%x" % (patchscan.TARGET_PREFIX, target), target, 0, STT_FUNC)
                yield (0, ("hook target", "memlens_target", format_hints.Hex(target), copied))

        finished = io.BytesIO()
        elf.write(finished)
        for address, where, what, target, _ in patchscan.scan(finished.getvalue()):
            yield (0, ("patched", "%s: %s %s" % (where, what, target), format_hints.Hex(address), 0))

        with self.open("kernel.elf") as handle:
            handle.write(finished.getvalue())
            yield (0, ("written", handle.preferred_filename, format_hints.Hex(0), len(elf.symbols)))

    @staticmethod
    def _module_regions(module) -> List[Tuple[str, int, int, int]]:
        """(label, start, end, ELF flags) of each part of a module that belongs to it.

        Since 6.4 the parts are separate allocations, so one base and the summed core size
        would run into whatever is mapped after the text and miss the module's own data.
        """
        text, read_only, writable = SHF_ALLOC | SHF_EXEC, SHF_ALLOC, SHF_ALLOC | SHF_WRITE
        if module.has_member("mem"):
            regions = []
            for label, kind, flags in (("text", "MOD_TEXT", text), ("rodata", "MOD_RODATA", read_only),
                                       ("ro_after_init", "MOD_RO_AFTER_INIT", read_only), ("data", "MOD_DATA", writable)):
                try:
                    start, size = int(module._get_mem_base(kind)), int(module._get_mem_size(kind))
                except AttributeError:
                    continue
                if start and size:
                    regions.append((label, start, start + size, flags))
            return regions
        base = int(module.get_module_base())
        if module.has_member("core_layout"):  # one allocation, ordered text, rodata, ro_after_init, data
            layout = module.core_layout
            marks = [("text", 0, int(layout.text_size), text), ("rodata", int(layout.text_size), int(layout.ro_size), read_only),
                     ("ro_after_init", int(layout.ro_size), int(layout.ro_after_init_size), read_only),
                     ("data", int(layout.ro_after_init_size), int(layout.size), writable)]
            return [(label, base + low, base + high, flags) for label, low, high, flags in marks if low < high]
        return [("core", base, base + int(module.get_core_size()), text)]

    @staticmethod
    def _hook_targets(elf) -> List[int]:
        """Addresses that patched entries lead to, in memory the image of the kernel does not cover."""
        draft = io.BytesIO()
        elf.write(draft)
        image = patchscan.Image(draft.getvalue())
        wanted = {target for _, _, _, _, target in patchscan.scan_functions(image) + patchscan.scan_syscalls(image) if target}
        return sorted(target for target in wanted if not image.segment(target))

    def run(self):
        return renderers.TreeGrid(
            [("Item", str), ("Name", str), ("Address", format_hints.Hex), ("Count", int)], self._generator()
        )
