#!/usr/bin/env python3
"""Find kernel functions whose entry was patched, and syscall table entries that look wrong.

Reads a kernel.elf written by linux.kernel2elf. It needs no IDA and no Volatility, so it can be
run and tested on its own. It only looks at code that is at a function entry: a patch in the middle
of a function, or one made by something that leaves the entry bytes alone, is not found.
"""
import bisect
import struct
import sys

ENDBR64 = b"\xf3\x0f\x1e\xfa"
FENTRY_NOP = b"\x0f\x1f\x44\x00\x00"
STT_FUNC = 2
# Trampolines that are jumps by design, and compiler padding symbols.
SKIP_PREFIXES = ("__SCT__", "__SCK__", "__static_call", "__pfx_", "__cfi_", "__x86_indirect", "__x86_return")
COMPILER_SUFFIXES = ("constprop", "isra", "part", "cold", "llvm", "lto_priv", "clone")  # foo.isra.0 is not module.symbol
# A live hook goes through these. "call __fentry__" is what the compiler wrote, not a patch.
FTRACE_TARGETS = ("ftrace_caller", "ftrace_regs_caller", "ftrace_stub", "return_to_handler")
# ftrace's own trampolines call ftrace_stub by design.
FTRACE_OWN = {"ftrace_caller", "ftrace_regs_caller", "ftrace_call", "ftrace_regs_call", "ftrace_graph_call", "ftrace_stub"}


TARGET_PREFIX = "memlens_target_"  # labels the exporter gives to hook targets it copied in


class Image:
    """The loadable segments and symbols of one kernel.elf."""

    def __init__(self, blob):
        self.blob = blob
        if blob[:4] != b"\x7fELF" or blob[4] != 2:
            raise ValueError("not a 64-bit ELF")
        phoff, shoff = struct.unpack_from("<QQ", blob, 32)
        phnum, shnum = struct.unpack_from("<H", blob, 56)[0], struct.unpack_from("<H", blob, 60)[0]
        self.segments = []
        for index in range(phnum):
            kind, flags, offset, vaddr, _, filesz = struct.unpack_from("<IIQQQQ", blob, phoff + 56 * index)
            if kind == 1:
                self.segments.append((vaddr, vaddr + filesz, offset, bool(flags & 1)))
        self.segments.sort()
        self.starts = [segment[0] for segment in self.segments]
        self.symbols = []
        for index in range(shnum):
            base = shoff + 64 * index
            kind = struct.unpack_from("<I", blob, base + 4)[0]
            if kind != 2:
                continue
            offset, size, link = struct.unpack_from("<QQI", blob, base + 24)
            strings = struct.unpack_from("<Q", blob, shoff + 64 * link + 24)[0]
            for entry in range(1, size // 24):
                name, info, _, _, value, length = struct.unpack_from("<IBBHQQ", blob, offset + 24 * entry)
                end = blob.index(b"\0", strings + name)
                self.symbols.append((value, length, blob[strings + name:end].decode("ascii", "replace"), info & 15))
        self.symbols.sort()
        self.addresses = [symbol[0] for symbol in self.symbols]
        self.by_name = {symbol[2]: symbol for symbol in self.symbols}

    def segment(self, address):
        index = bisect.bisect_right(self.starts, address) - 1
        if index >= 0 and address < self.segments[index][1]:
            return self.segments[index]
        return None

    def read(self, address, size):
        segment = self.segment(address)
        if not segment or address + size > segment[1]:
            return None
        start = segment[2] + address - segment[0]
        return self.blob[start:start + size]

    def symbol_at(self, address):
        """The symbol covering this address, or None. Unsized symbols cover 4 KB at most."""
        index = bisect.bisect_right(self.addresses, address) - 1
        if index < 0:
            return None
        value, length, name, _ = self.symbols[index]
        return name if address - value < (length or 0x1000) else None


def describe(image, address):
    return image.symbol_at(address) or ("%#x (no symbol)" % address)


def classify_entry(image, entry, name):
    """One finding (address, function, what, target label, target address), or None if unremarkable."""
    code = image.read(entry, 16)
    if code is None or name.startswith(SKIP_PREFIXES) or name in FTRACE_OWN:
        return None
    start = 4 if code[:4] == ENDBR64 else 0
    op = code[start]
    site = entry + start
    if code[start:start + 5] == FENTRY_NOP:
        return None
    if op == 0xCC:
        # A breakpoint replaces one byte, so the next one is still code; int3 padding runs on.
        if code[start + 1] == 0xCC or name.endswith(("_start", "_end")):
            return None
        return (entry, name, "int3 at entry (kprobe or breakpoint)", "", 0)
    if op not in (0xE8, 0xE9):
        return None
    target = site + 5 + struct.unpack_from("<i", code, start + 1)[0]
    target &= 0xFFFFFFFFFFFFFFFF
    label = describe(image, target)
    symbol = image.symbol_at(target)
    verb = "call" if op == 0xE8 else "jmp"
    if symbol and symbol.startswith(FTRACE_TARGETS):
        return (entry, name, "ftrace call at entry", label, target)
    if symbol is None or symbol.startswith(TARGET_PREFIX):
        return (entry, name, "%s to memory with no symbol" % verb, label, target)
    if "." in symbol and "." not in name and not symbol.split(".", 1)[1].startswith(COMPILER_SUFFIXES):
        return (entry, name, "%s from kernel into a module" % verb, label, target)
    return None


def scan_functions(image):
    findings = []
    for address, _, name, kind in image.symbols:
        if kind != STT_FUNC:
            continue
        segment = image.segment(address)
        if not segment or not segment[3]:
            continue
        finding = classify_entry(image, address, name)
        if finding:
            findings.append(finding)
    return findings


def scan_syscalls(image, count=512):
    """Entries of sys_call_table that do not point at a syscall handler."""
    table = image.by_name.get("sys_call_table")
    if not table:
        return []
    findings = []
    if table[1]:  # newer kernels have fewer slots than count; what follows the table is other data
        count = min(count, table[1] // 8)
    for number in range(count):
        raw = image.read(table[0] + 8 * number, 8)
        if raw is None:
            break
        target = struct.unpack("<Q", raw)[0]
        symbol = image.symbol_at(target)
        if symbol and symbol.startswith(("__x64_sys_", "__ia32_sys_", "sys_ni_syscall", "__x64_compat_sys_")):
            continue
        segment = image.segment(target)
        if target < 0xffff000000000000 or (segment and not segment[3]):  # not a code pointer: end of the table
            break
        findings.append((table[0] + 8 * number, "sys_call_table[%d]" % number, "syscall entry outside the handlers", describe(image, target), target))
    return findings


def scan(blob):
    image = Image(blob)
    return scan_functions(image) + scan_syscalls(image)


def main(argv):
    with open(argv[1], "rb") as handle:
        blob = handle.read()
    for address, name, kind, target, _ in scan(blob):
        print("%#x\t%s\t%s\t%s" % (address, name, kind, target))


if __name__ == "__main__":
    main(sys.argv)
