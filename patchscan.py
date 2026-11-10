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
# With IBT the kernel seals functions that are never called indirectly: it overwrites ENDBR with a
# 4-byte NOP (gen_endbr_poison, older and newer encodings). ftrace, kprobes and BPF still patch at +4.
ENDBR_FORMS = (ENDBR64, b"\x66\x0f\x1f\x00", b"\x0f\x1f\x40\xd6")
FENTRY_NOP = b"\x0f\x1f\x44\x00\x00"
STT_FUNC = 2
EM_X86_64 = 62
BAD_ELF = (ValueError, struct.error, IndexError)  # what a truncated or malformed file can raise
# Only a kernel file from disk has these: its alternatives are unapplied, so entry bytes are not live code.
ON_DISK_SECTIONS = {".altinstructions", ".altinstr_replacement", ".altinstr_aux", "__ksymtab"}
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
        machine = struct.unpack_from("<H", blob, 18)[0]
        if machine != EM_X86_64:
            raise ValueError("ELF machine %d is not x86-64, and these checks read x86-64 instructions" % machine)
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


HANDLER_KINDS = (("function_trace_call", "ftrace"), ("ftrace_ops_list_func", "ftrace"), ("ftrace_ops_assist_func", "ftrace"),
                 ("kprobe_ftrace_handler", "kprobe via ftrace"), ("__bpf_prog_enter", "BPF trampoline"),
                 ("__bpf_tramp_enter", "BPF trampoline"), ("arch_ftrace_ops_list_func", "ftrace"))


def first_handler(image, page, span=0x200):
    """The first named function a copied hook page calls (rel32 call landing exactly on a symbol start)."""
    segment = image.segment(page)
    if segment is None:
        return None
    code = image.read(page, min(span, segment[1] - page))
    if not code:
        return None
    for offset in range(len(code) - 4):
        if code[offset] != 0xE8:
            continue
        dest = (page + offset + 5 + struct.unpack_from("<i", code, offset + 1)[0]) & 0xFFFFFFFFFFFFFFFF
        index = bisect.bisect_left(image.addresses, dest)
        if index < len(image.addresses) and image.addresses[index] == dest:
            name = image.symbols[index][2]
            if not name.startswith(TARGET_PREFIX):
                return name
    return None


def hook_label(image, target):
    """describe(), plus what the hook page calls when the exporter copied the page in."""
    label = describe(image, target)
    symbol = image.symbol_at(target)
    if symbol and symbol.startswith(TARGET_PREFIX):
        handler = first_handler(image, target)
        if handler:
            kind = next((k for prefix, k in HANDLER_KINDS if handler.startswith(prefix)), None)
            label += " (calls %s%s)" % (handler, ", %s" % kind if kind else "")
    return label


def absolute_hook(code, start):
    """(how, target) for an absolute-address hook starting at code[start], or None.

    The compiler never puts these at a function entry, so any of them there is a patch:
    jmp [rip+0] followed by the 8-byte target; movabs <reg>, imm64 then jmp/call <reg>;
    push imm32 then ret.
    """
    at = code[start:]
    if at[:6] == b"\xff\x25\x00\x00\x00\x00" and len(at) >= 14:
        return "jmp [rip+0]", struct.unpack_from("<Q", at, 6)[0]
    if len(at) >= 13 and at[0] in (0x48, 0x49) and 0xB8 <= at[1] <= 0xBF:
        reg = at[1] - 0xB8
        tail = at[10:13] if at[0] == 0x49 else b"\x00" + at[10:12]
        if at[0] == 0x49 and tail[0] != 0x41:
            return None
        if tail[1] == 0xFF and tail[2] in (0xE0 + reg, 0xD0 + reg):
            return ("movabs+jmp reg" if tail[2] == 0xE0 + reg else "movabs+call reg"), struct.unpack_from("<Q", at, 2)[0]
        return None
    if len(at) >= 6 and at[0] == 0x68 and at[5] == 0xC3:
        return "push+ret", struct.unpack_from("<i", at, 1)[0] & 0xFFFFFFFFFFFFFFFF
    return None


def absolute_finding(image, entry, name, how, target):
    symbol = image.symbol_at(target)
    if symbol is None or symbol.startswith(TARGET_PREFIX):
        what = "%s to memory with no symbol" % how
    elif "." in symbol and "." not in name and not symbol.split(".", 1)[1].startswith(COMPILER_SUFFIXES):
        what = "%s from kernel into a module" % how
    else:
        what = "%s at entry" % how
    return (entry, name, what, hook_label(image, target), target)


def classify_entry(image, entry, name):
    """One finding (address, function, what, target label, target address), or None if unremarkable."""
    code = image.read(entry, 32) or image.read(entry, 16)
    if code is None or name.startswith(SKIP_PREFIXES) or name in FTRACE_OWN:
        return None
    first = 4 if code[:4] in ENDBR_FORMS else 0
    # Absolute-address hooks: at the entry, after endbr64 or its sealed form, or after the 5-byte ftrace NOP.
    for start in (first, first + 5) if code[first:first + 5] == FENTRY_NOP else (first,):
        hook = absolute_hook(code, start)
        if hook:
            return absolute_finding(image, entry, name, hook[0], hook[1])
    start = first
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
        return (entry, name, "%s to memory with no symbol" % verb, hook_label(image, target), target)
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


def section_names(blob):
    """The ELF's section names; empty if its section table cannot be read."""
    shoff = struct.unpack_from("<Q", blob, 40)[0]
    shnum, shstrndx = struct.unpack_from("<HH", blob, 60)
    if not shoff or shstrndx >= shnum or shoff + 64 * shnum > len(blob):
        return set()
    strings = struct.unpack_from("<Q", blob, shoff + 64 * shstrndx + 24)[0]
    names = set()
    for index in range(shnum):
        start = strings + struct.unpack_from("<I", blob, shoff + 64 * index)[0]
        end = blob.find(b"\0", start)
        if end >= 0:
            names.add(blob[start:end].decode("ascii", "replace"))
    return names


def on_disk_kernel(blob):
    """True for a kernel file from disk, which a memory export never is."""
    return bool(section_names(blob) & ON_DISK_SECTIONS)


def scan(blob):
    image = Image(blob)
    return scan_functions(image) + scan_syscalls(image)


def main(argv):
    with open(argv[1], "rb") as handle:
        blob = handle.read()
    try:
        if on_disk_kernel(blob):
            print("warning: this is a kernel file from disk, not a memory export; its unapplied alternatives show up as false rows", file=sys.stderr)
        findings = scan(blob)
    except BAD_ELF as error:
        sys.exit("patchscan: not a usable 64-bit ELF: %s" % error)
    for address, name, kind, target, _ in findings:
        print("%#x\t%s\t%s\t%s" % (address, name, kind, target))


if __name__ == "__main__":
    main(sys.argv)
