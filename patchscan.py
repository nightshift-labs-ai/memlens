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


def compiler_clone(name):
    """foo.isra.0 or foo.cold: a compiler-made copy. evil.cold_path is a module symbol, so whole components only."""
    return "." in name and name.split(".", 1)[1].split(".")[0] in COMPILER_SUFFIXES


def into_module(name, symbol):
    """True when a kernel function's target is a module symbol (module.symbol)."""
    return "." in symbol and not compiler_clone(symbol) and ("." not in name or compiler_clone(name))


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


def memory_hook(image, code, site, start):
    """(how, target) for jmp/call [rip+disp32] at code[start] (site = its address), reading the pointer it uses.

    jmp [rip+0] with the target inline is absolute_hook's case. The pointer can be anywhere, and a kernel can
    legitimately call through one, so the caller reports only targets that the compiler could not produce.
    """
    at = code[start:start + 6]
    if len(at) < 6 or at[0] != 0xFF or at[1] not in (0x25, 0x15):
        return None
    disp = struct.unpack_from("<i", at, 2)[0]
    raw = image.read((site + 6 + disp) & 0xFFFFFFFFFFFFFFFF, 8)
    if raw is None:
        return None
    return ("%s [rip%+#x]" % ("jmp" if at[1] == 0x25 else "call", disp)), struct.unpack("<Q", raw)[0]


def foreign_target(image, name, target):
    """'to memory with no symbol' or 'from kernel into a module' when compiler output could not jump there."""
    symbol = image.symbol_at(target)
    if symbol is None or symbol.startswith(TARGET_PREFIX):
        return "to memory with no symbol"
    if into_module(name, symbol):
        return "from kernel into a module"
    return None


def absolute_finding(image, entry, name, how, target):
    symbol = image.symbol_at(target)
    if symbol is None or symbol.startswith(TARGET_PREFIX):
        what = "%s to memory with no symbol" % how
    elif into_module(name, symbol):
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
    # Through a pointer in memory, at the entry or after the ftrace NOP: only foreign targets count.
    for start in (first, first + 5) if code[first:first + 5] == FENTRY_NOP else (first,):
        hook = memory_hook(image, code, entry + start, start)
        if hook:
            where = foreign_target(image, name, hook[1])
            if where:
                return (entry, name, "%s %s" % (hook[0], where), hook_label(image, hook[1]), hook[1])
            return None
    start = first
    op = code[start]
    site = entry + start
    if code[start:start + 5] == FENTRY_NOP:
        # ftrace is off here; the next instruction is ordinary code, so a rel32 there counts only when the
        # compiler could not have produced it (no symbol, or a kernel function into a module).
        start += 5
        if len(code) < start + 5 or code[start] not in (0xE8, 0xE9):
            return None
        target = (entry + start + 5 + struct.unpack_from("<i", code, start + 1)[0]) & 0xFFFFFFFFFFFFFFFF
        where = foreign_target(image, name, target)
        if not where:
            return None
        verb = "call" if code[start] == 0xE8 else "jmp"
        return (entry, name, "%s after the ftrace NOP %s" % (verb, where), hook_label(image, target), target)
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
    if into_module(name, symbol):
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
    # With a symbol size every slot inside it is a table entry (the size reaches the next symbol, so it can
    # include zero padding, which is skipped); a data pointer there is reported, not taken as the end, so
    # one odd slot cannot hide later ones. Without a size, the first slot that is not a code pointer ends the table.
    sized = bool(table[1])
    if sized:
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
        code = target >= 0xffff000000000000 and not (segment and not segment[3])
        if not code:
            if not sized:
                break
            if target == 0:
                continue
        what = "syscall entry outside the handlers" if code else "syscall entry is not a code pointer"
        findings.append((table[0] + 8 * number, "sys_call_table[%d]" % number, what, describe(image, target), target))
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
    if len(argv) != 2:
        sys.exit("usage: python3 patchscan.py kernel.elf   (the ELF that MemLens/kernel2elf exported)")
    with open(argv[1], "rb") as handle:
        blob = handle.read()
    try:
        if on_disk_kernel(blob):
            print("warning: this is a kernel file from disk, not a memory export; its unapplied alternatives show up as false rows", file=sys.stderr)
        image = Image(blob)
        functions = sum(1 for symbol in image.symbols if symbol[3] == STT_FUNC)
        print("%d function symbols scanned" % functions, file=sys.stderr)
        if not functions:
            print("warning: no function symbols, so nothing was checked; an empty list here does not mean clean", file=sys.stderr)
        findings = scan(blob)
    except BAD_ELF as error:
        sys.exit("patchscan: not a usable 64-bit ELF: %s" % error)
    for address, name, kind, target, _ in findings:
        print("%#x\t%s\t%s\t%s" % (address, name, kind, target))


if __name__ == "__main__":
    main(sys.argv)
