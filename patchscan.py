#!/usr/bin/env python3
"""Find kernel functions whose entry was patched, and syscall table entries that look wrong.

Reads a kernel.elf written by linux.kernel2elf. It needs no IDA and no Volatility, so it can be
run and tested on its own. It only looks at code that is at a function entry: a patch in the middle
of a function, or one made by something that leaves the entry bytes alone, is not found.
"""
import bisect
import collections
import os
import re
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
# Offset of func in struct ftrace_ops: 0 in the ISFs of Linux 6.1, 6.8, 6.12 and 7.0 we checked. Image.ftrace_ops_func
# takes it from an ISF when one is at hand (ftrace_ops_func_offset): patchscan.py --isf, and in IDA the ISF that Apply
# kernel types imported.
FTRACE_OPS_FUNC = 0


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
        self.ftrace_ops_func = FTRACE_OPS_FUNC  # where ops->func is read (page_owner)

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
MODULE_CALLBACK = "module callback"  # the kind of a page whose first named call is a module's function (module.symbol)


def page_code(image, page, span=0x200):
    """The bytes of a copied hook page, up to span and only up to the next symbol after page: trampolines packed next
    to each other each have their own label, and a page must not be read into its neighbour. None outside the ELF."""
    segment = image.segment(page)
    if segment is None:
        return None
    following = bisect.bisect_right(image.addresses, page)
    if following < len(image.addresses):
        span = min(span, image.addresses[following] - page)
    return image.read(page, min(span, segment[1] - page)) or None


def symbol_start(image, address):
    """The name of the (first) symbol that starts exactly at address, or None; None as well when that is one of the
    exporter's memlens_target_ labels."""
    index = bisect.bisect_left(image.addresses, address)
    if index < len(image.addresses) and image.addresses[index] == address:
        name = image.symbols[index][2]
        if not name.startswith(TARGET_PREFIX):
            return name
    return None


def named_calls(image, page, span=0x200):
    """(call address, destination, name) for each rel32 call in a copied hook page that lands exactly on a symbol start
    (not on a memlens_target_ label), in order. The bytes are searched, not disassembled (page_code limits the span)."""
    code = page_code(image, page, span)
    for offset in range(len(code) - 4 if code else 0):
        if code[offset] != 0xE8:
            continue
        dest = (page + offset + 5 + struct.unpack_from("<i", code, offset + 1)[0]) & 0xFFFFFFFFFFFFFFFF
        name = symbol_start(image, dest)
        if name:
            yield page + offset, dest, name


def handler_call(image, page, span=0x200):
    """(call address, handler address, handler name) for the first rel32 call in a copied hook page that lands exactly
    on a symbol start (not on another memlens_target_ label), or None. Only up to the next symbol after page, so a page
    does not get its neighbour's handler."""
    return next(named_calls(image, page, span), None)


def first_handler(image, page, span=0x200):
    """The first named function a copied hook page calls (rel32 call landing exactly on a symbol start)."""
    call = handler_call(image, page, span)
    return call[2] if call else None


def handler_kind(handler):
    """'ftrace', 'kprobe via ftrace' or 'BPF trampoline' from the handler's name, 'module callback' for a module's
    function (module.symbol, into_module), or None: a core-kernel function that is not ftrace, kprobe or BPF plumbing
    (_printk, kfree, a retpoline thunk) is a helper the hook code uses, not a handler (judge s160 finding 5)."""
    kind = next((kind for prefix, kind in HANDLER_KINDS if handler.startswith(prefix)), None)
    return kind or (MODULE_CALLBACK if into_module("", handler) else None)


def hook_label(image, target):
    """describe(), plus what the hook page calls when the exporter copied the page in."""
    label = describe(image, target)
    symbol = image.symbol_at(target)
    if symbol and symbol.startswith(TARGET_PREFIX):
        handler = first_handler(image, target)
        if handler:
            kind = handler_kind(handler)
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


def nothing_to_check(image):
    """Why a scan of image would check nothing (an empty list would then look clean), or None for a kernel.elf."""
    if not any(symbol[3] == STT_FUNC for symbol in image.symbols):
        return "no function symbols"
    if "linux_banner" not in image.by_name:
        return "no linux_banner symbol (not a kernel.elf exported by MemLens)"
    return None


def scan(blob, image=None):
    image = image or Image(blob)
    return scan_functions(image) + scan_syscalls(image)


# The hook chain: patched entry -> hook page -> handler. These functions decide what the IDA layer links and renames,
# so they can be tested without IDA; memlens_entry only applies their result.

# Role names for copied hook pages, by the kind of handler they call (handler_kind). The exporter labels such a page
# memlens_target_<address>; MemLens in IDA renames it, for example to ftrace_tramp_vfs_getattr or, when its first named
# call is a module's function, module_hook___x64_sys_kill, and keeps the old label in a comment there.
ROLE_PREFIXES = {"ftrace": "ftrace_tramp", "kprobe via ftrace": "kprobe_ftrace_tramp", "BPF trampoline": "bpf_tramp",
                 MODULE_CALLBACK: "module_hook"}
LONGEST_ROLE_NAME = 200  # longer than any kernel name we have seen; a longer one falls back to the address form


# One patched function entry and where it leads. handler_site, handler and handler_name are the copied hook page's first
# named call, None when the target is not a copied hook page or no named call was found in it; kind is handler_kind's,
# None also when that call goes into the core kernel and is no handler (_printk); owner (an Owner) is None when
# page_owner found none.
Link = collections.namedtuple("Link", "entry function site flow target page handler_site handler handler_name kind owner",
                              defaults=(None,))

# Who put a hook page there, as far as the ELF tells: text for the list, the owner's address when it is in the ELF (else
# None), how it was found ("ftrace_ops", "BPF program" or "module callback") and the references that lead there, as
# (from, to, "data") for a pointer in memory and (from, to, "call") for a call instruction.
Owner = collections.namedtuple("Owner", "text address how refs")

# An x86 ftrace trampoline (arch/x86/kernel/ftrace.c, create_trampoline) is a copy of ftrace_caller or ftrace_regs_caller,
# then its ret (ret, ret; int3, or a 5-byte jmp to the return thunk), then a pointer to the ftrace_ops it serves, which
# its mov rdx, [rip+disp32] loads as the callback's third argument. ops->func is the callback the ops registered, also
# when the trampoline calls ftrace_ops_assist_func instead (ops flagged RECURSION or RCU, as ftrace-hook helpers do).
OPS_LOAD = b"\x48\x8b\x15"
KERNEL_MAP = 0xffffffff80000000  # x86-64: the kernel image and module space (modules, trampolines, BPF) are above this


def ftrace_ops_func_offset(isf):
    """The offset of func in struct ftrace_ops from a loaded ISF (a dict), or None when the ISF does not have it."""
    try:
        return int(isf["user_types"]["ftrace_ops"]["fields"]["func"]["offset"])
    except (KeyError, TypeError, ValueError):
        return None


def ftrace_ops_slot(image, page, span=0x200):
    """(slot address, ftrace_ops address) for the ops pointer an ftrace trampoline page loads, or None.

    The slot must lie after the load, inside the page's span, right after a ret: a page that loads some other global
    rip-relative is not taken for a trampoline."""
    code = page_code(image, page, span)
    offset = code.find(OPS_LOAD) if code else -1
    while offset >= 0 and offset + 7 <= len(code):
        slot = page + offset + 7 + struct.unpack_from("<i", code, offset + 3)[0]
        before = slot - page
        if offset + 7 <= before and before + 8 <= len(code) and before >= 5:
            tail = code[before - 5:before]
            if tail[4] == 0xC3 or tail[3] == 0xC3 or tail[0] in (0xC3, 0xE9):
                ops = struct.unpack_from("<Q", code, before)[0]
                if ops >= 0xffff800000000000:
                    return slot, ops
        offset = code.find(OPS_LOAD, offset + 1)
    return None


def ftrace_owner(image, page):
    """An Owner from the ftrace_ops an ftrace trampoline page loads (its func read at image.ftrace_ops_func), or None."""
    found = ftrace_ops_slot(image, page)
    if found is None:
        return None
    slot, ops = found
    if image.segment(ops) is None:
        where = "heap" if ops < KERNEL_MAP else "module memory MemLens did not export"
        return Owner("ftrace_ops at %#x (no symbol: %s)" % (ops, where), None, "ftrace_ops", [])
    refs = [(slot, ops, "data")]
    field = ops + image.ftrace_ops_func
    raw = image.read(field, 8)
    if raw is None:
        return Owner("ftrace_ops %s (its func is not in the ELF)" % at(image, ops), None, "ftrace_ops", refs)
    func = struct.unpack("<Q", raw)[0]
    address = func if image.segment(func) else None
    if address is not None:
        refs.append((field, func, "data"))
    return Owner("%s (ftrace_ops %s)" % (at(image, func), at(image, ops)), address, "ftrace_ops", refs)


# A BPF trampoline (arch/x86/net/bpf_jit_comp.c, invoke_bpf_prog) runs each program right after a call to
# __bpf_prog_enter* (__bpf_prog_enter, __bpf_prog_enter_recur, ...): mov rbx, rax; test rax, rax; je over the program
# (a 2-byte NOP until patched); lea rdi, [rbp-N]; movabs rsi, prog->insnsi (interpreter only); call the program.
BPF_PROG_ENTER = "__bpf_prog_enter"
BPF_BEFORE_PROGRAM = ((b"\x48\x89\xc3", 3), (b"\x48\x85\xc0", 3), (b"\x74", 2), (b"\x66\x90", 2), (b"\x48\x8d\x7d", 4),
                      (b"\x48\x8d\xbd", 7), (b"\x48\xbe", 10))


def program_call(code, offset):
    """Offset of the call that runs the program, walking from code[offset] (just after the call to __bpf_prog_enter*)
    over the instructions invoke_bpf_prog emits before it; None as soon as anything else is there."""
    while offset + 5 <= len(code):
        if code[offset] == 0xE8:
            return offset
        size = next((size for start, size in BPF_BEFORE_PROGRAM if code.startswith(start, offset)), None)
        if size is None:
            return None
        offset += size
    return None


BPF_ENTER_LSM_CGROUP = "__bpf_prog_enter_lsm_cgroup"
BPF_PROG_NAME = re.compile(r"(bpf\.)?bpf_prog_[0-9a-f]{16}(_|$)")


def bpf_program_label(name, program, enter):
    """The Owner text for what a BPF trampoline calls after enter (the __bpf_prog_enter* it called). Only a BPF name
    (the export's bpf.bpf_prog_<tag>_<name>, or the kernel's own without "bpf.") or no symbol is called a BPF program; a
    kernel function there is the interpreter (a program that is not JIT-compiled), the kernel's cgroup LSM shim (whose
    programs hang off each cgroup), or else just a function the trampoline calls (review s166 m1, claims s170 F1)."""
    if not name:
        return "BPF program at %#x" % program
    if name.startswith("bpf.") or BPF_PROG_NAME.match(name):  # bpf. = the exporter's BPF list (5.5-5.7: bpf.<aux name>)
        return "%s (BPF program)" % name
    if name.startswith("__cgroup_bpf_run_lsm_") or enter.startswith(BPF_ENTER_LSM_CGROUP):
        # cgroup_shim_alloc makes the shim BPF_LSM_MAC, so the trampoline enters it through plain __bpf_prog_enter: the
        # callee (__cgroup_bpf_run_lsm_current/_sock/_socket) is what marks it (claims s170 F1)
        return "%s (cgroup LSM shim: runs each cgroup's programs, not named here)" % name
    if name.lstrip("_").startswith("bpf_prog_run"):
        return "%s (BPF interpreter: the program is not JIT-compiled)" % name
    return "%s (called by the BPF trampoline)" % name


def bpf_owner(image, page, span=0x1000):
    """An Owner naming the program(s) a BPF trampoline page runs, or None when none is found."""
    code = page_code(image, page, span)
    programs = []
    for site, _, name in named_calls(image, page, span):
        if not name.startswith(BPF_PROG_ENTER):
            continue
        offset = program_call(code, site - page + 5)
        if offset is not None:
            program = (page + offset + 5 + struct.unpack_from("<i", code, offset + 1)[0]) & 0xFFFFFFFFFFFFFFFF
            programs.append((page + offset, program, name))
    if not programs:
        return None
    names = [bpf_program_label(symbol_start(image, program), program, enter) for _, program, enter in programs]
    first = programs[0][1]
    refs = [(site, program, "call") for site, program, _ in programs if image.segment(program)]
    return Owner(", ".join(names), first if image.segment(first) else None, "BPF program", refs)


def page_owner(image, page, handler_site, handler, handler_name, kind):
    """The Owner of a copied hook page: the program(s) a BPF trampoline runs, ftrace_ops->func for an ftrace trampoline;
    else, when the page is a module callback (its first named call is a module's function), that callback, under the
    Handler column's label; else None (known plumbing, or a first call into the core kernel: on a hidden module's page
    that is _printk or a retpoline thunk, not the hook's owner; review s166 M1)."""
    owner = bpf_owner(image, page) if kind == "BPF trampoline" else ftrace_owner(image, page)
    if owner is None and kind == MODULE_CALLBACK:
        owner = Owner("%s (%s)" % (handler_name, MODULE_CALLBACK), handler, MODULE_CALLBACK, [])
    return owner


def transfer_site(image, entry, target):
    """(address, 'call' or 'jmp') of the instruction at a patched entry that sends control to target, or None.

    The places classify_entry looks: the entry, after endbr64 or its sealed NOP, and after the 5-byte ftrace NOP.
    movabs + jmp/call reg transfers at its jmp/call, 10 bytes in; push imm32; ret at its ret, which is a jump.
    """
    code = image.read(entry, 32) or image.read(entry, 16)
    if not code:
        return None
    first = 4 if code[:4] in ENDBR_FORMS else 0
    for start in (first, first + 5) if code[first:first + 5] == FENTRY_NOP else (first,):
        if len(code) >= start + 5 and code[start] in (0xE8, 0xE9):
            dest = (entry + start + 5 + struct.unpack_from("<i", code, start + 1)[0]) & 0xFFFFFFFFFFFFFFFF
            if dest == target:
                return entry + start, "call" if code[start] == 0xE8 else "jmp"
        hook = absolute_hook(code, start)
        if hook and hook[1] == target:
            if hook[0].startswith("movabs"):
                return entry + start + 10, "call" if hook[0].endswith("call reg") else "jmp"
            return entry + start + (5 if hook[0] == "push+ret" else 0), "jmp"
        hook = memory_hook(image, code, entry + start, start)
        if hook and hook[1] == target:
            return entry + start, hook[0].split()[0]
    return None


def copied_page(image, address):
    """True when the only symbols at address are the exporter's memlens_target_ labels: hook code that no module owns,
    copied into the ELF. Any other symbol there is a real name, and such an address is never treated as a hook page."""
    low, high = bisect.bisect_left(image.addresses, address), bisect.bisect_right(image.addresses, address)
    names = [image.symbols[index][2] for index in range(low, high)]
    return bool(names) and all(name.startswith(TARGET_PREFIX) for name in names)


def hook_links(image, findings):
    """A Link for every patched function entry whose target is in the ELF (IDA can only cross-reference what it has)
    and whose transfer instruction is found at the entry. Syscall-table rows and int3 rows have none."""
    links = []
    for entry, name, _, _, target in findings:
        if not target or not image.segment(target):
            continue
        site = transfer_site(image, entry, target)  # None for a syscall slot: its bytes are a pointer, not a jump
        if not site:
            continue
        page = copied_page(image, target)
        handler = page_handler(image, target if page else None)
        links.append(Link(entry, name, site[0], site[1], target, page, *handler, page_owner(image, target, *handler) if page else None))
    return links


def page_handler(image, page):
    """(handler call address, handler address, handler name, kind) for a copied hook page, or four Nones."""
    call = handler_call(image, page) if page is not None else None
    return (call[0], call[1], call[2], handler_kind(call[2])) if call else (None, None, None, None)


def copied_targets(image, findings):
    """The copied hook pages the findings point at (linked entries and syscall slots alike): the addresses whose name
    in the database the list shows."""
    return {target for _, _, _, _, target in findings if target and copied_page(image, target)}


def hook_xrefs(links):
    """(from, to, 'call', 'jmp' or 'data') cross-references for the links, sorted and without repeats: each transfer
    instruction to its target, each copied page's first named call to that function (once, however many entries share
    the page), and the references that lead to each page's owner (Owner.refs: a BPF program's call; for an ftrace
    trampoline the data references slot -> ftrace_ops -> callback), where they are in the ELF.

    The first named call is linked also on a page with no known role (kind None, a call to _printk say): the xref only
    repeats a real call instruction, so it claims no role; the list does not offer that function as the handler."""
    xrefs = set()
    for link in links:
        xrefs.add((link.site, link.target, link.flow))
        if link.handler is not None:
            xrefs.add((link.handler_site, link.handler, "call"))
        if link.owner is not None:
            xrefs.update(link.owner.refs)
    return sorted(xrefs)


def page_owners(links):
    """{page address: Owner} for the copied hook pages of the links that have an owner."""
    return {link.target: link.owner for link in links if link.page and link.owner is not None}


def ida_safe(text):
    """text with every character other than A-Z, a-z, 0-9 and _ replaced by _ (module.symbol -> module_symbol)."""
    return "".join(c if c.isascii() and (c.isalnum() or c == "_") else "_" for c in text)


def role_names(image, links):
    """{page address: new name} for copied hook pages whose handler has a known role (ROLE_PREFIXES): ftrace, kprobe via
    ftrace, BPF trampoline, or a module callback (the page's first named call is a module's function: module_hook_).

    A page that exactly one patched entry leads to is named after that function (ftrace_tramp_vfs_getattr); a page
    that several entries share, like one ftrace trampoline serving many functions, by role and address
    (ftrace_tramp_ffffffffc0b2b000). A page with any real symbol at its address is not a copied page (copied_page),
    so it is never renamed, and neither is a page whose role is unknown. Names use A-Z, a-z, 0-9 and _ only, start with
    the role, and are unique: never a symbol name in the ELF or another page's new name (the address form is used
    instead, or the page keeps its label).
    """
    users = {}
    for link in links:
        if link.page and link.kind in ROLE_PREFIXES:
            users.setdefault(link.target, (link.kind, {}))[1].setdefault(link.entry, []).append(link.function)
    taken = set(image.by_name)
    names = {}
    for page in sorted(users):
        kind, entries = users[page]
        role = ROLE_PREFIXES[kind]
        fallback = "%s_%x" % (role, page)
        name = "%s_%s" % (role, ida_safe(min(next(iter(entries.values()))))) if len(entries) == 1 else fallback
        if name in taken or len(name) > LONGEST_ROLE_NAME:
            name = fallback
        if name in taken:
            continue
        names[page] = name
        taken.add(name)
    return names


def page_comments(links):
    """{page address: comment} for every copied hook page with a link: its exporter label (memlens_target_<address>,
    kept findable after a rename), the functions that lead to it (up to five) and its first named call."""
    pages = {}
    for link in links:
        if link.page:
            pages.setdefault(link.target, (link, set()))[1].add(link.function)
    comments = {}
    for page, (link, functions) in sorted(pages.items()):
        callers = sorted(functions)
        text = "MemLens: hook page no module owns, copied from memory (exporter label %s%x); reached from %s" % (
            TARGET_PREFIX, page, ", ".join(callers[:5]) + (" and %d more" % (len(callers) - 5) if len(callers) > 5 else ""))
        if link.handler_name:
            text += "; first named call: %s%s" % (link.handler_name, " (%s)" % link.kind if link.kind else "")
        if link.owner is not None and link.owner.how != MODULE_CALLBACK:  # that one is in the comment already
            text += "; owner: %s" % link.owner.text
        comments[page] = text
    return comments


def handler_text(link):
    """The Handler column for a link: 'function_trace_call (ftrace)', 'evilmod.fh_sys_kill (module callback)', or '' when
    the page has no named call. On a page with no known role the first named call goes into the core kernel (_printk,
    kfree, a retpoline thunk): a helper the hook code uses, so it is not shown as the handler but as
    '(hook code; first call: _printk)'."""
    if link is None or link.handler_name is None:
        return ""
    if link.kind is None:
        return "(hook code; first call: %s)" % link.handler_name
    return "%s (%s)" % (link.handler_name, link.kind)


def list_rows(image, findings, links, names):
    """Rows of the IDA list: (address, function, what, target, handler, handler address or None, owner, owner address or
    None); the handler is handler_text, its address None when no handler is known (also on a page with no known role,
    whose first named call is not a handler: Jump to handler must not go there); the owner is page_owner's text, ''
    when none is known, and its address None when it is not in the ELF.

    names maps a hook page to the name the database gives it now (after renaming). For an entry linked to a copied hook
    page the target is that name, else the ELF's name for it (any other link keeps the scan's label); the handler has its own column. A syscall slot is never linked, but when it points
    at a copied hook page it gets the same: that page's name now and its handler. Other rows keep the scan's target
    label.
    """
    by_entry = {(link.entry, link.function): link for link in links}
    rows = []
    for address, function, what, label, target in findings:
        link = by_entry.get((address, function))
        if link is None and target and copied_page(image, target):
            handler = page_handler(image, target)
            link = Link(address, function, None, None, target, True, *handler, page_owner(image, target, *handler))
        if link is None:
            rows.append((address, function, what, label, "", None, "", None))
            continue
        shown = (names.get(link.target) or describe(image, link.target)) if link.page else label
        owner = link.owner if link.page else None
        rows.append((address, function, what, shown, handler_text(link), link.handler if link.kind else None,
                     owner.text if owner else "", owner.address if owner else None))
    return rows


def at(image, address):
    """name+0x<offset> for an address, as a disassembler prints it, or the plain address with no symbol."""
    index = bisect.bisect_right(image.addresses, address) - 1
    name = image.symbol_at(address)
    if name is None:
        return "%#x" % address
    offset = address - image.symbols[index][0]
    return "%s+%#x" % (name, offset) if offset else name


def print_links(image, findings):
    """The hook chain that MemLens adds in IDA, as tab-separated lines: xref <from> <to> <call|jmp|data> <where -> where>,
    rename <page> <exporter label> <new name>, and owner <page> <owner address, or - when not in the ELF> <owner> (the
    list's Owner column)."""
    links = hook_links(image, findings)
    for source, target, flow in hook_xrefs(links):
        print("xref\t%#x\t%#x\t%s\t%s -> %s" % (source, target, flow, at(image, source), at(image, target)))
    for page, name in sorted(role_names(image, links).items()):
        print("rename\t%#x\t%s\t%s" % (page, describe(image, page), name))
    for page, owner in sorted(page_owners(links).items()):
        print("owner\t%#x\t%s\t%s" % (page, "-" if owner.address is None else "%#x" % owner.address, owner.text))


USAGE = ("usage: python3 patchscan.py [--links] [--isf <isf>] kernel.elf   (the ELF that MemLens/kernel2elf exported; "
         "--links also prints the cross-references, hook page names and owners that MemLens adds in IDA; --isf takes the "
         "offset of ftrace_ops.func from that kernel's ISF instead of %d)" % FTRACE_OPS_FUNC)


def main(argv):
    links = "--links" in argv[1:]
    argv = [argv[0]] + [arg for arg in argv[1:] if arg != "--links"]
    isf_path = None
    if "--isf" in argv[1:]:
        at_isf = argv.index("--isf")
        if at_isf + 1 >= len(argv):
            sys.exit(USAGE)
        isf_path = argv[at_isf + 1]
        argv = argv[:at_isf] + argv[at_isf + 2:]
    if len(argv) != 2:
        sys.exit(USAGE)
    func_offset = None
    if isf_path is not None:
        here = os.path.dirname(os.path.abspath(__file__))
        if here not in sys.path:
            sys.path.insert(0, here)  # isf2c lives next to this file (python3 -I does not add the script's folder)
        import isf2c
        try:
            func_offset = ftrace_ops_func_offset(isf2c.load_isf(isf_path))
        except (isf2c.ISFError, OSError) as error:
            sys.exit("patchscan: cannot read the ISF %s: %s" % (isf_path, error))
        if func_offset is None:
            print("warning: %s has no ftrace_ops.func; ops->func is read at offset %d" % (isf_path, FTRACE_OPS_FUNC), file=sys.stderr)
    try:
        with open(argv[1], "rb") as handle:
            blob = handle.read()
    except OSError as error:
        sys.exit("patchscan: cannot read %s: %s" % (argv[1], error.strerror or error))
    try:
        if on_disk_kernel(blob):
            print("warning: this is a kernel file from disk, not a memory export; its unapplied alternatives show up as false rows", file=sys.stderr)
        image = Image(blob)
        if func_offset is not None:
            image.ftrace_ops_func = func_offset
        functions = sum(1 for symbol in image.symbols if symbol[3] == STT_FUNC)
        print("%d function symbols scanned" % functions, file=sys.stderr)
        reason = nothing_to_check(image)
        if reason:
            print("warning: %s, so nothing was checked; an empty list here does not mean clean" % reason, file=sys.stderr)
        findings = [] if reason else scan(blob, image)
    except BAD_ELF as error:
        sys.exit("patchscan: not a usable 64-bit ELF: %s" % error)
    for address, name, kind, target, _ in findings:
        print("%#x\t%s\t%s\t%s" % (address, name, kind, target))
    if links:
        print_links(image, findings)


if __name__ == "__main__":
    main(sys.argv)
