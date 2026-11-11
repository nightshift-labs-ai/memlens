#!/usr/bin/env python3
"""Hand-made ELFs with known patches: the classifier needs no IDA and no memory image here."""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import patchscan as ps
BASE = 0xffffffff81000000
TEXT = 0x4000
def elf(code, symbols, rodata=b""):
    """code at BASE; rodata at BASE + TEXT; symbols [(name, addr, size)]."""
    strtab, symtab = bytearray(b"\0"), bytearray(b"\0" * 24)
    for name, addr, size in symbols:
        symtab += struct.pack("<IBBHQQ", len(strtab), 0x12, 0, 1, addr, size); strtab += name.encode() + b"\0"
    head = 64 + 56 * 2
    ro = head + len(code); sy = ro + len(rodata); st = sy + len(symtab); sh = st + len(strtab)
    out = bytearray(b"\x7fELF\x02\x01\x01" + b"\0" * 9)
    out += struct.pack("<HHIQQQIHHHHHH", 2, 62, 1, BASE, 64, sh, 0, 64, 56, 2, 64, 3, 2)
    out += struct.pack("<IIQQQQQQ", 1, 5, head, BASE, BASE, len(code), len(code), 4096)
    out += struct.pack("<IIQQQQQQ", 1, 4, ro, BASE + TEXT, BASE + TEXT, len(rodata), len(rodata), 4096)
    out += bytes(code) + bytes(rodata) + bytes(symtab) + bytes(strtab)
    out += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    out += struct.pack("<IIQQQQIIQQ", 0, 2, 0, 0, sy, len(symtab), 2, 1, 8, 24)
    out += struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, st, len(strtab), 0, 0, 1, 0)
    return bytes(out)
def call(site, target, op=0xE8):
    return bytes([op]) + struct.pack("<i", target - (site + 5))
code = bytearray(b"\x90" * TEXT)
def put(offset, data): code[offset:offset + len(data)] = data
NOP = ps.FENTRY_NOP
put(0x000, b"\xf3\x0f\x1e\xfa" + NOP + b"\x55")                                 # traced function, idle: clean
put(0x100, b"\xf3\x0f\x1e\xfa" + call(BASE + 0x104, BASE + 0x900) + b"\x55")     # ftrace active
put(0x200, call(BASE + 0x200, 0xffffffffc0001000))                              # call to no symbol
put(0x300, call(BASE + 0x300, 0xffffffffc0002000, 0xE9))                        # jmp to no symbol
put(0x400, b"\xcc\x89\xe5")                                                     # kprobe
put(0x500, b"\xcc\xcc\xcc\xcc")                                                 # padding: clean
put(0x600, call(BASE + 0x600, BASE + 0x800))                                    # plain call into a kernel function: clean
put(0x700, call(BASE + 0x700, 0xffffffffc0003000, 0xE9))                        # static call trampoline: clean
put(0x900, b"\xc3")
symbols = [("clean_fn", BASE, 0x100), ("traced_fn", BASE + 0x100, 0x100), ("called_fn", BASE + 0x200, 0x100), ("jumped_fn", BASE + 0x300, 0x100),
           ("probed_fn", BASE + 0x400, 0x100), ("padding_fn", BASE + 0x500, 0x100), ("wrapper_fn", BASE + 0x600, 0x100), ("__SCT__tp", BASE + 0x700, 0x100),
           ("helper_fn", BASE + 0x800, 0x100), ("ftrace_caller", BASE + 0x900, 0x100), ("__x64_sys_read", BASE + 0xa00, 0x100),
           ("evil.hook", 0xffffffffc0004000, 0x100), ("sys_call_table", BASE + TEXT, 0x18)]
table = struct.pack("<QQQ", BASE + 0xa00, 0xffffffffc0005000, 0)
image = ps.Image(elf(code, symbols, table))
found = {row[1]: row for row in ps.scan_functions(image)}
assert set(found) == {"traced_fn", "called_fn", "jumped_fn", "probed_fn"}, found
assert found["traced_fn"][2] == "ftrace call at entry" and found["traced_fn"][3] == "ftrace_caller"
assert found["called_fn"][2] == "call to memory with no symbol" and found["called_fn"][4] == 0xffffffffc0001000
assert found["jumped_fn"][2] == "jmp to no symbol".replace("no", "memory with no")
assert found["probed_fn"][2].startswith("int3")
sys_rows = ps.scan_syscalls(image)
assert [r[1] for r in sys_rows] == ["sys_call_table[1]"] and sys_rows[0][4] == 0xffffffffc0005000, sys_rows
# Things seen on a clean Ubuntu 7.0 kernel that must not be reported.
code = bytearray(b"\x90" * TEXT)
put(0x000, call(BASE, BASE + 0x900))                                            # compile-time call __fentry__
put(0x100, call(BASE + 0x100, BASE + 0xa00))                                    # ftrace's own trampoline
put(0x200, call(BASE + 0x200, 0xffffffffc0001000))                              # a real hook still shows
put(0xb00, b"\xc3")
symbols = [("not_converted", BASE, 0x100), ("ftrace_call", BASE + 0x100, 0x100), ("hooked", BASE + 0x200, 0x100),
           ("__fentry__", BASE + 0x900, 0x100), ("ftrace_stub", BASE + 0xa00, 0x100), ("__x64_sys_read", BASE + 0xb00, 0x100),
           ("sys_call_table", BASE + TEXT, 0x18)]
past_end = 0xffffffffc0006000
image = ps.Image(elf(code, symbols, struct.pack("<QQQQ", BASE + 0xb00, 0xffffffffc0005000, BASE + 0xb00, past_end)))
assert [row[1] for row in ps.scan_functions(image)] == ["hooked"]
assert [row[1] for row in ps.scan_syscalls(image)] == ["sys_call_table[1]"]
symbols[-1] = ("sys_call_table", BASE + TEXT, 0x40)
image = ps.Image(elf(code, symbols, struct.pack("<QQQ", BASE + 0xb00, BASE + TEXT + 8, past_end)))
# Inside a known table size a data pointer is reported, not taken as the end of the table.
assert [(r[1], r[2]) for r in ps.scan_syscalls(image)] == [("sys_call_table[1]", "syscall entry is not a code pointer"),
                                                          ("sys_call_table[2]", "syscall entry outside the handlers")]
symbols[-1] = ("sys_call_table", BASE + TEXT, 0)                                # no size: a data pointer ends it
image = ps.Image(elf(code, symbols, struct.pack("<QQQ", BASE + 0xb00, BASE + TEXT + 8, past_end)))
assert ps.scan_syscalls(image) == []
# One odd slot must not hide later ones: data pointer, zero padding, handler, kernel code, unmapped, handler.
symbols[-1] = ("sys_call_table", BASE + TEXT, 0x30)
image = ps.Image(elf(code, symbols, struct.pack("<QQQQQQ", BASE + TEXT + 8, 0, BASE + 0xb00, BASE + 0x200, 0xffffffffc0005000, BASE + 0xb00)))
assert [r[1] for r in ps.scan_syscalls(image)] == ["sys_call_table[0]", "sys_call_table[3]", "sys_call_table[4]"], ps.scan_syscalls(image)
code = bytearray(b"\x90" * TEXT)
put(0x000, call(BASE, BASE + 0x900, 0xE9))                                      # kernel jumps to its own foo.constprop.0
put(0x100, call(BASE + 0x100, 0xffffffffc0007000, 0xE9))                        # kernel jumps into a module
symbols = [("foo", BASE, 0x100), ("bar", BASE + 0x100, 0x100), ("foo.constprop.0", BASE + 0x900, 0x100), ("evil.hook", 0xffffffffc0007000, 0x100)]
assert [row[1] for row in ps.scan_functions(ps.Image(elf(code, symbols)))] == ["bar"]
# Absolute-address inline hooks (not compiler output at an entry), at the entry, after endbr64, after the ftrace NOP.
EVIL = 0xffffffffc0009000
code = bytearray(b"\x90" * TEXT)
put(0x000, b"\xff\x25\x00\x00\x00\x00" + struct.pack("<Q", EVIL))                     # jmp [rip+0]; dq target
put(0x100, b"\xf3\x0f\x1e\xfa" + b"\x48\xb8" + struct.pack("<Q", EVIL) + b"\xff\xe0")   # endbr64; movabs rax; jmp rax
put(0x200, b"\x49\xbb" + struct.pack("<Q", EVIL) + b"\x41\xff\xe3")                  # movabs r11; jmp r11
put(0x300, NOP + b"\x68" + struct.pack("<i", EVIL - (1 << 64)) + b"\xc3")              # ftrace NOP; push imm32; ret
put(0x400, b"\x48\xb8" + struct.pack("<Q", EVIL) + b"\xff\xd0")                       # movabs rax; call rax
put(0x500, b"\x48\xb8" + struct.pack("<Q", 1234) + b"\x48\x89")                       # movabs rax, 1234; mov ...: clean
put(0x600, b"\x68" + struct.pack("<i", 5) + b"\x58")                                  # push 5; pop rax: clean
put(0x700, b"\x49\xbb" + struct.pack("<Q", BASE + 0x900) + b"\x41\xff\xe3")          # movabs r11 to a kernel symbol: still a patch
put(0x800, b"\x48\xb8" + struct.pack("<Q", 0xffffffffc0007000) + b"\xff\xe0")         # into a module
symbols = [("ripjmp", BASE, 0x100), ("movjmp", BASE + 0x100, 0x100), ("r11jmp", BASE + 0x200, 0x100), ("pushret", BASE + 0x300, 0x100),
           ("movcall", BASE + 0x400, 0x100), ("plain_mov", BASE + 0x500, 0x100), ("plain_push", BASE + 0x600, 0x100),
           ("to_kernel", BASE + 0x700, 0x100), ("to_module", BASE + 0x800, 0x100), ("helper", BASE + 0x900, 0x100),
           ("evil.hook", 0xffffffffc0007000, 0x100)]
found = {row[1]: row for row in ps.scan_functions(ps.Image(elf(code, symbols)))}
assert set(found) == {"ripjmp", "movjmp", "r11jmp", "pushret", "movcall", "to_kernel", "to_module"}, found
assert found["ripjmp"][2] == "jmp [rip+0] to memory with no symbol" and found["ripjmp"][4] == EVIL
assert found["movjmp"][2] == "movabs+jmp reg to memory with no symbol" and found["movjmp"][4] == EVIL
assert found["r11jmp"][4] == EVIL and found["pushret"][2] == "push+ret to memory with no symbol" and found["pushret"][4] == EVIL
assert found["movcall"][2].startswith("movabs+call reg")
assert found["to_kernel"][2] == "movabs+jmp reg at entry" and found["to_kernel"][3] == "helper"
assert found["to_module"][2] == "movabs+jmp reg from kernel into a module"
# A copied hook page is labelled with the first named function it calls.
code = bytearray(b"\x90" * TEXT)
put(0x200, call(BASE + 0x200, BASE + 0xc00))                                    # entry calls the copied page
put(0xc00 + 0x40, call(BASE + 0xc40, BASE + 0xd00))                             # page calls the handler
put(0x300, call(BASE + 0x300, BASE + 0xe00))                                    # page that calls nothing named
symbols = [("hooked", BASE + 0x200, 0x100), ("other", BASE + 0x300, 0x100), ("memlens_target_ffffffff81000c00", BASE + 0xc00, 0x100),
           ("kprobe_ftrace_handler", BASE + 0xd00, 0x100), ("memlens_target_ffffffff81000e00", BASE + 0xe00, 0x100)]
found = {row[1]: row for row in ps.scan_functions(ps.Image(elf(code, symbols)))}
assert found["hooked"][3] == "memlens_target_ffffffff81000c00 (calls kprobe_ftrace_handler, kprobe via ftrace)", found
assert found["other"][3] == "memlens_target_ffffffff81000e00", found
# Sealed ENDBR: the kernel replaced endbr64 with a 4-byte NOP, and hooks still sit at +4 (both poison encodings).
for poison in (b"\x66\x0f\x1f\x00", b"\x0f\x1f\x40\xd6"):
    code = bytearray(b"\x90" * TEXT)
    put(0x000, poison + NOP + b"\x55")                                              # sealed and idle: clean
    put(0x100, poison + call(BASE + 0x104, EVIL))                                   # sealed, call to no symbol
    put(0x200, poison + b"\xcc\x89\xe5")                                            # sealed, kprobe
    put(0x300, poison + b"\x48\xb8" + struct.pack("<Q", EVIL) + b"\xff\xe0")         # sealed, movabs + jmp
    put(0x400, poison + call(BASE + 0x404, BASE + 0x900))                           # sealed, call into the kernel: clean
    symbols = [("idle", BASE, 0x100), ("called", BASE + 0x100, 0x100), ("probed", BASE + 0x200, 0x100), ("absolute", BASE + 0x300, 0x100),
               ("plain", BASE + 0x400, 0x100), ("helper", BASE + 0x900, 0x100)]
    found = {row[1]: row for row in ps.scan_functions(ps.Image(elf(code, symbols)))}
    assert set(found) == {"called", "probed", "absolute"}, found
    assert found["called"][4] == EVIL and found["probed"][2].startswith("int3") and found["absolute"][4] == EVIL
# A module symbol whose name begins like a compiler suffix is still a module; real clones are not.
code = bytearray(b"\x90" * TEXT)
put(0x000, call(BASE, 0xffffffffc0007000, 0xE9))                                # jump to evil.cold_path
put(0x100, call(BASE + 0x100, BASE + 0x900, 0xE9))                              # jump to its own foo.cold
put(0x200, call(BASE + 0x200, 0xffffffffc0007100, 0xE9))                        # a compiler clone jumping into a module
symbols2 = [("a_fn", BASE, 0x100), ("b_fn", BASE + 0x100, 0x100), ("c_fn.isra.0", BASE + 0x200, 0x100), ("foo.cold", BASE + 0x900, 0x100),
            ("evil.cold_path", 0xffffffffc0007000, 0x100), ("evil.hook", 0xffffffffc0007100, 0x100)]
found = {row[1]: row for row in ps.scan_functions(ps.Image(elf(code, symbols2)))}
assert set(found) == {"a_fn", "c_fn.isra.0"}, found
# Hooks the compiler cannot produce after the ftrace NOP, and jmp/call through a pointer in memory.
code = bytearray(b"\x90" * TEXT)
def rip(site, slot, op):                                                       # jmp/call [rip+disp32]
    return b"\xff" + bytes([op]) + struct.pack("<i", slot - (site + 6))
put(0x000, NOP + call(BASE + 5, 0xffffffffc000a000))                            # NOP; call unmapped
put(0x100, NOP + call(BASE + 0x105, BASE + 0x900, 0xE9))                        # NOP; tail jump to own function: clean
put(0x200, b"\xf3\x0f\x1e\xfa" + NOP + call(BASE + 0x209, 0xffffffffc0007000, 0xE9))  # endbr; NOP; jmp into a module
put(0x300, rip(BASE + 0x300, BASE + TEXT, 0x25))                                # jmp [rip+X] -> unmapped
put(0x400, rip(BASE + 0x400, BASE + TEXT + 8, 0x15))                            # call [rip+X] -> kernel function: clean
put(0x500, NOP + rip(BASE + 0x505, BASE + TEXT + 16, 0x15))                     # NOP; call [rip+X] -> module
symbols3 = [("p0", BASE, 0x100), ("p1", BASE + 0x100, 0x100), ("p2", BASE + 0x200, 0x100), ("p3", BASE + 0x300, 0x100),
            ("p4", BASE + 0x400, 0x100), ("p5", BASE + 0x500, 0x100), ("own", BASE + 0x900, 0x100), ("evil.hook", 0xffffffffc0007000, 0x100)]
pointers = struct.pack("<QQQ", 0xffffffffc000b000, BASE + 0x900, 0xffffffffc0007000)
found = {row[1]: row[2] for row in ps.scan_functions(ps.Image(elf(code, symbols3, pointers)))}
assert found == {"p0": "call after the ftrace NOP to memory with no symbol", "p2": "jmp after the ftrace NOP from kernel into a module",
                 "p3": "jmp [rip+0x3cfa] to memory with no symbol", "p5": "call [rip+0x3b05] from kernel into a module"}, found
# Other architectures are refused, and a kernel file from disk is recognised.
blob = elf(code, symbols)
arm = blob[:18] + struct.pack("<H", 183) + blob[20:]
try:
    ps.Image(arm)
except ValueError as error:
    assert "not x86-64" in str(error)
else:
    raise AssertionError("arm64 ELF accepted")
assert not ps.on_disk_kernel(blob)
name = b".altinstructions\0"
shoff = struct.unpack_from("<Q", blob, 40)[0]
header = bytearray(blob[shoff + 128:shoff + 192]); struct.pack_into("<Q", header, 24, len(blob)); struct.pack_into("<I", header, 0, 0)
disk = bytearray(blob[:shoff + 128]) + header + name
assert ps.on_disk_kernel(bytes(disk))
print("patchscan tests OK")
