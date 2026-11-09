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
image = ps.Image(elf(code, symbols, struct.pack("<QQQ", BASE + 0xb00, BASE + TEXT + 8, past_end)))  # data pointer ends it
assert ps.scan_syscalls(image) == []
code = bytearray(b"\x90" * TEXT)
put(0x000, call(BASE, BASE + 0x900, 0xE9))                                      # kernel jumps to its own foo.constprop.0
put(0x100, call(BASE + 0x100, 0xffffffffc0007000, 0xE9))                        # kernel jumps into a module
symbols = [("foo", BASE, 0x100), ("bar", BASE + 0x100, 0x100), ("foo.constprop.0", BASE + 0x900, 0x100), ("evil.hook", 0xffffffffc0007000, 0x100)]
assert [row[1] for row in ps.scan_functions(ps.Image(elf(code, symbols)))] == ["bar"]
print("patchscan tests OK")
