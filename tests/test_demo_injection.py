#!/usr/bin/env python3
"""Plant syscall-table hooks in a copy of the demo kernel.elf and check patchscan reports all of them.

usage: python3 tests/test_demo_injection.py [path/to/demo/kernel.elf]
The demo is in memlens-demo-debian13.zip (demo-data release). Without it the test is skipped.
Slot 0 gets a data pointer first, so a scanner that stops at the first odd slot would miss the rest.
"""
import os, struct, sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import patchscan as ps

path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MEMLENS_DEMO_ELF", "")
if not path or not os.path.isfile(path):
    print("demo injection test SKIPPED (no demo kernel.elf given)")
    sys.exit(0)
blob = bytearray(open(path, "rb").read())
clean = ps.Image(bytes(blob))
baseline = [row[1] for row in ps.scan(bytes(blob))]
assert not any(name.startswith("sys_call_table") for name in baseline), baseline


def file_offset(address):
    phoff, phnum = struct.unpack_from("<Q", blob, 32)[0], struct.unpack_from("<H", blob, 56)[0]
    for index in range(phnum):
        kind, _, offset, vaddr, _, filesz, _, _ = struct.unpack_from("<IIQQQQQQ", blob, phoff + 56 * index)
        if kind == 1 and vaddr <= address < vaddr + filesz:
            return offset + address - vaddr
    raise AssertionError("address %#x not in the file" % address)


table = clean.by_name["sys_call_table"][0]
planted = {0: clean.by_name["init_task"][0], 62: clean.by_name["vfs_read"][0], 217: 0xffffffffc0dead00}
for slot, target in planted.items():
    struct.pack_into("<Q", blob, file_offset(table + 8 * slot), target)
rows = [row for row in ps.scan(bytes(blob)) if row[1].startswith("sys_call_table")]
assert [(row[1], row[2]) for row in rows] == [
    ("sys_call_table[0]", "syscall entry is not a code pointer"),
    ("sys_call_table[62]", "syscall entry outside the handlers"),
    ("sys_call_table[217]", "syscall entry outside the handlers")], rows
assert [row[1] for row in ps.scan(bytes(blob)) if not row[1].startswith("sys_call_table")] == baseline
print("demo injection test OK (3 of 3 planted syscall slots reported, function rows unchanged)")
