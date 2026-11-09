# linux.kernel2elf (Volatility 3)

Writes the Linux kernel found in a memory image as one ordinary ELF file, and lists the kernel functions whose entry was rewritten.

The ELF holds the kernel image and every loaded module at their real KASLR-adjusted addresses, with a full symbol table. `objdump`, Ghidra and similar tools open it with no custom loader, so a memory image can be disassembled like any binary.

## Use

Copy `vol_plugins/` and `patchscan.py` so that they keep this layout, then:

```
vol -p vol_plugins -s <symbols> -o <outdir> -f <image> linux.kernel2elf.Kernel2Elf
```

It needs the ordinary Linux ISF for the image's kernel. `--no-modules` leaves out the modules.

Each output row has an Item, a Name, an Address and a Count:

| Item | Meaning |
|---|---|
| `section` | Part of the kernel image; Count is bytes written |
| `symbols` | Kernel symbols added |
| `module` | A loaded module; Count is its symbols |
| `hook target` | A page of hook code outside the kernel and modules, copied into the ELF; it gets a `memlens_target_<address>` symbol |
| `patched` | A function entry that was rewritten, or a syscall table slot outside the handlers |
| `written` | The output file name; Count is symbols |

Then, for example:

```
objdump -d --disassemble=nf_tables.nft_do_chain kernel.elf
```

## What counts as patched

Only code bytes at each function entry are read, so this does not depend on ftrace's own data structures:

- a `call` or `jmp` to memory with no symbol (BPF trampolines, per-function ftrace trampolines, inline hooks)
- a `call` to `ftrace_caller` or a sibling
- `int3` at the entry (kprobes, breakpoints)
- a `jmp` or `call` from the kernel into a module
- `sys_call_table` slots that do not point to a syscall handler

## Limits

- x86-64 Linux only.
- Kernel symbols not mapped in the image, such as freed init code, are left out.
- Only function entries are checked, so a hook placed later in a function is not reported.
- A function with no symbol is not checked.
- A `patched` row says the entry was rewritten. It does not say the change is malicious: BPF LSM and tracing produce the same pattern.
- Modules unlinked from the module list are not exported.

Built by an AI agent (Claude, operated by Nightshift Labs). MIT licensed.
