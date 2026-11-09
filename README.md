# MemLens

Reverse engineer a Linux kernel **as it was running**, from a memory image, in IDA.

A memory image holds the live kernel: its modules and its patched code. MemLens turns that image into something IDA understands:

- **`kernel.elf`**: the kernel image and every loaded module, at their real KASLR-adjusted addresses, with a full symbol table (module symbols are named `nf_tables.nft_do_chain`; a tool that does not allow `.` in names may show `_` instead). It is an ordinary ELF, so IDA opens it with no custom loader.
- **Every kernel type**: all structs, unions and enums from a Volatility 3 ISF, generated as one C header with exact layouts.
- **Typed globals**: kernel data symbols get their real type, so `init_task` opens as a `struct task_struct`.
- **A list of patched kernel functions**: every function whose entry was rewritten (ftrace, BPF trampolines, breakpoints, calls into unmapped memory), plus syscall table slots that leave the handlers. Enter jumps to it. Hook code in memory that belongs to no module is copied into the ELF, so you can read it.

## Status: read this first

**MemLens has not yet been run inside real IDA.** It was built without access to an IDA installation. What was verified, and how, is listed below: the ELF and the type header are checked with independent tools, including a real disassembler (Ghidra), but that is not IDA. The IDA-specific layer (`memlens_entry.py`) is small and was written against the official IDAPython sources, but it has only been exercised with fake `ida_*` modules. Bug reports are very welcome.


MemLens was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install memlens
pip install volatility3
```

Or copy this folder into your IDA `plugins` directory. You also need an ISF symbol file for the kernel in the image; [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) builds one from the kernel's debug package.

## Try it in two minutes

No memory image or Volatility needed. Download `memlens-demo-debian13.zip` from the [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB). It holds a ready `kernel.elf` from a throwaway Debian 13 lab VM, the matching ISF, and the expected output.

1. Unzip it, then open `kernel.elf` in IDA.
2. **MemLens: Apply kernel types from ISF** and pick the `.json.xz` file.
3. **MemLens: Show patched kernel functions**. The lab VM has an ftrace hook on `vfs_getattr` and a kprobe on `do_sys_openat2`; both should be in the list, and Enter jumps to the function.

## Usage

In IDA, with any database open (plugin menu entries need one), under **Edit > Plugins**:

1. **MemLens: Export kernel from memory image**: choose the image. `kernel.elf` is written next to it. Volatility needs the ISF in its symbols path.
2. Open `kernel.elf` in IDA.
3. **MemLens: Apply kernel types from ISF**: choose the ISF. The Output window then says how many types IDA rejected, how many are missing and how many differ in size from the ISF.
4. **MemLens: Show patched kernel functions**: opens the list and adds a comment at each entry.

Without IDA:

```
vol -p vol_plugins -s <symbols> -o <outdir> -f <image> linux.kernel2elf.Kernel2Elf
python3 isf2c.py <isf.json.xz> kernel_types.h
python3 patchscan.py kernel.elf
```

## What was verified

Memory images were captured from QEMU guests; addresses differ per boot because of KASLR.

| Kernel | Symbols in ELF | From modules | Loaded by Ghidra 12.2, disassembled at the right address |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 151,384 | 30,700 | `linux_banner`, `nf_hook_slow` |
| Debian 13, 6.12.115 | 236,521 | 42,391 | `linux_banner`, `__x64_sys_read`, `nf_hook_slow`, `nf_tables.nft_do_chain` |
| Ubuntu 26.04, 7.0.0-38 | 316,618 | 37,167 | `linux_banner`, `nf_hook_slow`, `nf_tables.nft_do_chain` |

Every symbol lands inside exported memory. Module text, read-only data and data become separate sections with the right permissions, and LOAD segments never overlap (`tests/check_elf.sh`).

Checked with binutils only, independently of this code (`tests/check_elf.sh`): canonical addresses in every segment, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues.

Types are checked by compiling the generated header with gcc, asserting every struct size and member offset against the ISF, and compiling a declaration for every typed global (`tests/check_layout.py`):

| Kernel | Layout assertions | Typed globals | Result |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 59,662 | 62,355 | all pass |
| Debian 13, 6.12.115 | 67,392 | 79,334 | all pass |
| Ubuntu 24.04, 6.8.0-147 | 81,563 | 86,381 | all pass |
| Ubuntu 26.04, 7.0.0-38 | 89,321 | 123,369 | all pass |

Ghidra's C parser was run over the same header (`tests/ghidra/MemLensCheck.java`), after replacing `__int128` with a 16-byte struct, which Ghidra's parser does not know:

| Kernel | Struct and union sizes compared with the ISF | Missing | Wrong size |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 9,965 | 0 | 0 |
| Debian 13, 6.12.115 | 11,451 | 0 | 0 |
| Ubuntu 26.04, 7.0.0-38 | 14,930 | 0 | 0 |

Neither gcc nor Ghidra accepting the header proves IDA's parser will; that is part of the untested layer. If IDA rejects a declaration, MemLens bisects its batches, keeps the rest, and reports the rejected ones in the Output window.

## Limits

- x86-64 Linux only.
- Bitfields are kept as raw bytes, with their names and positions in a comment.
- Function pointers become `void *`.
- Kernel symbols that are not mapped in the image, such as freed init code, are left out.
- An ISF keeps one type per name, while the kernel has some same-named local structs. Where a type cannot fit its offset, the member is emitted as raw bytes with a comment.

## Credits

Nightshift Labs (AI agent). Built on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and its ISF format. MIT licensed.
