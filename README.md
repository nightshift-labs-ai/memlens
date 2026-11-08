# MemLens

Reverse engineer a Linux kernel **as it was running**, from a memory image, in IDA.

A memory image holds the live kernel: its modules, its patched code, and anything a rootkit added. MemLens turns that image into something IDA understands:

- **`kernel.elf`**: the kernel image and every loaded module, at their real KASLR-adjusted addresses, with a full symbol table (module symbols appear as `nf_tables.nft_do_chain`). It is an ordinary ELF, so IDA opens it with no custom loader.
- **Every kernel type**: all structs, unions and enums from a Volatility 3 ISF, generated as one C header with exact layouts.

## Status: read this first

**MemLens has not yet been run inside real IDA.** It was built without access to an IDA installation. What was verified, and how, is listed below. The IDA-specific layer (`memlens_entry.py`) is small and was written against the official IDAPython sources, but it has only been exercised with fake `ida_*` modules. Bug reports are very welcome.

MemLens was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install memlens
pip install volatility3
```

Or copy this folder into your IDA `plugins` directory. You also need an ISF symbol file for the kernel in the image; [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) builds one from the kernel's debug package.

## Usage

In IDA, under **Edit > Plugins**:

1. **MemLens: Export kernel from memory image**: choose the image. `kernel.elf` is written next to it. Volatility needs the ISF in its symbols path.
2. Open `kernel.elf` in IDA.
3. **MemLens: Apply kernel types from ISF**: choose the ISF.

Without IDA:

```
vol -p vol_plugins -s <symbols> -o <outdir> -f <image> linux.kernel2elf.Kernel2Elf
python3 isf2c.py <isf.json.xz> kernel_types.h
```

## What was verified

Memory images were captured from QEMU guests; addresses differ per boot because of KASLR.

| Kernel | Symbols in ELF | From modules | Module function at correct address |
|---|---|---|---|
| Debian 13, 6.12.115 | 233,213 | 49,049 | `nf_tables.nft_do_chain` |
| Ubuntu 26.04, 7.0.0-38 | 305,094 | 50,877 | `nf_tables.nft_do_chain` |

Checked with binutils only, independently of this code (`tests/check_elf.sh`): canonical addresses in every segment, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues.

Types are checked by compiling the generated header with gcc and asserting every struct size and member offset against the ISF (`tests/check_layout.py`):

| Kernel | Assertions | Result |
|---|---|---|
| Debian 12, 6.1.0-54 | 59,662 | all pass |
| Debian 13, 6.12.115 | 67,392 | all pass |
| Ubuntu 24.04, 6.8.0-147 | 81,563 | all pass |
| Ubuntu 26.04, 7.0.0-38 | 89,321 | all pass |

gcc accepting the header does not prove IDA's parser will; that is part of the untested layer.

## Limits

- x86-64 Linux only.
- Bitfields are kept as raw bytes, with their names and positions in a comment.
- Function pointers become `void *`.
- Kernel symbols that are not mapped in the image, such as freed init code, are left out.
- Modules are marked executable as a whole.
- An ISF keeps one type per name, while the kernel has some same-named local structs. Where a type cannot fit its offset, the member is emitted as raw bytes with a comment.

## Credits

Nightshift Labs (AI agent). Built on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and its ISF format. MIT licensed.
