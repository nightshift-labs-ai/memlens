# MemLens

Reverse engineer a Linux kernel **as it was running**, from a memory image, in IDA.

A memory image holds the live kernel: its modules and its patched code. MemLens turns that image into something IDA understands:

- **`kernel.elf`**: the kernel image and every loaded module, at their real KASLR-adjusted addresses, with a full symbol table (module symbols are named `nf_tables.nft_do_chain`; a tool that does not allow `.` in names may show `_` instead). It is an ordinary ELF: binutils and Ghidra 12.2 load it with no custom loader, and IDA's own ELF loader is meant to open it the same way (not yet tried in IDA).
- **Every kernel type**: all structs, unions and enums from a Volatility 3 ISF, generated as one C header with exact layouts.
- **Typed globals**: kernel data symbols get their real type, so `init_task` becomes a `struct task_struct` (the declarations compile with gcc; applying them in IDA is part of the untested layer).
- **A list of patched kernel functions**: named functions whose entry (or the instruction after `endbr64` or the NOP the kernel seals it with) was rewritten to a 5-byte `call`/`jmp` (ftrace and BPF trampolines, ftrace-based kprobes, calls into unmapped memory or from the kernel into a module) or to an `int3` breakpoint, or to an absolute-address hook (`jmp [rip+0]` + address, `movabs` + `jmp`/`call reg`, `push imm32; ret`; these also after the ftrace NOP), plus syscall table slots that leave the handlers. Patches deeper inside a function are not found, and functions without a symbol are not checked. Enter should jump to the function. Hook code in memory that belongs to no module is copied into the ELF, so you can read it, and the list names the handler each copied hook page calls (ftrace, kprobe via ftrace, BPF trampoline).

## Status: read this first

**MemLens has not yet been run inside real IDA.** It was built without access to an IDA installation. What was verified, and how, is listed below: the ELF and the type header are checked with independent tools, including a real disassembler (Ghidra), but that is not IDA. The IDA-specific layer (`memlens_entry.py`) is small and was written against the official IDAPython sources, but it has only been exercised with fake `ida_*` modules. Bug reports are very welcome.


MemLens was built by an AI agent (Claude, operated by Nightshift Labs).

## Install

```
hcli plugin install memlens
pipx install volatility3
```

Or copy this folder into your IDA `plugins` directory. The plugin index can lag behind the [GitHub releases](https://github.com/nightshift-labs-ai/memlens/releases); if `hcli plugin status` shows an older version, copy the folder from the latest release. You also need an ISF symbol file for the kernel in the image; [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) builds one from the kernel's debug package.

## Try it

No memory image or Volatility needed. Download `memlens-demo-debian13.zip` from the [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB). It holds a ready `kernel.elf` from a throwaway Debian 13 lab VM (67 MB, 233,305 symbols, 39,173 of them from modules; a different capture of the same kernel than the table below), the matching ISF, and the expected output. A whole kernel is a large database, so IDA's auto-analysis and the type import take a while; we have not timed them in IDA.

1. Unzip it, then open `kernel.elf` in IDA.
2. **MemLens: Apply kernel types from ISF** and pick the `.json.xz` file.
3. **MemLens: Show patched kernel functions**. The lab VM's script set an ftrace filter on `vfs_getattr` and a kprobe on `do_sys_openat2`; a third patched entry, `bpf_lsm_file_open`, was not set by the script: its hook page calls `__bpf_tramp_enter`, so it is a BPF trampoline that something else in the VM attached (what, was not investigated). All three should be listed as `call to memory with no symbol` (each entry calls a trampoline page that no module owns, copied in as `memlens_target_<address>`), and each label names the handler that page calls: `function_trace_call` (ftrace), `kprobe_ftrace_handler` (kprobe via ftrace) and `__bpf_tramp_enter` (a BPF trampoline). `expected-patched-functions.txt` in the zip was made with an earlier version, which did not name the handlers yet. Enter should jump to the function.

## What you get (real output from the demo, not IDA screenshots)

We have no IDA, so there are no IDA screenshots. Below is real output for the demo `kernel.elf`, from the same code the plugin runs (`patchscan.py`, `isf2c.py`) and from binutils `objdump`.

Patched functions, the same scan the IDA list runs (`python3 patchscan.py kernel.elf`):

```
0xffffffff8e4f9250  bpf_lsm_file_open  call to memory with no symbol  memlens_target_ffffffffc0004940 (calls __bpf_tramp_enter, BPF trampoline)
0xffffffff8e642210  do_sys_openat2     call to memory with no symbol  memlens_target_ffffffffc0b2d000 (calls kprobe_ftrace_handler, kprobe via ftrace)
0xffffffff8e64e370  vfs_getattr        call to memory with no symbol  memlens_target_ffffffffc0b2b000 (calls function_trace_call, ftrace)
```

A hooked entry and the hook page it calls, which no module owns and which MemLens copied into the ELF (`objdump -d kernel.elf`, excerpts):

```
ffffffff8e64e370 <vfs_getattr>:
ffffffff8e64e370:  endbr64
ffffffff8e64e374:  call   ffffffffc0b2b000 <memlens_target_ffffffffc0b2b000>

ffffffffc0b2b000 <memlens_target_ffffffffc0b2b000>:
ffffffffc0b2b094:  call   ffffffff8e434a40 <function_trace_call>

ffffffff8e642210 <do_sys_openat2>:
ffffffff8e642210:  call   ffffffffc0b2d000 <memlens_target_ffffffffc0b2d000>

ffffffffc0b2d000 <memlens_target_ffffffffc0b2d000>:
ffffffffc0b2d0d9:  call   ffffffff8e294ed0 <kprobe_ftrace_handler>
```

So the `vfs_getattr` page is an ftrace trampoline and the `do_sys_openat2` page leads to the kprobe handler, readable at their live addresses.

Types, an excerpt of the header the plugin imports (`python3 isf2c.py debian-6.12.115+deb13.1-amd64.json.xz kernel_types.h`), with explicit padding so every offset matches the ISF:

```c
struct kstat {
  unsigned int result_mask;
  unsigned short mode;
  unsigned char __pad_6[2];
  unsigned int nlink;
  unsigned int blksize;
  unsigned long long attributes;
  ...
};
```

Typed globals come from the same ISF, for example `struct task_struct init_task`, `struct net init_net` and `struct static_key nf_hooks_needed[11][5]` (79,316 of them for this kernel).

## Usage

In IDA, with any database open (plugin menu entries need one), under **Edit > Plugins**:

1. **MemLens: Export kernel from memory image**: choose the image. `kernel.elf` is written next to it. Volatility needs the ISF in its symbols path.
2. Open `kernel.elf` in IDA.
3. **MemLens: Apply kernel types from ISF**: choose the ISF. If its kernel banner differs from the one in the database, MemLens asks before importing anything. The Output window then says how many types IDA rejected, how many are missing and how many differ in size from the ISF.
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

Symbols whose address is not in exported memory are left out by design, so every symbol in the ELF points into a section. Module text, read-only data and data become separate sections with the right permissions, and LOAD segments never overlap (`tests/check_elf.sh`).

Checked with binutils and a short Python step, independently of this code (`tests/check_elf.sh`): canonical addresses in every segment, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues where those symbols are present (`nf_tables` is not loaded in the demo capture, so the script reports it missing there).

Types are checked by compiling the generated header with gcc, asserting every struct size and member offset against the ISF, and compiling a declaration for every typed global (`tests/check_layout.py`):

| Kernel | Layout assertions | Typed globals | Result |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 59,662 | 62,340 | all pass |
| Debian 13, 6.12.115 | 67,392 | 79,316 | all pass |
| Ubuntu 24.04, 6.8.0-147 | 81,563 | 86,362 | all pass |
| Ubuntu 26.04, 7.0.0-38 | 89,321 | 123,349 | all pass |

Typed-global counts are from the current code. The gcc run was made on an earlier build that also declared 15 to 20 globals named like C++ keywords (`new`, `class`, ...), which are now skipped.

Ghidra's C parser was run over the same header (`tests/ghidra/MemLensCheck.java`), after replacing `__int128` with a 16-byte struct, which Ghidra's parser does not know:

| Kernel | Struct and union sizes compared with the ISF | Missing | Wrong size |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 9,965 | 0 | 0 |
| Debian 13, 6.12.115 | 11,451 | 0 | 0 |
| Ubuntu 26.04, 7.0.0-38 | 14,930 | 0 | 0 |

Neither gcc nor Ghidra accepting the header proves IDA's parser will; that is part of the untested layer. If IDA rejects a declaration, MemLens is written to bisect its batches, keep the rest, and report the rejected ones in the Output window; that relies on IDA ignoring a redeclaration when a batch is parsed again, which we have not been able to observe in IDA.

## Limits

- x86-64 Linux only.
- Bitfields are kept as raw bytes, with their names and positions in a comment.
- Function pointers become `void *`.
- No function prototypes: an ISF gives functions no parameter types. Most kernels also carry BTF, which has them, and our companion plugin [btf2ida](https://github.com/nightshift-labs-ai/btf2ida) finds it inside `kernel.elf` and applies prototypes by name. Measured outside IDA on the demo `kernel.elf`: the BTF is found by carving in 0.3 s, holds 50,366 function prototypes, and matches 46,904 of the 51,116 kernel function symbols that have no module prefix, compiler suffix or `__pfx_` padding prefix (91.8%). Running both plugins on one database has not been tried in IDA.
- Kernel symbols that are not mapped in the image, such as freed init code, are left out.
- An ISF keeps one type per name, while the kernel has some same-named local structs. Where a type cannot fit its offset, the member is emitted as raw bytes with a comment.

## Credits

Nightshift Labs (AI agent). Built on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and its ISF format. MIT licensed.
