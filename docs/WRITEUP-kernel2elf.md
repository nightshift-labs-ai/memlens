# linux.kernel2elf: a memory image as a disassemblable kernel

**Plugin:** `linux.kernel2elf` (Volatility 3, Linux, x86-64)
**Author:** built by an autonomous AI agent operating a small software business; the human owner is the contest entrant and signs the CLA.

## 1. The problem

After a memory acquisition, an analyst often wants to read kernel code as it was running: what a module does, or what a hook actually jumps to. Volatility answers questions about kernel state, and a disassembler answers questions about code, but there has been no direct way to move the running kernel from one to the other. The analyst dumps pieces by hand and loses symbols and addresses along the way.

## 2. What exists

- `linux.module_extract` recreates one module as an ELF from a given address. This plugin writes the whole kernel and all listed modules together, at their live addresses, under one symbol table, so calls between the kernel and a module resolve.
- `linux.tracing.ftrace`, `linux.check_syscall` and `linux.malware.modxview` read kernel structures to report hooks and hidden modules. The `patched` rows here use a different source: the code bytes at each function entry. The two views are complementary.
- Kallsyms importers for disassemblers name a kernel that is already loaded; they do not start from a memory image.

A GitHub repository search (name and description, November 2026) found no tool that writes a whole kernel from a Volatility image as a symbolled ELF. That search is not exhaustive.

## 3. Design

**One ELF.** Each mapped run of the kernel image and each module becomes a PROGBITS section and a PT_LOAD segment at its real virtual address. Pages that are not mapped are left out rather than zero-filled, so a gap stays a gap.

**Module regions, not one range.** Since Linux 6.4 a module's text, read-only data, ro_after_init and data are separate allocations in `module.mem[]`. Treating the base and the summed size as one range runs into whatever is mapped after the text, and misses the module's data. The plugin exports each region with its own permissions, and falls back to `core_layout` on older kernels.

**Symbols.** Kernel symbols come from the ISF, module symbols from each module's own symbol table, as `module.symbol`. A symbol is written only if it lands in exported memory.

**Patched entries.** The finished ELF is scanned for each function's first instruction. Hook code in memory no module owns is copied in as a `.hook` section and labelled, so the target of a BPF or ftrace trampoline can be read like the rest of the kernel.

## 4. Validation

Every sample is a QEMU guest captured by us; addresses differ per boot because of KASLR. `make_dist_k2e.sh` (in the package) regenerates all of this and stops on any failure.

| Sample | Modules | Symbols | Module symbols | `patched` rows |
|---|---|---|---|---|
| Debian 12, 6.1.0-54 | 85 | 151,384 | 30,700 | none |
| Debian 13, 6.12.115 | 82 | 236,521 | 42,391 | `bpf_lsm_file_open` |
| Debian 13, 6.12.115, hooks set | 69 | 233,305 | 39,173 | `bpf_lsm_file_open`, `do_sys_openat2`, `vfs_getattr` |
| Ubuntu 24.04, 6.8.0-147 | 61 | 267,563 | 27,131 | `__hid_bpf_tail_call` |
| Ubuntu 26.04, 7.0.0-38 | 72 | 316,618 | 37,167 | none |

Checks with tools independent of this code (`tests/check_elf.sh`, binutils only): no LOAD segment overlaps, all addresses are canonical, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues where those symbols are present.

On Debian 12, Debian 13 and Ubuntu 26.04, the ELF was also imported into Ghidra 12.2 headless. It loaded, and the same functions disassembled correctly.

Hook test: on the "hooks set" sample our script placed an ftrace filter on `vfs_getattr` and a kprobe on `do_sys_openat2` (`tests/vm/scenario_ftrace_d13.sh`, standard tracing only, no custom module). Both are reported. `bpf_lsm_file_open` and `__hid_bpf_tail_call` were not set by us; they have the pattern of BPF attachments, which we did not confirm separately.

False positives found and removed during testing, each with a unit test in `tests/test_patchscan.py`: ftrace's own trampolines, `call __fentry__` sites that were never converted, reads past the end of a shorter `sys_call_table`, and compiler suffixes such as `.constprop.0` mistaken for module symbols.

## 5. Limits

See `README-kernel2elf.md`. Mainly: x86-64 only, function entries only, and modules unlinked from the list are not exported. A `patched` row reports a rewritten entry, not malice.
