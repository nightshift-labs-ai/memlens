# linux.kernel2elf: a memory image as a disassemblable kernel

*A Volatility 3 plugin that writes a Linux kernel and its modules from a memory image as one ELF with symbols, and lists patched kernel functions.*

> In the MemLens repository: this is the write-up of the Volatility 3 plugin that MemLens runs for its export step, prepared for the Volatility plugin contest. For the IDA plugin, see the main README.

**Plugin:** `linux.kernel2elf` (Volatility 3, Linux, x86-64)
**Author:** built by an autonomous AI agent operating a small software business; if it is entered, the human owner is the entrant and signs the CLA.

## 1. Motivation: the problem

After a memory acquisition, an analyst often wants to read kernel code as it was running: what a module does, or what a hook actually jumps to. Volatility answers questions about kernel state, and a disassembler answers questions about code, but there has been no direct way to move the running kernel from one to the other. The analyst dumps pieces by hand and loses symbols and addresses along the way.

## 2. What exists

- `linux.module_extract` recreates one module as an ELF from a given address. This plugin writes the whole kernel and all listed modules together, at their live addresses, under one symbol table, so calls between the kernel and a module resolve.
- `linux.tracing.ftrace`, `linux.check_syscall` and `linux.malware.modxview` read kernel structures to report hooks and hidden modules. The `patched` rows here use a different source: the code bytes at each function entry. The two views are complementary: on the shipped `trace.elf`, `linux.tracing.ftrace` prints `-` as the hooked symbol for `function_trace_call` and `call_direct_funcs`, while the `patched` rows name `vfs_getattr` and `bpf_lsm_file_open`.
- Kallsyms importers for disassemblers name a kernel that is already loaded; they do not start from a memory image. `vmlinux-to-elf` builds a symbolled ELF from a kernel file, without modules or live state.
- Volatility 2's `linux_check_inline_kernel` already decodes the first instructions of selected kernel functions and flags jumps, calls and push-ret to unknown targets. `crash` can disassemble a vmcore given a matching vmlinux, and volshell can disassemble an address. What this plugin adds is Volatility 3 support, every symbolled function instead of a fixed set of pointers, and the hook code copied into one file that a disassembler can follow.

A GitHub repository search (name and description, November 2026) found no tool that writes a whole kernel from a Volatility image as a symbolled ELF. That search is not exhaustive.

## 3. Design

**One ELF.** Each mapped run of the kernel image and each module becomes a PROGBITS section and a PT_LOAD segment at its real virtual address. Pages that are not mapped are left out rather than zero-filled, so a gap stays a gap.

**Module regions, not one range.** Since Linux 6.4 a module's text, read-only data, ro_after_init and data are separate allocations in `module.mem[]`. Treating the base and the summed size as one range runs into whatever is mapped after the text, and misses the module's data. The plugin exports each region with its own permissions, and falls back to `core_layout` on older kernels.

**Symbols.** Kernel symbols come from the ISF, module symbols from each module's own symbol table, as `module.symbol`. A symbol is written only if it lands in exported memory.

**Per-CPU areas.** Each CPU's copy of the per-CPU variables is read through `__per_cpu_offset[cpu]` (for `nr_cpu_ids` CPUs, at most 256) and written as section `.percpu.cpu<N>`, with symbols `cpu<N>.<name>`. x86-64 kernels up to 6.x link the per-CPU section at address 0; Linux 7.0 links it at a kernel address, which moves with KASLR, and both layouts are handled. On every sample in the table, CPU 0's current task points to `init_task` and each CPU's `this_cpu_off` holds that CPU's own per-CPU offset. Variables per CPU: 6.1 379, 6.8 402, 6.12 388, 7.0 447. `--no-percpu` leaves the areas out.

**Patched entries.** The finished ELF is scanned for each function's first instruction. Hook code in memory no module owns is copied in as a `.hook` section and labelled, so the target of a BPF or ftrace trampoline can be read like the rest of the kernel.

## 4. Validation

Every sample is a QEMU guest captured by us; addresses differ per boot because of KASLR. The table was produced by `make_dist_k2e.sh`, which stops on any failure. A copy sits at the root of the Volatility contest package to document the steps; it needs our own memory images, so a reader cannot rerun it.

| Sample | Modules | Symbols | Module symbols | `patched` rows |
|---|---|---|---|---|
| Debian 12, 6.1.0-54 | 85 | 152,142 | 30,700 | none |
| Debian 13, 6.12.115 | 82 | 237,297 | 42,391 | `bpf_lsm_file_open` |
| Debian 13, 6.12.115, hooks set | 69 | 234,081 | 39,173 | `bpf_lsm_file_open`, `do_sys_openat2`, `vfs_getattr` |
| Ubuntu 24.04, 6.8.0-147 | 61 | 268,367 | 27,131 | `__hid_bpf_tail_call` |
| Ubuntu 26.04, 7.0.0-38 | 72 | 317,512 | 37,167 | none |

Checks with tools independent of this code (`tests/check_elf.sh`, binutils and a short Python step): no LOAD segment overlaps, all addresses are canonical, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues where those symbols are present.

On Debian 12, Debian 13 and Ubuntu 26.04, the ELF was also imported into Ghidra 12.2 headless. It loaded, and the same functions disassembled correctly.

Hook test: on the "hooks set" sample our script placed an ftrace filter on `vfs_getattr` and a kprobe on `do_sys_openat2` (`tests/vm/scenario_ftrace_d13.sh`, standard tracing only, no custom module). Both are reported. `bpf_lsm_file_open` and `__hid_bpf_tail_call` were not set by us; they have the pattern of BPF attachments, which we did not confirm separately.

False positives found and removed during testing, each with a unit test in `tests/test_patchscan.py`: ftrace's own trampolines, `call __fentry__` sites that were never converted, reads past the end of a shorter `sys_call_table`, and compiler suffixes such as `.constprop.0` mistaken for module symbols.

Planted-slot test (`tests/test_demo_injection.py <kernel.elf>`): in a copy of the Debian 13 export, a data pointer in `sys_call_table[0]`, `vfs_read` in `[62]` and an unmapped address in `[217]` are all reported, and the function rows do not change. Every slot inside the table's symbol size is checked, so one odd slot cannot hide later ones; zero padding is skipped.

## 5. Limits

See `README-kernel2elf.md`. Mainly: x86-64 only, function entries only, and modules unlinked from the list are not exported. A `patched` row reports a rewritten entry, not malice.

## 6. Why it should win

- **It joins two tools that did not connect.** Volatility knows the state of a running kernel and a disassembler reads code. One command turns the first into input for the second, with live addresses and symbols, so a call from a module into the kernel resolves instead of pointing at nothing.
- **It is useful beyond one question.** The same ELF opens in objdump, Ghidra or other ELF tools, so an analyst can follow a suspicious module or hook with the tools they already use.
- **It adds an independent view of hooks.** The `patched` rows come from the code bytes at function entries, not from the kernel structures other plugins read, and hook code that no module owns is copied in where it can be read.
- **It gets the awkward parts right.** Since Linux 6.4 a module is several separate allocations. Each region is exported with its own permissions, and older kernels fall back to `core_layout`.
- **It is verified with tools that share none of its code.** Five samples on four kernel versions pass the independent checks: no overlapping segments, the true kernel banner, real function prologues. Ghidra 12.2 headless imported three of them. Four classes of false positive found in testing are removed and pinned by unit tests.
- **It says what it cannot do.** x86-64 only, function entries only, modules unlinked from the list are not exported, and a `patched` row reports a rewritten entry rather than malice.
