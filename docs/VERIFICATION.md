# What was verified

Part of the MemLens documentation; start with the [README](../README.md).

Memory images were captured from QEMU guests; addresses differ per boot because of KASLR.

| Kernel | Symbols in ELF | From modules | Loaded by Ghidra 12.2: functions disassembled at the right address, per-CPU data at the ELF address |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 152,142 | 30,700 | `linux_banner`, `nf_hook_slow`; `cpu0.current_task`, `cpu1.current_task`, `cpu0.runqueues` |
| Debian 13, 6.12.115 | 237,297 | 42,391 | `linux_banner`, `__x64_sys_read`, `nf_hook_slow`, `nf_tables.nft_do_chain`; `cpu0.pcpu_hot`, `cpu1.pcpu_hot`, `cpu0.runqueues` |
| Ubuntu 26.04, 7.0.0-38 | 317,512 | 37,167 | `linux_banner`, `nf_hook_slow`, `nf_tables.nft_do_chain`; `cpu0.current_task`, `cpu1.current_task`, `cpu0.runqueues` |

All three rows were re-measured on exports made with the current code (2026-11-11, per-CPU areas included) with `tests/ghidra/MemLensCheck.java` in Ghidra 12.2 headless (`-noanalysis`): Ghidra finds the per-CPU symbols at the same addresses as the ELF, inside their `.percpu.cpu<N>` sections (checked with `readelf`), and it lists 3 to 10 fewer symbols than the ELF holds (152,133, 237,287 and 317,509; not investigated).

Symbols whose address is not in exported memory are left out by design, so every symbol in the ELF points into a section. Module text, read-only data and data become separate sections with the right permissions, and LOAD segments never overlap (`tests/check_elf.sh`).

Checked with binutils and a short Python step, independently of this code (`tests/check_elf.sh`): canonical addresses in every segment, `linux_banner` reads back the true kernel version, and `__x64_sys_read`, `nf_hook_slow` and `nft_do_chain` disassemble to real function prologues where those symbols are present (`nf_tables` is not loaded in the demo capture, so the script reports it missing there).

Types are checked by compiling the generated header with gcc, asserting every struct size and member offset against the ISF, and compiling a declaration for every typed global (`tests/check_layout.py`):

| Kernel | Layout assertions | Global declarations | Result |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 59,662 | 62,340 | all pass |
| Debian 13, 6.12.115 | 67,392 | 79,316 | all pass |
| Ubuntu 24.04, 6.8.0-147 | 81,563 | 86,362 | all pass |
| Ubuntu 26.04, 7.0.0-38 | 89,321 | 123,349 | all pass |

Global declarations are every typed global in the ISF, compiled as `extern` declarations; fewer can be applied in IDA (Debian 13 demo: 33,500 plus 388 per-CPU variables, see [What you get](OUTPUT.md#what-you-get-real-output-from-the-demo-not-ida-screenshots)). Counts are from the current code. The gcc run was made on an earlier build that also declared 15 to 20 globals named like C++ keywords (`new`, `class`, ...), which are now skipped.

Ghidra's C parser was run over the same header (`tests/ghidra/MemLensCheck.java`), after replacing `__int128` with a 16-byte struct, which Ghidra's parser does not know:

| Kernel | Struct and union sizes compared with the ISF | Missing | Wrong size |
|---|---|---|---|
| Debian 12, 6.1.0-54 | 9,965 | 0 | 0 |
| Debian 13, 6.12.115 | 11,451 | 0 | 0 |
| Ubuntu 26.04, 7.0.0-38 | 14,930 | 0 | 0 |

Neither gcc nor Ghidra accepting the header proves IDA's parser will; that is part of the untested layer. If IDA rejects a declaration, MemLens is written to bisect its batches, keep the rest, and report the rejected ones in the Output window; that relies on IDA ignoring a redeclaration when a batch is parsed again, which we have not been able to observe in IDA.

The patch scan is tested without IDA: `python3 tests/test_patchscan.py` builds small ELFs with each hook pattern, including the cases that must stay quiet (ftrace's own trampolines, unconverted `__fentry__` calls, tail calls to the kernel's own functions, compiler clones). `python3 tests/test_demo_injection.py kernel.elf` plants a data pointer in `sys_call_table[0]`, `vfs_read` in `[62]` and an unmapped address in `[217]` in a copy of the demo `kernel.elf`; all three are reported and the function rows do not change. On five real captures (Debian 12, Debian 13 clean and with ftrace, kprobe and BPF hooks set, Ubuntu 24.04, Ubuntu 26.04) the hooks we set are reported and the clean Ubuntu 26.04 kernel reports none. `python3 tests/test_isf_formats.py` reads the same ISF in the four forms Volatility accepts (`.json`, `.json.xz`, `.json.gz`, `.json.bz2`), `python3 tests/test_findpatches_stub.py` checks, on fake IDA modules, that the patch list on a file that is not a kernel (a stripped `/bin/ls`, and a small unstripped program it compiles with `cc` when one is installed) gives a warning instead of an empty list, and `python3 tests/test_export_failure_stub.py` replays real Volatility 2.28.2 output (`tests/fixtures/vol-2.28.2`) through the export action on fake IDA modules with a fake `vol`: the dialog for each failure in [When the export fails](EXPORT.md#when-the-export-fails), Cancel during the export (no banner scan) and during the banner scan (with `MEMLENS_ISF` set to the demo ISF it also checks that ISF's banner). `python3 tests/test_hookchain.py [kernel.elf ...]` checks the hook chain decisions in `patchscan.py` (hooking instruction, hook page, handler, names) on hand-made ELFs (every hook form MemLens reports, also after `endbr64` and the ftrace NOP, `movabs` with r8-r15, `jmp [rip+X]`; trampolines packed next to each other; a syscall slot pointing at a hook page; a page shared by two functions, aliases, name collisions, a page with a real symbol, a first named call into the core kernel (shown as hook code: no handler, no owner), a module's function as the first named call (`module_hook_` names, also for a page two functions share; `bpf.` names and labels that start with a dot do not count)) and on real exports (it knows the demo, Debian 13 and Ubuntu 24.04 hooks; an export with no hooks or other hooks is skipped with a note), and `python3 tests/test_hookchain_stub.py [kernel.elf]` checks, on fake IDA modules, the calls the plugin makes (`add_cref`, `add_dref` and `set_name` arguments, the Handler and Owner columns, the Enter, Edit and Insert callbacks (`OnSelectLine`, `OnEditLine`, `OnInsertLine`), a second run that adds nothing, a page the user renamed or unnamed, a name IDA refuses, the ISF's `ftrace_ops.func` offset). `python3 tests/test_owner.py [kernel.elf ...]` checks the owner on hand-made ELFs laid out like the kernel's trampolines: ftrace_ops in kernel data, in a module's data behind `ftrace_ops_assist_func`, on the heap and in unexported module memory; the slot after `ret`, `ret; int3`, a bare `ret` or a jump to the return thunk; a `func` offset from an ISF; BPF trampolines with a JIT'ed program, a named one, the interpreter, a cgroup LSM shim, two programs, an unpatched `je`, and code that does not match; a module's function as the first named call; the kprobe owner from `.memlens.kprobes` (a tracefs event, a perf_event_open probe, a module's probe, hidden and post-only handlers, a probe at symbol+offset, a shared page, disabled probes, kretprobes, and old, garbage or malformed sections that give the old owner). It also checks real exports (the demo and Ubuntu 24.04 hooks, and on a fresh export that has the section the `memlens_kp` owner), and `patchscan.py --links` and `--isf`. `python3 tests/test_kernel2elf_bpf.py` checks the exporter's BPF names (sign-extended, none at a hook target, torn entries with a negative or huge size left out) and pages, on fake `volatility3` modules, and `python3 tests/test_kernel2elf_kprobes.py` its kprobe list (`.memlens.kprobes`: a tracefs event, a perf_event_open probe, a module's probe, an aggregate probe, `flags`, a tracefs `r:` event and a module's kretprobe, the Linux 6.12 and pre-5.4 layouts, a torn list and a torn aggregate ring, a name that ends just before an unmapped page), on fake `volatility3` modules and a fake memory layer.
