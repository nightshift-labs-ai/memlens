# Changelog

Taken from the GitHub release notes. Newest first.

## v0.3.24 (2026-11-12)

- **Per-CPU typing no longer stops at a missing CPU.** The exporter keeps real CPU numbers and leaves out a CPU whose per-CPU area is not in the memory image, so a capture can have `.percpu.cpu0` and `.percpu.cpu2` without `.percpu.cpu1`; Apply kernel types used to stop at the first gap. It now takes the CPU numbers from the `.percpu.cpu<N>` sections in the database (the old cpu0, cpu1, ... probe is kept for databases without such sections). Found by a judge-style review; tested with fake IDA modules only.
- README: the Ghidra column of the verification table was re-measured on exports from the current code for all three kernels (it was measured on an earlier per-CPU build for two of them), now including per-CPU symbols.

## v0.3.23 (2026-11-11)

- **The ELF entry point is kernel text again.** Since v0.3.20 it was the lowest section, which is now CPU 0's per-CPU data (`cpu0.fixed_percpu_data`); IDA would have queued data as code there. It is now the first executable section (`_text`), as before; `--no-percpu` output is unchanged.
- **Apply kernel types never retypes code as data.** The ISF can declare a variable with the same name as a kernel function (on the demo kernel: 78 names, among them `schedule`, `strlen`, `capable`); those addresses lie in executable segments and are now left alone and counted in the Output window. Found by a judge-style review.
- Demo data re-exported with v0.3.23 (only the ELF entry field differs from the v0.3.20 file); README: 33,500 globals typed on the demo (was 33,578, which included the 78 code names).
- Headless runner: a kernel file from disk exits 0 with "patch list skipped" (the v0.3.21 notes said 1). Stray `sha.txt` (a build note) removed from the repository.

## v0.3.22 (2026-11-11)

- **Per-CPU typing no longer depends on how IDA stores `.` in names.** If the loader keeps `cpu0.runqueues` as `cpu0_runqueues`, **Apply kernel types** now finds that form too, but only when the symbol lies in that CPU's `.percpu.cpu<N>` section, so a real kernel symbol of the same name elsewhere is never retyped. Stub test cases for both. (We have not seen which form IDA uses: not yet run in real IDA.)

## v0.3.21 (2026-11-11)

- **Headless runner for idalib** (IDA 9.0+): `python3 tools/memlens_headless.py kernel.elf <isf> [--no-analysis] [--any-kernel]` applies the types, comments the patched entries, prints the report and the patch list, and saves the database, using the plugin's own functions. Exit codes: 0 done, 1 IDA could not open the file (or it is not a MemLens ELF), 2 no idalib, 3 the ISF is for another kernel (nothing imported). New `tests/test_headless_stub.py` (fake `idapro` and `ida_*` modules). Not yet run with a real idalib.

## v0.3.20 (2026-11-11)

- **Per-CPU variables are exported, one copy per CPU.** Until now the per-CPU variables (`runqueues`, the current task, `this_cpu_off`, ...) were missing from `kernel.elf`: their ISF values are offsets, not addresses. The exporter now reads `__per_cpu_offset[]` and writes each CPU's live area as section `.percpu.cpu<N>` with symbols `cpu<N>.<name>`; **Apply kernel types** types every copy. Both layouts are handled: per-CPU linked at 0 (x86-64 up to 6.x) and at a KASLR-moved kernel address (Linux 7.0). Checked on all five captures (6.1, 6.8, 6.12 twice, 7.0): CPU 0's current task points to `init_task`, each CPU's `this_cpu_off` holds that CPU's own per-CPU offset, the other Volatility rows are unchanged, Ghidra 12.2 loads the demo ELF. Demo `kernel.elf`: 234,081 symbols (388 variables x 2 CPUs added).
- Absolute assembler constants that the ISF lists with small values (`L4_PAGE_OFFSET` = 273, `vector`, `pgtno`, ...) are not taken for per-CPU variables; on a per-CPU layout linked at 0, only `fixed_percpu_data` is taken at offset 0.
- `--no-percpu` writes the old layout, byte for byte. Visible change otherwise: the per-CPU areas sit below the kernel image, so Ghidra shows the lowest one as the image base.
- Demo data re-exported with v0.3.20 (new `SHA256SUMS.txt`).

## v0.3.19 (2026-11-11)

- **The plugin now loads on a Python built without `_lzma`.** `isf2c` imported `lzma` at load time, so on such a Python every MemLens action was missing. The import now happens only when a `.json.xz` ISF is read; there, IDA shows one warning ("this Python has no lzma module: decompress the ISF first (xz -dk ...) and choose the .json file") and `isf2c.py` prints one line and exits 1. Plain `.json` ISFs work as before.
- New `tests/test_no_lzma.py` blocks `lzma` and runs the whole stub test, the `.xz` warning and the command line. The header generated from the demo ISF is byte-identical to v0.3.18.

## Demo data update (2026-11-11, no code change)

- `memlens-demo-debian13.zip` re-exported with v0.3.18: linker markers such as `_stext` are now untyped symbols in the demo `kernel.elf` too (the old file predated that fix; only those symbol-type bytes changed). `expected-patched-functions.txt` names the hook handlers; `SHA256SUMS.txt` added.
- README: new "Export it yourself" section. The demo's source memory image (`trace.elf.xz`, 80 MB) is public; exporting it gives a byte-identical `kernel.elf` (checked from a fresh `pip install volatility3`, Volatility 3 2.28.2).

## v0.3.18 (2026-11-11)

Two more hook patterns from the judge-style review, plus the judge's injection as a permanent test:

- **A `call`/`jmp` rel32 right after the ftrace NOP** is now checked. That spot holds ordinary compiler code, so it is reported only when the compiler could not have produced it: a target with no symbol, or a kernel function jumping into a module.
- **`jmp`/`call [rip+disp32]` through a pointer in memory** (at the entry or after the ftrace NOP): the pointer is read from the image and reported under the same rule. Calls through a pointer to an ordinary kernel function are not reported.
- **`tests/test_demo_injection.py`**: plants a data pointer in `sys_call_table[0]`, `vfs_read` in `[62]` and an unmapped address in `[217]` in a copy of the demo `kernel.elf`; all 3 must be reported and the function rows must not change. Skipped when the demo file is not given.

Checked on 5 real captures (Debian 12, Debian 13 clean and with live ftrace/kprobe/BPF hooks, Ubuntu 24.04, Ubuntu 26.04): the patched rows are the same as before (no new false positives); the planted hooks are still found and the clean Ubuntu 26.04 kernel reports none. Unit tests cover each new pattern, including the cases that must stay quiet.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.17 (2026-11-11)

Syscall table scan no longer stops at the first odd slot (judge-style review finding).

Before, the first `sys_call_table` slot that was not a code pointer ended the scan, so a planted data pointer in an early slot hid every later hook. Now, when the table has a symbol size (it always does in a kernel2elf export), every slot inside it is checked: zero padding is skipped, a data pointer is reported as "syscall entry is not a code pointer", and kernel code or unmapped memory that is not a syscall handler is reported as before. Without a size the old rule stays (the first non-code slot ends the table).

Checked: new unit tests (data pointer in slot 0 followed by a real hook and an unmapped target: all reported), and the real Debian 13 capture still reports no syscall rows (inside the symbol size its table holds only handlers and one zero padding slot).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.16 (2026-11-11)

Two honesty fixes from the judge-style review:

- **Typed-global numbers restated.** The README said 79,316 typed globals for the Debian 13 kernel. That is how many the ISF declares (all compile with gcc), not how many can be typed: only globals whose symbol is in the ELF can be. On the demo `kernel.elf` that is 33,578. The other 45,738 have address 0 in the ISF (45,345), are per-CPU offsets (390) or lie outside exported memory (3). The README and the verification table now say so, and **Apply kernel types** prints "typed N of the M globals the ISF declares; F failed; K have no symbol in this database" in the Output window.
- **linux.kernel2elf `written` row** now names the file actually written. It was printed before Volatility settled the name, so a second run into the same folder said `kernel.elf` while the file was `kernel-1.elf`. Checked by running the plugin twice into one folder on a Debian 13 capture: the rows now say `kernel.elf`, then `kernel-1.elf`.

Tests: stub test (new assertion for the counts), patchscan tests, IDA API names 47 checked, 0 missing.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.15 (2026-11-11)

Export reports the file Volatility really wrote. When kernel.elf already exists next to the image, Volatility writes kernel-1.elf, but its "written" row is printed before the name is settled. The plugin now compares the folder before and after the run, and names the new .elf. Checked with the helper on a folder that already holds kernel.elf. The Volatility row itself is unchanged (still to fix in kernel2elf).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.14 (2026-11-11)

Small fixes from a fresh judge-style review that re-ran the README (all demo rows, objdump excerpts and header numbers reproduced):

- `python3 patchscan.py` with no argument prints usage instead of an IndexError traceback.
- ida-plugin.json description (shown on plugins.hex-rays.com) now says "Not yet run in real IDA.", like the README.
- README: "Enter should jump to the function" (design intent, not observed in IDA).
- The bad-ELF warning no longer doubles '%' (IDAPython wraps warning() as "%s").
- tests/check_ida_api.py also checks ida_bytes names (47 names, 0 missing against the IDA SDK).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.13 (2026-11-10)

Fixes from a review of the exporter:

- Linker boundary labels such as __softirqentry_text_end are no longer typed as functions, so they do not take the place of the real function name at the same address.
- The written row now counts the symbols actually in the ELF, and section, kernel and module rows print canonical addresses.
- A module symbol whose name begins like a compiler suffix (evil.cold_path) now counts as a module, and compiler clones such as foo.isra.0 are also checked for jumps into modules.
- patchscan says how many functions it scanned and warns when there were none, so an empty list cannot be mistaken for clean.
- tests/check_elf.sh no longer needs gawk.
- The write-up names the closest prior art (Volatility 2 linux_check_inline_kernel, crash, volshell, vmlinux-to-elf).

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.12 (2026-11-10)

Applying types now compares the kernel banner in the ISF with the one in the database. If they differ, MemLens shows both and asks before importing anything, because types from another kernel can be silently wrong. If either banner is unavailable, the import goes ahead as before.

Checked outside IDA against the demo kernel.elf: its own ISF matches, and the ISFs of three other kernels do not. The prompt itself is covered only by the stub test.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.11 (2026-11-10)

- The patch scan reports a clear error on an empty or truncated file instead of a traceback.
- The BTF coverage figure is now stated against real functions: 46,904 of 51,116 kernel function symbols with no module prefix, compiler suffix or __pfx_ padding prefix (91.8%).
- Install uses pipx for Volatility 3, because a plain pip install fails on current Debian and Ubuntu, and notes that the plugin index can lag behind releases.
- The verification note says that nf_tables is not loaded in the demo capture.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.10 (2026-11-10)

The patch list now sees hooks on functions the kernel sealed for IBT. On IBT kernels, a function that is never called indirectly has its endbr64 overwritten with a 4-byte NOP, and ftrace, kprobes and BPF trampolines patch the instruction after it. Those sites were skipped before; 12,060 function entries in the demo kernel have this form, including vfs_read and vfs_write. Both NOP encodings are handled, with unit tests.

Also in this release:
- The scan refuses non-x86-64 ELFs instead of decoding them as x86, and the IDA action refuses kernel files from disk, whose unapplied alternatives looked like hooks.
- Comments the scan adds no longer replace an existing comment at that address.
- A hook page near the end of a segment still gets its handler label.

Checked on five captured Debian and Ubuntu kernels: the reported rows are the same as before, and the clean Ubuntu 7.0 capture still reports none.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

## v0.3.9 (2026-11-10)

The patch list now names the handler each copied hook page calls. On the demo kernel.elf: vfs_getattr -> function_trace_call (ftrace), do_sys_openat2 -> kprobe_ftrace_handler (kprobe via ftrace), bpf_lsm_file_open -> __bpf_tramp_enter (BPF trampoline). Only calls that land exactly on a named function start count. Unit test added.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.3.8 (2026-11-10)

An unexpected error in any action now shows one warning, with the traceback in the Output window, instead of a traceback dialog.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.3.7 (2026-11-10)

Patch scan now also finds absolute-address inline hooks at a function entry, after endbr64 and after the ftrace NOP: jmp [rip+0] followed by the address, movabs <reg> + jmp/call <reg>, and push imm32; ret. Each has a unit test on a hand-made ELF. No new rows on the demo kernel.elf or on two static kernels (Debian 13 6.12, Ubuntu 26.04 7.0). Also in this version: README accuracy pass and a 'What you get' section with real output from the demo.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.3.6 (2026-11-10)

README accuracy pass after an independent review: it now says exactly which hook encodings the patch scan recognises (5-byte call/jmp and int3 at the entry or after endbr64; jmp [rip], movabs+jmp and push/ret are not recognised yet), marks IDA-side behaviour as not yet tried in IDA, gives the current typed-global counts, the demo capture's own numbers and its three expected rows, and explains where the kernel2elf write-up comes from. No code changes.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run inside real IDA.

## v0.3.5 (2026-11-10)

The success dialog after an export now escapes % in its text. ida_kernwin.info is a printf-style function in IDAPython (only msg, warning and error are wrapped), so an output folder name containing % could print garbage. Found by a review of every IDAPython call against the IDA 9.5 SDK sources (no load or API problems found otherwise). Not yet run inside real IDA; see the README. Built by an AI agent (Nightshift Labs).

## v0.3.4 (2026-11-09)

Renames struct member names that IDA's parser may treat as calling-model words. Not yet run inside real IDA; see the README. Built by an AI agent.

## v0.3.3 (2026-11-09)

Kernel export now uses the module listing Volatility supports (Lsmod.list_modules is deprecated and due for removal). Output is unchanged on the two kernels re-tested (Debian 12 and Debian 13).

Still not run in real IDA; see the README.

## v0.3.2 (2026-11-09)

Checked every IDAPython call against the official IDA SDK sources and fixed what that found: file dialog filter syntax, a message if a menu entry cannot be added, more IDA type keywords renamed, a clear warning on non-ELF input.

Still not run inside real IDA: see README.

## v0.3.1 (2026-11-09)

The Volatility plugin now lists patched functions directly. Removes false positives seen on clean kernels: ftrace's own trampolines, unconverted __fentry__ call sites, reads past the end of sys_call_table, and compiler suffixes such as .constprop.0 taken for module symbols.

Still not run inside real IDA: see README.

## v0.3.0 (2026-11-09)

First public release. Linux memory image to symbolled ELF and C types for IDA, plus a list of patched kernel functions. Pure Python: the source archive is the plugin archive.

Not yet run inside real IDA: see README, What was verified.

Built by an AI agent (Claude, operated by Nightshift Labs).
