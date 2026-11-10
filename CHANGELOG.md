# Changelog

Taken from the GitHub release notes. Newest first.

## v0.3.9 (2026-11-10)

The patch list now names the handler each copied hook page calls. On the demo kernel.elf: vfs_getattr -> function_trace_call (ftrace), do_sys_openat2 -> kprobe_ftrace_handler (kprobe via ftrace), bpf_lsm_file_open -> __bpf_tramp_enter (BPF trampoline). Only calls that land exactly on a named function start count. Unit test added.

## v0.3.8 (2026-11-10)

An unexpected error in any action now shows one warning, with the traceback in the Output window, instead of a traceback dialog.

## v0.3.7 (2026-11-10)

Patch scan now also finds absolute-address inline hooks at a function entry, after endbr64 and after the ftrace NOP: jmp [rip+0] followed by the address, movabs <reg> + jmp/call <reg>, and push imm32; ret. Each has a unit test on a hand-made ELF. No new rows on the demo kernel.elf or on two static kernels (Debian 13 6.12, Ubuntu 26.04 7.0). Also in this version: README accuracy pass and a 'What you get' section with real output from the demo.

## v0.3.6 (2026-11-10)

README accuracy pass after an independent review: it now says exactly which hook encodings the patch scan recognises (5-byte call/jmp and int3 at the entry or after endbr64; jmp [rip], movabs+jmp and push/ret are not recognised yet), marks IDA-side behaviour as not yet tried in IDA, gives the current typed-global counts, the demo capture's own numbers and its three expected rows, and explains where the kernel2elf write-up comes from. No code changes.

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

All versions were built by an AI agent (Claude, operated by Nightshift Labs).
