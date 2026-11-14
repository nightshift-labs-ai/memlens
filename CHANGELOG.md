# Changelog

Taken from the GitHub release notes. Newest first.

## Unreleased

- Supported IDA versions: 9.1 or later (`ida-plugin.json` `idaVersions` `>=9.1`; docs/USAGE.md and the headless runner's messages say the same). The IDA names are checked against the IDA 9.1 to 9.4 stubs and the 9.5 SDK's API list, so 9.0 was never checked; same rule as the sister plugins btf2ida, kflow and CFIScope. hcli no longer offers this version to IDA 9.0.
- New `tools/find_isf.py <image | banner>`: finds a ready-made ISF for an image in the community index (Abyss-W4tcher/volatility3-symbols `banners_plain.json`) and prints the URL and a `curl -LO` line, or the dwarf2json line and the debug package on a miss; the network only with `--download`. Exit status 0 when an ISF is found, 1 when none is, 2 on an error (unreadable index, failed download, compressed image, unknown option) with a message instead of a traceback; `--download` writes to a `.part` file and keeps it only when it reads as an index, so an interrupted download leaves no broken cache; only `Linux version <n>.<n>.<n>...` counts as a banner (Volatility's rule), so other text that starts with "Linux version" is not listed. Tested by `tests/test_find_isf.py` (no network). The export-failure dialog (no ISF, or the wrong one) adds that ISF's URL from the cached index, or says the image's lines are not in it, or names the helper. The dialog says when the index was downloaded, names the line when the hit is not the image's most frequent one (it may be a copy from an earlier boot), never offers the ISF that just failed, and quotes the helper's path (a Windows plugin folder has a space).
- New `tests/run_all.py`: runs every test one after another and prints a pass / skip / fail table; exit status 1 when one fails, 2 on an unknown argument. Each test gets 600 seconds (a hung test is a FAIL). With the demo `kernel.elf` (`MEMLENS_DEMO_ELF`) it also sets `MEMLENS_ISF` to the demo zip's ISF next to it, so the export-failure test checks the real ISF too: 15 passed, 0 skipped. Checked by `tests/check_run_all.py`.
- **kprobe owner from the kernel's kprobe list** (judge s178 item 5). The exporter walks `kprobe_table` (every offset from the ISF; an aggregate probe is replaced by the probes on its list) and writes the registered kprobes as JSON into `.memlens.kprobes`, a section that is not loaded; for a probe whose `pre_handler` is `kprobe_dispatcher` it reads the trace_kprobe's event name (`tp.event->call.name`). The Owner of a kprobe hook page is then the probe at the patched instruction: on a fresh export of the demo image (Volatility 2.28.2) `kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)` instead of `kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)`, the only `patchscan.py --links` line that changes (xrefs unchanged), and two exports give the same SHA-256. A module's probe reads `<module>.<pre_handler> (kprobe pre_handler)`, a probe perf_event_open made says it is not a tracefs event, and a page several probes share lists each (hand-made ELFs and fake `volatility3` only: `tests/test_owner.py`, `tests/test_kernel2elf_kprobes.py`; 12 mutants of the new code fail them). Exports without the section (the demo `kernel.elf`, v0.3.28 and older) give the same output as before, byte for byte. Not run in real IDA.
- kprobe owner: a kretprobe is named by its own handler, not by the kernel helper `pre_handler_kretprobe` that every kretprobe has as `pre_handler`. The exporter also writes the kretprobe's `handler`; a tracefs `r:` event reads `kretprobe <event> on <function> (tracefs kretprobe event; handler kretprobe_dispatcher)` and a module's kretprobe `<module>.<handler> (kretprobe handler)` (review s179 MINOR 1; kernel facts checked in Linux 6.12 `kernel/kprobes.c` and `kernel/trace/trace_kprobe.c`; hand-made ELFs and fake `volatility3` only). A kretprobe without a handler but with an `entry_handler` is named by its entry_handler (`evilmod.kp_ret (kretprobe entry_handler)`).
- kprobe owner: a disabled probe (for example a tracefs event that is defined but not enabled) no longer comes first in the Owner. The exporter now writes each probe's `flags`; when an enabled probe sits at the same instruction the disabled one is left out, so the Owner and Jump to owner name the enabled probe's handler. When all probes there are disabled, each reads `(disabled)`. Exports without `flags` give the same output as before (review s179 MINOR 2; hand-made ELFs and fake `volatility3` only).

## v0.3.29 (2026-11-17)

- README: a shorter front door (6,105 to 1,760 words: what it does, Status, Install, Try it, a short real before/after from the demo, Usage, Limits); the full demo output and Details moved to `docs/OUTPUT.md`, Usage in full, Without IDA and Headless to `docs/USAGE.md`, When the export fails and An ISF for your own image to `docs/EXPORT.md` (the README keeps the "An ISF for your own image" heading, which the export dialog names, with a link), What was verified to `docs/VERIFICATION.md` and the full Limits to `docs/LIMITS.md`; the moved text is unchanged apart from links and heading levels, and the README adds short summaries that link to it. `ida-plugin.json`: the keyword `rootkit` is dropped.

## v0.3.28 (2026-11-16)

- **Who hooked it: an Owner for a copied hook page when the memory shows it.** For an ftrace trampoline MemLens reads the `ftrace_ops` pointer the trampoline loads (stored right after its `ret`) and that ops' `func`. On the demo `kernel.elf` that gives `function_trace_call (ftrace_ops global_ops)` and `kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)`. It also names a module's callback when the trampoline calls `ftrace_ops_assist_func` (ops flagged RECURSION or RCU), tested on hand-made ELFs only: `evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)`. Ops outside the ELF are shown by address (`no symbol: heap`).
- For a BPF trampoline the owner is the program, the call right after `__bpf_prog_enter*`: `BPF program at 0xffffffffc0004664` on the demo `kernel.elf`, `BPF program at 0xffffffffc0043958` on an Ubuntu 24.04 export. Only a BPF name or an address with no symbol is called a BPF program. A kernel function in that place is labelled for what it is: the interpreter (`__bpf_prog_run32 (BPF interpreter: the program is not JIT-compiled)`) or the cgroup LSM shim (`__cgroup_bpf_run_lsm_current (cgroup LSM shim: runs each cgroup's programs, not named here)`); any other function reads `<name> (called by the BPF trampoline)`. Tested on hand-made ELFs only.
- **Hook pages with no ftrace, kprobe or BPF role.** When a copied hook page's first named call is a module's function (`module.symbol`), the page is a module callback: the Handler column reads `evilmod.fh_sys_kill (module callback)`, and so does the Owner column unless the page is an ftrace trampoline that calls the callback itself (its Owner still comes from its `ftrace_ops`); Jump to handler goes there, the page is renamed `module_hook_<hooked function>` (`module_hook___x64_sys_kill`; `module_hook_<address>` when several functions share it), and the patch list labels it `(calls evilmod.fh_sys_kill, module callback)`. A first call into the core kernel (`_printk`, `kfree`, a retpoline thunk) on a page that loads no `ftrace_ops` is a helper the hook code uses: no owner, the Handler column reads `(hook code; first call: _printk)` instead of presenting `_printk` as the handler, and Jump to handler says no handler is known instead of jumping there; the xref of that call stays, since it repeats a real `call`. An ftrace trampoline whose callback is another kernel function (a livepatch's `klp_ftrace_handler`) is labelled ftrace. In v0.3.27 any first named call was shown as the handler and such pages kept their `memlens_target_` label. Tested on hand-made ELFs only; the demo `kernel.elf` has no such page, so this change leaves its `patchscan.py --links` output (3 rows, 11 xrefs, 3 renames, 3 owners) byte for byte as it was.
- Only a module's own function makes a page a module callback: the exporter's BPF names (`bpf.bpf_prog_<tag>_<name>`) and core-kernel labels that start with a dot (`.E_copy`) contain a dot but are not module functions, so a page whose first named call is one of them gets no `module_hook_` name and no module-callback Owner; it is handled like a first call into the core kernel above (hook code, or ftrace when the page loads an `ftrace_ops`).
- `patchscan.py --links` prints one `owner` line per hook page that has an owner, and the xrefs that lead to the owner (demo: 11 xrefs, was 6). `--isf <isf>` reads the offset of `ftrace_ops.func` from the ISF; without it the offset is 0, as in the Linux 6.1, 6.8, 6.12 and 7.0 ISFs we checked. The plain patch list (without `--links`) has no owner lines.
- IDA: an Owner column in **Show patched kernel functions**, and the list's Insert command (**Jump to owner**) jumps there. MemLens adds user data xrefs from the trampoline's ops slot to the ops and from its `func` to the callback, and a code xref to the BPF program. Apply kernel types records the ISF's `ftrace_ops.func` offset for this. Checked with fake IDA modules only: on the demo 7 `add_cref`, 4 `add_dref`, and nothing on a second run. The 54 `ida_*`/`idc` names are all in the IDA 9.1 to 9.5 stubs.
- IDA: running **Show patched kernel functions** on a database an older MemLens annotated replaces an older MemLens line that the new line extends, instead of keeping both: the new line starts with the old one, less a final `)` if there is one, and goes on with a comma or a space (`(calls evilmod.fh_sys_kill)` at the entry becomes `(calls evilmod.fh_sys_kill, module callback)`, and the page's `first named call: evilmod.fh_sys_kill` gains `(module callback)`), or it starts with the whole old line and goes on with `;` (a v0.3.27 page line that already ended with a role and now gains `; owner: ...`, as on the demo's ftrace, kprobe and BPF pages). A line that only shares the start of the new one stays, and so does every other line, empty lines included. Checked with fake IDA modules only (`tests/test_plugin_stub.py`).
- Exporter: the BPF names Volatility's `Kallsyms` API lists (`bpf.bpf_prog_<tag>_<name>`; trampoline and dispatcher names too), plus the pages that hold them. A name at a hook target is left out so that page stays a copied hook page: on the Debian 13 capture the kernel lists one trampoline, `bpf_trampoline_6442509381`, exactly at `bpf_lsm_file_open`'s hook target, and none of our exports has a trampoline or dispatcher name. A fresh export of the demo image names its program `bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems`: 14 BPF names, 234,095 symbols instead of 234,081, the same 3 patched rows. The exporter leaves out Volatility's ftrace names, because those include stale names of freed module init code. A BPF name whose size is negative or larger than 64 MB (a torn entry in a smeared capture) is left out with a warning, so it cannot stop the export; a BPF entry Volatility gives no name (a program without a name on kernels before 5.8) gets no symbol rather than `bpf.None`; on 5.8 and later such a program is listed as `bpf.bpf_prog_<tag>`. The demo zip still holds the v0.3.23 export.
- Export from IDA: when Volatility finishes but the ELF is not a usable kernel export (for example `.text: 0 bytes` for a file that is not a memory image), MemLens now removes the file Volatility just wrote and says so; a file that was in the folder before the export is never touched.
- Export from IDA: when MemLens cannot list the output folder before or after the export, it treats the listing as unknown, not as an empty folder: the file name comes from Volatility's `written` row, and an unusable export is not removed; the dialog says MemLens could not list the folder to check that the file is new, left it in place, and that it should not be opened. A failed listing no longer makes every `.elf` file already in the folder look new. Stub test with a missing folder (`tests/test_plugin_stub.py`).
- Headless: the README gives the path of `tools/memlens_headless.py` after `hcli plugin install memlens` (`$IDAUSR/plugins/memlens`, by default `~/.idapro/plugins/memlens`).
- Tests: `tests/check_ida_api.py` without its argument prints its usage instead of a traceback; `tests/test_export_failure_stub.py` checks the demo ISF's banner only when `MEMLENS_ISF` names that file (before, it also looked at a fixed path on the developer's machine).

## v0.3.27 (2026-11-15)

- **Show patched kernel functions links the hook chain** (patched entry -> hook page -> handler). For each hooked entry it adds a code cross-reference from the hooking instruction to its target (`ida_xref.add_cref` with `fl_CN` for a call, `fl_JN` for a jump, both `XREF_USER` so IDA's reanalysis keeps them; for a `movabs` hook from its `jmp`/`call reg`, for `push imm32; ret` from the `ret`), and one from each copied hook page's first named call to that handler. Each copied hook page whose handler has a known role is renamed: `ftrace_tramp_`, `kprobe_ftrace_tramp_` or `bpf_tramp_` plus the function when exactly one entry leads there (`ftrace_tramp_vfs_getattr`), or plus the page's address when several share it; names use only `A-Z a-z 0-9 _` and are unique. A page with a real symbol at its address, a page whose handler is unknown, and a page that has another real name in the database (for example one you gave it) are not renamed; the exporter's `memlens_target_<address>` label stays in a comment at the page. What MemLens added is recorded in the database (netnode `$ memlens.hooks`), so running the action again adds no xref, renames nothing, and does not put back an xref or name the user removed. The list has a new Handler column; Enter still jumps to the entry, and the list's Edit command, captioned "Jump to handler" (usually Ctrl+E in IDA; not checked in IDA), jumps to the handler. A syscall slot that points at a copied hook page shows that page's name and handler as well. The handler search in a copied page stops at the next symbol, so trampolines packed next to each other do not get each other's handler. If adding the chain fails, the list is still shown and the traceback goes to the Output window, which says that xrefs or names added before the error are not recorded in the database. When the input file is missing and you pick a kernel.elf whose SHA-256 is not the one the database stored, MemLens asks before writing anything (default No). The headless runner applies the same chain. `python3 patchscan.py --links kernel.elf` prints the xrefs and renames without IDA. Measured on the demo `kernel.elf` and the Debian 13 hooks capture: 3 patched entries, 6 xrefs (3 entry to page, 3 page to handler) and 3 pages renamed in each (`ftrace_tramp_vfs_getattr`, `kprobe_ftrace_tramp_do_sys_openat2`, `bpf_tramp_bpf_lsm_file_open`), and no `add_cref` or `set_name` call on a second run; an Ubuntu 24.04 capture: 1 entry, 2 xrefs, `bpf_tramp___hid_bpf_tail_call`. No capture we have shares one hook page between functions; that case is tested on hand-made ELFs only. The decisions are pure functions in `patchscan.py` (`tests/test_hookchain.py`: hand-made ELFs and real exports); the IDA calls were checked only with fake `ida_*` modules (`tests/test_hookchain_stub.py`: recorded `add_cref` and `set_name` arguments, columns, a second run, a page the user renamed or unnamed, a name IDA refuses, a picked kernel.elf on a database with no stored SHA-256, a picked file with `%` in its name, Esc on the SHA-256 question, the record failing to save after xrefs were added), not in IDA. 51 mutants of the new code were all caught by these tests and `tests/test_headless_stub.py`, and so were 4 more that the review found survived before its tests were added. The 52 `ida_*` / `idc` names MemLens now uses are all in the IDA 9.1 to 9.5 stubs (PyPI `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11 and 0.0.12, `tests/check_ida_names.py`), and `tests/check_ida_api.py` also covers `ida_name`, `ida_netnode` and `ida_xref` (69 names, 0 missing against the IDAPython sources).
- README front door: a measured before/after (the demo's `trace.elf`, a 1 GB ELF core with 5 `LOAD` segments at physical addresses and no symbol table, versus `kernel.elf` with 234,081 symbols and the `vfs_getattr` -> hook page -> `function_trace_call` chain as an `objdump` excerpt), a mermaid diagram of the flow, five short bullets; the full text moved to a new "Details" section; the duplicate index-lag sentence removed; Status says IDA 9.1 to 9.5 (the 52 `ida_*` / `idc` names are in the `idapro` 0.0.5, 0.0.7, 0.0.9, 0.0.11 and 0.0.12 stubs).
- **A failed export says which kernel the image holds, or that it holds none.** Volatility 2.28.2 prints byte-identical output for a wrong ISF, for no ISF and for a file that is not a memory image (recorded: the demo `trace.elf` with a Debian 12 ISF and with no ISF, the demo `kernel.elf` with the Debian 12 ISF, 50 MiB of random bytes with and without the right ISF), and with an ISF chosen the dialog always said the ISF was probably built for another kernel, also for the random bytes. After that error MemLens now runs Volatility's `banners.Banners` on the image (through the same cancellable runner; not run when the export was cancelled; it reads the whole image, about 6 to 20 s for the 1 GB demo image here, depending on load and on whether the file is already in the OS cache; Cancel stops it and the dialog still shows Volatility's error) and reads the ISF's own `linux_banner` (no Volatility call). No `Linux version` line: "Volatility found no Linux kernel in this file", with the formats Volatility 2.28.2 reads (taken from its layer list and its file opener, which also decompresses xz, gzip and bzip2 copies; a VMware `.vmem` without its `.vmss` or `.vmsn` is read as a raw image). Otherwise the dialog shows `ISF: <its line>` next to `Image: <line>` for up to 3 different lines of the image, most frequent first (the demo image has 4, 3 of them different), and says whether the ISF's line is among them; it never says which line is the running kernel. When it is, MemLens also looks for the ISF's line in the image file as the kernel stores it (followed by a newline and a NUL byte, the exact bytes Volatility matches; at most one more read of the file, 0.1 to 5 s for the 1 GB demo image here, cancellable): banners.Banners cuts each line at the NUL and also lists copies such as the systemd journal's `MESSAGE=<line>`, which Volatility never matches. Found: the ISF fits and Volatility failed for another reason. Not found: the ISF was built for another kernel and its line is only a copy, listed and marked `(the ISF's, only a copy)` even when it is not among the 3 most frequent lines. A compressed image (xz, gzip, bzip2, AVML, zip) or Cancel: both causes are named, no verdict. Found by a code review that planted a journal copy of the Debian 12 line in a LiME copy of the demo image: with the Debian 12 ISF the first version of this change said the ISF fits; it now says it was built for another kernel (real Volatility 2.28.2 through the plugin code on fake IDA modules; recorded in `tests/fixtures/vol-2.28.2`). Without an ISF it shows the image's lines and points to the README section "An ISF for your own image". An ELF file that is not a core dump (the demo `kernel.elf` is ELF type EXEC) is reported first as not a memory image, with the advice to open a kernel file in IDA directly and use Apply kernel types, and no banner scan; the first version of this change listed `kernel.elf`'s kernel lines as the image's and asked for the ISF of that kernel, with which Volatility then exits 0 with an empty ELF (found by a code review; real Volatility 2.28.2 with the Debian 12 ISF, through the plugin code on fake IDA modules). A file shorter than its own ELF or LiME headers say (end of the last `PT_LOAD`, or the chain of LiME range headers) is reported first as probably an incomplete copy, with no banner scan: banners.Banners silently misses lines near the end of a cut file, and with the right ISF the first 125 MB of the demo `trace.elf` got "built for another kernel" and the first 110 MB "no Linux kernel in this file" from the first version of this change (found by a code review; real Volatility 2.28.2 on the first 110 MB and 125 MB of `trace.elf` and 125 MB of its LiME copy, through the plugin code on fake IDA modules). The case where the ISF's line is in the image as the kernel stores it but the export still fails was not seen in a real run (random bytes holding only the ISF's banner make Volatility exit 0 with an empty ELF, which the existing warning already reports). `tests/test_export_failure_stub.py` replays the recorded output (`tests/fixtures/vol-2.28.2`) through the export action on fake IDA modules with a fake `vol`, including Cancel during the export and during the banner scan, and checks that every wait box shown is hidden again, that none is stacked on another and that no dialog appears under one (6 mutants of the wait boxes fail it; before, the stub recorded no hide); 18 mutants of the new checks fail it, 14 more of the exact-bytes check, 10 of the size check and 8 of the ELF type check. The dialog texts before and after were taken from real Volatility runs through the plugin code on fake IDA modules, not in real IDA. The headless runner has no export path, so this change does not affect it.
- **Export: Volatility no longer inherits `PYTHONHOME`.** IDAPython in IDA 9.5 sets `PYTHONHOME` to the prefix of IDA's own Python when it is not set (IDA SDK `idapython.cpp`, before `Py_Initialize`), and the `vol` process MemLens starts inherited it. When `vol` runs on another Python (another version, a uv, Homebrew or python.org install), it could then not start (`No module named 'encodings'`) and Export failed with that error. MemLens now removes `PYTHONHOME` from the environment it gives `vol`; `PYTHONPATH` is still passed on. Found by reading the IDA 9.5 SDK source, not seen in a real IDA; test: a child Python started with a foreign `PYTHONHOME` set now runs (fails without the change).
- Export with a Volatility that cannot load MemLens' exporter (seen with 2.11.0: Volatility answers "invalid choice linux.kernel2elf.Kernel2Elf" and lists its other plugins) now says so, names the Volatility version, and gives the install line for 2.28.2 (the version MemLens is tested with) when Volatility printed an older version first (2.11 and 2.26 do); Volatility 2.27 and later stop at that check before printing their version (recorded with 2.28.2: `tests/fixtures/invalid_choice_vol2.28.2.stderr`), so then the dialog names both cases: `vol -h` shows the version, older than 2.28.2 → install 2.28.2, 2.28.2 or newer → run vol with `-vvv` and report it; before, the dialog showed only the tail of the plugin list. Stub test with the recorded message shape.
- Export no longer reports success when Volatility finished but copied no kernel code: with the demo `kernel.elf` (a kernel file, not a memory image) chosen as the image, Volatility 2.28.2 exits 0 and writes a 376-byte ELF with `.text` 0 bytes; the plugin said "Wrote kernel-1.elf ... Open it in IDA". It now warns that the file is probably not a memory image of a running kernel (and that a kernel file from disk is opened in IDA directly, then typed with Apply kernel types), and also when every per-CPU copy sits at the same address (the boot-time template of a kernel file). Checked with real Volatility 2.28.2 on the demo files (`trace.elf` still exports as before; `kernel.elf` now warns); stub test on the recorded output (`tests/fixtures/export_from_kernel_file.txt`). The exporter itself is unchanged.
- An AVML image that Volatility cannot read because the snappy library is missing gets its own hint (install snappy; Volatility loads `libsnappy.so.1` on Linux, `libsnappy.1.dylib` on macOS, `snappy64` on 64-bit Windows) and no banner scan; before, the dialog said the ISF was probably built for another kernel. Recorded with an AVML v2 header followed by random bytes on a machine without libsnappy; stub test on that output (2 mutants, no hint and a banner scan of the AVML file, fail it).
- ISF files compressed with gzip or bzip2 (`.json.gz`, `.json.bz2`, which Volatility also accepts) are now read by **Apply kernel types from ISF**, `isf2c.py` and the headless runner; before, only `.json` and `.json.xz` were, so the export accepted an ISF that Apply refused. The compression is taken from the file's first bytes. The file dialog's ISF filter lists `*.gz` and `*.bz2` too. `tests/test_isf_formats.py`.
- README: "An ISF for your own image": find the image's kernel with `banners.Banners`, then a ready-made ISF from the community collection Abyss-W4tcher/volatility3-symbols (found through its `banners/banners_plain.json` index, since its ISFs moved to GitHub Releases) or one built with dwarf2json from the kernel's debug package; "Without IDA" and "Headless, with idalib" have their own headings.
- **Show patched kernel functions** on a database whose input file is not a kernel (no function symbols, or no `linux_banner` symbol, as in a stripped or unstripped user-space binary) now warns that nothing was checked and opens no list; before, it opened an empty list that looked like a clean kernel (the command line `patchscan.py` gives the same warning and lists nothing, and the headless runner skips its patch list with the same reason, also under `--any-kernel`). `tests/test_findpatches_stub.py`.
- On Windows, each `vol` run started by Export (the export, and after a failure the banner scan) no longer opens a console window of its own (`CREATE_NO_WINDOW`). Not run on Windows: a stub test checks the flag is passed.
- The failure dialog quotes Volatility's output from the start of a line; it began with a cut-off `2.28.2`.
- The Output window's "declarations generated from the ISF" line prints counts in words (`9,734 structs, 1,715 unions, 2,149 enums, ...`) instead of a Python dict that also held the globals counts printed on the next line; the globals lines use thousands separators too (`typed 33,500 of the 79,316 globals`).

## v0.3.26 (2026-11-14)

- `tests/check_ida_names.py <stub dir>...`: checks that every `ida_*` / `idc` name MemLens uses exists in a folder of IDAPython stubs; all 40 are in the stubs of IDA 9.1 to 9.5 (PyPI `idapro` 0.0.5, 0.0.7, 0.0.9 and 0.0.11, and IDA 9.5 stubs).
- `patchscan.py` on a missing or unreadable file prints one line (`patchscan: cannot read ...`) instead of a traceback.
- README: the sample commands are the ones that print the samples (`objdump -d --disassemble=<name>`; patchscan's stderr line and tab columns stated); Volatility pinned to 2.28.2 (the version tested) in Install and Export it yourself; the same Export steps for Windows PowerShell (marked untested); export time stated as 25-50 s.
- **A failed export explains itself.** Volatility prints its explanation of a missing symbol table on stdout, which the dialog used to drop (it showed only `Unable to validate the plugin requirements: [...symbol_table_name]`). The dialog now adds a plain hint (no ISF chosen: a fresh pip install of Volatility has no Linux symbol files, so choose the ISF built for this kernel; ISF chosen: it was probably built for another kernel) and the tail of both outputs; the full output goes to the Output window.
- **A wrong or broken ISF file gives one clear message** instead of "unexpected error, please report it" and a traceback: picking `kernel.elf`, a text file, a truncated `.json.xz`, a missing file, or JSON that is not an ISF now says which file is not a readable Volatility ISF and why (plugin and `isf2c.py`). Found by a judge-style review.
- **Cancel is reported as cancelled.** Cancelling Apply kernel types used to print a summary that looked like a full import (and the first line showed the counts generated from the ISF, not what IDA took). The Output window now starts with `CANCELLED while importing types, after N of M declarations` (nothing typed) or `CANCELLED while typing globals, after N of M`, and the first counts line is labelled "declarations generated from the ISF".
- **Apply kernel types asks first when the database has no `linux_banner`** (it may not be a kernel): before, it imported the ISF's types (on the demo ISF about 13,600 structs, unions and enums, 25,464 declarations) into any database without a question. The headless runner refuses in that case unless `--any-kernel` is given.

## v0.3.25 (2026-11-13)

- **Apply kernel types reads the per-CPU copies in one pass.** It used to look up `cpu<N>.<name>` (and `cpu<N>_<name>`) for every CPU and every typed global the ISF declares: 79,316 globals on the demo kernel, so on a 64-CPU capture some 10 million name lookups. It now reads IDA's name list once (`idautils.Names()`) and keeps the same rules: `cpu<N>.<name>` anywhere, `cpu<N>_<name>` only inside that CPU's `.percpu.cpu<N>` section, `.` before `_`. A per-CPU variable whose copy for some CPU is missing from the name list (IDA can keep single names out of it) is still looked up by name for that CPU; if the list holds no per-CPU copy at all, every global is looked up one by one as before. Stub tests: the index gives the same copies as the old lookup on 3,000 random databases; mutants of each rule (`.` before `_`, the section check, the per-CPU fallbacks, the name pattern) fail the test. New `tests/test_demo_percpu_index.py` (skipped without the demo): on the demo `kernel.elf`, with names taken from its symbol table, both ways give the same 776 copies of the 388 per-CPU variables, also if IDA stores `cpu0.runqueues` as `cpu0_runqueues`. Found by a pre-release code review; two independent reviews of the change found test gaps, now closed. Tested with fake IDA modules only.
- tests/check_ida_api.py now also checks `idautils` names (`idautils.Names`; 53 names in total, 0 missing against the IDA SDK).
- README: the Credits section says how to list the authors, as the contest page asks of every README.

## v0.3.24 (2026-11-12)

- **Per-CPU typing no longer stops at a missing CPU.** The exporter keeps real CPU numbers and leaves out a CPU whose per-CPU area is not in the memory image, so a capture can have `.percpu.cpu0` and `.percpu.cpu2` without `.percpu.cpu1`; Apply kernel types used to stop at the first gap. It now takes the CPU numbers from the `.percpu.cpu<N>` sections in the database, including the `.percpu.cpu<N>.<k>` pieces the exporter writes when a CPU's area is only partly in the image (the old cpu0, cpu1, ... probe is kept for databases without such sections). Found by a judge-style review; the split-section case by a pre-release check. Tested with fake IDA modules only.
- README: the Ghidra column of the verification table was re-measured on exports from the current code for all three kernels (it was measured on an earlier per-CPU build for two of them), now including per-CPU symbols; its header now says that functions are checked for disassembly and per-CPU data for its address.
- README: the Export step says MemLens asks for the ISF (Cancel = Volatility's own symbols path), as the code already did.

Built by an AI agent (Claude, operated by Nightshift Labs). Not yet run in real IDA.

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
