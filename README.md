# MemLens

MemLens opens a Linux kernel **as it was running**, from a memory image, in IDA: every loaded module at its live address, every kernel type, and a list of hooked kernel functions with **who hooked each one** when the memory shows it (an ftrace or module callback, a BPF program or a kprobe). Real output from two public captures is below.

MemLens was built by an AI agent (Claude, operated by Nightshift Labs). It has **not yet been run in a real IDA**: see Status under [Install](#install).

<a href="docs/img/hookchain.svg"><img src="docs/img/hookchain.png" width="900" alt="Hook chain diagram drawn from patchscan.py --links output on the two demo kernel.elf files, not an IDA screenshot. Legend: white = hooked function, orange = hook page MemLens named, blue = handler, purple = owner. Top panel, hooks set by a test module (second sample): __x64_sys_kill hooked through ftrace, owner memlens_testhook.th_kill_callback; bpf_lsm_file_open, owner systemd's BPF program; __x64_sys_getdents64 hooked by a kprobe, owner memlens_testhook.th_getdents_pre. Bottom panel, hooks set through tracefs (demo, Debian 13 6.12 memory image): bpf_lsm_file_open, the same BPF program; do_sys_openat2, owner the tracefs kprobe memlens_kp; vfs_getattr, owner function_trace_call (ftrace_ops global_ops)."></a>

<sub>Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot. One lane per hooked function: the hooking call, the hook page copied from memory under the name MemLens's code gives it in IDA (the exporter's label under it), the page's first named call, and the owner in bold. The hook on `bpf_lsm_file_open` is systemd's BPF LSM program in both captures. How it is made and checked: [docs/img](docs/img/README.md).</sub>

## Install

```
hcli plugin install memlens
```

The plugin index can lag a day or more behind the [GitHub releases](https://github.com/nightshift-labs-ai/memlens/releases); if `hcli plugin status` shows an older version, install a release zip directly: `hcli plugin install https://github.com/nightshift-labs-ai/memlens/archive/refs/tags/v0.3.29.zip`.

Or copy this folder (from the latest release) into your IDA `plugins` directory. You also need an ISF symbol file for the kernel in the image; [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) builds one from the kernel's debug package.

**Status:** tested with fake IDA modules, with its IDA API names checked against the IDAPython stubs of IDA 9.1 to 9.5, but **not yet run in a real IDA**. What was verified, and how: [docs/VERIFICATION.md](docs/VERIFICATION.md). Bug reports are very welcome.

## Try it

No memory image or Volatility needed. Download `memlens-demo-debian13.zip` from the [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data) (22 MB). It holds a ready `kernel.elf` from a throwaway Debian 13 lab VM (68 MB, 234,095 symbols: 39,173 from modules and 776 per-CPU copies), the matching ISF, and the expected output. A whole kernel is a large database, so IDA's auto-analysis and the type import take a while; we have not timed them in IDA.

1. Unzip it, then open `kernel.elf` in IDA.
2. **Edit > Plugins > MemLens: Show patched kernel functions**. It should work right away, before auto-analysis finishes (checked with fake IDA modules, not in IDA). You should see these rows (the Owner column as in `expected-hook-chain.txt`; the VM's script set the ftrace filter on `vfs_getattr` and the kprobe on `do_sys_openat2`, and the BPF program is systemd's):

   ```
   Where             | Owner
   bpf_lsm_file_open | bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)
   do_sys_openat2    | kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)
   vfs_getattr       | function_trace_call (ftrace_ops global_ops)
   ```

   Then (not checked in IDA):
   - double-click a row to go to the hooked function;
   - right-click it, **Jump to owner**, to go to the owner (in the second sample, the module's callback);
   - `X` on a renamed hook page, such as `ftrace_tramp_vfs_getattr`, lists the hooked function's call to it.
3. **MemLens: Apply kernel types from ISF** and pick the `.json.xz` file.
4. Then try the second sample (module hooks): `memlens-demo-testhook.zip` from the same release, same steps; see [A hook set by a module](#a-hook-set-by-a-module-second-sample).

### Export it yourself

The demo `kernel.elf` comes from `trace.elf`, a 1 GB memory image of the same VM. The image is public (80 MB compressed, in our [Volatility samples release](https://github.com/nightshift-labs-ai/volatility-2026-samples/releases/tag/samples)), so you can run the exporter on it too. Volatility is only needed to export images, yours or this one: `pipx install volatility3==2.28.2` (the steps below use a venv instead). From the unzipped demo folder, with this repository at `<memlens>`:

```
curl -LO https://github.com/nightshift-labs-ai/volatility-2026-samples/releases/download/samples/trace.elf.xz
xz -dk trace.elf.xz
python3 -m venv v && v/bin/pip install volatility3==2.28.2
mkdir -p symbols/linux out && cp debian-6.12.115+deb13.1-amd64.json.xz symbols/linux/
v/bin/vol -q -p <memlens>/vol_plugins -s symbols -o out -f trace.elf linux.kernel2elf.Kernel2Elf
python3 <memlens>/patchscan.py out/kernel.elf
```

A fresh export also holds the kernel's kprobe list (the section `.memlens.kprobes`), so `python3 <memlens>/patchscan.py --links out/kernel.elf` names the probe on `do_sys_openat2`: `kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)`. The demo `kernel.elf` is such an export (MemLens 0.3.30), so it shows the same; exports from v0.3.29 or older show `kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)` there.

On Windows the same steps in PowerShell would be the following (we have no Windows machine, so these lines are not tested; `7z` is 7-Zip):

```
curl.exe -LO https://github.com/nightshift-labs-ai/volatility-2026-samples/releases/download/samples/trace.elf.xz
7z x trace.elf.xz
py -m venv v; v\Scripts\pip install volatility3==2.28.2
mkdir symbols\linux, out; copy debian-6.12.115+deb13.1-amd64.json.xz symbols\linux\
v\Scripts\vol.exe -q -p <memlens>\vol_plugins -s symbols -o out -f trace.elf linux.kernel2elf.Kernel2Elf
py <memlens>\patchscan.py out\kernel.elf
```

Volatility 2.28.2 is the version we tested; the exporter uses Volatility's Linux module API, which newer releases may change.

The export takes about 20-50 s on our machine. With this version, `out/kernel.elf` is byte-identical to the demo's (its SHA-256 is in `SHA256SUMS.txt`). v0.3.27 or older writes no BPF names or BPF program pages (v0.3.20 to v0.3.27: 234,081 symbols instead of 234,095), and v0.3.28 and v0.3.29 write no kprobe list; all of them list the same three `patched` rows. In IDA, **MemLens: Export kernel from memory image** does the same: choose `trace.elf`, then the ISF from the demo folder. It runs Volatility's `vol` command from your PATH, or asks where it is (`v/bin/vol` above). The ELF is written next to the image (`kernel-1.elf` if a `kernel.elf` is already there).

## Before and after (real output from the demo, not IDA screenshots)

We have no IDA, so there are no IDA screenshots. These excerpts are real output for the demo, from binutils `objdump` and from the plugin's own code run with fake IDA modules.

**Before:** `trace.elf`, the 1 GB memory image of the demo VM (not part of the demo zip), is an ELF core: 5 `LOAD` segments at physical addresses, no symbol table, no code sections.

**After:** `kernel.elf`, an ordinary ELF: the kernel and its loaded modules at their live addresses, 234,095 symbols, one copy of the per-CPU variables per CPU. With the kernel's ISF, MemLens types it in IDA (every struct, union and enum, and the typed globals that have a symbol) and lists the functions someone hooked. `objdump` excerpt of `kernel.elf` (`vfs_getattr`'s entry was rewritten by ftrace; the hook page was copied from memory):

```
ffffffff8e64e370 <vfs_getattr>:
ffffffff8e64e370:	endbr64
ffffffff8e64e374:	call   ffffffffc0b2b000 <memlens_target_ffffffffc0b2b000>
...
ffffffffc0b2b094:	call   ffffffff8e434a40 <function_trace_call>
```

The **Show patched kernel functions** list for the same `kernel.elf`, as the plugin code builds it for the demo (run with fake IDA modules by `tests/test_hookchain_stub.py`, not in IDA). Only the Where, Owner and Handler columns are shown here; the Address, What and Target columns are in the full rows in [docs/OUTPUT.md](docs/OUTPUT.md#what-you-get-real-output-from-the-demo-not-ida-screenshots):

```
Where             | Owner                                                                                     | Handler
bpf_lsm_file_open | bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)                          | __bpf_tramp_enter (BPF trampoline)
do_sys_openat2    | kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher) | kprobe_ftrace_handler (kprobe via ftrace)
vfs_getattr       | function_trace_call (ftrace_ops global_ops)                                               | function_trace_call (ftrace)
```

The rest of the demo output (the patch scan, the hook chain's cross-references, owners and renames, the type header and the typed globals): [docs/OUTPUT.md](docs/OUTPUT.md#what-you-get-real-output-from-the-demo-not-ida-screenshots).

### A hook set by a module (second sample)

The demo's hooks come from the kernel's own tracing (plus systemd's BPF LSM program on `bpf_lsm_file_open`, in both captures). For the rootkit-style case there is a second capture of the same kernel, with a small test module loaded, [tests/vm/testhook](tests/vm/testhook/README.md). It hooks `__x64_sys_kill` with an ftrace callback and `__x64_sys_getdents64` with a kprobe. These are the APIs that ftrace-based rootkits use; this module only counts calls. The Owner column names the module's callbacks: **memlens_testhook.th_kill_callback** (from the trampoline's `ftrace_ops`) and **memlens_testhook.th_getdents_pre** (the probe's `pre_handler`, from the kernel's kprobe list). The same list for its `kernel.elf`, built the same way (fake IDA modules, `tests/test_hookchain_stub.py`; only the Where, Owner and Handler columns, in the list's order; full rows in [docs/OUTPUT.md](docs/OUTPUT.md#the-second-sample-in-full-a-hook-set-by-a-module)):

```
Where                | Owner                                                                       | Handler
__x64_sys_kill       | memlens_testhook.th_kill_callback (ftrace_ops memlens_testhook.th_kill_ops) | ftrace_ops_assist_func (ftrace)
bpf_lsm_file_open    | bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)            | __bpf_tramp_enter (BPF trampoline)
__x64_sys_getdents64 | memlens_testhook.th_getdents_pre (kprobe pre_handler)                       | kprobe_ftrace_handler (kprobe via ftrace)
```

**Jump to owner** should lead to the module's callback (not checked in IDA). After **Apply kernel types**, the list should also type `memlens_testhook.th_kill_ops` as `struct ftrace_ops` and comment it and its trampoline with the flags read from memory, `0x857 = ENABLED|DYNAMIC|SAVE_REGS|RECURSION|INITIALIZED|ALLOC_TRAMP`, no IPMODIFY (as the guest's tracefs shows: `R` without `I`), so the ops does not declare that its callback may change where `__x64_sys_kill` continues; that is a declaration, not a guarantee ([docs/OUTPUT.md](docs/OUTPUT.md#the-second-sample-in-full-a-hook-set-by-a-module); fake IDA modules, not checked in IDA). Both owner addresses (`0xffffffffc0cc6010`, `0xffffffffc0cc6040`) match the guest's `/proc/kallsyms` at capture time ([hook-truth-guest.txt](tests/vm/testhook/hook-truth-guest.txt)), and the module's counters in the image, `memlens_testhook.th_kill_calls` = 2 and `th_getdents_calls` = 16, show both hooks ran. There is no `sys_call_table` row: since Linux 6.9, x86-64 dispatches syscalls through `x64_sys_call()`, so a table hook would be inert (`tests/test_demo_injection.py` plants table slots instead).

To try it, download `memlens-demo-testhook.zip` (21 MB) from the same [demo-data release](https://github.com/nightshift-labs-ai/memlens/releases/tag/demo-data), follow steps 1-3 of Try it and compare with its `expected-hook-chain.txt`; it holds the `kernel.elf`, the same ISF and the module source. The memory image itself, `testhook.elf.xz` (91 MB), is in the [Volatility samples release](https://github.com/nightshift-labs-ai/volatility-2026-samples/releases/tag/samples), so you can also export it yourself. The hooked entry, the trampoline and the module's code at its live address, in `objdump`: [docs/OUTPUT.md](docs/OUTPUT.md#the-second-sample-in-full-a-hook-set-by-a-module).

## What Volatility already tells you

Volatility 3 already lists ftrace callbacks (`linux.tracing.ftrace`), and MemLens uses Volatility for its export. For the 6 hook sites in the two public captures, stock Volatility 2.28.2 (cells as printed) and the MemLens list (Owner text before its parenthesis) name:

| Hook (capture) | Volatility 2.28.2: hooked function / owner | MemLens: hooked function / owner |
|---|---|---|
| ftrace, test module (second sample) | `-` / `-`, Module `memlens_testhook` | `__x64_sys_kill` / `memlens_testhook.th_kill_callback` |
| kprobe, test module (second sample) | `-` / `kprobe_ftrace_handler` | `__x64_sys_getdents64` / `memlens_testhook.th_getdents_pre` |
| BPF LSM program (second sample) | `-` / `call_direct_funcs` | `bpf_lsm_file_open` / `bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems` |
| BPF LSM program (demo) | `-` / `call_direct_funcs` | `bpf_lsm_file_open` / `bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems` |
| kprobe, tracefs (demo) | `do_sys_openat2` / `kprobe_ftrace_handler` | `do_sys_openat2` / `kprobe memlens_kp on do_sys_openat2` |
| ftrace, tracefs (demo) | `-` / `function_trace_call` | `vfs_getattr` / `function_trace_call` |
| **Named** | hooked function 1 of 6, owner 1 of 6 (and 1 module name) | hooked function 6 of 6, owner 6 of 6 |

- **Why `-`:** 5 of the 6 sites are at function+0x4, after `endbr64`, and the plugin looks up exact symbol addresses (`do_sys_openat2` has no `endbr64`). A later Volatility could name them.
- **Other gaps:** Volatility 2.28.2 has no kprobe plugin, so a probe's own handler is not shown; `linux.ebpf` lists the program (`restrict_filesy`, `BPF_PROG_TYPE_LSM`) but not where it is attached; the module's callback is shown by address, with no symbol.
- **Independent of the kernel's lists** (simulated on a copy of the second sample's image): with the module's `ftrace_ops` unlinked from `ftrace_ops_list`, `linux.tracing.ftrace` printed 2 rows instead of 3, without the module's, and MemLens still named `memlens_testhook.th_kill_callback`, from the ops pointer the trampoline itself holds.
- **Where Volatility does more:** hook kinds MemLens does not scan (tracepoints, the IDT, keyboard notifiers, afinfo and tty ops, netfilter), every BPF program with its type, and modules hidden from the module list (`linux.malware.hidden_modules`), which MemLens does not export ([Limits](#limits)). `--show-ftrace-flags` gives the same flags decode MemLens adds after Apply kernel types. Use both.
- **In IDA,** the list should lead from each row to the hooked entry, the hook page and the owner at its live address (not checked in IDA); `patchscan.py --links` prints the same answer without IDA.

Recorded outputs and commands: [tests/fixtures/vol-2.28.2/compare](tests/fixtures/vol-2.28.2/compare/README.txt); `tests/test_compare.py` checks this table against them and against MemLens's output.

## What it does

```mermaid
flowchart LR
  img[memory image] --> vol["MemLens: Export<br/>(Volatility 3 + linux.kernel2elf)"]
  isf[ISF of that kernel] --> vol
  vol --> elf[kernel.elf]
  elf --> ida[IDA + MemLens]
  isf --> ida
  ida --> types[kernel types + typed globals]
  ida --> pcpu["per-CPU copies (cpu0.runqueues, ...)"]
  ida --> hooks[patched functions list]
```

- **`kernel.elf`**: the kernel and every loaded module at their real (KASLR) addresses, with a full symbol table. An ordinary ELF.
- **Every kernel type**: all structs, unions and enums from a Volatility 3 ISF, as one C header with exact layouts.
- **Typed globals**: kernel data symbols get their real type, so `init_task` becomes a `struct task_struct`.
- **Per-CPU variables, one copy per CPU**: each CPU's live copy (`cpu0.runqueues`, `cpu1.pcpu_hot`, ...), typed like the globals.
- **Patched kernel functions**: entries rewritten by ftrace, kprobes, BPF trampolines or hook code, and syscall slots that leave the handlers, with the hook's owner when the memory shows it (the BPF program, the `ftrace_ops` and its callback, or a module's callback; for an ftrace-based kprobe, in an export from v0.3.30 on, the probe itself: its tracefs event name or the module function its `pre_handler` is, for a kretprobe its `handler`).

The full description of each is under [Details](docs/OUTPUT.md#details).

## Usage

In IDA, with any database open (plugin menu entries need one), under **Edit > Plugins**:

1. **MemLens: Export kernel from memory image**: choose the image. `kernel.elf` is written next to it (`kernel-1.elf` if one is already there; the message names the file). MemLens asks for the ISF and hands it to Volatility.
2. Open `kernel.elf` in IDA.
3. **MemLens: Apply kernel types from ISF**: choose the ISF. If its kernel banner differs from the one in the database, MemLens asks before importing anything.
4. **MemLens: Show patched kernel functions**: opens the list, adds a comment at each entry and links the hook chain. Enter jumps to the entry, **Jump to handler** to the handler and **Jump to owner** to the owner when it is in the database. Not yet tried in IDA.

Each action in full: [docs/USAGE.md](docs/USAGE.md#usage).

### An ISF for your own image

The export dialog points here. The ISF must come from exactly the kernel that was running when the image was taken. Find that kernel's `Linux version` line with `banners.Banners`, then get a ready-made ISF or build one with dwarf2json: [step by step in docs/EXPORT.md](docs/EXPORT.md#an-isf-for-your-own-image).

## Limits

- x86-64 Linux only.
- Bitfields are kept as raw bytes, with their names and positions in a comment.
- Function pointers become `void *`.
- No function prototypes: an ISF gives functions no parameter types. Most kernels also carry BTF, which has them; our companion plugin [btf2ida](https://github.com/nightshift-labs-ai/btf2ida) applies them by name (91.8% of kernel functions on the demo; not tried together with MemLens in IDA).
- Kernel symbols that are not mapped in the image, such as freed init code, are left out.
- Finds rewritten function entries and syscall-table slots. It does not walk tracepoints, notifier chains, the IDT, netfilter hooks or file, seq or tty ops (Volatility 2.28.2 has plugins for these; for notifiers, the keyboard chain).
- Modules hidden from the module list are not exported: their hooks are still listed, but the owner shows as an address with no name (`ftrace_ops at 0x... (no symbol: module memory MemLens did not export)`). Measured on a copy of the second sample's image with the module unlinked.

All limits, with measurements: [docs/LIMITS.md](docs/LIMITS.md).

## More documentation

- All demo output, with the hook chain and its owners: [docs/OUTPUT.md](docs/OUTPUT.md#what-you-get-real-output-from-the-demo-not-ida-screenshots)
- Each output in full: [docs/OUTPUT.md, Details](docs/OUTPUT.md#details)
- The menu actions in full: [docs/USAGE.md](docs/USAGE.md#usage)
- Without IDA (`vol`, `isf2c.py`, `patchscan.py`): [docs/USAGE.md](docs/USAGE.md#without-ida)
- Headless, with idalib: [docs/USAGE.md](docs/USAGE.md#headless-with-idalib)
- When the export fails: [docs/EXPORT.md](docs/EXPORT.md#when-the-export-fails)
- An ISF for your own image: [docs/EXPORT.md](docs/EXPORT.md#an-isf-for-your-own-image)
- What was verified (Ghidra, binutils, gcc, the tests): [docs/VERIFICATION.md](docs/VERIFICATION.md)
- Run every test: `python3 tests/run_all.py` (no IDA, no packages; with `MEMLENS_DEMO_ELF=kernel.elf` it also checks the demo export: 17 passed on the demo `kernel.elf`)
- Limits in full: [docs/LIMITS.md](docs/LIMITS.md)
- The exporter on its own, as a Volatility 3 plugin: [docs/README-kernel2elf.md](docs/README-kernel2elf.md), [docs/WRITEUP-kernel2elf.md](docs/WRITEUP-kernel2elf.md)

## Credits

Author: Nightshift Labs (built by an AI agent, Claude). Please list the authors as "Nightshift Labs". Built on [Volatility 3](https://github.com/volatilityfoundation/volatility3) and its ISF format. MIT licensed.
