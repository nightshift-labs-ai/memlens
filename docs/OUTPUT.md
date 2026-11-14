# MemLens output in full

Part of the MemLens documentation; start with the [README](../README.md).

## What you get (real output from the demo, not IDA screenshots)

We have no IDA, so there are no IDA screenshots. Below is real output for the demo `kernel.elf`, from the same code the plugin runs (`patchscan.py`, `isf2c.py`) and from binutils `objdump`.

Patched functions, the same scan the IDA list runs (`python3 patchscan.py kernel.elf`; it first prints `125674 function symbols scanned` on stderr, and its columns are tab-separated, aligned here for reading):

```
0xffffffff8e4f9250  bpf_lsm_file_open  call to memory with no symbol  memlens_target_ffffffffc0004940 (calls __bpf_tramp_enter, BPF trampoline)
0xffffffff8e642210  do_sys_openat2     call to memory with no symbol  memlens_target_ffffffffc0b2d000 (calls kprobe_ftrace_handler, kprobe via ftrace)
0xffffffff8e64e370  vfs_getattr        call to memory with no symbol  memlens_target_ffffffffc0b2b000 (calls function_trace_call, ftrace)
```

A hooked entry and the hook page it calls, which no module owns and which MemLens copied into the ELF (excerpts of `objdump -d --no-show-raw-insn --disassemble=vfs_getattr kernel.elf`, and the same with `do_sys_openat2`, `memlens_target_ffffffffc0b2b000` and `memlens_target_ffffffffc0b2d000`; a plain `objdump -d` prints the whole kernel, about 8.6 million lines; tabs shown as two spaces):

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

The hook chain that **Show patched kernel functions** adds to the IDA database, as `python3 patchscan.py --links kernel.elf` prints it for the demo after the rows above (tab-separated, aligned here). The decisions are made in `patchscan.py`, so this is the same code the plugin runs:

```
xref    0xffffffff8e4f9254  0xffffffffc0004940  call  bpf_lsm_file_open+0x4 -> memlens_target_ffffffffc0004940
xref    0xffffffff8e642210  0xffffffffc0b2d000  call  do_sys_openat2 -> memlens_target_ffffffffc0b2d000
xref    0xffffffff8e64e374  0xffffffffc0b2b000  call  vfs_getattr+0x4 -> memlens_target_ffffffffc0b2b000
xref    0xffffffff8ff42660  0xffffffff8e434a40  data  global_ops -> function_trace_call
xref    0xffffffff900670e0  0xffffffff8e294ed0  data  kprobe_ftrace_ops -> kprobe_ftrace_handler
xref    0xffffffffc0004963  0xffffffff8e4cea70  call  memlens_target_ffffffffc0004940+0x23 -> __bpf_tramp_enter
xref    0xffffffffc0004993  0xffffffffc0004664  call  memlens_target_ffffffffc0004940+0x53 -> bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems
xref    0xffffffffc0b2b094  0xffffffff8e434a40  call  memlens_target_ffffffffc0b2b000+0x94 -> function_trace_call
xref    0xffffffffc0b2b0dd  0xffffffff8ff42660  data  memlens_target_ffffffffc0b2b000+0xdd -> global_ops
xref    0xffffffffc0b2d0d9  0xffffffff8e294ed0  call  memlens_target_ffffffffc0b2d000+0xd9 -> kprobe_ftrace_handler
xref    0xffffffffc0b2d162  0xffffffff900670e0  data  memlens_target_ffffffffc0b2d000+0x162 -> kprobe_ftrace_ops
rename  0xffffffffc0004940  memlens_target_ffffffffc0004940  bpf_tramp_bpf_lsm_file_open
rename  0xffffffffc0b2b000  memlens_target_ffffffffc0b2b000  ftrace_tramp_vfs_getattr
rename  0xffffffffc0b2d000  memlens_target_ffffffffc0b2d000  kprobe_ftrace_tramp_do_sys_openat2
owner   0xffffffffc0004940  0xffffffffc0004664  bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)
owner   0xffffffffc0b2b000  0xffffffff8e434a40  function_trace_call (ftrace_ops global_ops)
owner   0xffffffffc0b2d000  0xffffffff8e463660  kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)
```

Each `xref` line becomes a cross-reference marked `XREF_USER`, which IDA's reanalysis does not delete. A `call` or `jmp` line is a code xref (`ida_xref.add_cref` with `fl_CN` or `fl_JN`): from the hooking instruction to the hook page, from the page's first named call to that function, and from a BPF trampoline's call to its program. A `data` line is a data xref (`ida_xref.add_dref` with `dr_O`): from an ftrace trampoline's `ftrace_ops` slot to the ops, and from the ops' `func` to the callback. Each `rename` line renames the page, and a comment there keeps the exporter's label and names the owner: `MemLens: hook page no module owns, copied from memory (exporter label memlens_target_ffffffffc0b2b000); reached from vfs_getattr; first named call: function_trace_call (ftrace); owner: function_trace_call (ftrace_ops global_ops)`. After **Apply kernel types**, which records the offset of `ftrace_ops.flags` and the `FTRACE_OPS_FL_*` values (read by name from the ISF's anonymous enum, because their numbering changed across kernel versions), an ftrace trampoline whose owner is its `ftrace_ops` gets a second line, and the ops the same comment, decoding the flags read from memory: on the demo, at `ftrace_tramp_vfs_getattr` and at `global_ops`, `MemLens: ftrace_ops flags 0x2841 = ENABLED|INITIALIZED|ALLOC_TRAMP|PID; no IPMODIFY: the callback did not declare that it may change where the hooked function continues (a declaration, not a guarantee: read the callback to be sure)` (on the second sample: [below](#the-second-sample-in-full-a-hook-set-by-a-module)). kprobe trampolines get no such comment: a kprobe's `pre_handler` can change `regs->ip` whatever the flags of the kprobe layer's shared ops say (`kprobe_ftrace_ops` is `0x845` in both captures). Without that layout, or when the ISF has no `FTRACE_OPS_FL_IPMODIFY`, nothing is said. These three hooks are `call rel32`, so IDA's own analysis should find the same calls; the user xrefs matter most for absolute hooks (`movabs` + `jmp reg`, `push imm32; ret`, `jmp [rip+0]`), whose target IDA cannot see.

Each `owner` line is the page's Owner column (`-` when the owner is not in the ELF). The handler is the page's first named call when that call has a known role: ftrace, kprobe or BPF plumbing, or a module's function (a module callback, below); the owner is the code the hook page runs for whoever set the hook (for an ftrace-based kprobe, the probe itself when the export holds the kernel's kprobe list, below):

- **ftrace trampoline:** the trampoline loads its `ftrace_ops` with `mov rdx, [rip+X]` from a slot the kernel stores right after the trampoline's `ret`. MemLens reads that pointer and the ops' `func` (its offset comes from the ISF, `--isf` or Apply kernel types, else 0, the offset in the Linux 6.1, 6.8, 6.12 and 7.0 ISFs we checked). That is the callback the ops registered, also when the trampoline calls `ftrace_ops_assist_func` instead, as the kernel does for ops flagged RECURSION or RCU. On the demo both ftrace owners are the kernel's own tracing (the function tracer and the kprobe layer). A module's hook through `ftrace_ops_assist_func` is tested on hand-made ELFs (`tests/test_owner.py`, where the Owner column reads `evilmod.fh_ftrace_thunk (ftrace_ops evilmod.hooks+0x20)`) and on one real capture, the second sample (README, [A hook set by a module](../README.md#a-hook-set-by-a-module-second-sample)), where it reads `memlens_testhook.th_kill_callback (ftrace_ops memlens_testhook.th_kill_ops)`. Ops outside the ELF are shown by address, as `ftrace_ops at 0x... (no symbol: heap)` or `(no symbol: module memory MemLens did not export)`. An ftrace trampoline whose callback is another kernel function, for example a livepatch's `klp_ftrace_handler`, is an ftrace page too: its Handler column reads `klp_ftrace_handler (ftrace)` and it is renamed `ftrace_tramp_<function>`.
- **kprobe via ftrace:** the trampoline's `ftrace_ops` is `kprobe_ftrace_ops` (`kprobe_ipmodify_ops` for a probe with a `post_handler`, Linux 6.12 `kernel/kprobes.c`), shared by every such probe, so it does not say whose probe it is. An export from v0.3.30 on also holds the kernel's kprobe list: the exporter walks `kprobe_table` (hash lists of `struct kprobe`; in place of an aggregate probe, the probes on its list), with every offset taken from the ISF, and writes each probe's address, `symbol_name`, offset, `pre_handler`, `post_handler` and `flags` (for a kretprobe also its `handler`) as JSON into the section `.memlens.kprobes`, which is not loaded (no program header, address 0; `readelf -p .memlens.kprobes kernel.elf` shows it). When `pre_handler` is `kprobe_dispatcher` (for a kretprobe: when its `handler` is `kretprobe_dispatcher`) the probe belongs to a `struct trace_kprobe`: the exporter goes there from the `struct kprobe` (container_of over `rp.kp`) and reads the event name (`tp.event->call.name`, before Linux 5.4 `tp.call.name`). The probe at the patched instruction is then the Owner, and Jump to owner goes to its `pre_handler`. On a fresh export of the demo image the list holds one probe and the owner line reads `owner  0xffffffffc0b2d000  0xffffffff8e463660  kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)` (the probe `tests/vm/scenario_ftrace_d13.sh` set); compared with an export of the same image made with v0.3.28, it is the only `--links` line that changes. A module's probe reads `<module>.<pre_handler> (kprobe pre_handler)`, for example `evilmod.kp_pre (kprobe pre_handler)`, and on the second sample `memlens_testhook.th_getdents_pre (kprobe pre_handler)`; a trace_kprobe that is not on tracefs' dynamic event list was made by perf_event_open (BPF, perf) and reads `kprobe <event> on <function> (made by perf_event_open, not a tracefs event; pre_handler kprobe_dispatcher)`; a handler outside the ELF reads `kprobe pre_handler at 0x... (no symbol)`. A kretprobe's `pre_handler` is always the kernel's `pre_handler_kretprobe` (`register_kretprobe`, Linux 6.12 `kernel/kprobes.c`), so the kretprobe's `handler` names it instead: a tracefs `r:` event (handler `kretprobe_dispatcher`, `kernel/trace/trace_kprobe.c`) reads `kretprobe <event> on <function> (tracefs kretprobe event; handler kretprobe_dispatcher)`, a module's kretprobe `<module>.<handler> (kretprobe handler)`, and Jump to owner goes to that handler. A disabled probe (`flags` GONE or DISABLED, such as a tracefs event that is defined but not enabled) is left out when an enabled probe sits at the same instruction; when every probe there is disabled, each reads `... (disabled)`. (Lists written by development builds of 0.3.30 may lack `handler` or `flags`: without `handler` a kretprobe reads `pre_handler_kretprobe (kprobe pre_handler)`, without `flags` every probe counts as enabled.) One trampoline serves every function that only that ops hooks, so each row names its own probe, and the page's `owner` line and comment list them all, separated by `;`. These cases are tested on hand-made ELFs and fake `volatility3` modules (`tests/test_owner.py`, `tests/test_kernel2elf_kprobes.py`); of them, the tracefs event (the demo image) and the module's probe (the second sample) also on real exports. The xrefs stay those of the `ftrace_ops`. Without the section (exports from v0.3.29 or older) the Owner is `kprobe_ftrace_handler (ftrace_ops kprobe_ftrace_ops)`, as before; the demo `kernel.elf` (exported with 0.3.30) has the section. A kprobe that is an `int3` at the entry (an `int3 at entry` row) gets no owner. Not run in real IDA.
- **BPF trampoline:** the program, which is the call right after `__bpf_prog_enter*`. MemLens follows the instructions the kernel's BPF JIT puts between the two; anything else there gives no owner. A kernel function in the program's place is not called a program: the interpreter reads `__bpf_prog_run32 (BPF interpreter: the program is not JIT-compiled)`, a cgroup LSM trampoline's shim `__cgroup_bpf_run_lsm_current (cgroup LSM shim: runs each cgroup's programs, not named here)`, anything else `<name> (called by the BPF trampoline)` (hand-made ELFs only). Exports from v0.3.27 or older have no BPF names and show `BPF program at 0xffffffffc0004664` for the demo image. An export from v0.3.28 on holds the kernel's BPF names (from Volatility's `Kallsyms` API) and the pages of every BPF program. On the demo image the owner is then `bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)`.
- **Module callback:** when the page's first named call is a module's function (`module.symbol`), the Handler and Owner columns both read, for example, `evilmod.fh_sys_kill (module callback)`, Jump to handler and Jump to owner go there, and the page is renamed `module_hook_` plus the hooked function (`module_hook___x64_sys_kill` for a hook on `__x64_sys_kill`), or plus the page's address when several functions share it. An ftrace trampoline that calls a module's callback itself (an ops not flagged RECURSION or RCU) is named this way too; its Owner still comes from its `ftrace_ops`. Tested on hand-made ELFs only (`tests/test_owner.py`, `tests/test_hookchain.py`, `tests/test_hookchain_stub.py`): none of our captures has such a page.
- **Otherwise:** a first call into the core kernel (`_printk`, `kfree`, a retpoline thunk) on a page that loads no `ftrace_ops` gives no handler and no owner: on a hidden module's page it is a helper the hook code uses. The Handler column reads `(hook code; first call: _printk)`, Jump to handler says that no handler is known instead of jumping into `_printk`, and the page keeps its `memlens_target_` label. The xref of that call is still added: it only repeats a real `call` instruction.

The list before and after, as the plugin code builds it for the demo (run with fake IDA modules by `tests/test_hookchain_stub.py`, not in IDA; columns separated by `|` and aligned here). Before this change:

```
Address          | Where             | What                          | Target
FFFFFFFF8E4F9250 | bpf_lsm_file_open | call to memory with no symbol | memlens_target_ffffffffc0004940 (calls __bpf_tramp_enter, BPF trampoline)
FFFFFFFF8E642210 | do_sys_openat2    | call to memory with no symbol | memlens_target_ffffffffc0b2d000 (calls kprobe_ftrace_handler, kprobe via ftrace)
FFFFFFFF8E64E370 | vfs_getattr       | call to memory with no symbol | memlens_target_ffffffffc0b2b000 (calls function_trace_call, ftrace)
```

After (Handler since v0.3.27, Owner since v0.3.28, kprobe owner since v0.3.30):

```
Address          | Where             | What                          | Target                             | Handler                                   | Owner
FFFFFFFF8E4F9250 | bpf_lsm_file_open | call to memory with no symbol | bpf_tramp_bpf_lsm_file_open        | __bpf_tramp_enter (BPF trampoline)        | bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)
FFFFFFFF8E642210 | do_sys_openat2    | call to memory with no symbol | kprobe_ftrace_tramp_do_sys_openat2 | kprobe_ftrace_handler (kprobe via ftrace) | kprobe memlens_kp on do_sys_openat2 (tracefs kprobe event; pre_handler kprobe_dispatcher)
FFFFFFFF8E64E370 | vfs_getattr       | call to memory with no symbol | ftrace_tramp_vfs_getattr           | function_trace_call (ftrace)              | function_trace_call (ftrace_ops global_ops)
```

The Output window line from the same run: `[MemLens] hook chain: 3 patched entries lead into this database, 3 to a hook page MemLens copied; 7 code xrefs added; 4 data xrefs added; 3 hook pages renamed by role`. Run a second time, it made no `add_cref`, `add_dref` or `set_name` call. A fresh export of the Debian 13 hooks capture (the same three hooks at other KASLR addresses) gives the same counts, names and owners, with the program named `bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems`. On an Ubuntu 24.04 capture `patchscan.py --links` gives 1 entry, 3 xrefs, `bpf_tramp___hid_bpf_tail_call` and the owner `BPF program at 0xffffffffc0043958`; a fresh export names it `bpf.bpf_prog_7cc47bbf07148bfe_hid_tail_call`. None of our captures has a hook page that several functions share (one ftrace trampoline for many filters); MemLens then names the page by role and address (`ftrace_tramp_<address>`), which is tested on hand-made ELFs only.

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

Typed globals come from the same ISF, for example `struct task_struct init_task`, `struct net init_net` and `struct static_key nf_hooks_needed[11][5]`. The ISF declares 79,316 typed globals for this kernel, but only those with a symbol in the ELF can be typed: 33,500 in the demo `kernel.elf`, plus 388 per-CPU variables, typed in each CPU's copy (`cpu0.runqueues`, `cpu1.runqueues`). Another 78 names that the ISF declares as variables are kernel functions here (`schedule`, `strlen`, ...): they are left alone, because typing code as data would break it. The other 45,350 have address 0 in the ISF (45,344) or an address outside exported memory (6, among them small assembler constants such as `vector`). The Output window says how many were typed and how many have no symbol in your database.

## The second sample in full (a hook set by a module)

Real output for the `kernel.elf` in `memlens-demo-testhook.zip` (the test module [tests/vm/testhook](../tests/vm/testhook/README.md) loaded in the same Debian 13 kernel as the demo; binutils `objdump` and `patchscan.py`, not IDA).

The hooked entry: ftrace turned the `__fentry__` NOP of `__x64_sys_kill` into a call to a trampoline page that MemLens copied from memory:

```
ffffffffb08dcac0 <__x64_sys_kill>:
ffffffffb08dcac0:	endbr64
ffffffffb08dcac4:	call   ffffffffc0cd0000 <memlens_target_ffffffffc0cd0000>
```

The trampoline loads its `ftrace_ops` from the slot after its `ret` and calls `ftrace_ops_assist_func` (the module's ops is flagged RECURSION), so the callback is not a direct call:

```
ffffffffc0cd0065:	mov    0xf6(%rip),%rdx        # ffffffffc0cd0162 <memlens_target_ffffffffc0cd0000+0x162>
ffffffffc0cd00d9:	call   ffffffffb0a0c740 <ftrace_ops_assist_func>
ffffffffc0cd015d:	ret
```

The slot holds `0xffffffffc0cc80a0`, which is `memlens_testhook.th_kill_ops`, and that ops' `func` (offset 0) holds `0xffffffffc0cc6010`, the module's callback at its live address:

```
ffffffffc0cc6010 <memlens_testhook.th_kill_callback>:
ffffffffc0cc6010:	endbr64
ffffffffc0cc6014:	lock incq 0x26ac(%rip)        # ffffffffc0cc86c8 <memlens_testhook.th_kill_calls>
ffffffffc0cc601c:	ret
```

The ops' `flags` (offset 16 in this ISF) hold `0x857`: ENABLED, DYNAMIC, SAVE_REGS, RECURSION, INITIALIZED and ALLOC_TRAMP, without IPMODIFY (`0x1000` in this ISF), as the guest's tracefs shows (`__x64_sys_kill (1) R` in [hook-truth-guest.txt](../tests/vm/testhook/hook-truth-guest.txt): `R` without `I`). After Apply kernel types the list types `memlens_testhook.th_kill_ops` as `struct ftrace_ops` (a module's symbol, which Apply kernel types does not type by itself; once, recorded in `$ memlens.hooks`) and writes this comment at it and at `ftrace_tramp___x64_sys_kill` (fake IDA modules, `tests/test_hookchain_stub.py`; not checked in IDA):

```
MemLens: ftrace_ops flags 0x857 = ENABLED|DYNAMIC|SAVE_REGS|RECURSION|INITIALIZED|ALLOC_TRAMP; no IPMODIFY: the callback did not declare that it may change where the hooked function continues (a declaration, not a guarantee: read the callback to be sure)
```

IPMODIFY is what a callback declares when it may change where the hooked function continues (livepatch, ftrace hooks that replace a function); ftrace lets only one such callback register on a function (`include/linux/ftrace.h`). It is a declaration, not a guarantee: after the callback returns, this trampoline copies `regs->ip` back to its return address (`mov 0x80(%rsp),%rax` at `ffffffffc0cd00ee`, `mov %rax,0xb0(%rsp)` at `ffffffffc0cd00f6`; the demo's trampoline does the same), so read the callback too. This one only counts calls.

`patchscan.py --links kernel.elf` (the hook chain the IDA list applies; `xref` lines become cross-references, `rename` lines names, `owner` lines the Owner column):

```
0xffffffffb08dcac0	__x64_sys_kill	call to memory with no symbol	memlens_target_ffffffffc0cd0000 (calls ftrace_ops_assist_func, ftrace)
0xffffffffb0af9250	bpf_lsm_file_open	call to memory with no symbol	memlens_target_ffffffffc01a0940 (calls __bpf_tramp_enter, BPF trampoline)
0xffffffffb0c65950	__x64_sys_getdents64	call to memory with no symbol	memlens_target_ffffffffc0cd2000 (calls kprobe_ftrace_handler, kprobe via ftrace)
xref	0xffffffffb08dcac4	0xffffffffc0cd0000	call	__x64_sys_kill+0x4 -> memlens_target_ffffffffc0cd0000
xref	0xffffffffb0af9254	0xffffffffc01a0940	call	bpf_lsm_file_open+0x4 -> memlens_target_ffffffffc01a0940
xref	0xffffffffb0c65954	0xffffffffc0cd2000	call	__x64_sys_getdents64+0x4 -> memlens_target_ffffffffc0cd2000
xref	0xffffffffb26670e0	0xffffffffb0894ed0	data	kprobe_ftrace_ops -> kprobe_ftrace_handler
xref	0xffffffffc01a0963	0xffffffffb0acea70	call	memlens_target_ffffffffc01a0940+0x23 -> __bpf_tramp_enter
xref	0xffffffffc01a0993	0xffffffffc01a0668	call	memlens_target_ffffffffc01a0940+0x53 -> bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems
xref	0xffffffffc0cc80a0	0xffffffffc0cc6010	data	memlens_testhook.th_kill_ops -> memlens_testhook.th_kill_callback
xref	0xffffffffc0cd00d9	0xffffffffb0a0c740	call	memlens_target_ffffffffc0cd0000+0xd9 -> ftrace_ops_assist_func
xref	0xffffffffc0cd0162	0xffffffffc0cc80a0	data	memlens_target_ffffffffc0cd0000+0x162 -> memlens_testhook.th_kill_ops
xref	0xffffffffc0cd20d9	0xffffffffb0894ed0	call	memlens_target_ffffffffc0cd2000+0xd9 -> kprobe_ftrace_handler
xref	0xffffffffc0cd2162	0xffffffffb26670e0	data	memlens_target_ffffffffc0cd2000+0x162 -> kprobe_ftrace_ops
rename	0xffffffffc01a0940	memlens_target_ffffffffc01a0940	bpf_tramp_bpf_lsm_file_open
rename	0xffffffffc0cd0000	memlens_target_ffffffffc0cd0000	ftrace_tramp___x64_sys_kill
rename	0xffffffffc0cd2000	memlens_target_ffffffffc0cd2000	kprobe_ftrace_tramp___x64_sys_getdents64
owner	0xffffffffc01a0940	0xffffffffc01a0668	bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)
owner	0xffffffffc0cd0000	0xffffffffc0cc6010	memlens_testhook.th_kill_callback (ftrace_ops memlens_testhook.th_kill_ops)
owner	0xffffffffc0cd2000	0xffffffffc0cc6040	memlens_testhook.th_getdents_pre (kprobe pre_handler)
```

The **Show patched kernel functions** list for this `kernel.elf`, all six columns, as the plugin code builds it (run with fake IDA modules by `tests/test_hookchain_stub.py`, not in IDA; columns separated by `|` and aligned here; the list gives the patched functions in address order):

```
Address          | Where                | What                          | Target                                   | Handler                                   | Owner
FFFFFFFFB08DCAC0 | __x64_sys_kill       | call to memory with no symbol | ftrace_tramp___x64_sys_kill              | ftrace_ops_assist_func (ftrace)           | memlens_testhook.th_kill_callback (ftrace_ops memlens_testhook.th_kill_ops)
FFFFFFFFB0AF9250 | bpf_lsm_file_open    | call to memory with no symbol | bpf_tramp_bpf_lsm_file_open              | __bpf_tramp_enter (BPF trampoline)        | bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems (BPF program)
FFFFFFFFB0C65950 | __x64_sys_getdents64 | call to memory with no symbol | kprobe_ftrace_tramp___x64_sys_getdents64 | kprobe_ftrace_handler (kprobe via ftrace) | memlens_testhook.th_getdents_pre (kprobe pre_handler)
```

The kprobe on `__x64_sys_getdents64` runs through ftrace too, so its page's `ftrace_ops` is the shared `kprobe_ftrace_ops`; the Owner comes from the kernel's kprobe list in the export (`.memlens.kprobes`), whose probe at `__x64_sys_getdents64+0x4` has the module's `pre_handler`. The guest's own view right before the dump (tracefs `enabled_functions`, the kprobes list and `/proc/kallsyms`) is in [tests/vm/testhook/hook-truth-guest.txt](../tests/vm/testhook/hook-truth-guest.txt).

## Details

A memory image holds the live kernel: its modules and its patched code. In full:

- **`kernel.elf`**: the kernel image and every loaded module, at their real KASLR-adjusted addresses, with a full symbol table (module symbols are named `nf_tables.nft_do_chain`; a tool that does not allow `.` in names may show `_` instead). It is an ordinary ELF: binutils and Ghidra 12.2 load it with no custom loader, and IDA's own ELF loader is meant to open it the same way (not yet tried in IDA).
- **Every kernel type**: all structs, unions and enums from a Volatility 3 ISF, generated as one C header with exact layouts.
- **Typed globals**: kernel data symbols get their real type, so `init_task` becomes a `struct task_struct` (the declarations compile with gcc; applying them in IDA is part of the untested layer).
- **Per-CPU variables, one copy per CPU**: the kernel keeps a private copy of variables such as `runqueues` and the current task for every CPU. `kernel.elf` holds each CPU's live copy as section `.percpu.cpu<N>` (`.percpu.cpu<N>.0`, `.1`, ... if part of that area is missing from the image; a CPU whose area is missing entirely is left out), with symbols `cpu<N>.<name>` (`cpu0.runqueues`, `cpu1.pcpu_hot`, ...), and **Apply kernel types** types every copy. In the demo, `cpu0.pcpu_hot` (Linux 6.12; `cpu0.current_task` on 6.1 and 7.0) points to `init_task`, CPU 0's idle task, each CPU's `this_cpu_off` holds that CPU's own offset, and `cpu0.fixed_percpu_data` holds the stack canary. These areas sit below the kernel image, so Ghidra shows the lowest per-CPU address as the image base; IDA may do the same (not tried). `--no-percpu` on the command line writes the old layout, byte for byte.
- **A list of patched kernel functions**: named functions whose entry (or the instruction after `endbr64` or the NOP the kernel seals it with) was rewritten to a 5-byte `call`/`jmp` (ftrace and BPF trampolines, ftrace-based kprobes, calls into unmapped memory or from the kernel into a module) or to an `int3` breakpoint, or to an absolute-address hook (`jmp [rip+0]` + address, `movabs` + `jmp`/`call reg`, `push imm32; ret`; these also after the ftrace NOP), a `call`/`jmp` after the ftrace NOP or through a pointer in memory (`[rip+disp32]`) that lands in memory with no symbol or goes from the kernel into a module, plus syscall table slots that leave the handlers. Patches deeper inside a function are not found, and functions without a symbol are not checked. Enter should jump to the function. Hook code in memory that belongs to no module is copied into the ELF, so you can read it, and the list names the handler each copied hook page calls when its role is known (ftrace, kprobe via ftrace, BPF trampoline, or a module's function: module callback). In IDA, MemLens also links the hook chain: a code cross-reference from each hooked entry to its hook page and from the page's first named call to that function, a name for each copied hook page whose role is known (`ftrace_tramp_vfs_getattr`, `module_hook___x64_sys_kill`), a Handler column in the list and the list's Edit command (usually Ctrl+E) to jump to the handler. An Owner column says who put the hook there: the BPF program a BPF trampoline runs, the `ftrace_ops` an ftrace trampoline loads and its callback, or the module callback a hook page calls. It comes with xrefs that lead there and the list's Insert command (**Jump to owner**). All of this is written against the IDAPython API and checked with fake IDA modules only.
