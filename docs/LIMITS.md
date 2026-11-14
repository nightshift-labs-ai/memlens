# Limits

Part of the MemLens documentation; start with the [README](../README.md).

- x86-64 Linux only.
- Bitfields are kept as raw bytes, with their names and positions in a comment.
- Function pointers become `void *`.
- No function prototypes: an ISF gives functions no parameter types. Most kernels also carry BTF, which has them, and our companion plugin [btf2ida](https://github.com/nightshift-labs-ai/btf2ida) finds it inside `kernel.elf` and applies prototypes by name. Measured outside IDA on the demo `kernel.elf`: the BTF is found by carving in 0.3 s, holds 50,366 function prototypes, and matches 46,904 of the 51,116 kernel function symbols that have no module prefix, compiler suffix or `__pfx_` padding prefix (91.8%). Running both plugins on one database has not been tried in IDA.
- Kernel symbols that are not mapped in the image, such as freed init code, are left out.
- An ISF keeps one type per name, while the kernel has some same-named local structs. Where a type cannot fit its offset, the member is emitted as raw bytes with a comment.
- **Hook kinds MemLens does not scan.** MemLens finds rewritten function entries and syscall-table slots (`scan_functions` and `scan_syscalls` in `patchscan.py`), nothing else: `patchscan.py`, `memlens_entry.py` and the exporter never mention tracepoints, notifiers, the IDT, netfilter, afinfo or file operations. Volatility 3 2.28.2 has plugins for these: `linux.tracing.tracepoints`, `linux.malware.check_idt`, `linux.malware.keyboard_notifiers` (the keyboard notifier chain), `linux.malware.netfilter`, `linux.malware.check_afinfo` (network protocols' file and seq ops) and `linux.malware.tty_check` (tty ops). BPF programs that are not attached through a trampoline, such as the 12 cgroup programs `linux.ebpf` lists in each public capture, get a name in `kernel.elf` (`bpf.bpf_prog_<tag>_<name>`) but no row in the list, and neither tool says where they are attached. How the two tools compare on the public captures: [README, What Volatility already tells you](../README.md#what-volatility-already-tells-you).
- **Modules hidden from the module list are not exported.** The exporter takes the modules from Volatility's module list (`Modules.list_modules`). A module that unlinked itself from that list, as rootkits do, is not in `kernel.elf`: its hooks are still listed, because MemLens reads the rewritten entries and the trampolines, but the owner shows as an address with no name. Measured on a copy of the second sample's image (`testhook.elf`) in which `memlens_testhook` was unlinked from `modules` by rewriting four list pointers, as `list_del` does (an edit of the file, Volatility 2.28.2; how such an edit behaves on a live system was not tested):

  | | Original image | Copy with the module unlinked |
  |---|---|---|
  | `linux.lsmod` | lists `memlens_testhook` | does not list it |
  | `linux.malware.hidden_modules` | no rows | `memlens_testhook` (Offset `0xffffc0cc81c0`, as printed) |
  | `linux.tracing.ftrace`, the module's ops | Callback `-`, Module `memlens_testhook` | the same row |
  | MemLens export | 70 modules, 234,115 symbols | 69 modules, 234,095 symbols |
  | Owner of `__x64_sys_kill` | `memlens_testhook.th_kill_callback (ftrace_ops memlens_testhook.th_kill_ops)` | `ftrace_ops at 0xffffffffc0cc80a0 (no symbol: module memory MemLens did not export)` |
  | Owner of `__x64_sys_getdents64` | `memlens_testhook.th_getdents_pre (kprobe pre_handler)` | `kprobe pre_handler at 0xffffffffc0cc6040 (no symbol)` |

  The three patched rows, the three renamed hook pages and the BPF owner are the same in both. Here Volatility names the module and MemLens does not.
