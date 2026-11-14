# memlens_testhook: test module for the hook-owner demo

A small kernel module used only to make a memory image with module-owned hooks.
It attaches to two syscall entry points with public kernel APIs and only counts calls:

| Hook | API | Callback (what the Owner column should name) |
|---|---|---|
| `__x64_sys_kill` | `register_ftrace_function` (flags `SAVE_REGS` + `RECURSION`, so ftrace calls it through `ftrace_ops_assist_func`) | `memlens_testhook.th_kill_callback` |
| `__x64_sys_getdents64` | `register_kprobe` with a `pre_handler` (on an ftrace site, so the kprobe runs via ftrace) | `memlens_testhook.th_getdents_pre` |

These are the same APIs that tracers use, and that ftrace-based rootkits use. This module does not change arguments,
return values or control flow, and it hides nothing. It does not patch `sys_call_table`: since Linux 6.9, x86-64
dispatches syscalls through `x64_sys_call()`, so a table slot hook would be inert on this 6.12 kernel.

## Build (against the guest's kernel, on the host)

```
# Debian 13 headers for 6.12.115+deb13.1-amd64 (deb.debian.org pool/main/l/linux/):
#   linux-headers-6.12.115+deb13.1-amd64, linux-headers-6.12.115+deb13.1-common, linux-kbuild-6.12.115+deb13.1
# unpacked with dpkg -x into $ROOT; point $ROOT/usr/src/linux-headers-6.12.115+deb13.1-amd64/Makefile at the unpacked -common/Makefile.
# The kernel was built with gcc-14 (it needs -fmin-function-alignment), so use gcc-14.
make -C $ROOT/usr/src/linux-headers-6.12.115+deb13.1-amd64 M=$PWD CC=x86_64-linux-gnu-gcc-14 PAHOLE=true modules
strip --strip-debug -o disk/memlens_testhook.ko memlens_testhook.ko
mke2fs -q -t ext2 -d disk th.img 4M
```

`PAHOLE=true` skips the module's own BTF (not needed here). The module is unsigned; the Debian kernel loads it
(`CONFIG_MODULE_SIG_FORCE` is off) and marks itself tainted.

## Capture

`../scenario_testhook_d13.sh` runs in the guest (Debian 13 nocloud image 20261103-2651, root password emptied,
`systemd-firstboot` masked), with `th.img` as a second virtio disk, and the memory is dumped with QEMU's
`dump-guest-memory`.
