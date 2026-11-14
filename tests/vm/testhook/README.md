# memlens_testhook: test module for the hook-owner demo

A small kernel module used only to make a memory image with module-owned hooks.
It attaches to two syscall entry points with public kernel APIs and only counts calls:

| Hook | API | Callback (what the Owner column should name) |
|---|---|---|
| `__x64_sys_kill` | `register_ftrace_function` (flags `RECURSION`, so ftrace calls it through `ftrace_ops_assist_func`, and `SAVE_REGS`; no `IPMODIFY`, so it cannot redirect the call: tracefs shows `R` without `I`) | `memlens_testhook.th_kill_callback` |
| `__x64_sys_getdents64` | `register_kprobe` with a `pre_handler` (on an ftrace site, so the kprobe runs via ftrace) | `memlens_testhook.th_getdents_pre` |

These are the same APIs that tracers use, and that ftrace-based rootkits use. This module does not change arguments,
return values or control flow, and it hides nothing. It does not patch `sys_call_table`: since Linux 6.9, x86-64
dispatches syscalls through `x64_sys_call()`, so a table slot hook would be inert on this 6.12 kernel.

## Build (against the guest's kernel, on the host)

Run in this folder. The Debian 13 packages for 6.12.115+deb13.1-amd64 are in deb.debian.org `pool/main/l/linux/`
until a newer kernel replaces them, then in snapshot.debian.org.

```
ROOT=$PWD/root
# linux-headers-6.12.115+deb13.1-amd64_6.12.115-2_amd64.deb, linux-headers-6.12.115+deb13.1-common_6.12.115-2_all.deb,
# linux-kbuild-6.12.115+deb13.1_6.12.115-2_amd64.deb downloaded here:
for d in *.deb; do dpkg -x "$d" "$ROOT"; done
H=$ROOT/usr/src/linux-headers-6.12.115+deb13.1-amd64
echo "include $ROOT/usr/src/linux-headers-6.12.115+deb13.1-common/Makefile" > $H/Makefile   # it names /usr/src/... otherwise
# The kernel was built with gcc-14 (it needs -fmin-function-alignment), so use gcc-14:
make -C $H M=$PWD CC=x86_64-linux-gnu-gcc-14 PAHOLE=true modules
mkdir -p disk && strip --strip-debug -o disk/memlens_testhook.ko memlens_testhook.ko
mke2fs -q -t ext2 -d disk th.img 4M
```

`PAHOLE=true` skips the module's own BTF (not needed here). The module is unsigned; the Debian kernel loads it
(`CONFIG_MODULE_SIG_FORCE` is off) and marks itself tainted. The VM boots with SeaBIOS (no Secure Boot); under
Secure Boot this kernel locks down and refuses unsigned modules.

## Capture

`../scenario_testhook_d13.sh` runs in the guest (Debian 13 nocloud image 20261103-2651, root password emptied,
`systemd-firstboot` masked), with `th.img` as a second virtio disk, and the memory is dumped with QEMU's
`dump-guest-memory`: the monitor command `dump-guest-memory /path/to/image.elf` (no options), which writes an ELF core
(`readelf -h`: Type CORE, Machine X86-64).
