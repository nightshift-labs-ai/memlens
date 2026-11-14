# Sample for the hook-owner view: the TEST module tests/vm/testhook/memlens_testhook.c hooks __x64_sys_kill (ftrace callback) and __x64_sys_getdents64 (kprobe pre_handler) and only counts calls. Guest: Debian 13 nocloud 20261103-2651 (kernel 6.12.115+deb13.1-amd64), module on a second virtio disk (/dev/vdb). Truth = tracefs enabled_functions + debugfs kprobes/list.
mount -t tracefs tracefs /sys/kernel/tracing 2>&1 | tail -1
mount -t debugfs debugfs /sys/kernel/debug 2>&1 | tail -1
mkdir -p /mnt/th && mount -o ro /dev/vdb /mnt/th && echo MOUNT_OK
insmod /mnt/th/memlens_testhook.ko && echo INSMOD_OK
kill -0 1; kill -0 $$; ls / > /dev/null; ls /etc > /dev/null
dmesg | grep memlens_testhook
uname -r
grep memlens_testhook /proc/modules
echo HOOK_TRUTH_BEGIN; cat /sys/kernel/tracing/enabled_functions; cat /sys/kernel/debug/kprobes/list; echo HOOK_TRUTH_END
grep -E ' th_(kill_callback|getdents_pre|kill_ops|getdents_kp)' /proc/kallsyms
sync; sleep 2
