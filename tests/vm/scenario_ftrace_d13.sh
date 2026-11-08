# Sample for the patched-function view: only standard kernel tracing, no modules. Truth = tracefs enabled_functions.
mount -t tracefs tracefs /sys/kernel/tracing 2>&1 | tail -1
cd /sys/kernel/tracing
echo vfs_getattr > set_ftrace_filter
echo function > current_tracer
echo 'p:memlens_kp do_sys_openat2' > kprobe_events
echo 1 > events/kprobes/memlens_kp/enable
ls /etc > /dev/null; stat /etc > /dev/null
uname -r
echo HOOK_TRUTH_BEGIN; cat enabled_functions; echo HOOK_TRUTH_END
sync; sleep 2
