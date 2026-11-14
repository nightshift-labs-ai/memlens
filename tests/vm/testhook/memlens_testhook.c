// SPDX-License-Identifier: GPL-2.0
/*
 * memlens_testhook: a TEST module for the memlens hook-owner demo.
 *
 * It attaches to two syscall entry points with the public kernel APIs that
 * tracers use (and that ftrace-based rootkits use too), and only counts calls:
 *   1. an ftrace callback (register_ftrace_function) on __x64_sys_kill;
 *   2. a kprobe with a pre_handler on __x64_sys_getdents64.
 * It does not change arguments, return values or control flow, and it hides
 * nothing. Load with insmod, unload with rmmod.
 */
#include <linux/module.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include <linux/string.h>

static atomic64_t th_kill_calls = ATOMIC64_INIT(0);
static atomic64_t th_getdents_calls = ATOMIC64_INIT(0);
static unsigned char th_kill_filter[] = "__x64_sys_kill";

static void notrace th_kill_callback(unsigned long ip, unsigned long parent_ip,
				     struct ftrace_ops *op,
				     struct ftrace_regs *fregs)
{
	atomic64_inc(&th_kill_calls);
}

static struct ftrace_ops th_kill_ops = {
	.func = th_kill_callback,
	.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION,
};

static int th_getdents_pre(struct kprobe *p, struct pt_regs *regs)
{
	atomic64_inc(&th_getdents_calls);
	return 0;
}

static struct kprobe th_getdents_kp = {
	.symbol_name = "__x64_sys_getdents64",
	.pre_handler = th_getdents_pre,
};

static int __init th_init(void)
{
	int ret;

	ret = ftrace_set_filter(&th_kill_ops, th_kill_filter,
				strlen(th_kill_filter), 0);
	if (ret)
		return ret;
	ret = register_ftrace_function(&th_kill_ops);
	if (ret)
		goto free_filter;
	ret = register_kprobe(&th_getdents_kp);
	if (ret)
		goto unreg_ftrace;
	pr_info("memlens_testhook: ftrace callback on __x64_sys_kill, kprobe on __x64_sys_getdents64 (counting only)\n");
	return 0;

unreg_ftrace:
	unregister_ftrace_function(&th_kill_ops);
free_filter:
	ftrace_free_filter(&th_kill_ops);
	return ret;
}

static void __exit th_exit(void)
{
	unregister_kprobe(&th_getdents_kp);
	unregister_ftrace_function(&th_kill_ops);
	ftrace_free_filter(&th_kill_ops);
	pr_info("memlens_testhook: unloaded (kill %lld, getdents64 %lld calls counted)\n",
		(long long)atomic64_read(&th_kill_calls),
		(long long)atomic64_read(&th_getdents_calls));
}

module_init(th_init);
module_exit(th_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("memlens test fixture: counts calls through an ftrace callback and a kprobe");
