Real Volatility 3 Framework 2.28.2 output (pip install volatility3==2.28.2, Python 3.12, Linux) and MemLens output, recorded
2026-11-14. tests/test_compare.py checks the README section "What Volatility already tells you" and the hidden-module rows
of docs/LIMITS.md against these files, and, when MEMLENS_DEMO_ELF and MEMLENS_TESTHOOK_ELF name the two demo kernel.elf
files, against patchscan.py --links on them.

Images (both public, see the README):
  trace.elf     the demo's 1 GB memory image (trace.elf.xz in the Volatility samples release), sha256 ed26d7a0...4d58
  testhook.elf  the second sample's 528 MB memory image (testhook.elf.xz, same release), sha256 f840569f...6e80
ISF: debian-6.12.115+deb13.1-amd64.json.xz (the demo zip's), in <symbols>/linux/.

Files made by record.sh (vol -q -s <symbols> -f <image> -r pretty <plugin>; stdout as written):
  demo.ftrace.txt / th.ftrace.txt               linux.tracing.ftrace.CheckFtrace
  demo.ftrace-flags.txt / th.ftrace-flags.txt   linux.tracing.ftrace.CheckFtrace --show-ftrace-flags
  demo.ebpf.txt / th.ebpf.txt                   linux.ebpf.EBPF
  th.hidden_modules.txt                         linux.malware.hidden_modules.Hidden_modules
  plugins.txt                                   the first line of vol -h and its linux.* plugin names (59)
All runs exited 0. Every file here but plugins.txt (the edited copies' files too) is byte for byte what the s194 review
recorded on 2026-11-14 with the same commands, except that the s194 review and the edited copy used the old name
linux.hidden_modules.Hidden_modules. Volatility 2.28.2 says that name has been renamed and will be removed in the first
release after 2026-06-07; th.hidden_modules.txt re-recorded with linux.malware.hidden_modules.Hidden_modules (2026-11-14)
is byte for byte the same.
Volatility prints kernel addresses cut to 48 bits (0xffffc0cc80a0 is 0xffffffffc0cc80a0).

Files from edited copies of testhook.elf (offline edits of the image file, made to see what each tool shows when a
kernel list is edited; how such an edit behaves on a live system was not tested):
  module unlinked: memlens_testhook removed from the `modules` list, four list pointers rewritten as list_del does
    (modules.next, the next module's list.prev, the module's own list.next/prev set to LIST_POISON)
      th-module-unlinked.ftrace.txt          linux.tracing.ftrace.CheckFtrace
      th-module-unlinked.hidden_modules.txt  linux.hidden_modules.Hidden_modules (the old name of the same plugin)
      th-module-unlinked.owners.txt          the owner lines of patchscan.py --links on that copy's MemLens export
                                             (69 modules, 234,095 symbols; the original image's export: 70, 234,115)
  ops unlinked: kprobe_ftrace_ops.next rewritten to skip memlens_testhook's th_kill_ops on ftrace_ops_list (one pointer)
      th-ops-unlinked.ftrace.txt             linux.tracing.ftrace.CheckFtrace
      th-ops-unlinked.owners.txt             the owner lines of patchscan.py --links on that copy's MemLens export
                                             (the whole --links output is identical to the original's)
