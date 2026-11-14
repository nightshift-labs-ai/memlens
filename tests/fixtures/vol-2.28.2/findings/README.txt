Real Volatility 3 Framework 2.28.2 JSON output (the vol3 venv here: pip volatility3 2.28.2, Python 3.12.3, Linux),
recorded 2026-11-14 with record.sh in this folder. tests/test_volfind_stub.py reads these files: they are what the action
"MemLens: Add Volatility hook findings (JSON)" reads, and every file is kept as Volatility wrote it (nothing trimmed).

Images (both public, see the README):
  trace.elf     the demo's 1 GB memory image (trace.elf.xz in the Volatility samples release),
                sha256 ed26d7a0a7a643865fe98a6330db07d56070ecc8c2de995e1126e24856d04d58
  testhook.elf  the second sample's 528 MB memory image (testhook.elf.xz, same release),
                sha256 f840569f3b1f143d9adae7b286846cbb781cd7d8b1ff014ab1f1d973dd566e80
ISF: debian-6.12.115+deb13.1-amd64.json.xz (the demo zip's), in <symbols>/linux/.

Command lines (record.sh; <image> is trace.elf for demo/, testhook.elf for testhook/; stdout as written):
  vol -q -s <symbols> -f <image> -r json linux.tracing.tracepoints.CheckTracepoints            > tracepoints.json
  vol -q -s <symbols> -f <image> -r json linux.malware.keyboard_notifiers.Keyboard_notifiers   > keyboard_notifiers.json
  vol -q -s <symbols> -f <image> -r json linux.malware.check_idt.Check_idt                     > check_idt.json
  vol -q -s <symbols> -f <image> -r json linux.malware.check_afinfo.Check_afinfo               > check_afinfo.json
  vol -q -s <symbols> -f <image> -r json linux.malware.netfilter.Netfilter                     > netfilter.json
  vol -q -s <symbols> -f <image> -r json linux.tracing.ftrace.CheckFtrace --show-ftrace-flags  > ftrace-flags.json
All 12 runs exited 0 (182 s together on this machine); each printed "Volatility 3 Framework 2.28.2" on stderr and
nothing else there.

Rows per file (demo / testhook):
  tracepoints.json         3 / 0   (demo: sched_wakeup, sched_wakeup_new, sched_switch; the tracer's own probes)
  keyboard_notifiers.json  0 / 0
  check_idt.json          21 / 21  (vectors 0x0-0x13 and 0x80, as the plugin checks them)
  check_afinfo.json        0 / 0   (the plugin lists a member only when no kernel symbol starts at its handler)
  netfilter.json           2 / 2   ("Is Hooked": "False", a string, as printed)
  ftrace-flags.json        3 / 3
testhook/ftrace-flags.json is byte for byte the th.ftrace.json the s194 review recorded with the same command.

not-read/tty_check.json: a plugin MemLens does not read, recorded the same way on trace.elf (2026-11-14, exit 0, 17.7 s):
  vol -q -s <symbols> -f trace.elf -r json linux.malware.tty_check.Tty_Check                    > tty_check.json
Its fields (Name, Address, Module, Symbol) hold all three of keyboard notifiers' (Address, Module, Symbol), so the test
checks that MemLens skips it with one warning line instead of reading its 3 rows (ttyS0, tty1, tty6 at
n_tty_receive_buf) as keyboard notifiers.

Volatility prints kernel addresses cut to 48 bits: JSON 281473643531984 is 0xffffb0894ed0, for 0xffffffffb0894ed0.
The field names are the plugins' TreeGrid column names in 2.28.2 (an empty file, "[]", has none).
