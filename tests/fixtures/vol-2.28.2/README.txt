Real Volatility 3 Framework 2.28.2 output (pip install volatility3==2.28.2, Python 3.12, Linux), recorded
2026-11-12, each run with a fresh empty Volatility cache (XDG_CACHE_HOME). <name>.stdout and <name>.stderr are the
bytes vol wrote. tests/test_export_failure_stub.py replays them.

Images:
  trace.elf        the public 1 GB memory image of the Debian 13 demo VM (kernel 6.12.115+deb13.1-amd64)
  kernel.elf       the demo kernel.elf (a kernel file exported by MemLens, not a memory image)
  random.bin       50 MiB of pseudo-random bytes (Python random.Random(157).randbytes)
  header_only.avml 8 MiB: the 8-byte AVML v2 header ("AVML", version 2), then random bytes; no libsnappy installed
  random_with_banner.bin  50 MiB random bytes with the Debian 13 ISF's linux_banner (with its "\n\0") at 0x100000
  journal_copy.lime       trace.elf converted to LiME (same ranges), with one systemd journal DATA object
                          "MESSAGE=<the Debian 12 ISF's line>" then NUL bytes planted in a zero page at 0x30000000
                          (a copy of an earlier boot's kernel line; the image's own journal holds such a copy of its
                          kernel's line at 0xc066ae8). Made by a code review (s158), recorded 2026-11-12.
ISFs (copied into <symbols>/linux/ as MemLens does):
  Debian 13  debian-6.12.115+deb13.1-amd64.json.xz (the demo ISF, matches trace.elf)
  Debian 12  debian-6.1.0-54.json.xz (another kernel: wrong for trace.elf)

name                          exit  seconds  command (vol -q ...)
banners_trace                 0     13.8     -f trace.elf banners.Banners
banners_kernel_file           0     5.8      -f kernel.elf banners.Banners
banners_random                0     5.9      -f random.bin banners.Banners
banners_avml_header           0     4.1      -f header_only.avml banners.Banners
export_trace_wrong_isf        1     9.3      -p <memlens>/vol_plugins -s <Debian 12> -o <out> -f trace.elf linux.kernel2elf.Kernel2Elf
export_kernel_file_wrong_isf  1     7.8      -p <memlens>/vol_plugins -s <Debian 12> -o <out> -f kernel.elf linux.kernel2elf.Kernel2Elf
export_random_isf             1     7.3      -p <memlens>/vol_plugins -s <Debian 13> -o <out> -f random.bin linux.kernel2elf.Kernel2Elf
export_trace_no_isf           1     5.7      -p <memlens>/vol_plugins -o <out> -f trace.elf linux.kernel2elf.Kernel2Elf
export_random_no_isf          1     5.2      -p <memlens>/vol_plugins -o <out> -f random.bin linux.kernel2elf.Kernel2Elf
export_avml_header_isf        1     5.1      -p <memlens>/vol_plugins -s <Debian 13> -o <out> -f header_only.avml linux.kernel2elf.Kernel2Elf
export_random_with_banner_isf 0     32.7     -p <memlens>/vol_plugins -s <Debian 13> -o <out> -f random_with_banner.bin linux.kernel2elf.Kernel2Elf
banners_journal_copy          0     11.5     -f journal_copy.lime banners.Banners
export_journal_copy_wrong_isf 1     7.4      -p <memlens>/vol_plugins -s <Debian 12> -o <out> -f journal_copy.lime linux.kernel2elf.Kernel2Elf

The six failed exports other than AVML print byte-identical stdout and stderr: Volatility's text cannot tell a wrong
ISF from no ISF or from a file that is not a memory image. random_with_banner.bin is not a failure: Volatility exits 0
and writes an ELF with 0 bytes of .text.
