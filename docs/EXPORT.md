# When the export fails, and an ISF for your own image

Part of the MemLens documentation; start with the [README](../README.md).

The export itself, on the demo image, is in the README under [Export it yourself](../README.md#export-it-yourself).

## When the export fails

Volatility 2.28.2 prints the same error, byte for byte, for a wrong ISF, for no ISF and for a file that is not a memory image ("A translation layer requirement was not fulfilled ... A symbol table requirement was not fulfilled"). After that error MemLens runs `vol -q -f <image> banners.Banners` (it reads the whole image: about 6 to 20 s for the 1 GB demo image on our machine, depending on load and on whether the file is already in the OS cache, so a larger image takes longer; Cancel stops it and the dialog still shows Volatility's error), reads the ISF's own `linux_banner`, and the dialog says which case it is:

- An ELF file that is not a core dump (for example the demo `kernel.elf`, ELF type EXEC): it is not a memory image, so no banner scan runs (banners.Banners would find the kernel's lines in a kernel file too). The dialog says to open a kernel file from disk in IDA directly and use Apply kernel types.
- The file is shorter than its own ELF or LiME headers say (ELF: the end of the last `PT_LOAD`; LiME: the chain of range headers): it is probably an incomplete copy, so copy or download it again. This is checked first and no banner scan runs, because banners.Banners silently misses kernel lines near the end of a cut file: on the first 125 MB of the demo `trace.elf` it lists only a variant of the line (`# SMP` for `#1 SMP`), though the kernel's own line is in that part.
- No `Linux version` line in the file: Volatility found no Linux kernel in it, so it is probably not a Linux memory image. The dialog lists what Volatility 2.28.2 reads (from its layer list and its file opener): raw images, LiME, 64-bit ELF core dumps, VMware `.vmem` (read as a raw image; its `.vmss` or `.vmsn` next to it is needed for the right layout), QEMU suspend images and Xen core dumps, and xz, gzip or bzip2 compressed copies of these (named `.xz`, `.gz` or `.bz2`; Volatility decompresses them itself, which is slow: `banners.Banners` on an xz copy of the demo image took 123 s here); AVML needs the snappy library.
- The ISF's line is not among the image's: the ISF was built for another kernel. Both are shown; with the Debian 12 ISF on the demo `trace.elf` (lines shortened here):
  ```
  ISF: Linux version 6.1.0-54-amd64 (debian-kernel@lists.debian.org) ... Debian 6.1.190-1 (2026-10-16)
  Image: Linux version 6.12.115+deb13.1-amd64 (...) #1 SMP PREEMPT_DYNAMIC Debian 6.12.115-2 (2026-11-01)
  Image: Linux version 6.12.115+deb13.1-amd64 (...) # SMP PREEMPT_DYNAMIC Debian 6.12.115-2 (2026-11-01)
  Image: Linux version 6.12.115+deb13.1-amd64 (...) #1 SMP PREEMPT_DYNAMIC Debian 6.12.115-2 (2026-11-01)1)
  ```
  An image can hold several such lines (the demo image has 4, 3 of them different), so up to 3 are shown, most frequent first. MemLens does not say which one is the running kernel.
- The ISF's line is among the image's: banners.Banners also lists copies of a line (for example `MESSAGE=<line>` in the systemd journal of an earlier boot), but Volatility only matches the line as the kernel stores it, followed by a newline and a NUL byte. So MemLens then looks for exactly those bytes in the image file (at most one more read of the file, 0.1 to 5 s for the 1 GB demo image here; Cancel stops it). Found: the ISF fits a kernel in the image and Volatility failed for another reason. Not found: the line is only a copy and the ISF was built for another kernel; the dialog lists the ISF's line among the image's, marked `(the ISF's, only a copy)`, also when it is not among the 3 most frequent. A compressed file (xz, gzip, bzip2, AVML, zip) cannot be checked this way, so the dialog then names both causes.
- No ISF chosen: the image's lines, so you know which ISF to get (next section).
- An AVML image that Volatility cannot read because the snappy library is missing: the dialog says so (Volatility's own warning).

These cases were run with real Volatility 2.28.2 (the demo `trace.elf` with a Debian 12 ISF and with none, the demo `kernel.elf` with the Debian 12 ISF, 50 MiB of random bytes with and without the right ISF, an AVML header without snappy, a LiME copy of `trace.elf` with a journal copy of the Debian 12 line planted in it, with the Debian 12 ISF, the first 110 MB and 125 MB of `trace.elf` and 125 MB of its LiME copy, with the right ISF) through the plugin's export code on fake IDA modules, not in real IDA.

## An ISF for your own image

The ISF must come from exactly the kernel that was running when the image was taken.

1. Find that kernel: `vol -q -f <image> banners.Banners` prints its `Linux version ...` line.
2. Get an ISF for that banner. A ready-made one may exist in the community collection [Abyss-W4tcher/volatility3-symbols](https://github.com/Abyss-W4tcher/volatility3-symbols) (Debian, Ubuntu, Kali, AlmaLinux, Rocky): grep your banner line in its [`banners/banners_plain.json`](https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners_plain.json), which gives the ISF's download URL (since 2026-10-20 the ISFs are GitHub Release assets and the old `raw/master/<Distro>/...` paths stop working after 2026-11-21, so use the index). Otherwise build one with [dwarf2json](https://github.com/volatilityfoundation/dwarf2json) from the kernel's debug image: `dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-<version> | xz > <version>.json.xz` (Debian: package `linux-image-<version>-dbg`; Ubuntu: `linux-image-unsigned-<version>-dbgsym` from ddebs.ubuntu.com).
   `python3 tools/find_isf.py <image>` does steps 1 and 2 in one go, without Volatility: it reads the banners from the image's bytes, looks them up in that index (`--download` fetches it once into `~/.cache/memlens/`, or give `--index <file>`; no other network use) and prints the ISF URL with a `curl -LO` line, or on a miss the dwarf2json line and the debug package. Checked by `tests/test_find_isf.py` on a 5-entry index; on the demo `kernel.elf` (Debian 13) it is a miss with the Debian hint, and the Ubuntu 24.04 `6.8.0-147-generic` banner is a hit in the index of 2026-11-13.
3. Export with that ISF ([Usage](USAGE.md#usage) step 1), then apply the same ISF (step 3).
