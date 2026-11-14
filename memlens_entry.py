"""MemLens: reverse engineer a Linux kernel from a memory image in IDA.

Three actions under Edit > Plugins:
  * Export kernel from memory image: runs Volatility 3 and writes a symbolled ELF to open in IDA.
  * Apply kernel types from ISF: imports every struct, union and enum of that kernel.
  * Show patched kernel functions: lists hooked entries and odd syscall slots, Enter jumps there; links each hooked
    entry to its hook page and the page to its handler (code xrefs) and to its owner (the BPF program, or the
    ftrace_ops and its callback), and names the hook pages by role.
"""
import base64
import hashlib
import itertools
import json
import traceback
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

import ida_bytes
import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_name
import ida_netnode
import ida_typeinf
import ida_xref
import idc

ISF_FILTER = "FILTER Volatility ISF|*.json;*.xz;*.gz;*.bz2|All files|*\n"
HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import isf2c  # noqa: E402  (needs the plugin folder on sys.path)
import patchscan  # noqa: E402


def parse_batch(text):
    return idc.parse_decls(text, idc.PT_SIL | idc.PT_PAK1)


def check_sizes(expected):
    """Compare what IDA stored with the ISF. Returns (missing, wrong size) as lists of names."""
    missing, wrong = [], []
    til = ida_typeinf.get_idati()
    for name, size in sorted(expected.items()):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, name):
            missing.append(name)
        elif tif.get_size() != size:
            wrong.append(name)
    return missing, wrong


def isf_linux_banner(isf):
    """The ISF's own kernel version line (its linux_banner constant, up to the NUL), or None if it has none."""
    data = (isf.get("symbols", {}).get("linux_banner") or {}).get("constant_data")
    return base64.b64decode(data).split(b"\0")[0] if data else None


def banner_mismatch(isf):
    """(ISF banner, database banner) if the ISF was built for another kernel, or (ISF banner, b"") if the database has
    no linux_banner at all (so it may not be a kernel); None if they agree or the ISF has no banner to compare."""
    expected = isf_linux_banner(isf)
    if expected is None:
        return None
    address = idc.get_name_ea_simple("linux_banner")
    if address == idc.BADADDR:
        return (expected, b"")
    actual = ida_bytes.get_bytes(address, len(expected)) or b""
    return None if actual == expected else (expected, actual)


def confirm_other_kernel(expected, actual):
    ida_kernwin.hide_wait_box()
    isf_banner = expected.decode("ascii", "replace").strip()
    if actual:
        text = "This ISF was built for a different kernel, so its types may be wrong here.\n\nISF: %s\nDatabase: %s\n\nImport anyway?" % (
            isf_banner, actual.decode("ascii", "replace").strip())
    else:
        text = ("This database has no linux_banner symbol, so it may not be a Linux kernel (MemLens: Export kernel "
                "writes one).\n\nISF: %s\n\nImport the kernel types anyway?" % isf_banner)
    answer = ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, text.replace("%", "%%"))
    ida_kernwin.show_wait_box("MemLens: importing types")
    return answer == ida_kernwin.ASKBTN_YES


def apply_types(isf_path, confirm=None):
    """Import the ISF's types, type the globals, and check the result against the ISF.

    confirm(expected, actual) decides whether to go on when the ISF's kernel banner differs from the database's;
    returning False stops before anything is imported, and apply_types returns None.
    """
    isf = isf2c.load_isf(isf_path)
    mismatch = banner_mismatch(isf)
    if mismatch and confirm and not confirm(*mismatch):
        return None
    # where Show patched kernel functions reads ops->func and ops->flags, and the FTRACE_OPS_FL_* values: when this ISF
    # has struct ftrace_ops, its keys replace those of an ISF imported before, which may be another kernel's
    layout = isf_layout(isf)
    if "ftrace_ops.func" in layout:  # the struct is there (an ISF with only the enum must not drop the offsets)
        save_layout(dict({key: value for key, value in load_layout().items() if key not in LAYOUT_KEYS}, **layout))
    generator = isf2c.Generator(isf)

    stopped = {}

    def progress(done, total):
        ida_kernwin.replace_wait_box("MemLens: importing types (%d of %d)" % (done, total))
        if ida_kernwin.user_cancelled():
            stopped["at"] = "while importing types, after %d of %d declarations; no global was typed" % (done, total)
            return True
        return False

    rejected = isf2c.import_in_batches(generator.declarations(), parse_batch, progress=progress)
    if stopped:
        return {"stats": dict(generator.stats), "rejected": rejected, "missing": [], "wrong_size": [], "cancelled": stopped["at"]}
    missing, wrong = check_sizes(generator.expected_sizes())
    typed = failed = absent = percpu = code = 0
    decls = isf2c.global_decls(generator, isf)
    cpus = percpu_cpus()
    copies_by_name = percpu_index(cpus) if cpus else None
    if copies_by_name is not None and not any(copies_by_name.values()):
        # IDA can keep names out of its name list; with no copy found there, look each one up as before.
        copies_by_name = None
    for index, (name, declaration) in enumerate(decls):
        if index % 2000 == 0:
            ida_kernwin.replace_wait_box("MemLens: typing globals (%d of %d)" % (index, len(decls)))
            if ida_kernwin.user_cancelled():
                stopped["at"] = "while typing globals, after %d of %d" % (index, len(decls))
                break
        address = idc.get_name_ea_simple(name)
        # A per-CPU variable has one copy per CPU, named cpu<N>.<name> by the exporter. Kernels that link the
        # per-CPU section at a kernel address (Linux 7.0) also keep a plain symbol for the boot template.
        copies = list(percpu_copies(name, cpus, copies_by_name))
        if address == idc.BADADDR and not copies:
            # Most of these have address 0 in the ISF, so the ELF has no symbol for them.
            absent += 1
            continue
        if address != idc.BADADDR and in_code(address):
            # The ISF can name a variable like a kernel function (schedule, strlen): never retype code as data.
            code += 1
            address = idc.BADADDR
            if not copies:
                continue
        ok = True
        if address != idc.BADADDR:
            if idc.SetType(address, declaration + ";"):
                typed += 1
            else:
                ok = False
        if copies:
            if all(idc.SetType(copy, declaration + ";") for copy in copies):
                percpu += 1
            else:
                ok = False
        if not ok:
            failed += 1
    stats = dict(generator.stats, globals_declared=len(decls), globals_typed=typed, globals_failed=failed,
                 globals_not_in_database=absent, percpu_typed=percpu, globals_skipped_code=code)
    result = {"stats": stats, "rejected": rejected, "missing": missing, "wrong_size": wrong}
    if stopped:
        result["cancelled"] = stopped["at"]
    return result


SEGPERM_EXEC = 1  # ida_segment.SEGPERM_EXEC


def in_code(address):
    """True inside an executable segment (the ELF loader sets segment permissions from the program headers)."""
    return bool((idc.get_segm_attr(address, idc.SEGATTR_PERM) or 0) & SEGPERM_EXEC)


# .percpu.cpu<N>, or .percpu.cpu<N>.<k> when the exporter split a partly mapped per-CPU area into several sections.
PERCPU_SEGMENT = re.compile(r"percpu\.cpu(\d+)(?:\.\d+)?$")


def segment_cpu(segment_name):
    """The CPU number of a .percpu.cpu<N> section name ('_' read as '.'), or None."""
    match = PERCPU_SEGMENT.search((segment_name or "").replace("_", "."))
    return int(match.group(1)) if match else None


def percpu_cpus():
    """CPU numbers that have a .percpu.cpu<N> (or split .percpu.cpu<N>.<k>) section in this database, in order.

    The exporter keeps real CPU numbers and leaves out a CPU whose per-CPU area is not in the memory image,
    so the numbers can have gaps. Segment names are compared with '_' read as '.' in case IDA changed them.
    """
    cpus = set()
    ea = idc.get_first_seg()
    while ea is not None and ea != idc.BADADDR:
        cpu = segment_cpu(idc.get_segm_name(ea))
        if cpu is not None:
            cpus.add(cpu)
        ea = idc.get_next_seg(ea)
    return sorted(cpus)


# cpu<N>.<name> as the exporter writes it, or cpu<N>_<name> if IDA stored the '.' as '_'. <N> is written like "%d".
PERCPU_SYMBOL = re.compile(r"cpu(0|[1-9][0-9]*)([._])(.+)$")


def percpu_index(cpus):
    """{name: {cpu: address}} for the per-CPU copies of the listed CPUs, from one pass over the database's names.

    Same rule as the one-by-one lookup in percpu_copies: cpu<N>.<name> anywhere, cpu<N>_<name> only inside that
    CPU's .percpu.cpu<N> section, and the '.' form wins when both exist. One pass instead of two name lookups
    per CPU for every ISF global (about 79,000 globals x 64 CPUs = 10 million lookups on a 64-CPU capture).
    """
    import idautils  # only needed here, so databases without per-CPU sections never touch it

    wanted = set(cpus)
    index = {}
    for address, symbol in idautils.Names():
        match = PERCPU_SYMBOL.match(symbol or "")
        if not match:
            continue
        cpu, separator, name = int(match.group(1)), match.group(2), match.group(3)
        if cpu not in wanted:
            continue
        copies = index.setdefault(name, {})
        if separator == ".":
            copies[cpu] = address  # the exporter's own form: always wins
        elif cpu not in copies and segment_cpu(idc.get_segm_name(address)) == cpu:
            copies[cpu] = address
    return index


def percpu_copy(name, cpu):
    """Address of CPU cpu's copy of name looked up by name, or None.

    cpu<N>.<name> as the exporter writes it; in case IDA stored the '.' as '_', cpu<N>_<name>, but only inside that
    CPU's .percpu.cpu<N> section.
    """
    address = idc.get_name_ea_simple("cpu%d.%s" % (cpu, name))
    if address != idc.BADADDR:
        return address
    address = idc.get_name_ea_simple("cpu%d_%s" % (cpu, name))
    if address != idc.BADADDR and segment_cpu(idc.get_segm_name(address)) == cpu:
        return address
    return None


def percpu_copies(name, cpus=None, index=None):
    """Addresses of cpu<N>.<name> for every CPU in cpus, in CPU order (from index when given, see percpu_index).

    With an index, a name that has no copy in it is not a per-CPU variable; for one that has, a listed CPU missing
    from it is still looked up by name (IDA can keep single names out of its name list). Without per-CPU sections
    (cpus empty or None) the old rule applies: cpu0, cpu1, ... up to the first CPU without one.
    """
    if cpus and index is not None:
        copies = index.get(name)
        if not copies:
            return
        for cpu in cpus:
            address = copies.get(cpu)
            if address is None:
                address = percpu_copy(name, cpu)
            if address is not None:
                yield address
        return
    for cpu in (iter(cpus) if cpus else itertools.count()):
        address = percpu_copy(name, cpu)
        if address is None:
            if cpus:
                continue  # this CPU's copy has no such symbol: try the next CPU
            return
        yield address


def report(result):
    """The import summary, so a user can see exactly what did and did not arrive."""
    stats = result["stats"]
    lines = ["[MemLens] CANCELLED %s: the counts below are partial" % result["cancelled"]] if result.get("cancelled") else []
    parts = ["{:,} structs".format(stats.get("structs", 0)), "{:,} unions".format(stats.get("unions", 0)),
             "{:,} enums".format(stats.get("enums", 0))]
    if stats.get("bitfields_as_storage"):
        parts.append("{:,} bitfields kept as raw storage bytes".format(stats["bitfields_as_storage"]))
    if stats.get("skipped"):
        parts.append("{:,} skipped".format(stats["skipped"]))
    if stats.get("resized"):
        parts.append("{:,} resized to the ISF size".format(stats["resized"]))
    lines.append("[MemLens] declarations generated from the ISF: %s" % ", ".join(parts))
    if "globals_declared" in stats:
        lines.append("[MemLens] typed {:,} of the {:,} globals the ISF declares, plus {:,} per-CPU variables in every CPU's copy; "
                     "{:,} failed; {:,} have no symbol in this database (address 0 in the ISF, or outside exported memory)"
                     .format(stats["globals_typed"], stats["globals_declared"], stats.get("percpu_typed", 0),
                             stats["globals_failed"], stats["globals_not_in_database"]))
    if stats.get("globals_skipped_code"):
        lines.append("[MemLens] left {:,} names alone that the ISF declares as variables but that are code here (for example a function "
                     "with the same name as a variable elsewhere)".format(stats["globals_skipped_code"]))
    lines += ["[MemLens] rejected by IDA's parser: %d" % len(result["rejected"]),
              "[MemLens] types missing afterwards: %d" % len(result["missing"]),
              "[MemLens] types with a size differing from the ISF: %d" % len(result["wrong_size"])]
    lines += ["[MemLens]   rejected: %s" % text.splitlines()[0] for text in result["rejected"][:10]]
    lines += ["[MemLens]   wrong size: %s" % name for name in result["wrong_size"][:10]]
    return "\n".join(lines) + "\n"


def export_command(vol, image, output, symbols=None):
    command = [vol, "-q", "-p", os.path.join(HERE, "vol_plugins"), "-o", output]
    if symbols:
        command += ["-s", symbols]
    return command + ["-f", image, "linux.kernel2elf.Kernel2Elf"]


def symbols_folder(isf_path, parent):
    """Volatility wants <folder>/linux/<isf>; build that around the file the user picked."""
    target = os.path.join(parent, "linux")
    os.makedirs(target, exist_ok=True)
    shutil.copy(isf_path, target)
    return parent


def elf_files(folder):
    try:
        return {name for name in os.listdir(folder) if name.endswith(".elf")}
    except OSError:
        return None  # unknown, not empty: a failed listing must never make an old file look new (code review s170 n-2)


def written_file(stdout, folder=None, before=None):
    """The file Volatility really wrote. If kernel.elf already exists Volatility picks a new name (kernel-1.elf)
    when it closes the file. kernel2elf prints its row after the close since 0.3.16; older copies printed it
    before, so the folder is still trusted over the row."""
    now = elf_files(folder) if folder is not None and before is not None else None
    if now is not None:
        new = sorted(now - before)
        if len(new) == 1:
            return new[0]
    for line in stdout.decode("utf-8", "replace").splitlines():
        cells = line.split("\t")
        if len(cells) > 1 and cells[0].strip() == "written":
            return cells[1].strip()
    return "kernel.elf"


def remove_unusable(folder, name, before):
    """Remove an unusable export so nobody opens it by mistake, but only a file that was not in the folder before the
    export (before = elf_files(folder) then); returns the sentence for the dialog (judge s160 finding 6)."""
    now = elf_files(folder)
    if before is None or now is None:
        return "MemLens could not list that folder to check that the file is new, so MemLens left it in place; do not open it."
    if name not in now - before:
        return "It is not a new file in that folder, so MemLens left it in place."
    try:
        os.remove(os.path.join(folder, name))
    except OSError as error:
        return "MemLens could not remove it (%s); do not open it." % error
    return "MemLens removed it, so it cannot be opened by mistake."


def export_rows(stdout):
    """kernel2elf's rows (kind, name, address, count) from Volatility's tab-separated text output."""
    rows = []
    for line in stdout.decode("utf-8", "replace").splitlines():
        cells = [cell.strip() for cell in line.split("\t")]
        if len(cells) >= 4:
            try:
                rows.append((cells[0], cells[1], cells[2], int(cells[3])))
            except ValueError:
                pass  # the header line and anything else that is not a row
    return rows


def export_problems(stdout):
    """Reasons an export that Volatility finished without an error is still not a usable live kernel."""
    rows = export_rows(stdout)
    problems = []
    text = [count for kind, name, _, count in rows if kind == "section" and name.startswith(".text")]
    written = [count for kind, _, _, count in rows if kind == "written"]
    if (text and not sum(text)) or (written and not written[0]):
        problems.append("Volatility copied no kernel code from this file (.text: 0 bytes), so the ELF it wrote is "
                        "empty. The file is probably not a memory image of a running Linux kernel: a kernel file from "
                        "disk (vmlinux, kernel.elf) or another file. To type a kernel file from disk, open that file in IDA "
                        "directly and use Apply kernel types.")
    bases = [address for kind, name, address, _ in rows if kind == "percpu" and name.startswith("cpu")]
    if len(bases) > 1 and len(set(bases)) == 1:
        problems.append("All %d per-CPU copies sit at the same address (%s), which is the boot-time template of a kernel "
                        "file, not the per-CPU areas of a running kernel: is this a memory image?" % (len(bases), bases[0]))
    return problems


def exporter_not_loaded(out, err):
    """Volatility could not load kernel2elf at all, so argparse rejected the plugin name (out, err: decoded text)."""
    return "invalid choice" in out + err and "kernel2elf" in out + err


def kernel_not_found(out, err):
    """Volatility built no kernel layer or symbol table (out, err: decoded text). Version 2.28.2 prints exactly the same
    text for a wrong ISF, for no ISF and for a file that is not a memory image (tests/fixtures/vol-2.28.2)."""
    return ("symbol_table_name" in err or "symbol table requirement" in out
            or "kernel.layer_name" in err or "translation layer requirement" in out)


# Volatility's own warning for an AVML image when it cannot load the snappy library (volatility3/framework/layers/avml.py).
AVML_WITHOUT_SNAPPY = "AVML file detected, but snappy library could not be found"
ISF_README = "README, \"An ISF for your own image\""
# the community ISF index as tools/find_isf.py --download caches it; read only, IDA never downloads it
INDEX_CACHE = os.path.join(os.path.expanduser("~"), ".cache", "memlens", "banners_plain.json")


def isf_index_text(banners):
    """One paragraph for a failed export with no ISF or the wrong one: the ready-made ISF for one of the image's kernel
    version lines from the cached community index, or that none is there, or how to look them up (tools/find_isf.py)."""
    try:
        with open(INDEX_CACHE, encoding="utf-8") as handle:
            index = {key.strip(): urls for key, urls in json.load(handle).items()}
    except (OSError, ValueError, AttributeError):
        helper = os.path.join(HERE, "tools", "find_isf.py")
        return ("To look these kernel version lines up in the community ISF index (Abyss-W4tcher/volatility3-symbols): "
                'python3 "%s" <image> --download (it fetches the index once; MemLens itself never downloads it).' % helper)
    try:
        fetched = " on %s" % time.strftime("%Y-%m-%d", time.localtime(os.path.getmtime(INDEX_CACHE)))
    except (OSError, ValueError, OverflowError):
        fetched = ""
    source = "the community index that tools/find_isf.py downloaded%s" % fetched  # the date tells a stale cache apart
    for banner in banners:
        urls = index.get(banner.strip())
        urls = [u for u in urls if isinstance(u, str)] if isinstance(urls, list) else []  # a damaged cache: no crash
        if urls and banner == banners[0]:
            return "A ready-made ISF for this image's kernel, from %s: %s" % (source, urls[0])
        if urls:  # review s179 MINOR 3: name the line, which may be a copy from an earlier boot
            return ("A ready-made ISF for the line %s (not the image's most frequent line; it may be a copy from an "
                    "earlier boot), from %s: %s" % (banner, source, urls[0]))
    return "None of these kernel version lines is in %s: build the ISF with dwarf2json (%s)." % (source, ISF_README)
SHOWN_BANNERS = 3


def banner_command(vol, image):
    return [vol, "-q", "-f", image, "banners.Banners"]


def image_banners(stdout):
    """The distinct "Linux version ..." lines in banners.Banners' output, most frequent first (ties in file order).
    An image can hold several: the kernel's own, a copy in the log buffer, leftovers and lines of older kernels."""
    counts = {}
    for line in stdout.decode("utf-8", "replace").splitlines():
        cells = line.split("\t", 1)
        if len(cells) == 2 and cells[1].strip().startswith("Linux version "):
            banner = cells[1].strip()
            counts[banner] = counts.get(banner, 0) + 1
    return sorted(counts, key=lambda banner: -counts[banner])  # dicts keep file order and sorted() is stable


def isf_banner(isf_path):
    """(the ISF's kernel version line, the exact bytes Volatility looks for, None), or (None, None, why there is none).
    Read with isf2c, no Volatility call. Volatility's Linux identifier is the whole base64-decoded constant_data of
    linux_banner, its trailing "\\n\\0" included (automagic/symbol_cache.py, LinuxIdentifier); the line is that up to the
    NUL, stripped, as banners.Banners prints the image's lines."""
    try:
        data = (isf2c.load_isf(isf_path).get("symbols", {}).get("linux_banner") or {}).get("constant_data")
        exact = base64.b64decode(data) if data else None
    except isf2c.ISFError as error:
        return None, None, str(error)
    except (ValueError, TypeError, AttributeError) as error:  # a damaged linux_banner entry (not base64, not text)
        return None, None, "its linux_banner is not readable (%s)" % error
    if not exact or not exact.split(b"\0")[0]:
        return None, None, "it has no linux_banner"
    return exact.split(b"\0")[0].decode("ascii", "replace").strip(), exact, None


# Files whose raw bytes are not the image's: xz, gzip and bzip2 (Volatility decompresses them itself,
# layers/resources.py), AVML (snappy-compressed) and zip.
COMPRESSED_MAGIC = (b"\xfd7zXZ\x00", b"\x1f\x8b", b"BZh", b"AVML", b"PK\x03\x04")


def holds_bytes(path, needle, chunk=1 << 24):
    """(True or False, None) whether the file holds these exact bytes, or (None, why it cannot tell): a compressed file,
    a read error, or Cancel (checked after each chunk). Reads the whole file once if the bytes are not there."""
    keep = len(needle) - 1
    try:
        with open(path, "rb") as handle:
            if handle.read(8).startswith(COMPRESSED_MAGIC):
                return None, "the file is compressed"
            handle.seek(0)
            carry = b""
            while True:
                block = handle.read(chunk)
                if not block:
                    return False, None
                data = carry + block  # carry: the end of the previous chunk, for a match across the boundary
                if needle in data:
                    return True, None
                carry = data[max(len(data) - keep, 0):] if keep > 0 else b""
                if ida_kernwin.user_cancelled():
                    return None, "you cancelled that check"
    except OSError as error:
        return None, "the file could not be read (%s)" % error


def kernel_check_wanted(stdout, stderr):
    """After a failed export: is banners.Banners worth running? Only when no kernel was found, and not for an AVML
    image Volatility cannot decompress (it would scan compressed bytes)."""
    out, err = stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    return kernel_not_found(out, err) and AVML_WITHOUT_SNAPPY not in out + err


LIME_MAGIC = 0x4C694D45  # "EMiL" on disk
ELF_TYPES = {0: "file of no type (ELF type NONE)", 1: "relocatable file (ELF type REL), such as a kernel module",
             2: "executable (ELF type EXEC), such as a kernel file", 3: "shared object or PIE program (ELF type DYN)"}


def elf_not_core(path):
    """The ELF type (e_type) of an ELF file that is not a core dump, else None. A memory image in ELF form is a core
    dump (ET_CORE, 4); an executable, a module or a library is not, whatever banners.Banners finds in it."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(18)
    except OSError:
        return None
    if len(head) < 18 or head[:4] != b"\x7fELF" or head[5] not in (1, 2):
        return None
    e_type, = struct.unpack_from("<H" if head[5] == 1 else ">H", head, 16)
    return e_type if e_type != 4 else None


def short_file(path):
    """(file size, size its own header describes, "ELF" or "LiME") when the file is shorter than its 64-bit ELF program
    headers (end of the last PT_LOAD) or its chain of LiME range headers say, else None. banners.Banners silently misses
    kernel lines near the end of such a cut file, so no banner-based verdict holds for it."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as handle:
            head = handle.read(64)
            if head[:4] == b"\x7fELF" and len(head) == 64 and head[4] == 2 and head[5] == 1:  # 64-bit, little-endian
                phoff, = struct.unpack_from("<Q", head, 32)
                phentsize, phnum = struct.unpack_from("<HH", head, 54)
                if phentsize < 56:
                    return None
                handle.seek(phoff)
                table = handle.read(phentsize * phnum)
                end, kind = phoff + phentsize * phnum, "ELF"
                if len(table) == phentsize * phnum:
                    for index in range(phnum):
                        p_type, _, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", table, index * phentsize)
                        if p_type == 1:  # PT_LOAD
                            end = max(end, p_offset + p_filesz)
            elif len(head) >= 4 and struct.unpack_from("<I", head)[0] == LIME_MAGIC:
                end, kind = 0, "LiME"
                for _ in range(1 << 16):  # one 32-byte header per physical range
                    if end + 32 > size:
                        handle.seek(end)
                        rest = handle.read(4)
                        if rest and struct.pack("<I", LIME_MAGIC).startswith(rest):
                            end += 32  # a cut header
                        break
                    handle.seek(end)
                    magic, _, start, stop = struct.unpack("<IIQQ", handle.read(24))
                    if magic != LIME_MAGIC:
                        break
                    end += 32 + stop - start + 1
            else:
                return None
    except (OSError, struct.error):
        return None
    return (size, end, kind) if end > size else None


def check_kernel(vol, image, isf_path):
    """Which kernel the image holds (Volatility's banners.Banners, cancellable) and which one the ISF was built for.
    Called only after Volatility found no kernel layer or symbol table; the dict goes to export_failure_text."""
    not_core = elf_not_core(image)
    if not_core is not None:
        return {"not_core": not_core}  # a kernel file or a program: the ISF and the banners do not matter
    short = short_file(image)
    if short:
        return {"short": short}  # no banner scan: it would miss lines in the missing part without a word
    ida_kernwin.show_wait_box("MemLens: export failed, Volatility is looking for the image's kernel version")
    try:
        code, stdout, stderr = run_cancellable(banner_command(vol, image))
        if code is None:
            return {"cancelled": True}
        ida_kernwin.msg("[MemLens] banners.Banners (exit %s):\n%s\n%s\n" % (
            code, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")))
        if code:
            return {"failed": code}
        check = {"banners": image_banners(stdout)}
        if isf_path and check["banners"]:
            ida_kernwin.replace_wait_box("MemLens: reading the ISF's kernel version")  # about 1.5 s for the demo ISF
            check["isf_banner"], exact, check["isf_problem"] = isf_banner(isf_path)
            if check["isf_banner"] in check["banners"]:
                # banners.Banners cuts each hit at the NUL and strips it, so it also lists copies (a journal's
                # "MESSAGE=<line>\0") that Volatility never matches: it looks for the exact bytes, "\n\0" included.
                ida_kernwin.replace_wait_box("MemLens: looking for the ISF's exact kernel version line in the image")
                check["isf_exact"], check["isf_exact_unknown"] = holds_bytes(image, exact)
        return check
    finally:
        ida_kernwin.hide_wait_box()


def banner_lines(banners, isf_line=None, mark=" (the ISF's)"):
    """Up to SHOWN_BANNERS "Image: ..." lines, plus the ISF's line when the image holds it further down; it is marked."""
    shown = banners[:SHOWN_BANNERS] + ([isf_line] if isf_line in banners[SHOWN_BANNERS:] else [])
    lines = ["Image: %s%s" % (banner, mark if banner == isf_line else "") for banner in shown]
    if len(banners) > len(shown):
        lines.append("... and %d more" % (len(banners) - len(shown)))
    if len(banners) > 1:
        lines.append("(%d different \"Linux version\" lines in the image, most frequent first. An image can hold more "
                     "than the running kernel's: copies in logs, lines of older kernels and damaged ones.)" % len(banners))
    return "\n".join(lines)


def kernel_hint(check, isf_given):
    """The paragraphs that explain a failed export from what check_kernel found, or None if it found nothing to go by."""
    if check and check.get("not_core") is not None:
        return ["This file is not a memory image: it is an ELF %s, while a memory image in ELF form is a core dump (ELF "
                "type CORE). A kernel file from disk (vmlinux, or a kernel.elf written by MemLens) needs no export: open "
                "that file in IDA directly and use Apply kernel types." % ELF_TYPES.get(
                    check["not_core"], "file of type %d" % check["not_core"])]
    if check and check.get("short"):
        size, described, kind = check["short"]
        return ["The image file is shorter than its own %s headers say (%s bytes; they describe at least %s): it is probably an "
                "incomplete copy, so Volatility cannot read all of it, and its search for the kernel's version line can "
                "miss it. Copy or download the image again, then export again." % (kind, "{:,}".format(size),
                                                                                    "{:,}".format(described))]
    if not check or "banners" not in check:
        return None
    banners = check["banners"]
    if not banners:
        return ["Volatility found no Linux kernel in this file: banners.Banners found no \"Linux version\" line in it, "
                "so it is probably not a Linux memory image, or one in a format Volatility cannot read. Volatility 2.28.2 "
                "reads raw images, LiME, 64-bit ELF core dumps, VMware .vmem (read as a raw image; its .vmss or .vmsn file "
                "next to it is needed for the right layout), QEMU suspend images and Xen core dumps, and xz, gzip or bzip2 "
                "compressed copies of these (named .xz, .gz or .bz2); AVML images need the snappy library."]
    if not isf_given:
        return ["It found no symbols for this image's kernel. Without an ISF it only uses the Linux symbol files it already "
                "has, and a fresh pip install has none. Get the ISF built for this image's kernel: its linux_banner must be "
                "one of the lines below (%s). Then run Export again with it." % ISF_README, banner_lines(banners),
                isf_index_text(banners)]
    isf_line, problem = check.get("isf_banner"), check.get("isf_problem")
    if isf_line is None:
        return ["The file you chose as the ISF cannot be compared with the image: %s. Volatility picks a Linux ISF by "
                "finding the ISF's kernel version line (linux_banner) in the image. Use the ISF built for the image's "
                "kernel (%s)." % (problem, ISF_README), banner_lines(banners)]
    exact = check.get("isf_exact")  # only looked for when the ISF's line is among the image's lines
    if isf_line in banners and exact:
        return ["This image holds the ISF's kernel version line as the kernel stores it, so the ISF fits a kernel in this "
                "image; Volatility still failed, so the cause is something else (see its output below).",
                "ISF: %s\n%s" % (isf_line, banner_lines(banners, isf_line))]
    if isf_line in banners and exact is False:
        return ["The ISF you chose was built for another kernel: its kernel version line is in this image only as a copy "
                "(for example in the system log of an earlier boot), not as the kernel stores it (followed by a newline "
                "and a NUL byte), which is what Volatility looks for. Use the ISF built for the image's kernel (%s)."
                % ISF_README, "ISF: %s\n%s" % (isf_line, banner_lines(banners, isf_line, " (the ISF's, only a copy)")),
                isf_index_text([b for b in banners if b != isf_line])]
    if isf_line in banners:
        return ["This image holds the ISF's kernel version line, but MemLens could not check whether it is there as the "
                "kernel stores it (followed by a newline and a NUL byte), which is what Volatility looks for: %s. So "
                "either the ISF fits a kernel in this image and Volatility failed for another reason (see its output "
                "below), or the line is only a copy (for example in the system log of an earlier boot) and the ISF was "
                "built for another kernel (%s)." % (check.get("isf_exact_unknown"), ISF_README),
                "ISF: %s\n%s" % (isf_line, banner_lines(banners, isf_line))]
    return ["The ISF you chose was built for another kernel: its kernel version line (linux_banner) is not in this image, "
            "and Volatility picks a Linux ISF by finding that exact line. Use the ISF built for the image's kernel (%s)."
            % ISF_README, "ISF: %s\n%s" % (isf_line, banner_lines(banners)), isf_index_text(banners)]


def export_failure_text(stdout, stderr, isf_given, check=None):
    """The dialog text for a failed export: a plain hint for the common cause, then the tail of what Volatility said.
    Volatility prints its own explanation of a missing symbol table on stdout, not stderr. check is what
    check_kernel found (None when it did not run)."""
    out, err = stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    lines = ["Volatility failed."]
    hint = kernel_hint(check, isf_given) if kernel_not_found(out, err) else None
    if exporter_not_loaded(out, err):
        # The exporter was not loaded, so argparse lists every other plugin. Usually an older Volatility whose Linux
        # module API the exporter cannot import (seen with 2.11.0).
        version = re.search(r"Volatility 3 Framework ([0-9][0-9.]*)", out + err)
        number = version.group(1).rstrip(".") if version else ""
        parts = tuple(int(part) for part in number.split(".") if part.isdigit())
        if parts and parts >= (2, 28, 2):
            # Not the old-API case: say so instead of telling the user to install the version they already have.
            lines.append("This Volatility (%s) could not load MemLens' exporter (linux.kernel2elf), and it is not older "
                         "than 2.28.2, the version MemLens is tested with, so the usual cause does not apply. Run vol with "
                         "-vvv to see why the plugin failed to import, and please report it with the text below." % number)
        elif not number:
            # Volatility 2.27 and later stop at the plugin-name check before printing their version (2.11 and 2.26 print
            # it first), so a modern Volatility gives no number here: name both cases instead of guessing.
            lines.append("This Volatility could not load MemLens' exporter (linux.kernel2elf). `vol -h` shows its version "
                         "on the first line. Older than 2.28.2 (seen with 2.11.0): MemLens is tested with Volatility 2.28.2, "
                         "so pipx install volatility3==2.28.2 (or a venv, see the README), then make sure IDA finds that vol "
                         "first on PATH. 2.28.2 or newer: run vol with -vvv to see why the plugin failed to import, and "
                         "please report it with the text below.")
        else:
            lines.append("This Volatility%s could not load MemLens' exporter (linux.kernel2elf), usually because it is older "
                         "than the Linux module API the exporter uses. MemLens is tested with Volatility 2.28.2: "
                         "pipx install volatility3==2.28.2 (or a venv, see the README), then make sure IDA finds that vol "
                         "first on PATH." % (" (%s)" % number))
    elif AVML_WITHOUT_SNAPPY in out + err:
        lines.append("This is an AVML image, which Volatility reads only with the snappy library, and it could not load "
                     "that library. Install snappy and export again (Volatility loads libsnappy.so.1 on Linux, "
                     "libsnappy.1.dylib on macOS and snappy64 on 64-bit Windows).")
    elif hint:
        lines += hint
    elif kernel_not_found(out, err):
        # No kernel check, or it did not finish: Volatility's text alone cannot tell a wrong ISF from a file that is
        # not a memory image (2.28.2 prints the same for both).
        if isf_given:
            lines.append("It found no symbols matching this image's kernel: either the ISF you chose was built for another "
                         "kernel (its linux_banner must match the image's), or the file is not a Linux memory image.")
        else:
            lines.append("It found no symbols for this image's kernel. Without an ISF it only uses the Linux symbol files it "
                         "already has, and a fresh pip install has none: run Export again and choose the ISF built for this "
                         "kernel (%s)." % ISF_README)
        if check and check.get("cancelled"):
            lines.append("(You cancelled the check for the image's kernel version.)")
        elif check and check.get("failed"):
            lines.append("(The check for the image's kernel version failed too: banners.Banners exited with %s, its output "
                         "is in the Output window.)" % check["failed"])
    lines.append("Full output is in the Output window. Volatility said:")
    if out.strip():
        lines.append(tail(out, 700))
    if err.strip():
        lines.append(tail(err, 800))
    return "\n\n".join(lines)


def child_environment():
    """IDA's environment for Volatility, minus PYTHONHOME. IDAPython in IDA 9.5 sets PYTHONHOME to the prefix of
    IDA's own Python when it is not set (SDK idapython.cpp, before Py_Initialize), and child processes inherit it.
    Volatility runs on its own Python: with another Python's PYTHONHOME it cannot find its standard library
    ("No module named 'encodings'") or its venv. PYTHONPATH is kept, since a user may need it to find volatility3."""
    env = dict(os.environ)
    env.pop("PYTHONHOME", None)
    return env


def tail(text, size):
    """About the last size characters of text, starting at a whole line (a line longer than size is cut)."""
    text = text.strip()
    if len(text) <= size:
        return text
    cut = text[-size:]
    if text[-size - 1] == "\n":
        return cut.lstrip("\n")  # the cut is already at a line start
    newline = cut.find("\n")
    return cut[newline + 1:].lstrip("\n") if 0 <= newline < len(cut) - 1 else cut


def run_cancellable(command):
    """Run without freezing IDA. Returns (exit code, stdout, stderr); exit code None means cancelled."""
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        # No console window per vol.exe started from IDA's GUI on Windows (the flag exists only there).
        process = subprocess.Popen(command, stdout=output, stderr=errors, env=child_environment(),
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        while process.poll() is None:
            if ida_kernwin.user_cancelled():
                process.kill()
                process.wait()
                return None, b"", b""
            time.sleep(0.2)
        output.seek(0)
        errors.seek(0)
        return process.returncode, output.read(), errors.read()



ISSUES_URL = "https://github.com/nightshift-labs-ai/memlens/issues"


def guarded(activate):
    """Any unexpected error becomes one warning plus the traceback in the Output window."""
    def wrapper(self, ctx):
        try:
            return activate(self, ctx)
        except Exception:  # noqa: BLE001  (last line of defence inside IDA)
            ida_kernwin.msg("[MemLens] unexpected error:\n%s\n" % traceback.format_exc())
            ida_kernwin.warning("MemLens: unexpected error, details are in the Output window.\nPlease report it: %s" % ISSUES_URL)
            return 0
    return wrapper

class ApplyTypes(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        path = ida_kernwin.ask_file(False, None, ISF_FILTER + "Volatility ISF for this kernel")
        if not path:
            return 0
        ida_kernwin.show_wait_box("MemLens: reading ISF")
        try:
            try:
                result = apply_types(path, confirm_other_kernel)
            finally:
                ida_kernwin.hide_wait_box()
        except isf2c.ISFError as error:
            ida_kernwin.warning("MemLens: %s" % error)
            return 0
        if result is None:
            return 0
        ida_kernwin.msg(report(result))
        refresh_hook_chain()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ExportKernel(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        image = ida_kernwin.ask_file(False, "*", "Linux memory image")
        if not image:
            return 0
        vol = shutil.which("vol") or ida_kernwin.ask_file(False, "vol*", "Where is Volatility 3's 'vol' command?")
        if not vol:
            return 0
        isf = ida_kernwin.ask_file(False, None, ISF_FILTER + "ISF for this kernel (Cancel = use Volatility's own symbols)")
        output = os.path.dirname(os.path.abspath(image))
        with tempfile.TemporaryDirectory() as folder:
            symbols = symbols_folder(isf, folder) if isf else None
            ida_kernwin.show_wait_box("MemLens: Volatility is scanning the image, this can take minutes")
            try:
                before = elf_files(output)
                code, stdout, stderr = run_cancellable(export_command(vol, image, output, symbols))
            finally:
                ida_kernwin.hide_wait_box()
        if code is None:
            return 0
        if code:
            ida_kernwin.msg("[MemLens] Volatility failed (exit %s).\n[MemLens] its stdout:\n%s\n[MemLens] its stderr:\n%s\n"
                            % (code, stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")))
            check = check_kernel(vol, image, isf) if kernel_check_wanted(stdout, stderr) else None
            ida_kernwin.warning(export_failure_text(stdout, stderr, bool(isf), check))
            return 0
        problems = export_problems(stdout)
        if problems:
            name = written_file(stdout, output, before)
            message = "Volatility wrote %s in %s, but it is not a usable kernel export. %s\n\n%s" % (
                name, output, remove_unusable(output, name, before), "\n\n".join(problems))
            ida_kernwin.msg("[MemLens] %s\n[MemLens] Volatility's output:\n%s\n" % (message, stdout.decode("utf-8", "replace")))
            ida_kernwin.warning(message)
            return 0
        message = "Wrote %s in %s. Open it in IDA, then use Apply kernel types." % (written_file(stdout, output, before), output)
        ida_kernwin.msg("[MemLens] %s\n" % message)  # info() can be silenced for good by its checkbox
        ida_kernwin.info(message.replace("%", "%%"))  # info() is printf-style in IDAPython (not wrapped like msg/warning)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class PatchList(ida_kernwin.Choose):
    """Patched entries and odd syscall slots. Enter jumps to the entry; Ctrl+E (the chooser's Edit command, captioned
    "Jump to handler" in its context menu) jumps to the handler the hook page calls, when its role is known (not to the
    first call of a page with no known role, a core-kernel helper); Ins (the Insert command, captioned "Jump to owner")
    jumps to the page's owner when it is in the database."""

    def __init__(self, rows):
        columns = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Where", 34], ["What", 34], ["Target", 40], ["Handler", 36],
                   ["Owner", 48]]
        ida_kernwin.Choose.__init__(self, "MemLens: patched kernel functions", columns,
                                    ida_kernwin.Choose.CH_CAN_EDIT | ida_kernwin.Choose.CH_CAN_INS,
                                    popup_names=["Jump to owner", "Delete", "Jump to handler", "Refresh"])
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        address, name, what, target, handler, _, owner, _ = self.rows[n]
        return ["%X" % address, name, what, target, handler, owner]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnEditLine(self, n):
        handler = self.rows[n][5]
        if handler is None and self.rows[n][4]:  # "(hook code; first call: _printk)": no known role
            ida_kernwin.msg("[MemLens] no handler is known for %s %s: the first named call of a hook page with no known "
                            "role goes to a kernel function the hook code uses, not to its handler\n"
                            % (self.rows[n][1], self.rows[n][4]))
        elif handler is None:
            ida_kernwin.msg("[MemLens] no handler is known for %s (only hook pages that MemLens copied have one)\n" % self.rows[n][1])
        else:
            ida_kernwin.jumpto(handler)
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnInsertLine(self, n):
        if not 0 <= n < len(self.rows):  # IDA passes -1 when no row is selected
            ida_kernwin.msg("[MemLens] select a row to jump to its owner\n")
        elif self.rows[n][7] is not None:
            ida_kernwin.jumpto(self.rows[n][7])
        elif self.rows[n][6]:
            ida_kernwin.msg("[MemLens] the owner of %s is not in this database: %s\n" % (self.rows[n][1], self.rows[n][6]))
        else:
            ida_kernwin.msg("[MemLens] no owner is known for %s (MemLens reads it from the BPF program a trampoline runs, "
                            "the ftrace_ops an ftrace trampoline loads, or the module callback a hook page calls)\n" % self.rows[n][1])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)


def scan_current_input():
    """(image, findings) for the ELF open in IDA, which is plain data: the database is only annotated. None if there
    is nothing to show."""
    path = ida_nalt.get_input_file_path()
    picked = not path or not os.path.isfile(path)
    if picked:
        path = ida_kernwin.ask_file(False, "*.elf", "kernel.elf exported by MemLens")
        if not path:
            return None
    with open(path, "rb") as handle:
        blob = handle.read()
    if picked and not same_as_database(path, blob):
        return None
    try:
        if patchscan.on_disk_kernel(blob):
            raise ValueError("this is a kernel file from disk, whose entry bytes are not what ran")
        image = patchscan.Image(blob)
        reason = patchscan.nothing_to_check(image)
        if reason:
            # An empty list would look like a clean kernel (the command line warns the same way).
            ida_kernwin.warning("MemLens checked nothing: %s has %s, so an empty list would not "
                                "mean clean. This works on the kernel.elf that MemLens exported from a memory image."
                                % (os.path.basename(path), reason))
            return None
        return image, patchscan.scan(blob, image)
    except patchscan.BAD_ELF as error:
        ida_kernwin.warning("MemLens needs the kernel.elf it exported: %s" % error)
        return None


def same_as_database(path, blob):
    """True when blob is the file the database was made from (its SHA-256 as the database stored it), or when the user
    says to go on anyway. Comments, xrefs and names from another file would land on the wrong addresses."""
    stored = ida_nalt.retrieve_input_file_sha256()
    if not stored:
        return True  # nothing to compare with
    digest = hashlib.sha256(blob)
    if bytes(stored) in (digest.digest(), digest.hexdigest().encode()):
        return True
    text = ("%s is not the file this database was made from (its SHA-256 differs), so comments, xrefs and names "
            "would go to the wrong addresses. Use it anyway?" % os.path.basename(path))
    return ida_kernwin.ask_yn(ida_kernwin.ASKBTN_NO, text.replace("%", "%%")) == ida_kernwin.ASKBTN_YES


def add_comment(address, text):
    """Adds our line to the comment at address and keeps whatever is already there."""
    old = idc.get_cmt(address, False) or ""
    if text in old:
        return
    # A line an older build wrote, which this text only extends (a kind added after a comma or a space), is replaced,
    # so re-running on an older database does not keep both (code review s170 m-1).
    def extended(line):
        if not line.startswith("MemLens: "):
            return False
        if text.startswith(line) and text[len(line):len(line) + 1] == ";":  # a v0.3.27 line ending with a role, now + "; owner: ..."
            return True
        stem = line[:-1] if line.endswith(")") else line
        return text.startswith(stem) and text[len(stem):len(stem) + 1] in (",", " ")
    if not old:
        idc.set_cmt(address, text, False)
        return
    lines = [line for line in old.split("\n") if not extended(line)]  # empty lines in an analyst's comment stay (claims check s171)
    idc.set_cmt(address, "\n".join(lines + [text]), False)


def set_flags_comment(address, text):
    """add_comment for an ftrace_ops flags line, after dropping any other flags line at address: one an earlier ISF
    decoded differently (a wrong ISF applied first, then the right one) must not stay next to it (review s193). Our
    line with a note the analyst added after it stays, as add_comment keeps it (review s194)."""
    old = idc.get_cmt(address, False) or ""
    lines = old.split("\n")
    kept = [line for line in lines if not (line.startswith(patchscan.OPS_FLAGS_PREFIX) and text not in line)]
    if kept != lines:
        idc.set_cmt(address, "\n".join(kept), False)
    add_comment(address, text)


HOOK_RECORD = "$ memlens.hooks"  # netnode: what MemLens linked and renamed, so running it again adds nothing twice
HOOK_RECORD_TAG = "B"
LAYOUT_RECORD = "$ memlens.layout"  # netnode: struct offsets from the ISF that Apply kernel types imported
LAYOUT_TAG = "L"


LAYOUT_KEYS = ("ftrace_ops.func", "ftrace_ops.flags", "FTRACE_OPS_FL")


def isf_layout(isf):
    """What Apply kernel types records from a loaded ISF: {"ftrace_ops.func": offset, "ftrace_ops.flags": offset,
    "FTRACE_OPS_FL": {"FTRACE_OPS_FL_ENABLED": 1, ...}}, each key only when the ISF has it (the values are read by name
    from the ISF's enum, which is anonymous in Linux and numbered differently across versions)."""
    layout = {"ftrace_ops.func": patchscan.ftrace_ops_func_offset(isf),
              "ftrace_ops.flags": patchscan.ftrace_ops_field_offset(isf, "flags"),
              "FTRACE_OPS_FL": patchscan.ftrace_ops_flag_values(isf)}
    return {key: value for key, value in layout.items() if value is not None and value != {}}


def load_layout():
    """isf_layout's record as Apply kernel types saved it, or {} (no ISF applied yet, or an unreadable record)."""
    blob = ida_netnode.netnode(LAYOUT_RECORD, 0, True).getblob(0, LAYOUT_TAG)
    try:
        layout = json.loads(blob.decode("utf-8")) if blob else {}
    except ValueError:
        layout = {}
    return layout if isinstance(layout, dict) else {}


def save_layout(layout):
    ida_netnode.netnode(LAYOUT_RECORD, 0, True).setblob(json.dumps(layout).encode("utf-8"), 0, LAYOUT_TAG)


def load_hook_record():
    """(netnode, record) with record = {"xrefs": [[from, to, flow], ...], "names": [[page, old name, new name], ...],
    "types": [[address, type], ...]}."""
    node = ida_netnode.netnode(HOOK_RECORD, 0, True)
    blob = node.getblob(0, HOOK_RECORD_TAG)
    try:
        record = json.loads(blob.decode("utf-8")) if blob else {}
    except ValueError:
        record = {}
    return node, {"xrefs": list(record.get("xrefs", [])), "names": list(record.get("names", [])),
                  "types": list(record.get("types", []))}


OPS_TYPE = "struct ftrace_ops"


def ops_type_known():
    """True when the database has struct ftrace_ops (Apply kernel types imported it)."""
    return ida_typeinf.tinfo_t().get_named_type(ida_typeinf.get_idati(), "ftrace_ops")


def link_hooks(image, findings):
    """Apply the hook chain that patchscan decides: a user code xref from each hooking instruction to its target and
    from each copied hook page's first named call to that function, a role name for each such page whose role is known
    (ftrace, kprobe via ftrace, BPF trampoline or module callback; once, and only while it still has the exporter's
    memlens_target_ label or no name but IDA's dummy one), and a comment there with the old label. What was added is
    kept in the HOOK_RECORD netnode, so a second run adds no xref and renames nothing again, and an xref or name the
    user removed since is not put back. The owner's references are added too: the call to a BPF program, and for an
    ftrace trampoline user data xrefs (dr_O) from its ftrace_ops slot to the ops and from ops->func to the callback;
    ops->func is read at the ISF's offset when Apply kernel types recorded one.

    After Apply kernel types (its layout has ftrace_ops.flags and the FTRACE_OPS_FL_* values): a comment at each such
    trampoline (not a kprobe's) and at its ops decodes the ops' flags, saying whether IPMODIFY is set; nothing is said
    without that layout. When the database has struct ftrace_ops, an ops that a module's symbol starts at gets that
    type once (kept in HOOK_RECORD too). Returns (links, counts)."""
    layout = load_layout()
    func_offset = layout.get("ftrace_ops.func")
    if isinstance(func_offset, int):
        image.ftrace_ops_func = func_offset
    links = patchscan.hook_links(image, findings)
    flow_types = {"call": ida_xref.fl_CN, "jmp": ida_xref.fl_JN}  # near call or near jump, as the hooking instruction is
    node, record = load_hook_record()
    done = {tuple(xref) for xref in record["xrefs"]}
    counts = dict.fromkeys(("xrefs", "xrefs_before", "xrefs_failed", "drefs", "drefs_before", "drefs_failed", "renamed",
                            "named_before", "kept", "rename_failed", "typed", "typed_before", "type_failed"), 0)
    for source, target, flow in patchscan.hook_xrefs(links):
        kind = "drefs" if flow == "data" else "xrefs"
        if (source, target, flow) in done:
            counts[kind + "_before"] += 1
        elif (ida_xref.add_dref(source, target, ida_xref.dr_O | ida_xref.XREF_USER) if flow == "data"
              else ida_xref.add_cref(source, target, flow_types[flow] | ida_xref.XREF_USER)):
            record["xrefs"].append([source, target, flow])
            done.add((source, target, flow))
            counts[kind] += 1
        else:
            counts[kind + "_failed"] += 1
    renamed = {page for page, _, _ in record["names"]}
    for page, name in sorted(patchscan.role_names(image, links).items()):
        label = "%s%x" % (patchscan.TARGET_PREFIX, page)
        current = ida_name.get_name(page)
        if current == name:
            counts["named_before"] += 1
        elif page in renamed or (current != label and ida_bytes.has_user_name(ida_bytes.get_flags(page))):
            counts["kept"] += 1  # renamed or unnamed by the user since MemLens named it, or a real name: leave it
        elif ida_name.set_name(page, name, ida_name.SN_NOWARN | ida_name.SN_NON_AUTO):  # SN_NON_AUTO: not an auto name
            record["names"].append([page, label, name])
            counts["renamed"] += 1
        else:
            counts["rename_failed"] += 1  # IDA refused it, for example because the name is used elsewhere
    for page, text in patchscan.page_comments(links).items():
        add_comment(page, text)
    typed = {address for address, _ in record["types"]}
    for ops in (patchscan.module_ops(image, links) if ops_type_known() else []):
        if ops in typed:
            counts["typed_before"] += 1  # also when the user retyped it since: leave it
        elif idc.SetType(ops, OPS_TYPE + ";"):
            record["types"].append([ops, OPS_TYPE])
            counts["typed"] += 1
        else:
            counts["type_failed"] += 1
    flags = patchscan.ops_flags_comments(image, links, layout.get("ftrace_ops.flags"), layout.get("FTRACE_OPS_FL"))
    for address, text in sorted(flags.items()):
        set_flags_comment(address, text)
    node.setblob(json.dumps(record).encode("utf-8"), 0, HOOK_RECORD_TAG)
    return links, counts


def refresh_hook_chain():
    """After Apply kernel types: when Show patched kernel functions already ran on this database (its hook record is
    there), scan kernel.elf and apply the hook chain again, so that the module ops' struct ftrace_ops type and the
    ftrace_ops flags comments, which need the types and the layout just imported, appear without opening the list a
    second time (README Try it opens the list first). On a database where the list never ran it does nothing and reads no
    file. An error here is printed to the Output window and never hides the types report printed before it. Returns
    True when the hook chain was applied again."""
    if not ida_netnode.netnode(HOOK_RECORD, 0, True).getblob(0, HOOK_RECORD_TAG):
        return False
    try:
        scanned = scan_current_input()
        if scanned is None:
            return False
        links, counts = link_hooks(*scanned)
        ida_kernwin.msg(link_report(links, counts))
        ida_kernwin.msg("[MemLens] hook chain refreshed with this ISF's ftrace_ops layout (Show patched kernel functions "
                        "ran before Apply kernel types)\n")
        return True
    except Exception:
        ida_kernwin.msg("[MemLens] hook chain refresh stopped by this error (the types above are imported):\n%s\n"
                        % traceback.format_exc())
        return False


def link_report(links, counts):
    """One Output-window line on what link_hooks did."""
    line = ("[MemLens] hook chain: %d patched entries lead into this database, %d to a hook page MemLens copied; "
            "%d code xrefs added" % (len(links), sum(1 for link in links if link.page), counts["xrefs"]))
    extra = [("%d already added by an earlier run" % counts["xrefs_before"]) if counts["xrefs_before"] else "",
             ("%d refused by IDA" % counts["xrefs_failed"]) if counts["xrefs_failed"] else ""]
    line += "".join(" (%s)" % text for text in extra if text)
    drefs, before, failed = (counts.get(key, 0) for key in ("drefs", "drefs_before", "drefs_failed"))
    if drefs or before or failed:  # ftrace_ops pointers toward an owner; the line is unchanged without any
        line += "; %d data xrefs added" % drefs
        extra = [("%d already added by an earlier run" % before) if before else "", ("%d refused by IDA" % failed) if failed else ""]
        line += "".join(" (%s)" % text for text in extra if text)
    line += "; %d hook pages renamed by role" % counts["renamed"]
    for key, text in (("named_before", "%d already named by an earlier run"), ("kept", "%d left alone, they have another name now"),
                      ("rename_failed", "%d refused by IDA")):
        if counts[key]:
            line += ", " + text % counts[key]
    typed, before, failed = (counts.get(key, 0) for key in ("typed", "typed_before", "type_failed"))
    if typed or before or failed:  # module ftrace_ops; the line is unchanged without any
        line += "; %d module ftrace_ops typed as %s" % (typed, OPS_TYPE)
        extra = [("%d already typed by an earlier run" % before) if before else "", ("%d refused by IDA" % failed) if failed else ""]
        line += "".join(" (%s)" % text for text in extra if text)
    return line + "\n"


class FindPatches(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        scanned = scan_current_input()
        if scanned is None:
            return 0
        image, findings = scanned
        for address, _, what, target, _ in findings:
            add_comment(address, "MemLens: %s %s" % (what, target))
        ida_kernwin.msg("[MemLens] %d patched entries or odd syscall slots\n" % len(findings))
        try:
            links, counts = link_hooks(image, findings)
            ida_kernwin.msg(link_report(links, counts))
        except Exception:  # the list is still worth showing, with the names the database has
            links = []
            ida_kernwin.msg("[MemLens] hook chain stopped by this error (xrefs or names added before it are not "
                            "recorded in the database):\n%s\n" % traceback.format_exc())
        names = {page: ida_name.get_name(page) for page in patchscan.copied_targets(image, findings)}
        global _open_list  # a non-modal chooser must outlive this call
        _open_list = PatchList(patchscan.list_rows(image, findings, links, names))
        _open_list.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


MENU_PATHS = ("Edit/Plugins/", "View/Open subviews/Strings")  # the second is the path IDA's own example uses

ACTIONS = [
    ("memlens:export", "MemLens: Export kernel from memory image", ExportKernel),
    ("memlens:types", "MemLens: Apply kernel types from ISF", ApplyTypes),
    ("memlens:patches", "MemLens: Show patched kernel functions", FindPatches),
]


class MemLens(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_HIDE  # the actions are in the menu; no extra run() entry
    comment = "Linux kernel from a memory image, with symbols and types"
    help = "Export a kernel from a memory image and import its types"
    wanted_name = "MemLens"
    wanted_hotkey = ""

    def init(self):
        for action, label, handler in ACTIONS:
            ida_kernwin.register_action(ida_kernwin.action_desc_t(action, label, handler()))
            attached = any(ida_kernwin.attach_action_to_menu(path, action, ida_kernwin.SETMENU_APP) for path in MENU_PATHS)
            if not attached:
                ida_kernwin.msg("[MemLens] could not add %r to a menu\n" % label)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info("MemLens actions are under Edit > Plugins.")

    def term(self):
        for action, _, _ in ACTIONS:
            ida_kernwin.unregister_action(action)


def PLUGIN_ENTRY():
    return MemLens()
