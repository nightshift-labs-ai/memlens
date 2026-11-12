"""MemLens: reverse engineer a Linux kernel from a memory image in IDA.

Three actions under Edit > Plugins:
  * Export kernel from memory image: runs Volatility 3 and writes a symbolled ELF to open in IDA.
  * Apply kernel types from ISF: imports every struct, union and enum of that kernel.
  * Show patched kernel functions: lists hooked entries and odd syscall slots, Enter jumps there; links each hooked
    entry to its hook page and the page to its handler (code xrefs) and names the hook pages by role.
"""
import base64
import hashlib
import itertools
import json
import traceback
import os
import re
import shutil
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


def banner_mismatch(isf):
    """(ISF banner, database banner) if the ISF was built for another kernel, or (ISF banner, b"") if the database has
    no linux_banner at all (so it may not be a kernel); None if they agree or the ISF has no banner to compare."""
    data = (isf.get("symbols", {}).get("linux_banner") or {}).get("constant_data")
    if not data:
        return None
    address = idc.get_name_ea_simple("linux_banner")
    expected = base64.b64decode(data).split(b"\0")[0]
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
        return set()


def written_file(stdout, folder=None, before=None):
    """The file Volatility really wrote. If kernel.elf already exists Volatility picks a new name (kernel-1.elf)
    when it closes the file. kernel2elf prints its row after the close since 0.3.16; older copies printed it
    before, so the folder is still trusted over the row."""
    if folder is not None and before is not None:
        new = sorted(elf_files(folder) - before)
        if len(new) == 1:
            return new[0]
    for line in stdout.decode("utf-8", "replace").splitlines():
        cells = line.split("\t")
        if len(cells) > 1 and cells[0].strip() == "written":
            return cells[1].strip()
    return "kernel.elf"


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


def export_failure_text(stdout, stderr, isf_given):
    """The dialog text for a failed export: a plain hint for the common cause, then the tail of what Volatility said.
    Volatility prints its own explanation of a missing symbol table on stdout, not stderr."""
    out, err = stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    lines = ["Volatility failed."]
    if "invalid choice" in out + err and "kernel2elf" in out + err:
        # The exporter was not loaded, so argparse lists every other plugin. Usually an older Volatility whose Linux
        # module API the exporter cannot import (seen with 2.11.0).
        version = re.search(r"Volatility 3 Framework ([0-9][0-9.]*)", out + err)
        number = version.group(1).rstrip(".") if version else ""
        parts = tuple(int(part) for part in number.split(".") if part.isdigit())
        if parts and parts >= (2, 28, 2):
            # Not the old-API case: say so instead of telling the user to install the version they already have.
            lines.append("This Volatility (%s) could not load MemLens' exporter (linux.kernel2elf), and it is not older "
                         "than 2.28.2, the version MemLens is tested with, so the usual cause does not apply. Please report "
                         "it with the text below." % number)
        else:
            lines.append("This Volatility%s could not load MemLens' exporter (linux.kernel2elf), usually because it is older "
                         "than the Linux module API the exporter uses. MemLens is tested with Volatility 2.28.2: "
                         "pipx install volatility3==2.28.2 (or a venv, see the README), then make sure IDA finds that vol "
                         "first on PATH." % (" (%s)" % number if number else ""))
    elif "symbol_table_name" in err or "symbol table requirement" in out:
        if isf_given:
            lines.append("It found no symbols matching this image's kernel: the ISF you chose was probably built for another "
                         "kernel (its linux_banner must match the image's).")
        else:
            lines.append("It found no symbols for this image's kernel. Without an ISF it only uses the Linux symbol files it "
                         "already has, and a fresh pip install has none: run Export again and choose the ISF built for this "
                         "kernel (dwarf2json, see the README).")
    lines.append("Full output is in the Output window. Volatility said:")
    if out.strip():
        lines.append(out.strip()[-700:])
    if err.strip():
        lines.append(err.strip()[-800:])
    return "\n\n".join(lines)


def run_cancellable(command):
    """Run without freezing IDA. Returns (exit code, stdout, stderr); exit code None means cancelled."""
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.Popen(command, stdout=output, stderr=errors)
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
            ida_kernwin.warning(export_failure_text(stdout, stderr, bool(isf)))
            return 0
        problems = export_problems(stdout)
        if problems:
            message = "Volatility wrote %s in %s, but it is not a usable kernel export.\n\n%s" % (
                written_file(stdout, output, before), output, "\n\n".join(problems))
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
    "Jump to handler" in its context menu) jumps to the handler the hook page calls."""

    def __init__(self, rows):
        columns = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Where", 34], ["What", 34], ["Target", 40], ["Handler", 36]]
        ida_kernwin.Choose.__init__(self, "MemLens: patched kernel functions", columns, ida_kernwin.Choose.CH_CAN_EDIT,
                                    popup_names=["Insert", "Delete", "Jump to handler", "Refresh"])
        self.rows = rows

    def OnGetSize(self):
        return len(self.rows)

    def OnGetLine(self, n):
        address, name, what, target, handler, _ = self.rows[n]
        return ["%X" % address, name, what, target, handler]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.rows[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)

    def OnEditLine(self, n):
        handler = self.rows[n][5]
        if handler is None:
            ida_kernwin.msg("[MemLens] no handler is known for %s (only hook pages that MemLens copied have one)\n" % self.rows[n][1])
        else:
            ida_kernwin.jumpto(handler)
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
    if text not in old:
        idc.set_cmt(address, old + "\n" + text if old else text, False)


HOOK_RECORD = "$ memlens.hooks"  # netnode: what MemLens linked and renamed, so running it again adds nothing twice
HOOK_RECORD_TAG = "B"


def load_hook_record():
    """(netnode, record) with record = {"xrefs": [[from, to, flow], ...], "names": [[page, old name, new name], ...]}."""
    node = ida_netnode.netnode(HOOK_RECORD, 0, True)
    blob = node.getblob(0, HOOK_RECORD_TAG)
    try:
        record = json.loads(blob.decode("utf-8")) if blob else {}
    except ValueError:
        record = {}
    return node, {"xrefs": list(record.get("xrefs", [])), "names": list(record.get("names", []))}


def link_hooks(image, findings):
    """Apply the hook chain that patchscan decides: a user code xref from each hooking instruction to its target and
    from each copied hook page's handler call to the handler, a role name for each such page (once, and only while it
    still has the exporter's memlens_target_ label or no name but IDA's dummy one), and a comment there with the old
    label. What was added is kept in the HOOK_RECORD netnode, so a second run adds no xref and renames nothing again,
    and an xref or name the user removed since is not put back. Returns (links, counts)."""
    links = patchscan.hook_links(image, findings)
    flow_types = {"call": ida_xref.fl_CN, "jmp": ida_xref.fl_JN}  # near call or near jump, as the hooking instruction is
    node, record = load_hook_record()
    done = {tuple(xref) for xref in record["xrefs"]}
    counts = dict.fromkeys(("xrefs", "xrefs_before", "xrefs_failed", "renamed", "named_before", "kept", "rename_failed"), 0)
    for source, target, flow in patchscan.hook_xrefs(links):
        if (source, target, flow) in done:
            counts["xrefs_before"] += 1
        elif ida_xref.add_cref(source, target, flow_types[flow] | ida_xref.XREF_USER):
            record["xrefs"].append([source, target, flow])
            done.add((source, target, flow))
            counts["xrefs"] += 1
        else:
            counts["xrefs_failed"] += 1
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
    node.setblob(json.dumps(record).encode("utf-8"), 0, HOOK_RECORD_TAG)
    return links, counts


def link_report(links, counts):
    """One Output-window line on what link_hooks did."""
    line = ("[MemLens] hook chain: %d patched entries lead into this database, %d to a hook page MemLens copied; "
            "%d code xrefs added" % (len(links), sum(1 for link in links if link.page), counts["xrefs"]))
    extra = [("%d already added by an earlier run" % counts["xrefs_before"]) if counts["xrefs_before"] else "",
             ("%d refused by IDA" % counts["xrefs_failed"]) if counts["xrefs_failed"] else ""]
    line += "".join(" (%s)" % text for text in extra if text)
    line += "; %d hook pages renamed by role" % counts["renamed"]
    for key, text in (("named_before", "%d already named by an earlier run"), ("kept", "%d left alone, they have another name now"),
                      ("rename_failed", "%d refused by IDA")):
        if counts[key]:
            line += ", " + text % counts[key]
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
            ida_kernwin.msg("[MemLens] hook chain not added (no xrefs or renames) because of this error:\n%s\n"
                            % traceback.format_exc())
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
