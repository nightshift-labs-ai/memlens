"""MemLens: reverse engineer a Linux kernel from a memory image in IDA.

Three actions under Edit > Plugins:
  * Export kernel from memory image: runs Volatility 3 and writes a symbolled ELF to open in IDA.
  * Apply kernel types from ISF: imports every struct, union and enum of that kernel.
  * Show patched kernel functions: lists hooked entries and odd syscall slots, Enter jumps there.
"""
import base64
import itertools
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
import ida_typeinf
import idc

ISF_FILTER = "FILTER Volatility ISF|*.json;*.xz|All files|*\n"
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
    """(ISF banner, database banner) if the ISF was built for another kernel; None if they agree or cannot be compared."""
    data = (isf.get("symbols", {}).get("linux_banner") or {}).get("constant_data")
    address = idc.get_name_ea_simple("linux_banner")
    if not data or address == idc.BADADDR:
        return None
    expected = base64.b64decode(data).split(b"\0")[0]
    actual = ida_bytes.get_bytes(address, len(expected)) or b""
    return None if actual == expected else (expected, actual)


def confirm_other_kernel(expected, actual):
    ida_kernwin.hide_wait_box()
    text = "This ISF was built for a different kernel, so its types may be wrong here.\n\nISF: %s\nDatabase: %s\n\nImport anyway?" % (
        expected.decode("ascii", "replace").strip(), actual.decode("ascii", "replace").strip())
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

    def progress(done, total):
        ida_kernwin.replace_wait_box("MemLens: importing types (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    rejected = isf2c.import_in_batches(generator.declarations(), parse_batch, progress=progress)
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
    return {"stats": stats, "rejected": rejected, "missing": missing, "wrong_size": wrong}


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
    lines = ["[MemLens] imported: %s" % stats]
    if "globals_declared" in stats:
        lines.append("[MemLens] typed %d of the %d globals the ISF declares, plus %d per-CPU variables in every CPU's copy; "
                     "%d failed; %d have no symbol in this database (address 0 in the ISF, or outside exported memory)"
                     % (stats["globals_typed"], stats["globals_declared"], stats.get("percpu_typed", 0),
                        stats["globals_failed"], stats["globals_not_in_database"]))
    if stats.get("globals_skipped_code"):
        lines.append("[MemLens] left %d names alone that the ISF declares as variables but that are code here (for example a function "
                     "with the same name as a variable elsewhere)" % stats["globals_skipped_code"])
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
            ida_kernwin.warning("Volatility failed:\n" + stderr[-1500:].decode("utf-8", "replace"))
            return 0
        message = "Wrote %s in %s. Open it in IDA, then use Apply kernel types." % (written_file(stdout, output, before), output)
        ida_kernwin.msg("[MemLens] %s\n" % message)  # info() can be silenced for good by its checkbox
        ida_kernwin.info(message.replace("%", "%%"))  # info() is printf-style in IDAPython (not wrapped like msg/warning)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class PatchList(ida_kernwin.Choose):
    """Patched entries and odd syscall slots; Enter jumps to one."""

    def __init__(self, findings):
        columns = [["Address", 18 | ida_kernwin.Choose.CHCOL_HEX], ["Where", 34], ["What", 34], ["Target", 40]]
        ida_kernwin.Choose.__init__(self, "MemLens: patched kernel functions", columns)
        self.findings = findings

    def OnGetSize(self):
        return len(self.findings)

    def OnGetLine(self, n):
        address, name, what, target, _ = self.findings[n]
        return ["%X" % address, name, what, target]

    def OnSelectLine(self, n):
        ida_kernwin.jumpto(self.findings[n][0])
        return (ida_kernwin.Choose.NOTHING_CHANGED,)


def scan_current_input():
    """Findings for the ELF open in IDA, which is plain data: the database is only annotated."""
    path = ida_nalt.get_input_file_path()
    if not path or not os.path.isfile(path):
        path = ida_kernwin.ask_file(False, "*.elf", "kernel.elf exported by MemLens")
        if not path:
            return None
    with open(path, "rb") as handle:
        blob = handle.read()
    try:
        if patchscan.on_disk_kernel(blob):
            raise ValueError("this is a kernel file from disk, whose entry bytes are not what ran")
        return patchscan.scan(blob)
    except patchscan.BAD_ELF as error:
        ida_kernwin.warning("MemLens needs the kernel.elf it exported: %s" % error)
        return None


def add_comment(address, text):
    """Adds our line to the comment at address and keeps whatever is already there."""
    old = idc.get_cmt(address, False) or ""
    if text not in old:
        idc.set_cmt(address, old + "\n" + text if old else text, False)


class FindPatches(ida_kernwin.action_handler_t):
    @guarded
    def activate(self, ctx):
        findings = scan_current_input()
        if findings is None:
            return 0
        for address, _, what, target, _ in findings:
            add_comment(address, "MemLens: %s %s" % (what, target))
        ida_kernwin.msg("[MemLens] %d patched entries or odd syscall slots\n" % len(findings))
        global _open_list  # a non-modal chooser must outlive this call
        _open_list = PatchList(findings)
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
