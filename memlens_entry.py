"""MemLens: reverse engineer a Linux kernel from a memory image in IDA.

Two actions under Edit > Plugins:
  * Export kernel from memory image: runs Volatility 3 and writes a symbolled ELF to open in IDA.
  * Apply kernel types from ISF: imports every struct, union and enum of that kernel.
  * Show patched kernel functions: lists hooked entries and odd syscall slots, Enter jumps there.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

import ida_idaapi
import ida_kernwin
import ida_nalt
import ida_typeinf
import idc

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


def apply_types(isf_path):
    """Import the ISF's types, type the globals, and check the result against the ISF."""
    isf = isf2c.load_isf(isf_path)
    generator = isf2c.Generator(isf)

    def progress(done, total):
        ida_kernwin.replace_wait_box("MemLens: importing types (%d of %d)" % (done, total))
        return ida_kernwin.user_cancelled()

    rejected = isf2c.import_in_batches(generator.declarations(), parse_batch, progress=progress)
    missing, wrong = check_sizes(generator.expected_sizes())
    typed = failed = 0
    decls = isf2c.global_decls(generator, isf)
    for index, (name, declaration) in enumerate(decls):
        if index % 2000 == 0:
            ida_kernwin.replace_wait_box("MemLens: typing globals (%d of %d)" % (index, len(decls)))
            if ida_kernwin.user_cancelled():
                break
        address = idc.get_name_ea_simple(name)
        if address == idc.BADADDR:
            continue
        if idc.SetType(address, declaration + ";"):
            typed += 1
        else:
            failed += 1
    stats = dict(generator.stats, globals_typed=typed, globals_failed=failed)
    return {"stats": stats, "rejected": rejected, "missing": missing, "wrong_size": wrong}


def report(result):
    """The import summary, so a user can see exactly what did and did not arrive."""
    lines = ["[MemLens] imported: %s" % result["stats"],
             "[MemLens] rejected by IDA's parser: %d" % len(result["rejected"]),
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


def written_file(stdout):
    """The file Volatility really wrote: if kernel.elf exists it picks a new name."""
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


class ApplyTypes(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        path = ida_kernwin.ask_file(False, "*.json;*.xz", "Volatility ISF for this kernel")
        if not path:
            return 0
        ida_kernwin.show_wait_box("MemLens: reading ISF")
        try:
            result = apply_types(path)
        finally:
            ida_kernwin.hide_wait_box()
        ida_kernwin.msg(report(result))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ExportKernel(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        image = ida_kernwin.ask_file(False, "*", "Linux memory image")
        if not image:
            return 0
        vol = shutil.which("vol") or ida_kernwin.ask_file(False, "vol*", "Where is Volatility 3's 'vol' command?")
        if not vol:
            return 0
        isf = ida_kernwin.ask_file(False, "*.json;*.xz", "ISF for this kernel (Cancel = use Volatility's own symbols)")
        output = os.path.dirname(os.path.abspath(image))
        with tempfile.TemporaryDirectory() as folder:
            symbols = symbols_folder(isf, folder) if isf else None
            ida_kernwin.show_wait_box("MemLens: Volatility is scanning the image, this can take minutes")
            try:
                code, stdout, stderr = run_cancellable(export_command(vol, image, output, symbols))
            finally:
                ida_kernwin.hide_wait_box()
        if code is None:
            return 0
        if code:
            ida_kernwin.warning("Volatility failed:\n" + stderr[-1500:].decode("utf-8", "replace"))
            return 0
        ida_kernwin.info("Wrote %s in %s. Open it in IDA, then use Apply kernel types." % (written_file(stdout), output))
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
        return patchscan.scan(handle.read())


class FindPatches(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        findings = scan_current_input()
        if findings is None:
            return 0
        for address, _, what, target, _ in findings:
            idc.set_cmt(address, "MemLens: %s %s" % (what, target), 0)
        ida_kernwin.msg("[MemLens] %d patched entries or odd syscall slots\n" % len(findings))
        global _open_list  # a non-modal chooser must outlive this call
        _open_list = PatchList(findings)
        _open_list.Show()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


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
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", action, ida_kernwin.SETMENU_APP)
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg):
        ida_kernwin.info("MemLens actions are under Edit > Plugins.")

    def term(self):
        for action, _, _ in ACTIONS:
            ida_kernwin.unregister_action(action)


def PLUGIN_ENTRY():
    return MemLens()
