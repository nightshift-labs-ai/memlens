"""MemLens: reverse engineer a Linux kernel from a memory image in IDA.

Two actions under Edit > Plugins:
  * Export kernel from memory image: runs Volatility 3 and writes a symbolled ELF to open in IDA.
  * Apply kernel types from ISF: imports every struct, union and enum of that kernel.
"""
import os
import shutil
import subprocess
import tempfile

import sys

import ida_idaapi
import ida_kernwin
import idc

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import isf2c  # noqa: E402  (needs the plugin folder on sys.path)


def apply_types(isf_path):
    """Import the ISF's types, then type the kernel globals. Returns (parser errors, stats)."""
    isf = isf2c.load_isf(isf_path)
    generator = isf2c.Generator(isf)
    with tempfile.TemporaryDirectory() as folder:
        header = os.path.join(folder, "kernel_types.h")
        with open(header, "w", encoding="utf-8") as handle:
            handle.write(generator.generate())
        errors = idc.parse_decls(header, idc.PT_FILE)
    typed = failed = 0
    for name, declaration in isf2c.global_decls(generator, isf):
        address = idc.get_name_ea_simple(name)
        if address == idc.BADADDR:
            continue
        if idc.SetType(address, declaration + ";"):
            typed += 1
        else:
            failed += 1
    stats = dict(generator.stats, globals_typed=typed, globals_failed=failed)
    return errors, stats


def export_command(vol, image, output, symbols=None):
    command = [vol, "-q", "-p", os.path.join(HERE, "vol_plugins"), "-o", output]
    if symbols:
        command += ["-s", symbols]
    return command + ["-f", image, "linux.kernel2elf.Kernel2Elf"]


class ApplyTypes(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        path = ida_kernwin.ask_file(False, "*.json;*.xz", "Volatility ISF for this kernel")
        if not path:
            return 0
        errors, stats = apply_types(path)
        ida_kernwin.msg("[MemLens] imported %s, parser errors: %s\n" % (stats, errors))
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class ExportKernel(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        image = ida_kernwin.ask_file(False, "*", "Linux memory image")
        if not image:
            return 0
        vol = shutil.which("vol")
        if not vol:
            ida_kernwin.warning("MemLens needs Volatility 3: put its 'vol' command on PATH.")
            return 0
        output = os.path.dirname(os.path.abspath(image))
        result = subprocess.run(export_command(vol, image, output), capture_output=True, text=True)
        if result.returncode:
            ida_kernwin.warning("Volatility failed:\n" + result.stderr[-1500:])
            return 0
        ida_kernwin.info("Wrote kernel.elf in %s. Open it in IDA, then use Apply kernel types." % output)
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


ACTIONS = [
    ("memlens:export", "MemLens: Export kernel from memory image", ExportKernel),
    ("memlens:types", "MemLens: Apply kernel types from ISF", ApplyTypes),
]


class MemLens(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_KEEP
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
