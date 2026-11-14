# Using MemLens

Part of the MemLens documentation; start with the [README](../README.md).

## Usage

In IDA, with any database open (plugin menu entries need one), under **Edit > Plugins**:

1. **MemLens: Export kernel from memory image**: choose the image. `kernel.elf` is written next to it (`kernel-1.elf` if one is already there; the message names the file). MemLens asks for the ISF and hands it to Volatility (Cancel uses Volatility's own symbols path, which has no Linux ISFs after a plain pip install). If Volatility finds no kernel, the error dialog says which kernel the image holds, or that it holds none (see [When the export fails](EXPORT.md#when-the-export-fails)).
2. Open `kernel.elf` in IDA.
3. **MemLens: Apply kernel types from ISF**: choose the ISF. If its kernel banner differs from the one in the database, MemLens asks before importing anything. The Output window then says how many types IDA rejected, how many are missing and how many differ in size from the ISF. If **Show patched kernel functions** already ran on this database, Apply kernel types then applies the hook chain again (and says so in the Output window), so the ftrace_ops flags comments and the module ops' `struct ftrace_ops` type appear without opening the list a second time; on a database where the list never ran it reads no file (checked with fake IDA modules, not in IDA).
4. **MemLens: Show patched kernel functions**: opens the list, adds a comment at each entry (at a hooked entry that leads to a copied hook page, written after the hook chain below: the chain and its owner, also as the comment of a function that starts there, IDA's or the one MemLens makes, unless that function already has another comment; see [docs/OUTPUT.md](OUTPUT.md#what-you-get-real-output-from-the-demo-not-ida-screenshots)) and links the hook chain: a code cross-reference from each hooked entry to its hook page and from the page's first named call to that function, cross-references toward the page's owner (a code xref to the BPF program; data xrefs from an ftrace trampoline's `ftrace_ops` slot to the ops and from its `func` to the callback, read at the offset from the last ISF applied with Apply kernel types that has `ftrace_ops`, else 0), and a name by role for each copied hook page whose role is known (`ftrace_tramp_`, `kprobe_ftrace_tramp_`, `bpf_tramp_`, or `module_hook_` when the page's first named call is a module's function; then the hooked function's name, or the page's address when several functions share it). It renames a page once, and only while it still has its `memlens_target_<address>` label or no real name, so a name you gave it is kept; the old label stays in a comment at the page. It then makes a function (`ida_funcs.add_func`) at each address on the chain where code starts (hooked entry, hook page, handler, BPF program, owner) that is in an executable segment and in no function yet, so the chain should read as code before auto-analysis reaches the module area; it never deletes or redefines anything, and the Output window line counts them (`n functions created now`, plus how many were already in a function or refused by IDA). After Apply kernel types (whose ISF gives the offset of `ftrace_ops.flags` and the `FTRACE_OPS_FL_*` values by name) it also comments each ftrace trampoline whose owner is its `ftrace_ops` (not a kprobe's), and that ops, with the ops' flags decoded and whether IPMODIFY is set, and types an ops that a module's symbol starts at as `struct ftrace_ops`, once. What it added is recorded in the database (netnode `$ memlens.hooks`), so running it again adds nothing twice and does not put back an xref or name you removed. Enter jumps to the entry; the list's Edit command, captioned **Jump to handler** in its context menu (usually Ctrl+E in IDA; not checked in IDA), jumps to the handler (on a page with no known role, whose first named call is a core-kernel helper, it says so instead), and its Insert command, captioned **Jump to owner** (usually Ins; not checked in IDA), to the owner when it is in the database. If adding the chain fails, the list is still shown and the error is in the Output window (xrefs or names added before the error are not recorded, so a second run counts them again). If the input file is missing and you pick a kernel.elf that is not the file the database was made from (by SHA-256), it asks before writing anything. Not yet tried in IDA.

## Without IDA

```
vol -p vol_plugins -s <symbols> -o <outdir> -f <image> linux.kernel2elf.Kernel2Elf [--no-percpu] [--no-modules]
python3 isf2c.py <isf.json.xz> kernel_types.h
python3 patchscan.py [--links] [--isf <isf.json.xz>] kernel.elf
```

`--links` also prints the cross-references, hook page names and owners that **Show patched kernel functions** adds in IDA. `--isf` reads the offset of `ftrace_ops.func` from that kernel's ISF (otherwise 0).

## Headless, with idalib

IDA 9.1 or newer (the IDA names MemLens uses are checked against the IDA 9.1 to 9.4 Python stubs and the 9.5 SDK's API list); set up the `idapro` module as Hex-Rays describes. After `hcli plugin install memlens` the script is in the plugin's folder, `$IDAUSR/plugins/memlens` (by default `~/.idapro/plugins/memlens` on Linux and macOS, `%APPDATA%\Hex-Rays\IDA Pro\plugins\memlens` on Windows):

```
python3 ~/.idapro/plugins/memlens/tools/memlens_headless.py kernel.elf <isf.json.xz> [--no-analysis] [--any-kernel]
```

It opens `kernel.elf` as a database, applies the types (the per-CPU copies too), comments every patched entry, links the hook chain as the menu action does, prints the same report and patch list and saves the database. It calls the plugin's own functions; like the rest of the IDA layer it has only been run against fake modules (`tests/test_headless_stub.py`), not a real idalib.
