"""Volatility 3 hook findings for the MemLens list: reads the JSON that `vol -r json` writes for six hook plugins and
turns each row into a row of the list (Python 3.8, standard library only).

Volatility's JSON is not a stable API, so the field names are pinned to Volatility 2.28.2 (the plugins' column names
there). A file is told apart by its field names, not by its file name; a field 2.28.2 does not write is ignored (except
in a keyboard notifiers file, see EXACT), and a file of any other plugin is skipped, each with one warning line.
Volatility writes kernel addresses cut to 48 bits (281473643531984 = 0xffffb0894ed0 for 0xffffffffb0894ed0); they are
sign-extended back to 64 bits here.
"""
import collections
import json
import os

VOLATILITY = "2.28.2"
MAX_SIZE = 16 << 20  # bytes; these plugins write a few KB, so a bigger .json file (an ISF, say) is not read
# (plugin, the fields 2.28.2 writes, fields it writes only with an option): IDT before keyboard notifiers, whose three
# fields check_idt also writes.
PLUGINS = (
    ("linux.tracing.ftrace", ("ftrace_ops address", "Callback", "Callback address", "Hooked symbols", "Module",
                              "Module address"), ("Flags",)),  # Flags: --show-ftrace-flags
    ("linux.malware.netfilter", ("Net NS", "Proto", "Hook", "Priority", "Handler", "Module", "Symbol", "Is Hooked"), ()),
    ("linux.tracing.tracepoints", ("tracepoint", "tracepoint address", "Probe", "Probe address", "Probe priority",
                                   "Module", "Module address"), ()),
    ("linux.malware.check_idt", ("Index", "Address", "Module", "Symbol"), ()),
    ("linux.malware.check_afinfo", ("Symbol Name", "Member", "Handler Address"), ()),
    ("linux.malware.keyboard_notifiers", ("Address", "Module", "Symbol"), ()),
)
# Keyboard notifiers' three fields are also written, with one more, by check_idt (Index) and tty_check (Name, a plugin
# MemLens does not read): a file with more fields than these three is not taken for keyboard notifiers.
EXACT = ("linux.malware.keyboard_notifiers",)
LAST = ("linux.malware.check_idt",)  # its rows go after the other Volatility rows: it lists every vector it checks
CHILDREN = "__children"  # the JSON renderer's nesting, not a field
MEMLENS = "MemLens"

# plugin; address: the callback Enter jumps to (sign-extended, or None); where, what: Volatility's words; owner: its
# Module column; ops: the ftrace_ops address of an ftrace row (sign-extended), else None
Finding = collections.namedtuple("Finding", "plugin address where what owner ops")
# findings; read: [(file name, plugin or None for an empty file, rows)]; warnings: one line per file skipped or partly read
Loaded = collections.namedtuple("Loaded", "findings read warnings")


def sign_extend(value):
    """A kernel address from Volatility's JSON (an int cut to 48 bits) as 64 bits; None when value is not an address."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << 64:
        return None
    return value | 0xffff000000000000 if value < 1 << 48 and value >> 47 & 1 else value


def rows_of(rows):
    """Every row of the renderer's tree, children after their parent."""
    for row in rows:
        yield row
        children = row.get(CHILDREN)
        if isinstance(children, list):
            yield from rows_of(child for child in children if isinstance(child, dict))


def plugin_of(fields):
    """(plugin, fields it does not know) for a file's set of field names, or None."""
    for plugin, known, optional in PLUGINS:
        if set(known) <= fields and (plugin not in EXACT or fields <= set(known) | set(optional)):
            return plugin, sorted(fields - set(known) - set(optional))
    return None


def text(value):
    """A cell as Volatility's pretty renderer prints an absent value: '-'."""
    return "-" if value is None else str(value)


def hexa(value):
    return "%#x" % value if isinstance(value, int) and not isinstance(value, bool) else text(value)


def finding(plugin, row):
    """The Finding for one row of a plugin's output (None when it has no address to jump to)."""
    get = row.get
    ops = None
    if plugin == "linux.tracing.ftrace":
        ops = sign_extend(get("ftrace_ops address"))
        address, where = get("Callback address"), "ftrace_ops %s" % hexa(ops if ops is not None else get("ftrace_ops address"))
        what = "callback %s, hooked symbols %s" % (text(get("Callback")), text(get("Hooked symbols")))
        if get("Flags") is not None:
            what += "; flags %s" % text(get("Flags")).replace("FTRACE_OPS_FL_", "")
    elif plugin == "linux.malware.netfilter":
        address, where = get("Handler"), "netfilter %s %s" % (text(get("Proto")), text(get("Hook")))
        what = "%s, priority %s, net ns %s; Is Hooked: %s" % (text(get("Symbol")), text(get("Priority")), text(get("Net NS")),
                                                            text(get("Is Hooked")))
    elif plugin == "linux.tracing.tracepoints":
        address, where = get("Probe address"), "tracepoint %s" % text(get("tracepoint"))
        what = "probe %s, priority %s" % (text(get("Probe")), text(get("Probe priority")))
    elif plugin == "linux.malware.check_idt":
        address, where, what = get("Address"), "IDT %s" % hexa(get("Index")), "handler %s" % text(get("Symbol"))
    elif plugin == "linux.malware.check_afinfo":
        address, where = get("Handler Address"), "afinfo %s.%s" % (text(get("Symbol Name")), text(get("Member")))
        what = "listed by Volatility: no kernel symbol starts at this handler"
    else:  # linux.malware.keyboard_notifiers
        address, where, what = get("Address"), "keyboard notifier", "notifier_call %s" % text(get("Symbol"))
    address = sign_extend(address)
    if address is None:
        return None
    return Finding(plugin, address, where, what, text(get("Module")) if "Module" in row else "", ops)


def read_rows(path):
    """(rows, problem): the renderer's top-level row list, or None and why the file is not one."""
    try:
        size = os.path.getsize(path)
        if size > MAX_SIZE:
            return None, "not read, %d bytes is more than a findings file has (the limit is %d)" % (size, MAX_SIZE)
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError as error:  # no permission, gone since the folder was listed, ...
        return None, "not read (%s)" % (error.strerror or error)
    try:
        rows = json.loads(raw)  # bytes: UTF-8, or UTF-16 as PowerShell's > writes it
    except ValueError as error:
        return None, "not read, not JSON (%s)" % error
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        return None, "not read, not the list of rows that vol -r json writes"
    return rows, None


def load(paths):
    """Loaded for these files, in this order. A plugin read from an earlier file is not read again."""
    findings, read, warnings, seen = [], [], [], {}
    for path in paths:
        name = os.path.basename(path)
        rows, problem = read_rows(path)
        if rows is None:
            warnings.append("%s: %s" % (name, problem))
            continue
        rows = list(rows_of(rows))
        fields = {key for row in rows for key in row if key != CHILDREN}
        if not rows:
            read.append((name, None, 0))
            continue
        found = plugin_of(fields)
        if found is None:
            warnings.append("%s: not read, its fields are not those of a plugin MemLens reads (as Volatility %s names them): %s"
                            % (name, VOLATILITY, ", ".join(sorted(fields))))
            continue
        plugin, unknown = found
        if plugin in seen:
            warnings.append("%s: not read, %s was read from %s already" % (name, plugin, seen[plugin]))
            continue
        seen[plugin] = name
        made = [finding(plugin, row) for row in rows]
        findings.extend(item for item in made if item is not None)
        read.append((name, plugin, len(made)))
        problems = []
        if unknown:
            problems.append("fields Volatility %s does not write, ignored: %s" % (VOLATILITY, ", ".join(unknown)))
        if None in made:
            problems.append("%d rows with no address left out" % made.count(None))
        if problems:
            warnings.append("%s: read as %s; %s" % (name, plugin, "; ".join(problems)))
    return Loaded(findings, read, warnings)


def load_folder(picked):
    """Loaded for every .json file in the folder of the picked file, in name order."""
    folder = os.path.dirname(os.path.abspath(picked))
    names = sorted(name for name in os.listdir(folder) if name.lower().endswith(".json")
                   and os.path.isfile(os.path.join(folder, name)))
    return load([os.path.join(folder, name) for name in names])


def report(loaded, folder):
    """The Output window lines for a load: what each file was read as, then each warning."""
    parts = ["%s (%s)" % (name, "%s, %d rows" % (plugin, count) if plugin else "no rows") for name, plugin, count in loaded.read]
    lines = ["[MemLens] Volatility findings in %s: %s\n" % (folder, ", ".join(parts) or "no file read")]
    return "".join(lines + ["[MemLens] warning: %s\n" % line for line in loaded.warnings])


def repeats(item, by_ops):
    """The MemLens rows that a finding repeats: for an ftrace row, those whose hook page loads the same ftrace_ops."""
    return by_ops.get(item.ops, []) if item.ops is not None else []


def merge(rows, ops, findings, name_at):
    """(rows, sources, merged): the MemLens rows (patchscan.list_rows) with a Source each, then one row per finding that
    repeats none of them (in the order of findings, the IDT rows last; an exact repeat once), and the number of findings
    merged into MemLens rows instead.

    ops[i] is the ftrace_ops that MemLens row i's hook page loads, or None; an ftrace finding with that ops adds Volatility
    to that row's Source. name_at(address) is kernel.elf's name for an address, or None when it is not in the ELF. A
    finding's row: the callback (Address, where Enter jumps), Volatility's words (Where, What), kernel.elf's name for the
    callback (Target), no handler, Volatility's Module (Owner; Jump to owner goes to the callback when it is in the ELF)."""
    by_ops = {}
    for index, value in enumerate(ops):
        if value is not None:
            by_ops.setdefault(value, []).append(index)
    out, sources, seen, merged = list(rows), [MEMLENS] * len(rows), set(), 0
    for item in sorted(findings, key=lambda item: item.plugin in LAST):  # stable: file order otherwise
        same = repeats(item, by_ops)
        if same:
            for index in same:
                sources[index] = "%s; Volatility %s: same ftrace_ops" % (MEMLENS, item.plugin)
            merged += 1
            continue
        key = (item.plugin, item.address, item.where, item.what)
        if key in seen:
            continue
        seen.add(key)
        name = name_at(item.address)
        target = name if name is not None else "%#x (not in this kernel.elf)" % item.address
        out.append((item.address, item.where, item.what, target, "", None, item.owner, item.address if name is not None else None))
        sources.append("Volatility %s" % item.plugin)
    return out, sources, merged
