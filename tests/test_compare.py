#!/usr/bin/env python3
"""The README section "What Volatility already tells you" against recorded Volatility 3 2.28.2 output
(tests/fixtures/vol-2.28.2/compare, see its README.txt) and against MemLens's own output, so its table cannot go stale.

    python3 tests/test_compare.py                    # the recorded Volatility output only
    MEMLENS_DEMO_ELF=<demo kernel.elf> MEMLENS_TESTHOOK_ELF=<second sample's kernel.elf> python3 tests/test_compare.py

Every Volatility cell must be what the recorded plugin printed for that hook, every Volatility row must be used once, the
"Named" row must be the count of the cells above it, and the section's other numbers and plugin names must match the
recordings (plugins by their linux.malware.* name where 2.28.2 has one; the old names are aliases it will remove), and each row's hook kind must fit Volatility's callback (kprobe: kprobe_ftrace_handler, BPF: call_direct_funcs,
both ways). With a sample's kernel.elf, every MemLens cell must be what `patchscan.py --links` prints for it, a `-` in
Volatility's hooked-function column must be exactly a hook site after the function's start, and the ftrace_ops address
Volatility prints must be the ops MemLens reads from that hook's trampoline. The hidden-module rows of docs/LIMITS.md are
checked against the recorded owner lines too. Then each hook label (kind, who set it, capture), each code span (the
MemLens ones with the samples given) and each Named number is changed in turn, and every change must fail the check.
No IDA, no Volatility, no network.
"""
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures", "vol-2.28.2", "compare")
PATCHSCAN = [sys.executable, "-I", os.path.join(ROOT, "patchscan.py")]
HEADING = "## What Volatility already tells you"
CAPTURES = {"demo": "demo", "second sample": "th"}
SAMPLES = (("MEMLENS_DEMO_ELF", "demo"), ("MEMLENS_TESTHOOK_ELF", "th"))
# callbacks every hook of a kind shares (the kprobe layer's, the direct-call one, none): not the hook's own owner
SHARED = {"-", "kprobe_ftrace_handler", "call_direct_funcs"}
FORBIDDEN = re.compile(r"\bonly\b|\bunique\b|no other tool", re.I)
# changes of a hook label (first column) for the mutants: its kind, who set the hook, its capture
LABEL_SWAPS = (("ftrace, ", "kprobe, "), ("kprobe, ", "ftrace, "), ("ftrace, test module", "BPF LSM program"),
               ("kprobe, tracefs", "BPF LSM program"), ("BPF LSM program", "ftrace, tracefs"), ("test module", "tracefs"),
               ("tracefs", "test module"), ("(demo)", "(second sample)"), ("(second sample)", "(demo)"))


def read(*parts):
    with open(os.path.join(*parts), encoding="utf-8") as handle:
        return handle.read()


def vol_table(name):
    """(columns, rows) of a Volatility pretty-renderer output: the header line has '|' first, each row '* |'."""
    columns, rows = None, []
    for line in read(FIXTURES, name).splitlines():
        if line.startswith("* |"):
            cells = [cell.strip() for cell in line.split("|")[1:]]
            rows.append(dict(zip(columns, cells)))
        elif columns is None and line.strip().startswith("|"):
            columns = [cell.strip() for cell in line.split("|")[1:]]
    return columns, rows


def sign_extend(address):
    """Volatility prints kernel addresses cut to 48 bits."""
    return address | 0xffff000000000000 if address >> 47 & 1 else address


def code(text):
    """`x` -> x; anything else -> None."""
    match = re.fullmatch(r"`([^`]+)`", text.strip())
    return match.group(1) if match else None


def section(readme):
    start = readme.find("\n" + HEADING + "\n")
    if start < 0:
        return None
    end = readme.find("\n## ", start + 1)
    return readme[start:end if end > 0 else len(readme)]


def table_rows(text):
    """The section's table rows (header and separator dropped), each a list of stripped cells."""
    lines = [line for line in text.splitlines() if line.startswith("|")]
    return [[cell.strip() for cell in line.strip().strip("|").split("|")] for line in lines[2:]]


def parse_links(text):
    """{hooked function: {site offset, hook page, owner text, ops addresses the page loads}} from patchscan --links."""
    entries, xrefs, owners = {}, [], {}
    for line in text.splitlines():
        fields = line.split("\t")
        if fields[0] == "xref":
            xrefs.append((int(fields[1], 16), int(fields[2], 16), fields[3], fields[4].split(" -> ")[0]))
        elif fields[0] == "owner":
            owners[int(fields[1], 16)] = fields[3]
        elif fields[0].startswith("0x") and len(fields) >= 4:
            entries[fields[1]] = {"offset": None, "page": None, "owner": None, "ops": set()}
    for site, target, kind, origin in xrefs:
        name, _, offset = origin.partition("+")
        if kind in ("call", "jmp") and name in entries and entries[name]["page"] is None:
            entries[name].update(page=target, offset=offset)
    for entry in entries.values():
        if entry["page"] is None:
            continue
        entry["owner"] = owners.get(entry["page"])
        label = "memlens_target_%x" % entry["page"]
        entry["ops"] = {target for site, target, kind, origin in xrefs
                        if kind == "data" and origin.partition("+")[0] == label}
    return entries


def check(readme, limits, output_md, links):
    """Errors (empty when the docs match the recordings and, for the samples in `links`, MemLens's output)."""
    errors = []
    text = section(readme)
    if text is None:
        return ["README has no section %r" % HEADING]
    if readme.find(HEADING) > readme.find("\n## What it does"):
        errors.append("the section must come before 'What it does'")
    if "2.28.2" not in text:
        errors.append("the section does not pin Volatility 2.28.2")
    for word in FORBIDDEN.findall(text):
        errors.append("the section says %r; no measured row proves that" % word)
    plugins = read(FIXTURES, "plugins.txt").splitlines()
    if plugins[0] != "Volatility 3 Framework 2.28.2":
        errors.append("plugins.txt is not from Volatility 2.28.2: %r" % plugins[0])
    for name, source in [(n, "README") for n in re.findall(r"`(linux\.[A-Za-z_.]+)`", text)] + \
                        [(n, "docs/LIMITS.md") for n in re.findall(r"`(linux\.[A-Za-z_.]+)`", limits)]:
        if not any(p == name or p.startswith(name + ".") for p in plugins[1:]):
            errors.append("%s names %s, which Volatility 2.28.2 does not have" % (source, name))
        elif not name.startswith("linux.malware.") and any(p.startswith("linux.malware." + name[6:] + ".") for p in plugins[1:]):
            # 2.28.2 keeps the old name as an alias that "will be removed in the first release after 2026-06-07"
            errors.append("%s names %s, an old name: use linux.malware.%s" % (source, name, name[6:]))
    if "no kprobe plugin" in text and any("kprobe" in p.lower() for p in plugins[1:]):
        errors.append("the section says there is no kprobe plugin, but plugins.txt has one")

    ftrace = {tag: vol_table(tag + ".ftrace.txt")[1] for tag in ("demo", "th")}
    flags = {tag: vol_table(tag + ".ftrace-flags.txt")[1] for tag in ("demo", "th")}
    ebpf = {tag: vol_table(tag + ".ebpf.txt") for tag in ("demo", "th")}
    rows, totals = [], None
    for cells in table_rows(text):
        if len(cells) != 3:
            errors.append("table row with %d cells: %r" % (len(cells), cells))
            continue
        if cells[0] == "**Named**":
            totals = cells
            continue
        capture = re.search(r"\((%s)\)$" % "|".join(CAPTURES), cells[0])
        label = re.fullmatch(r"(?:(ftrace|kprobe), (test module|tracefs)|BPF LSM program) \((?:%s)\)" % "|".join(CAPTURES), cells[0])
        vol = cells[1].split(" / ", 1)
        mine = cells[2].split(" / ", 1)
        owner = re.fullmatch(r"`([^`]+)`(?:, Module `([^`]+)`)?", vol[1]) if len(vol) == 2 else None
        if not capture or not label or len(vol) != 2 or len(mine) != 2 or not owner \
                or None in (code(vol[0]), code(mine[0]), code(mine[1])):
            errors.append("cannot read table row %r" % cells)
            continue
        rows.append({"kind": cells[0], "hook": label.group(1) or "BPF", "setter": label.group(2),
                     "tag": CAPTURES[capture.group(1)], "hooked": code(vol[0]),
                     "callback": owner.group(1), "module": owner.group(2) or "__kernel__",
                     "where": code(mine[0]), "owner": code(mine[1])})
    sites = re.search(r"For the (\d+) hook sites", text)
    if not sites or int(sites.group(1)) != len(rows):
        errors.append("the intro's number of hook sites is not the %d table rows" % len(rows))

    used = {"demo": [], "th": []}
    for row in rows:
        found = [r for r in ftrace[row["tag"]] if r["Callback"] == row["callback"] and r["Module"] == row["module"]]
        if len(found) != 1:
            errors.append("%s: Volatility printed no single ftrace row with Callback %s, Module %s"
                          % (row["kind"], row["callback"], row["module"]))
            continue
        vol = row["vol"] = found[0]
        used[row["tag"]].append(vol["ftrace_ops address"])
        if vol["Hooked symbols"] != row["hooked"]:
            errors.append("%s: Volatility printed hooked symbol %r, the README says %r"
                          % (row["kind"], vol["Hooked symbols"], row["hooked"]))
        if row["module"] != "__kernel__" and not re.fullmatch(r"0x[0-9a-f]+", vol["Callback address"]):
            errors.append("%s: no callback address printed" % row["kind"])
        if "BPF" in row["kind"]:
            direct = [r for r in flags[row["tag"]] if r["ftrace_ops address"] == vol["ftrace_ops address"]]
            if row["callback"] != "call_direct_funcs" or not direct or "FTRACE_OPS_FL_DIRECT" not in direct[0]["Flags"]:
                errors.append("%s: not the direct-call ops (call_direct_funcs, FTRACE_OPS_FL_DIRECT)" % row["kind"])
            columns, programs = ebpf[row["tag"]]
            if not any(p["Name"] == "restrict_filesy" and p["Type"] == "BPF_PROG_TYPE_LSM" for p in programs):
                errors.append("%s: linux.ebpf did not list restrict_filesy as BPF_PROG_TYPE_LSM" % row["kind"])
            if any("attach" in column.lower() for column in columns):
                errors.append("%s: linux.ebpf has an attach column %r" % (row["kind"], columns))
        # both ways, so a relabelled kind fails too: kprobe <=> kprobe_ftrace_handler, BPF <=> call_direct_funcs
        for hook, callback in (("kprobe", "kprobe_ftrace_handler"), ("BPF", "call_direct_funcs")):
            if (row["hook"] == hook) != (row["callback"] == callback):
                errors.append("%s: the hook kind does not match Volatility's callback %s" % (row["kind"], row["callback"]))
        # the test module is loaded in the second sample, the demo's hooks were set through tracefs
        if row["setter"] and (row["setter"] == "test module") != (row["tag"] == "th"):
            errors.append("%s: the test module's hooks are in the second sample, the tracefs ones in the demo" % row["kind"])
    for tag in used:
        if sorted(used[tag]) != sorted(r["ftrace_ops address"] for r in ftrace[tag]):
            errors.append("%s: the README uses Volatility's ftrace rows %s, it printed %s"
                          % (tag, used[tag], [r["ftrace_ops address"] for r in ftrace[tag]]))
    if "`restrict_filesy`, `BPF_PROG_TYPE_LSM`" not in text:
        errors.append("the section does not quote linux.ebpf's row as printed")

    named = (sum(r["hooked"] != "-" for r in rows), sum(r["callback"] not in SHARED for r in rows),
             sum(r["callback"] == "-" and r["module"] != "__kernel__" for r in rows))
    mine = (sum(r["where"] not in ("", "-") for r in rows),
            sum(not re.search(r"no symbol|^ftrace_ops at|^BPF program at", r["owner"]) for r in rows))
    want = ("hooked function %d of %d, owner %d of %d (and %d module name)" % (named[0], len(rows), named[1], len(rows), named[2]),
            "hooked function %d of %d, owner %d of %d" % (mine[0], len(rows), mine[1], len(rows)))
    if totals is None or tuple(totals[1:]) != want:
        errors.append("the Named row is %r, the rows above give %r" % (totals and totals[1:], want))

    unlinked, original = vol_table("th-ops-unlinked.ftrace.txt")[1], ftrace["th"]
    match = re.search(r"printed (\d+) rows instead of (\d+), without the module's, and MemLens still named `([^`]+)`", text)
    owners = read(FIXTURES, "th-ops-unlinked.owners.txt")
    if not match or (int(match.group(1)), int(match.group(2))) != (len(unlinked), len(original)) \
            or any(r["Module"] == "memlens_testhook" for r in unlinked) \
            or not any(r["Module"] == "memlens_testhook" for r in original) \
            or "\t%s (" % match.group(3) not in owners:
        errors.append("the ops-unlinked sentence does not match th-ops-unlinked.*")

    for doc, name, pattern, tag, key in ((readme, "README", r"`0x857 = ([A-Z_|]+)`", "th", ("Module", "memlens_testhook")),
                                         (output_md, "docs/OUTPUT.md", r"0x2841 = ([A-Z_|]+);", "demo", ("Callback", "function_trace_call"))):
        found = re.search(pattern, doc)
        row = [r for r in flags[tag] if r[key[0]] == key[1]]
        printed = set(f.replace("FTRACE_OPS_FL_", "") for f in row[0]["Flags"].split(",")) if row else None
        if not found or set(found.group(1).split("|")) != printed:
            errors.append("%s's flags decode is not the set --show-ftrace-flags printed (%s)" % (name, printed))

    hidden = read(FIXTURES, "th-module-unlinked.owners.txt").splitlines()
    hidden_owners = [line.split("\t")[3] for line in hidden if "no symbol" in line]
    if len(hidden_owners) != 2 or any("`%s`" % owner not in limits for owner in hidden_owners):
        errors.append("docs/LIMITS.md does not quote the owners recorded on the module-unlinked copy: %s" % hidden_owners)
    shown = re.search(r"`(ftrace_ops at 0x\.\.\. \(no symbol: [^`]+)`", readme)
    if not shown or not any(re.fullmatch(re.escape(shown.group(1)).replace(r"0x\.\.\.", "0x[0-9a-f]+"), o) for o in hidden_owners):
        errors.append("the README Limits owner text is not the one recorded on the module-unlinked copy")
    before, after = vol_table("th.hidden_modules.txt")[1], vol_table("th-module-unlinked.hidden_modules.txt")[1]
    cell = "`memlens_testhook` (Offset `%s`, as printed)" % (after[0]["Offset"] if after else "?")
    if before or [r["Module Name"] for r in after] != ["memlens_testhook"] or cell not in limits:
        errors.append("docs/LIMITS.md's linux.malware.hidden_modules row does not match the recordings")
    if vol_table("th-module-unlinked.ftrace.txt")[1] != original:
        errors.append("docs/LIMITS.md says linux.tracing.ftrace shows the same row; the recordings differ")

    plus4 = 0
    for tag, entries in links.items():
        mine = [r for r in rows if r["tag"] == tag]
        if sorted(r["where"] for r in mine) != sorted(entries):
            errors.append("%s: the README rows are %s, MemLens lists %s" % (tag, [r["where"] for r in mine], sorted(entries)))
        for row in mine:
            entry = entries.get(row["where"])
            if entry is None:
                continue
            if not entry["owner"] or not (entry["owner"] == row["owner"] or entry["owner"].startswith(row["owner"] + " (")):
                errors.append("%s: MemLens's owner is %r, the README says %r" % (row["kind"], entry["owner"], row["owner"]))
            if row["setter"] and entry["owner"] and (row["setter"] == "test module") != entry["owner"].startswith("memlens_testhook."):
                errors.append("%s: MemLens's owner is %r" % (row["kind"], entry["owner"]))
            if (row["hooked"] == "-") != bool(entry["offset"]):
                errors.append("%s: the hook site is %s+%s, but Volatility's cell is %r"
                              % (row["kind"], row["where"], entry["offset"], row["hooked"]))
            plus4 += entry["offset"] == "0x4"
            if entry["ops"] and "vol" in row and sign_extend(int(row["vol"]["ftrace_ops address"], 16)) not in entry["ops"]:
                errors.append("%s: Volatility's ftrace_ops %s is not the ops MemLens reads from the trampoline (%s)"
                              % (row["kind"], row["vol"]["ftrace_ops address"], sorted(hex(o) for o in entry["ops"])))
    match = re.search(r"(\d+) of the (\d+) sites are at function\+0x4", text)
    if not match or int(match.group(2)) != len(rows) or (len(links) == 2 and int(match.group(1)) != plus4):
        errors.append("the '+0x4' sentence does not match (%s sites at +0x4 measured)" % (plus4 if len(links) == 2 else "?"))
    return errors


def mutants(readme, sampled):
    """README texts with one table cell changed: each hook label's kind, setter and capture, each code span (MemLens
    cells only for the samples given) and each number of the Named row."""
    text = section(readme)
    out = []
    for line in [l for l in text.splitlines() if l.startswith("|")][2:]:
        cells = line.strip().strip("|").split("|")
        capture = re.search(r"\((%s)\)\s*$" % "|".join(CAPTURES), cells[0])
        named = cells[0].strip() == "**Named**"
        for old, changed in LABEL_SWAPS if not named else ():
            if old in cells[0]:
                out.append(readme.replace(line, "|" + "|".join([cells[0].replace(old, changed, 1)] + cells[1:]) + "|", 1))
        for index in (1, 2):
            if index == 2 and not named and not (capture and CAPTURES[capture.group(1)] in sampled):
                continue
            spans = [(m.start(), m.end()) for m in re.finditer(r"`[^`]+`|\d+", cells[index])
                     if m.group(0).startswith("`") or named]
            for start, end in spans:
                token = cells[index][start:end]
                changed = token[:-1] + "X`" if token.startswith("`") else str(int(token) + 1)
                new = list(cells)
                new[index] = cells[index][:start] + changed + cells[index][end:]
                out.append(readme.replace(line, "|" + "|".join(new) + "|", 1))
    return out


def main():
    readme = read(ROOT, "README.md")
    limits = read(ROOT, "docs", "LIMITS.md")
    output_md = read(ROOT, "docs", "OUTPUT.md")
    links = {}
    for variable, tag in SAMPLES:
        path = os.environ.get(variable, "")
        if not path or not os.path.isfile(path):
            print("SKIP: %s not set: the MemLens cells of the %s rows are not checked" % (variable, tag))
            continue
        run = subprocess.run(PATCHSCAN + ["--links", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        if run.returncode != 0:
            print("patchscan.py --links %s failed:\n%s" % (path, run.stderr))
            return 1
        links[tag] = parse_links(run.stdout)
    errors = check(readme, limits, output_md, links)
    if errors:
        print("README section %r does not match:\n  %s" % (HEADING, "\n  ".join(errors)))
        return 1
    changed = mutants(readme, set(links))
    survived = [text for text in changed if not check(text, limits, output_md, links)]
    if survived or not changed:
        print("%d of %d changed README tables passed the check" % (len(survived), len(changed)))
        return 1
    count = len(table_rows(section(readme))) - 1
    print("compare test OK (%d rows against the recorded Volatility 2.28.2 output; MemLens output of %d of 2 samples; "
          "%d changed cells fail it)" % (count, len(links), len(changed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
