#!/usr/bin/env python3
"""tools/hookgraph.py and the picture it drew (docs/img/hookchain.svg and .png), with no IDA.

usage: python3 tests/test_hookgraph.py [<kernel.elf> ...]
Without arguments it takes MEMLENS_DEMO_ELF and MEMLENS_TESTHOOK_ELF from the environment (tests/run_all.py passes
both on). Each kernel.elf is told apart by its sha256, so the order does not matter.

Always:
- docs/img/hookchain.svg parses with xml.etree, uses only the generic monospace font, and has no script, style, image,
  link or event attribute (GitHub sanitises SVG). Panel i is sample i (top: testhook, bottom: demo), checked against the
  stdout lines of docs/img/expected-hook-chain.testhook.txt and .demo.txt (copies of the two demo zips'
  expected-hook-chain.txt): every text node is a piece of one field of that output, each bold text a piece of an
  'owner' line. The only exceptions are the tool's own words, exactly these strings in their places (HEADING, LEGEND):
  panel i's heading at its top, outside the lanes, and the colour legend line above the panels, each colour square in
  the colours of its role's boxes (COLOURS, which every box of that role has). Lane by lane (problems, lane_problems):
  its site, first edge and page label are an xref line of that type; its page name is that page's rename; its handler
  and kind are the entry line's '(calls H, kind)' and the edge to it that xref's type; its owner lines joined are that
  page's owner line (the name in bold) and the down edge a piece of it; every --links link is one lane. Each text sits
  in one box of its role, each arrow goes from the right box to the right box with its head at its end and its label
  beside it. Mutants fail: an owner renamed, truncated or moved to another lane, a handler, kind, page name or site
  swapped between lanes, an edge label changed, a hand-typed label, a line kind ('owner') or two fields as a label, a
  text outside the panels, a site made bold, an owner box removed, an arrowhead reversed, the panels swapped, a panel
  too many, a heading reworded, swapped, dropped, doubled or replaced by a --links word, the legend reworded,
  reordered, recoloured, extended or dropped, a box recoloured.
- docs/img/hookchain.png is the SVG rasterised at device scale SCALE (its size the SVG's times SCALE) and under 300 KB.
- docs/img/README.md has the README snippet with the caption, the image paths (which exist), and a Where | Handler |
  Owner table that is the top panel's lanes, row by row, from the testhook --links text.
- A hand-made kernel.elf (ftrace, module callback and unknown-role pages): the tool's SVG for it passes the same check
  against a fresh `patchscan.py --links` of it, the CLI and the function give the same bytes, and the exit codes.
With a demo kernel.elf (its sha256 is DEMO_SHA or TESTHOOK_SHA): `patchscan.py --links` on it must print its sample's
expected stdout lines (else the picture is stale: FAIL), and the tool's SVG for it alone (under its heading) passes the
check; with both,
the tool gives docs/img/hookchain.svg byte for byte, twice (and through the CLI). A kernel.elf with another sha256 (your
own export) is checked against its own --links output only (SKIP for the picture).
"""
import contextlib
import hashlib
import io
import math
import os
import re
import runpy
import struct
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import patchscan as ps  # noqa: E402
import hookgraph  # noqa: E402

IMG = os.path.join(ROOT, "docs", "img")
SVG_PATH, PNG_PATH = os.path.join(IMG, "hookchain.svg"), os.path.join(IMG, "hookchain.png")
DEMO_SHA = "1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5"  # memlens-demo-debian13.zip's kernel.elf
TESTHOOK_SHA = "8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9"  # memlens-demo-testhook.zip's kernel.elf
SAMPLES = [("testhook", os.path.join(IMG, "expected-hook-chain.testhook.txt"), TESTHOOK_SHA),  # top panel
           ("demo", os.path.join(IMG, "expected-hook-chain.demo.txt"), DEMO_SHA)]  # bottom panel
SCALE = 1.5  # the PNG's device scale (docs/img/README.md step 2)
NS = "{http://www.w3.org/2000/svg}"
TOOL = [sys.executable, "-I", os.path.join(ROOT, "tools", "hookgraph.py")]
PATCHSCAN = [sys.executable, "-I", os.path.join(ROOT, "patchscan.py")]
CAPTION = "Drawn by tools/hookgraph.py from `patchscan.py --links` on the two demo kernel.elf files; not an IDA screenshot"
SCANNED = re.compile(r"^\d+ function symbols scanned$")  # patchscan's stderr line, in the testhook zip's file too
CALLS = re.compile(r"^(?P<label>.+) \(calls (?P<handler>[^,()]+)(?:, (?P<kind>[^()]+))?\)$")  # patchscan.hook_label
FAMILY = {"site": "site", "page": "page", "page-label": "page", "handler": "handler", "handler-label": "handler",
          "owner": "owner"}  # text class -> the box it belongs in
EDGES = {("site", "page"): "flow", ("page", "handler"): "hflow", ("page", "owner"): "how"}  # arrow (from box, to box)
TOUCH, NEAR = 2, 12  # px: an arrow starts and ends this close to its boxes; its label's anchor this close to its line
# The tool's own words, the only texts in the picture that are not pieces of the --links output, typed here again so that
# a word changed in tools/hookgraph.py fails: the heading of each demo sample's panel (no other kernel.elf gets one) and
# the colour legend, whose colour words name the colours the boxes of each role are drawn in.
HEADING = {"testhook": "Second sample: test module hooks", "demo": "Demo: Debian 13 6.12 memory image"}
LEGEND = (("site", "white = hooked function"), ("page", "orange = hook page MemLens named"),
          ("handler", "blue = handler"), ("owner", "purple = owner"))
COLOURS = {"site": ("#ffffff", "#8c959f"),  # (fill, stroke): white, grey border
           "page": ("#fff1e5", "#e16f24"),  # orange
           "handler": ("#ddf4ff", "#218bff"),  # blue
           "owner": ("#fbefff", "#8250df")}  # purple
assert hookgraph.HEADINGS == {TESTHOOK_SHA: HEADING["testhook"], DEMO_SHA: HEADING["demo"]}, hookgraph.HEADINGS
assert tuple(hookgraph.LEGEND) == LEGEND and hookgraph.STYLE == COLOURS, (hookgraph.LEGEND, hookgraph.STYLE)


def read(path, mode="r"):
    with open(path, mode) as handle:
        return handle.read()


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def stdout_lines(text):
    """The lines of an expected-hook-chain text that patchscan prints on stdout (without its stderr line)."""
    return [line for line in text.splitlines() if not SCANNED.match(line)]


def fields(text):
    """The tab-separated fields of a --links text, without the line kinds (xref, rename, owner): a label must be a piece
    of one field, so a word that only the line kinds hold ('owner') or that spans two fields is not from the output."""
    out = []
    for line in text.splitlines():
        parts = line.split("\t")
        out += parts[1:] if parts[0] in ("xref", "rename", "owner") else parts
    return out


def owner_texts(text):
    return [line.split("\t", 3)[3] for line in text.splitlines() if line.startswith("owner\t")]


def parse(text):
    """The stdout lines of a --links text as (entries, xrefs, renames, owners): entries [(function, target column)] in
    order, xrefs {(where from, where to, type): to address}, renames {page address: (label, new name)}, owners {page
    address: owner text}."""
    entries, xrefs, renames, owners = [], {}, {}, {}
    for line in stdout_lines(text):
        parts = line.split("\t")
        if parts[0] == "xref" and len(parts) == 5 and " -> " in parts[4]:
            source, target = parts[4].split(" -> ", 1)
            xrefs[(source, target, parts[3])] = int(parts[2], 16)
        elif parts[0] == "rename" and len(parts) == 4:
            renames[int(parts[1], 16)] = (parts[2], parts[3])
        elif parts[0] == "owner" and len(parts) == 4:
            owners[int(parts[1], 16)] = parts[3]
        elif parts[0].startswith("0x") and len(parts) == 4:
            entries.append((parts[1], parts[3]))
    return entries, xrefs, renames, owners


def leads_to(column, label):
    """True when an entry line's target column is label, or label with the page's '(calls ...)' after it."""
    return column == label or column.startswith(label + " (")


def link_pairs(parsed):
    """The (site, target) of every link in a --links text: the xref lines from an entry's function to its target."""
    entries, xrefs = parsed[0], parsed[1]
    return sorted({(source, target) for source, target, _ in xrefs
                   if any(function == source.split("+")[0] and leads_to(column, target) for function, column in entries)})


def numbers(element, *names):
    try:
        return [int(element.get(name)) for name in names]
    except (TypeError, ValueError):
        return None


def touches(rect, x, y):
    left, top, width, height = rect
    return left - TOUCH <= x <= left + width + TOUCH and top - TOUCH <= y <= top + height + TOUCH


def distance(point, start, end):
    """From point to the segment start-end."""
    (px, py), (ax, ay), (bx, by) = point, start, end
    length = (bx - ax) ** 2 + (by - ay) ** 2
    t = max(0.0, min(1.0, ((px - ax) * (bx - ax) + (py - ay) * (by - ay)) / length)) if length else 0.0
    return math.hypot(px - (ax + t * (bx - ax)), py - (ay + t * (by - ay)))


def tag_of(element):
    return element.tag[len(NS):] if element.tag.startswith(NS) else element.tag


def lane_parts(lane):
    """(boxes, edges, found) for a lane: boxes {role: [(class, text, bold)]} from the texts in each box, edges {(from
    role, to role): label} from each line + arrowhead + label, and what is wrong with the drawing itself."""
    found, rects, elements, texts, arrows = [], [], [], [], []
    children, index = list(lane), 0
    while index < len(children):
        child, tag = children[index], tag_of(children[index])
        if tag == "rect":
            rect = numbers(child, "x", "y", "width", "height")
            if rect is None:
                found.append("a box without its size")
            else:
                rects.append(rect)
                elements.append(child)
        elif tag == "text" and child.get("class") in FAMILY:
            texts.append(child)
        elif tag == "line":
            arrow = children[index + 1:index + 3]
            if len(arrow) != 2 or tag_of(arrow[0]) != "polygon" or tag_of(arrow[1]) != "text" or arrow[1].get("class") != "edge":
                found.append("a line without its arrowhead and label")
            else:
                arrows.append((child, arrow[0], arrow[1]))
                index += 2
        else:
            found.append("%s %r in a lane is no box, box line or arrow" % (tag, child.text))
        index += 1
    roles = [set() for _ in rects]
    lines = [[] for _ in rects]
    for text in texts:
        where = numbers(text, "x", "y")
        holders = [number for number, (x, y, w, h) in enumerate(rects)
                   if where and x < where[0] < x + w and y < where[1] < y + h]
        if len(holders) != 1:
            found.append("%r is in %d boxes" % (text.text, len(holders)))
            continue
        roles[holders[0]].add(FAMILY[text.get("class")])
        lines[holders[0]].append((text.get("class"), text.text, text.get("font-weight") == "bold"))
    boxes, role_of = {}, []
    for role, box, element in zip(roles, lines, elements):
        if len(role) != 1:
            found.append("a box with %s lines" % (" and ".join(sorted(role)) or "no"))
            role_of.append(None)
            continue
        role = role.pop()
        if role in boxes:
            found.append("two %s boxes" % role)
        if (element.get("fill"), element.get("stroke")) != COLOURS[role]:
            found.append("a %s box in %s/%s, not its colours %s/%s" % (
                (role, element.get("fill"), element.get("stroke")) + COLOURS[role]))
        boxes[role] = box
        role_of.append(role)
    edges = {}
    for line, head, label in arrows:
        ends, points = numbers(line, "x1", "y1", "x2", "y2"), re.findall(r"(-?\d+),(-?\d+)", head.get("points", ""))
        anchor = numbers(label, "x", "y")
        if ends is None or len(points) != 3 or anchor is None:
            found.append("arrow %r: no coordinates" % label.text)
            continue
        x1, y1, x2, y2 = ends
        dx, dy = (x2 > x1) - (x2 < x1), (y2 > y1) - (y2 < y1)
        points = [(int(x), int(y)) for x, y in points]
        along = [x * dx + y * dy for x, y in points]
        tips = [point for point, value in zip(points, along) if along.count(value) == 1]
        if abs(dx) + abs(dy) != 1 or len(tips) != 1:
            found.append("arrow %r: not a straight arrow with one head" % label.text)
            continue
        tip, base = tips[0], [value for value in along if along.count(value) == 2][0]
        on_line = tip[1] == y1 if dx else tip[0] == x1
        if not on_line or tip[0] * dx + tip[1] * dy <= base or tip[0] * dx + tip[1] * dy < x2 * dx + y2 * dy:
            found.append("arrow %r: its head does not point on from the end of its line" % label.text)
            continue
        source = [role for role, rect in zip(role_of, rects) if touches(rect, x1, y1)]
        target = [role for role, rect in zip(role_of, rects) if touches(rect, tip[0], tip[1])]
        pair = (source[0], target[0]) if len(source) == 1 and len(target) == 1 else None
        if pair not in EDGES:
            found.append("arrow %r goes from %s to %s" % (label.text, source, target))
            continue
        if pair in edges:
            found.append("two arrows from %s to %s" % pair)
        if distance(anchor, (x1, y1), (x2, y2)) > NEAR:
            found.append("arrow label %r is not beside its arrow" % label.text)
        edges[pair] = label.text
    return boxes, edges, found


def lane_problems(lane, parsed):
    """(what is wrong with a lane against the --links text parsed, its (site, target) pair)."""
    entries, xrefs, renames, owners = parsed
    boxes, edges, found = lane_parts(lane)
    site = [text for kind, text, _ in boxes.get("site", []) if kind == "site"]
    page = boxes.get("page", [])
    if len(site) != 1 or len(boxes["site"]) != 1 or not page or page[0][0] != "page" or len(page) > 2 or (
            len(page) == 2 and page[1][0] != "page-label"):
        return found + ["no site box with one line or no page box with its name and label: %r %r" % (site, page)], None
    site, target = site[0], page[-1][1]  # the page's label line (or its only line): the xref line's target
    found = ["%s: %s" % (site, problem) for problem in found]
    flow = edges.get(("site", "page"))
    if (site, target, flow) not in xrefs:
        return found + ["%s: no xref line '%s -> %s' of type %r" % (site, site, target, flow)], (site, target)
    address = xrefs[(site, target, flow)]
    rename = renames.get(address)
    if rename and [line[1] for line in page] != [rename[1], rename[0]]:
        found.append("%s: page %r, not the rename %r over %r" % (site, [line[1] for line in page], rename[1], rename[0]))
    if not rename and len(page) != 1:
        found.append("%s: page %r has a name but --links renames nothing at %#x" % (site, [line[1] for line in page], address))
    entry = [column for function, column in entries if function == site.split("+")[0] and leads_to(column, target)]
    calls = CALLS.match(entry[0]) if entry else None
    if not entry:
        found.append("%s: no entry line of %s leading to %s" % (site, site.split("+")[0], target))
    handler = [(kind, text) for kind, text, _ in boxes.get("handler", [])]
    if calls:
        want = [("handler", calls.group("handler"))] + ([("handler-label", calls.group("kind"))] if calls.group("kind") else [])
        if handler != want:
            found.append("%s: handler %r, the entry line says %r" % (site, handler, want))
        hflow = edges.get(("page", "handler"))
        if not any(source.split("+")[0] == target and to == calls.group("handler") and kind == hflow
                   for source, to, kind in xrefs):
            found.append("%s: no xref line '%s+... -> %s' of type %r" % (site, target, calls.group("handler"), hflow))
    elif handler or ("page", "handler") in edges:
        found.append("%s: handler %r, but the entry line names no call" % (site, handler))
    owner, drawn = owners.get(address), boxes.get("owner", [])
    if owner is not None:
        cut = owner.find(" (")
        name = owner[:cut] if cut > 0 and owner.endswith(")") else owner
        if " ".join(text for _, text, _ in drawn) != owner:
            found.append("%s: owner lines %r, the owner line says %r" % (site, [text for _, text, _ in drawn], owner))
        if " ".join(text for _, text, bold in drawn if bold) != name or any(
                bold for _, _, bold in drawn[sum(1 for _, _, bold in drawn if bold):]):
            found.append("%s: the bold owner lines are not its name %r" % (site, name))
        how = edges.get(("page", "owner"))
        if not how or how not in owner:
            found.append("%s: owner arrow %r is not a piece of the owner %r" % (site, how, owner))
    elif drawn or ("page", "owner") in edges:
        found.append("%s: an owner, but --links has no owner line for %#x" % (site, address))
    return found, (site, target)


def legend_problems(root):
    """(what is wrong with the legend, its texts): one <g class="legend"> at the top level, before and above the panels,
    holding for each LEGEND entry, in order, a colour square in its role's COLOURS and then its words beside it."""
    children = list(root)
    groups = [g for g in root.iter(NS + "g") if g.get("class") == "legend"]
    if len(groups) != 1 or groups[0] not in children:
        return ["%d legend lines at the top level, not one" % sum(1 for g in groups if g in children)], set()
    items = list(groups[0])
    pairs = list(zip(items[0::2], items[1::2]))
    if len(items) != 2 * len(LEGEND) or any(tag_of(square) != "rect" or tag_of(words) != "text" or words.get("class") != "legend"
                                            for square, words in pairs):
        return ["the legend is not a colour square and its words for each of the %d roles" % len(LEGEND)], set()
    found = []
    panels = [child for child in children if tag_of(child) == "g" and child.get("class") == "panel"]
    first = numbers(panels[0][0], "y") if panels and len(panels[0]) and tag_of(panels[0][0]) == "rect" else None
    if panels and (children.index(groups[0]) > children.index(panels[0]) or first is None):
        found.append("the legend is not before the panels")
    for (square, words), (role, want) in zip(pairs, LEGEND):
        box, at = numbers(square, "x", "y", "width", "height"), numbers(words, "x", "y")
        if words.text != want:
            found.append("legend %r, not %r" % (words.text, want))
        if (square.get("fill"), square.get("stroke")) != COLOURS[role]:
            found.append("legend %r: its square is %s/%s, the %s boxes %s/%s" % (
                (words.text, square.get("fill"), square.get("stroke"), role) + COLOURS[role]))
        if box is None or at is None or not (box[0] + box[2] <= at[0] <= box[0] + box[2] + NEAR
                                             and box[1] <= at[1] <= box[1] + box[3]):
            found.append("legend %r is not beside its square" % words.text)
        elif first and first[0] is not None and box[1] + box[3] > first[0]:
            found.append("legend %r is not above the panels" % words.text)
    return found, {words for _, words in pairs}


def problems(svg_text, expected, headings=None):
    """What is wrong with an SVG drawn from len(expected) kernel.elf files, panel i from the --links output expected[i]
    under the heading headings[i] (None: no heading): [] when every text node in panel i is a substring of expected[i],
    and of one of its fields (fields), each bold text a piece of one of its owner lines, every lane passes
    lane_problems, its lanes are the links of expected[i], no text is outside a lane, and there are as many panels as
    texts; the only exceptions, the tool's own words: panel i's heading, at its top and outside its lanes, and the
    legend line (legend_problems)."""
    root = ET.fromstring(svg_text)
    found, inside = legend_problems(root)
    headings = list(headings) if headings else [None] * len(expected)
    panels = [g for g in root.iter(NS + "g") if g.get("class") == "panel"]
    if len(panels) != len(expected):
        found.append("%d panels for %d samples" % (len(panels), len(expected)))
    for number, (panel, text, heading) in enumerate(zip(panels, expected, headings), 1):
        owners, pieces, parsed = owner_texts(text), fields(text), parse(text)
        lanes = [g for g in panel.iter(NS + "g") if g.get("class") == "lane"]
        in_lanes = {node for lane in lanes for node in lane.iter()}
        titles = [element for element in panel.iter() if element.get("class") == "heading"]
        if [title.text for title in titles] != ([heading] if heading else []):
            found.append("panel %d: headings %r, not %r" % (number, [title.text for title in titles], heading))
        lane_tops = [numbers(rect, "y")[0] for lane in lanes for rect in lane if tag_of(rect) == "rect" and numbers(rect, "y")]
        for title in titles:
            at = numbers(title, "y")
            if title.text == heading and title in list(panel) and at and lane_tops and at[0] < min(lane_tops):
                inside.add(title)  # the tool's own words, in their place
            else:
                found.append("panel %d: heading %r is not %r at the top of the panel, outside its lanes" % (number, title.text, heading))
        for element in panel.iter():
            if element in inside:
                continue
            if element.text and element.text.strip():
                inside.add(element)
                if element not in in_lanes:
                    found.append("panel %d: text outside its lanes: %r" % (number, element.text))
                if element.text not in text:
                    found.append("not in the --links output: %r" % element.text)
                elif not any(element.text in piece for piece in pieces):
                    found.append("not in one field of the --links output: %r" % element.text)
                if element.get("font-weight") == "bold" and not any(element.text in owner for owner in owners):
                    found.append("bold but not an owner: %r" % element.text)
        drawn = []
        for lane in lanes:
            lane_found, pair = lane_problems(lane, parsed)
            found += ["panel %d, lane %s" % (number, problem) for problem in lane_found]
            drawn.append(pair)
        if sorted(map(repr, drawn)) != sorted(map(repr, link_pairs(parsed))):
            found.append("panel %d: lanes %r, but --links links %r" % (number, drawn, link_pairs(parsed)))
    for element in root.iter():
        if element.text and element.text.strip() and element not in inside:
            found.append("text outside the panels: %r" % element.text)
        if element.tail and element.tail.strip():
            found.append("text between elements: %r" % element.tail)
    return found


def safe(svg_text):
    """What GitHub's sanitiser or an offline viewer would trip on: [] when there is none."""
    root = ET.fromstring(svg_text)
    found = []
    if root.tag != NS + "svg" or root.get("font-family") != "monospace":
        found.append("root %s, font-family %r" % (root.tag, root.get("font-family")))
    for element in root.iter():
        tag = tag_of(element)
        if tag in ("script", "style", "image", "foreignObject", "a", "use", "font", "font-face"):
            found.append("element %s" % tag)
        for name, value in element.attrib.items():
            if name.lower().startswith("on") or name.endswith("href") or "url(" in value:
                found.append("attribute %s=%r" % (name, value))
        if element.get("font-family") not in (None, "monospace"):
            found.append("font-family %r" % element.get("font-family"))
    return found


def lanes_of(svg_text):
    """[[lane element, ...] per panel]."""
    root = ET.fromstring(svg_text)
    return [[lane for lane in panel.iter(NS + "g") if lane.get("class") == "lane"]
            for panel in root.iter(NS + "g") if panel.get("class") == "panel"]


def bold(element):
    return [node.text for node in element.iter() if node.get("font-weight") == "bold"]


def in_panel(svg_text, number, pattern, replacement):
    """svg_text with the first match of the regular expression pattern in panel number (1 = top) replaced."""
    parts = svg_text.split('<g class="panel">')
    parts[number], count = re.subn(pattern, replacement, parts[number], count=1)
    assert count == 1, (number, pattern)
    return '<g class="panel">'.join(parts)


def table_rows(text):
    """The Where | Handler | Owner rows patchscan's --links text gives, in its entries' order: the function, 'H (kind)'
    from its '(calls H, kind)', and its page's owner line."""
    entries, xrefs, _, owners = parse(text)
    rows = []
    for function, column in entries:
        calls = CALLS.match(column)
        address = [to for (source, target, _), to in xrefs.items()
                   if calls and target == calls.group("label") and source.split("+")[0] == function]
        rows.append([function, "%s (%s)" % (calls.group("handler"), calls.group("kind")) if calls else "",
                     owners.get(address[0], "") if address else ""])
    return rows


# 1. The committed picture against the committed --links texts.
texts = [read(path) for _, path, _ in SAMPLES]
headings = [HEADING[name] for name, _, _ in SAMPLES]
svg_text = read(SVG_PATH)
assert safe(svg_text) == [], safe(svg_text)
assert problems(svg_text, texts, headings) == [], problems(svg_text, texts, headings)
panels = lanes_of(svg_text)
entries = [sum(1 for line in stdout_lines(text) if line.startswith("0x")) for text in texts]
assert [len(panel) for panel in panels] == entries, ([len(panel) for panel in panels], entries)  # one lane per patched entry
for panel, text in zip(panels, texts):
    for lane in panel:
        names = bold(lane)
        assert len(names) == 1 and any(owner.startswith(names[0]) for owner in owner_texts(text)), names  # the owner, in bold
root = ET.fromstring(svg_text)
width, height = int(root.get("width")), int(root.get("height"))
assert root.get("viewBox") == "0 0 %d %d" % (width, height) and 880 <= width <= 1000, (width, height)


def in_legend(svg_text, old, new):
    """svg_text with the first old in the legend (before the first panel) replaced by new."""
    head, rest = svg_text.split('<g class="panel">', 1)
    assert old in head, old
    return head.replace(old, new, 1) + '<g class="panel">' + rest


def head_reversed(match):
    """An arrowhead pointing back along its line: the tip and the base swap places along the arrow."""
    tip_x, tip_y, base_x, base_y1, _, base_y2 = match.groups()
    return '<polygon points="%s,%s %s,%s %s,%s"' % (base_x, tip_y, tip_x, base_y1, tip_x, base_y2)


# Mutants: each must fail. Panel 1 is the testhook sample, panel 2 the demo.
mutants = {
    "owner renamed": in_panel(svg_text, 1, r">memlens_testhook\.th_kill_callback<", ">memlens_testhook.th_kill_handler<"),
    "owner truncated": in_panel(svg_text, 1, r">memlens_testhook\.th_kill_callback<", ">memlens_testhook.th_kill<"),
    "edge label": svg_text.replace(">call<", ">jump<", 1),
    "first edge call -> data": in_panel(svg_text, 1, ">call<", ">data<"),
    "hand-typed label": svg_text.replace('<g class="lane">', '<g class="lane">\n<text x="0" y="0">hook page</text>', 1),
    "a line kind as a label": svg_text.replace(">ftrace_ops<", ">owner<", 1),
    "two fields as one label": svg_text.replace(">call<", ">call\tbpf_lsm_file_open+0x4<", 1),
    "text outside the panels": svg_text.replace('<g class="panel">', '<text x="0" y="0">call</text>\n<g class="panel">', 1),
    "site made bold": re.sub(r'(<text class="site"[^>]*?) fill=', r'\1 font-weight="bold" fill=', svg_text, count=1),
    "owner moved to another lane": in_panel(svg_text, 2, r'(font-weight="bold" fill="#1f2328">)function_trace_call<',
                                            r"\1bpf.bpf_prog_e8932b6bae2b9745_restrict_filesystems<"),
    "handler swapped": in_panel(svg_text, 2, r'(<text class="handler" [^>]*>)function_trace_call<', r"\1kprobe_ftrace_handler<"),
    "kind swapped": in_panel(svg_text, 2, r'(<text class="handler-label" [^>]*>)ftrace<', r"\1kprobe via ftrace<"),
    "page name swapped": in_panel(svg_text, 2, ">ftrace_tramp_vfs_getattr<", ">kprobe_ftrace_tramp_do_sys_openat2<"),
    "site swapped": in_panel(svg_text, 2, r'(<text class="site" [^>]*>)do_sys_openat2<', r"\1vfs_getattr<"),
    "owner arrow label swapped": in_panel(svg_text, 2, ">kprobe<", ">ftrace_ops<"),
    "owner box removed": in_panel(svg_text, 1, r'<rect [^>]*fill="%s"[^>]*/>\n' % hookgraph.STYLE["owner"][0], ""),
    "arrowhead reversed": re.sub(r'<polygon points="(\d+),(\d+) (\d+),(\d+) (\d+),(\d+)"', head_reversed, svg_text, count=1),
    "heading reworded": in_panel(svg_text, 1, ">Second sample: test module hooks<", ">Second sample: rootkit hooks<"),
    "headings swapped": svg_text.replace(HEADING["testhook"], "@").replace(HEADING["demo"], HEADING["testhook"]).replace(
        "@", HEADING["demo"]),
    "heading dropped": in_panel(svg_text, 2, r'<text class="heading"[^>]*>[^<]*</text>\n', ""),
    "heading doubled into a lane": in_panel(svg_text, 1, r'(<g class="lane">\n)',
                                            r'\1<text class="heading" x="22" y="90" font-size="15" fill="#1f2328">%s</text>\n'
                                            % HEADING["testhook"]),
    "a --links word as the heading": in_panel(svg_text, 2, ">%s<" % HEADING["demo"], ">kprobe<"),
    "legend reworded": in_legend(svg_text, ">purple = owner<", ">red = owner<"),
    "legend reordered": in_legend(in_legend(svg_text, ">blue = handler<", ">@<"), ">purple = owner<", ">blue = handler<").replace(
        ">@<", ">purple = owner<", 1),
    "legend square recoloured": in_legend(svg_text, 'fill="%s" stroke="%s"' % COLOURS["owner"], 'fill="#ffebe9" stroke="#cf222e"'),
    "legend extended": in_legend(svg_text, "</g>", '<rect x="800" y="10" width="14" height="14" rx="3" fill="#ffffff" stroke="#8c959f"/>\n'
                                 '<text class="legend" x="820" y="21" font-size="12" fill="#1f2328">grey = trampoline</text>\n</g>'),
    "legend dropped": re.sub(r'<g class="legend">.*?</g>\n', "", svg_text, count=1, flags=re.S),
    "a box recoloured": in_panel(svg_text, 2, 'fill="%s" stroke="%s"' % COLOURS["page"], 'fill="%s" stroke="%s"' % COLOURS["handler"]),
}
for name, mutant in mutants.items():
    assert mutant != svg_text, name
    assert problems(mutant, texts, headings), name
assert problems(svg_text, texts[::-1], headings[::-1]), "panels swapped"
assert problems(svg_text, texts[:1], headings[:1]), "a panel too many"
assert problems(svg_text, texts), "headings where none are expected"
assert safe(svg_text.replace("<rect ", '<rect onclick="x" ', 1)) and safe(svg_text.replace('font-family="monospace"', 'font-family="Fira Code"'))

# 2. The PNG and the README snippet.
png = read(PNG_PATH, "rb")
assert png[:8] == b"\x89PNG\r\n\x1a\n" and png[12:16] == b"IHDR", png[:16]
size = struct.unpack(">II", png[16:24])
assert abs(size[0] - width * SCALE) <= 1 and abs(size[1] - height * SCALE) <= 1, (size, width, height, SCALE)
assert len(png) < 300 * 1024, len(png)
notes = read(os.path.join(IMG, "README.md"))
assert CAPTION in notes and "docs/img/hookchain.png" in notes and "tools/hookgraph.py" in notes, notes[:300]
snippet = notes[notes.index("```markdown\n") + len("```markdown\n"):]
snippet = snippet[:snippet.index("\n```")]
for link in re.findall(r'(?:src|href)="([^"#]+)"|\]\(([^)#]+)\)', snippet):
    target = link[0] or link[1]
    assert "://" in target or os.path.exists(os.path.join(ROOT, target)), target  # what the README link check will ask
assert 'width="%d"' % width in snippet, "embed the %gx PNG at the SVG's width" % SCALE
rows = [[re.sub(r"[`*]", "", cell).strip() for cell in line.strip().strip("|").split("|")]
        for line in snippet.splitlines() if line.startswith("|") and not re.match(r"^\|[-| :]+\|$", line)]
assert rows[0] == ["Where", "Handler", "Owner"], rows[:1]
assert rows[1:] == table_rows(texts[0]), (rows[1:], table_rows(texts[0]))  # the top panel's lanes, from --links
assert [row[0] for row in rows[1:]] == [lane.find(NS + "text").text.split("+")[0] for lane in panels[0]], rows
print("committed picture OK (%dx%d px; %s lanes; %d mutants fail; PNG %dx%d, %d bytes; README table = top panel)" % (
    width, height, "+".join(str(len(panel)) for panel in panels), len(mutants) + 2, size[0], size[1], len(png)))

# 3. A hand-made kernel.elf: an ftrace page with no owner, a module callback (owner), a page whose role is unknown.
with contextlib.redirect_stdout(io.StringIO()):  # reuse test_patchscan's ELF builder; its own checks run silently
    builder = runpy.run_path(os.path.join(HERE, "test_patchscan.py"))
elf, call, BASE, TEXT = builder["elf"], builder["call"], builder["BASE"], builder["TEXT"]
code = bytearray(b"\x90" * TEXT)


def put(offset, data):
    code[offset:offset + len(data)] = data


FTRACE, OTHER, MODCB = BASE + 0x1000, BASE + 0x1100, BASE + 0x1900
PAGES = {"F": (BASE + 0x2000, FTRACE), "M": (BASE + 0x2200, MODCB), "U": (BASE + 0x2400, OTHER)}
for page, handler in PAGES.values():
    put(page - BASE + 0x40, call(page + 0x40, handler))
put(0x000, b"\xf3\x0f\x1e\xfa" + call(BASE + 4, PAGES["F"][0]))                     # traced_a: endbr64; call page F
put(0x100, call(BASE + 0x100, PAGES["M"][0]))                                       # modhook: call page M
put(0x200, b"\x68" + struct.pack("<i", PAGES["U"][0] - (1 << 64)) + b"\xc3")        # pushret: push page U; ret
symbols = [("traced_a", BASE, 0x100), ("modhook", BASE + 0x100, 0x100), ("pushret", BASE + 0x200, 0x100),
           ("function_trace_call", FTRACE, 0x100), ("some_helper", OTHER, 0x100), ("evilmod.fh_cb", MODCB, 0x100),
           ("linux_banner", BASE + 0xf00, 0x10)] + [("%s%x" % (ps.TARGET_PREFIX, page), page, 0) for page, _ in PAGES.values()]
with tempfile.TemporaryDirectory() as work:
    path, out = os.path.join(work, "kernel.elf"), os.path.join(work, "out.svg")
    with open(path, "wb") as handle:
        handle.write(elf(code, symbols))
    linked = subprocess.run(PATCHSCAN + ["--links", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert linked.returncode == 0, linked.stderr
    assert hookgraph.heading(path) is None  # not a demo kernel.elf: no heading
    made = hookgraph.svg([hookgraph.lanes(path)])
    assert made == hookgraph.svg([hookgraph.lanes(path)], [None])
    cli = subprocess.run(TOOL + [path, "-o", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert cli.returncode == 0 and read(out, "rb") == made.encode("utf-8"), (cli.returncode, cli.stderr)
    assert safe(made) == [] and problems(made, [linked.stdout]) == [], (safe(made), problems(made, [linked.stdout]))
    lanes = lanes_of(made)[0]
    assert len(lanes) == 3 and [bold(lane) for lane in lanes] == [[], ["evilmod.fh_cb"], []], [bold(lane) for lane in lanes]
    assert "ftrace_tramp_traced_a" in made and "module_hook_modhook" in made and ">some_helper<" in made, made
    assert problems(made.replace(">evilmod.fh_cb<", ">evilmod.fh_cbx<"), [linked.stdout])
    assert ">module callback<" in made and problems(made.replace(">module callback<", ">owner<"), [linked.stdout])  # only a line kind
    assert problems(made.replace(">some_helper<", ">function_trace_call<"), [linked.stdout])  # another lane's handler
    codes = {}
    for name, argv in (("no -o", [path]), ("no file", ["-o", out]), ("-o without a path", [path, "-o"]),
                       ("unknown option", [path, "--isf", "x", "-o", out]), ("missing", [path + ".no", "-o", out]),
                       ("not an ELF", [SVG_PATH, "-o", out]), ("not a kernel export", [path + ".bin", "-o", out]),
                       ("unwritable -o", [path, "-o", os.path.join(work, "no", "x.svg")])):
        if name == "not a kernel export":
            with open(path + ".bin", "wb") as handle:
                handle.write(elf(code, [("traced_a", BASE, 0x100)]))  # no linux_banner: patchscan checks nothing
        run = subprocess.run(TOOL + argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        codes[name] = run.returncode
        assert "Traceback" not in run.stderr, (name, run.stderr)
    assert codes == {"no -o": 2, "no file": 2, "-o without a path": 2, "unknown option": 2, "missing": 2, "not an ELF": 2,
                     "not a kernel export": 1, "unwritable -o": 2}, codes
print("hand-made kernel.elf OK (3 lanes, 1 owner; CLI and function give the same bytes; exit codes)")

# 4. The demo kernel.elf files, told apart by sha256: a demo kernel.elf whose --links output is no longer the committed
# text means the picture is stale (FAIL); only a kernel.elf that is neither (your own export) is checked against itself.
given = sys.argv[1:] or [os.environ.get(name, "") for name in ("MEMLENS_DEMO_ELF", "MEMLENS_TESTHOOK_ELF")]
given = [path for path in given if path]
matched = {}
for path in given:
    digest = sha256(path)
    run = subprocess.run(PATCHSCAN + ["--links", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    assert run.returncode == 0, (path, run.stderr)
    alone = hookgraph.svg([hookgraph.lanes(path)], [hookgraph.heading(path)])
    sample = [index for index, (_, _, sha) in enumerate(SAMPLES) if sha == digest]
    if not sample:
        print("SKIP: %s (sha256 %s) is neither demo kernel.elf; checked against its own --links output only" % (path, digest))
        assert problems(alone, [run.stdout]) == [], problems(alone, [run.stdout])  # and with no heading
        continue
    name = SAMPLES[sample[0]][0]
    text = texts[sample[0]]
    assert run.stdout.splitlines() == stdout_lines(text), (
        "%s is the %s sample's kernel.elf (by sha256) but patchscan.py --links no longer prints docs/img/expected-hook-chain.%s.txt: "
        "redraw docs/img (README steps 1-3)" % (path, name, name))
    assert problems(alone, [text], [HEADING[name]]) == [], problems(alone, [text], [HEADING[name]])
    beside = os.path.join(os.path.dirname(os.path.abspath(path)), "expected-hook-chain.txt")
    if os.path.isfile(beside):  # the zip's own copy, when kernel.elf is where the zip put it (stdout lines: a re-upload
        assert stdout_lines(read(beside)) == stdout_lines(text), beside  # may drop the stderr line)
    matched[name] = path
    print("%s: the %s sample (%d lanes, every label in its expected-hook-chain.txt)" % (path, name, len(lanes_of(alone)[0])))
if set(matched) == {name for name, _, _ in SAMPLES}:
    both = [matched[name] for name, _, _ in SAMPLES]  # the panel order: testhook on top
    first = hookgraph.svg([hookgraph.lanes(path) for path in both], [hookgraph.heading(path) for path in both])
    second = hookgraph.svg([hookgraph.lanes(path) for path in both], [hookgraph.heading(path) for path in both])
    assert first == second, "two runs differ"
    with tempfile.TemporaryDirectory() as work:
        out = os.path.join(work, "hookchain.svg")
        cli = subprocess.run(TOOL + both + ["-o", out], stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        assert cli.returncode == 0, cli.stderr
        made = read(out, "rb")
    assert made == first.encode("utf-8") == read(SVG_PATH, "rb"), "docs/img/hookchain.svg is not what tools/hookgraph.py draws now"
    print("docs/img/hookchain.svg is what tools/hookgraph.py draws from the two demo kernel.elf files, byte for byte (twice, and the CLI)")
else:
    print("SKIP: regenerating docs/img/hookchain.svg needs both demo kernel.elf files (MEMLENS_DEMO_ELF, MEMLENS_TESTHOOK_ELF)")
print("hookgraph tests OK (%s)" % ("both demo kernel.elf files" if len(matched) == 2 else "%d demo kernel.elf file(s)" % len(matched)))
