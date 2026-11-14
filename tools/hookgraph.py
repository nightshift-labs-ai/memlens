#!/usr/bin/env python3
"""Draw the hook chain that `patchscan.py --links` finds in MemLens kernel.elf exports, as one SVG picture.

    python3 tools/hookgraph.py <kernel.elf> [<kernel.elf> ...] -o hookchain.svg

One panel per kernel.elf, stacked in the order given, and one lane per patched function entry that patchscan links to
its target (hook_links): the hooking instruction (function+offset) --call or jmp--> the hook page copied from memory
(the name MemLens gives it in IDA, with the exporter's memlens_target_ label under it) --call--> the page's first named
call (with its kind: ftrace, kprobe via ftrace, BPF trampoline), and under the page its owner in bold, the arrow
labelled with how patchscan found the owner (ftrace_ops, kprobe, BPF program, module callback).

Every word in the lanes is a piece of what `patchscan.py --links <kernel.elf>` prints for that file (the same
functions: scan, hook_links, hook_xrefs, role_names, page_owners, at); nothing there is typed by hand: the edge words
are patchscan's xref types (hook_xrefs) and Owner.how. tests/test_hookgraph.py checks each text node against the
--links output, lane by lane. A long owner is cut at spaces only, so each line is still a piece of it.
The tool's own words are only these, fixed strings: the colour legend line above the panels (LEGEND: one entry per box
colour, as STYLE draws it), and a heading on the panel of each of the two public demo kernel.elf files (HEADINGS, by
the file's sha256; any other kernel.elf gets no heading).
The same files give the same bytes. The SVG has no fonts, scripts, styles or links (GitHub sanitises SVG): plain
<text> in the generic monospace font, laid out for that font's usual advance width. Needs Python 3.8+ only.

Exit status: 0 the SVG was written, 1 a kernel.elf has no linked hook or is not one patchscan checks (nothing to
draw; nothing is written), 2 a usage error, a file that cannot be read or is not a usable 64-bit ELF, or an SVG
that cannot be written.
"""
import collections
import hashlib
import math
import os
import sys
from xml.sax.saxutils import escape, quoteattr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)  # patchscan.py is in the repository folder (python3 -I does not add the script's folder)
import patchscan as ps  # noqa: E402

USAGE = "usage: python3 tools/hookgraph.py <kernel.elf> [<kernel.elf> ...] -o <out.svg>"

WIDTH = 900  # px, about GitHub's README column; the picture is wider only when the names need it
BIG, SMALL = 13, 11  # font sizes in px: names, and the second line of a box / the edge labels
ADVANCE = 0.61  # monospace advance width per px of font size (DejaVu Sans Mono and Menlo 0.602, Consolas 0.55)
PITCH = {BIG: 17, SMALL: 15}  # line height per font size
PAD_X, PAD_Y = 10, 6  # inside a box
GAP_X, GAP_Y = 56, 26  # between the boxes of a lane: across (room for the edge label), and down to the owner
MARGIN, PANEL_PAD, LANE_GAP, PANEL_GAP = 10, 12, 14, 12
INK, MUTED, EDGE = "#1f2328", "#59636e", "#59636e"
STYLE = {  # box fill and stroke per role
    "site": ("#ffffff", "#8c959f"),
    "page": ("#fff1e5", "#e16f24"),
    "handler": ("#ddf4ff", "#218bff"),
    "owner": ("#fbefff", "#8250df"),  # neutral: most owners are benign (the function tracer, systemd's BPF program)
}

# One lane: site (function+offset of the hooking instruction), flow (call or jmp), page ([new name,] address label),
# handler (the page's first named call, or None), hflow (the xref type from the page to it, hook_xrefs), kind (its kind,
# or None), owner (Owner text or None), how (Owner.how).
Lane = collections.namedtuple("Lane", "site flow page handler hflow kind owner how")

# The tool's own words, the only text that is not a piece of the --links output (tests/test_hookgraph.py exempts exactly
# these strings). The panel heading of each public demo kernel.elf (demo-data release), by its sha256:
HEADINGS = {
    "1481bdbfd0d12b907e208b873d5810c6d1e2adacdf8dbc9cebfb0ae8ad80efa5": "Hooks set through tracefs (demo)",  # memlens-demo-debian13.zip
    "8d95998eacc39055c81417983f3dcdf7bea1d1c811272b13725035971dd149f9": "Hooks set by a test module (second sample)",  # memlens-demo-testhook.zip
}
# The colour legend, one line above the panels: each box role, with its colour as STYLE draws it.
LEGEND = (("site", "white = hooked function"), ("page", "orange = hook page MemLens named"),
          ("handler", "blue = handler"), ("owner", "purple = owner"))
HEAD, LEGEND_SIZE = 15, 12  # font sizes in px: a panel heading, the legend
HEAD_PITCH = 26  # a panel heading's line, down to its first lane
SWATCH, SWATCH_GAP, LEGEND_GAP = 14, 6, 24  # a legend colour square, then its words, then the next entry
LEGEND_PITCH = 24  # the legend's line, down to the first panel


class NotChecked(Exception):
    """patchscan checks nothing in this file (patchscan.nothing_to_check: not a kernel export, say); the reason."""


def lanes(path):
    """The lanes of one kernel.elf, in the order patchscan lists the entries, from the code path of patchscan.py --links
    (main and print_links: Image, nothing_to_check, scan, hook_links, hook_xrefs, role_names, page_owners, at). Raises
    OSError, one of patchscan.BAD_ELF, or NotChecked."""
    with open(path, "rb") as handle:
        blob = handle.read()
    image = ps.Image(blob)
    reason = ps.nothing_to_check(image)
    if reason:
        raise NotChecked(reason)
    links = ps.hook_links(image, ps.scan(blob, image))
    names, owners = ps.role_names(image, links), ps.page_owners(links)
    flows = {(source, target): flow for source, target, flow in ps.hook_xrefs(links)}  # the xref lines' types
    out = []
    for link in links:
        page = [names[link.target]] if link.target in names else []
        page.append(ps.at(image, link.target))  # the xref line's target, as print_links writes it
        owner = owners.get(link.target) if link.page else None
        handler = link.handler is not None
        out.append(Lane(ps.at(image, link.site), flows[(link.site, link.target)], page,
                        ps.at(image, link.handler) if handler else None,
                        flows[(link.handler_site, link.handler)] if handler else None, link.kind,
                        owner.text if owner else None, owner.how if owner else None))
    return out


def heading(path):
    """The panel heading for a kernel.elf: HEADINGS by its sha256, or None (not one of the public demo files)."""
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return HEADINGS.get(digest.hexdigest())


def width_of(text, size):
    return int(math.ceil(len(text) * size * ADVANCE))


def wrap(text, limit):
    """text cut at spaces into lines of at most limit characters (a longer word keeps a line of its own). Each line is a
    piece of text as it is, so it is still a substring of the --links output."""
    lines, line = [], ""
    for word in text.split(" "):
        if line and len(line) + 1 + len(word) > limit:
            lines.append(line)
            line = word
        else:
            line = line + " " + word if line else word
    lines.append(line)
    return lines


def owner_lines(text, room):
    """[(line, size, bold)] for an owner: its name in bold, then the part in parentheses that says how it owns the page
    (the --links owner text cut at its first ' (', when the text ends with ')'), each wrapped to room px."""
    cut = text.find(" (")
    head, tail = (text[:cut], text[cut + 1:]) if cut > 0 and text.endswith(")") else (text, "")
    lines = [(line, BIG, True) for line in wrap(head, max(1, room // width_of("x", BIG)))]
    if tail:
        lines += [(line, SMALL, False) for line in wrap(tail, max(1, room // width_of("x", SMALL)))]
    return lines


def box_lines(lane):
    """[(line, size, bold)] for the three boxes of a lane's first row: site, page, handler (empty when it has none)."""
    page = [(lane.page[0], BIG, False)] + [(label, SMALL, False) for label in lane.page[1:]]
    handler = [(lane.handler, BIG, False)] + ([(lane.kind, SMALL, False)] if lane.kind else []) if lane.handler else []
    return [(lane.site, BIG, False)], page, handler


def box_width(lines):
    return max(width_of(text, size) for text, size, _ in lines) + 2 * PAD_X if lines else 0


def box_height(lines):
    return 2 * PAD_Y + sum(PITCH[size] for _, size, _ in lines)


class Canvas:
    """SVG elements as lines of text, attributes in a fixed order: the same drawing gives the same bytes."""

    def __init__(self):
        self.out = []

    def add(self, line):
        self.out.append(line)

    def rect(self, x, y, w, h, fill, stroke, rx=6):
        self.add('<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="%s" stroke="%s"/>' % (x, y, w, h, rx, fill, stroke))

    def text(self, x, y, text, size, role, bold=False, anchor="start", fill=INK):
        self.add('<text class=%s x="%d" y="%d" font-size="%d"%s%s fill="%s">%s</text>' % (
            quoteattr(role), x, y, size, ' font-weight="bold"' if bold else "",
            ' text-anchor="%s"' % anchor if anchor != "start" else "", fill, escape(text)))

    def box(self, x, y, w, h, lines, role):
        """A box of height h with its lines centred in it, left-aligned."""
        fill, stroke = STYLE[role]
        self.rect(x, y, w, h, fill, stroke)
        top = y + (h - box_height(lines)) // 2 + PAD_Y
        for index, (line, size, bold) in enumerate(lines):
            self.text(x + PAD_X, top + size, line, size, role if index == 0 or role == "owner" else role + "-label", bold,
                      fill=INK if size == BIG else MUTED)
            top += PITCH[size]

    def arrow_right(self, x1, x2, y, label):
        self.add('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5"/>' % (x1 + 1, y, x2 - 8, y, EDGE))
        self.add('<polygon points="%d,%d %d,%d %d,%d" fill="%s"/>' % (x2 - 1, y, x2 - 9, y - 4, x2 - 9, y + 4, EDGE))
        self.text((x1 + x2) // 2, y - 5, label, SMALL, "edge", anchor="middle", fill=MUTED)

    def arrow_down(self, x, y1, y2, label):
        self.add('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="1.5"/>' % (x, y1 + 1, x, y2 - 8, EDGE))
        self.add('<polygon points="%d,%d %d,%d %d,%d" fill="%s"/>' % (x, y2 - 1, x - 4, y2 - 9, x + 4, y2 - 9, EDGE))
        self.text(x + 8, (y1 + y2) // 2 + 4, label, SMALL, "edge", fill=MUTED)


def legend_width():
    return sum(SWATCH + SWATCH_GAP + width_of(words, LEGEND_SIZE) for _, words in LEGEND) + LEGEND_GAP * (len(LEGEND) - 1)


def svg(panels, headings=None):
    """The SVG text for panels (one list of Lanes per kernel.elf), each under its heading (headings: one string or None
    per panel; heading(path) gives it), with the colour legend above them."""
    headings = list(headings or []) + [None] * (len(panels) - len(headings or []))
    rows = [box_lines(lane) for panel in panels for lane in panel]
    columns = [max(box_width(row[index]) for row in rows) for index in range(3)]
    left = MARGIN + PANEL_PAD
    xs = [left, left + columns[0] + GAP_X, left + columns[0] + columns[1] + 2 * GAP_X]
    right = max(WIDTH, xs[2] + columns[2] + PANEL_PAD + MARGIN, left + legend_width() + PANEL_PAD + MARGIN,
                max([left + width_of(title, HEAD) + PANEL_PAD + MARGIN for title in headings if title] or [0]))
    room = right - MARGIN - PANEL_PAD - xs[1] - 2 * PAD_X  # for an owner's lines, under the page and handler
    owners = [owner_lines(lane.owner, room) if lane.owner else [] for panel in panels for lane in panel]
    width = max([right] + [xs[1] + box_width(lines) + PANEL_PAD + MARGIN for lines in owners])

    canvas, y, index = Canvas(), MARGIN, 0
    canvas.add('<g class="legend">')
    x = left
    for role, words in LEGEND:
        fill, stroke = STYLE[role]
        canvas.rect(x, y, SWATCH, SWATCH, fill, stroke, rx=3)
        canvas.text(x + SWATCH + SWATCH_GAP, y + SWATCH - 3, words, LEGEND_SIZE, "legend")
        x += SWATCH + SWATCH_GAP + width_of(words, LEGEND_SIZE) + LEGEND_GAP
    canvas.add("</g>")
    y += LEGEND_PITCH
    for panel, title in zip(panels, headings):
        heights = []
        for offset in range(len(panel)):
            row, lines = rows[index + offset], owners[index + offset]
            heights.append(max(box_height(box) for box in row if box) + (GAP_Y + box_height(lines) if lines else 0))
        panel_height = 2 * PANEL_PAD + (HEAD_PITCH if title else 0) + sum(heights) + LANE_GAP * (len(panel) - 1)
        canvas.add('<g class="panel">')
        canvas.rect(MARGIN, y, width - 2 * MARGIN, panel_height, "#f6f8fa", "#d1d9e0", rx=10)
        top = y + PANEL_PAD
        if title:
            canvas.text(left, top + HEAD - 2, title, HEAD, "heading")
            top += HEAD_PITCH
        for offset, lane in enumerate(panel):
            row, lines = rows[index + offset], owners[index + offset]
            if offset:
                line_y = top - LANE_GAP // 2
                canvas.add('<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="#d1d9e0"/>' % (
                    MARGIN + 8, line_y, width - MARGIN - 8, line_y))
            canvas.add('<g class="lane">')
            row_height = max(box_height(box) for box in row if box)
            for box, role, x, w in zip(row, ("site", "page", "handler"), xs, columns):
                if box:
                    canvas.box(x, top, w, row_height, box, role)
            middle = top + row_height // 2
            canvas.arrow_right(xs[0] + columns[0], xs[1], middle, lane.flow)
            if row[2]:
                canvas.arrow_right(xs[1] + columns[1], xs[2], middle, lane.hflow)
            if lines:
                owner_top = top + row_height + GAP_Y
                canvas.arrow_down(xs[1] + 28, top + row_height, owner_top, lane.how)
                canvas.box(xs[1], owner_top, box_width(lines), box_height(lines), lines, "owner")
            canvas.add("</g>")
            top += heights[offset] + LANE_GAP
        canvas.add("</g>")
        y += panel_height + PANEL_GAP
        index += len(panel)
    height = y - PANEL_GAP + MARGIN
    body = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="monospace">' % (
        width, height, width, height), '<rect width="%d" height="%d" fill="#ffffff"/>' % (width, height)]
    return "\n".join(body + canvas.out + ["</svg>"]) + "\n"


def main(argv):
    args, out = list(argv[1:]), None
    if "-o" in args:
        at_o = args.index("-o")
        if at_o + 1 >= len(args):
            print(USAGE, file=sys.stderr)
            return 2
        out = args[at_o + 1]
        args = args[:at_o] + args[at_o + 2:]
    if out is None or not args or any(arg.startswith("-") for arg in args):
        print(USAGE, file=sys.stderr)
        return 2
    panels, headings = [], []
    for path in args:
        try:
            panel = lanes(path)
            title = heading(path)
        except OSError as error:
            print("hookgraph: cannot read %s: %s" % (path, error.strerror or error), file=sys.stderr)
            return 2
        except ps.BAD_ELF as error:
            print("hookgraph: %s is not a usable 64-bit ELF: %s" % (path, error), file=sys.stderr)
            return 2
        except NotChecked as reason:
            print("hookgraph: %s: %s, so patchscan checked nothing; nothing to draw" % (path, reason), file=sys.stderr)
            return 1
        if not panel:
            print("hookgraph: %s has no linked hook (patchscan.py --links prints no xref), nothing to draw" % path, file=sys.stderr)
            return 1
        panels.append(panel)
        headings.append(title)
    text = svg(panels, headings)
    try:
        with open(out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
    except OSError as error:
        print("hookgraph: cannot write %s: %s" % (out, error.strerror or error), file=sys.stderr)
        return 2
    print("hookgraph: wrote %s (%d panel%s, %d lanes)" % (out, len(panels), "s" if len(panels) > 1 else "",
                                                          sum(len(panel) for panel in panels)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
