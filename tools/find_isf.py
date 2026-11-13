#!/usr/bin/env python3
"""Find a ready-made Volatility ISF for a Linux memory image (or a kernel banner).

    python3 tools/find_isf.py <memory image>                    # the "Linux version ..." banners found in it
    python3 tools/find_isf.py "Linux version 6.8.0-147-generic (buildd@...) ..."
    python3 tools/find_isf.py <image> --index banners_plain.json   # a local copy of the index
    python3 tools/find_isf.py <image> --download                # fetch the index once into ~/.cache/memlens/

It looks each banner up in the community index of Abyss-W4tcher/volatility3-symbols (banners/banners_plain.json:
banner -> ISF download URLs) and prints the URL and a curl line. On a miss it prints the dwarf2json command and the
debug package to build the ISF yourself (the same steps as docs/EXPORT.md). The network is used only with
--download. Needs Python 3.8+ only. Banners are read straight from the image's bytes (like `vol banners.Banners`, by
the text "Linux version "), most frequent first.
"""
import json
import mmap
import os
import re
import sys
import urllib.request

INDEX_URL = "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners_plain.json"
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "memlens", "banners_plain.json")
BANNER = re.compile(rb"Linux version [ -~]{8,500}")  # printable ASCII up to the banner's newline / NUL


def banners_in(path):
    """Distinct banners in a file, most frequent first (ties in file order)."""
    counts, order = {}, []
    with open(path, "rb") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            return []
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for match in BANNER.finditer(data):
                text = match.group().decode("ascii").strip()
                words = text.split()
                if "(" not in text or len(words) < 3 or "%" in words[2]:  # the kernel's "Linux version %s (%s@%s)"
                    continue                                               # format string, other non-banners
                if text not in counts:
                    order.append(text)
                counts[text] = counts.get(text, 0) + 1
    return sorted(order, key=lambda b: -counts[b])


def load_index(path):
    with open(path, encoding="utf-8") as handle:
        return {key.strip(): urls for key, urls in json.load(handle).items()}


def build_hint(banner):
    """The dwarf2json line and the debug package for a banner with no ready-made ISF."""
    release = banner.split()[2] if len(banner.split()) > 2 else "<version>"
    line = "dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-%s | xz > %s.json.xz" % (release, release)
    if "Debian" in banner or "deb1" in release:
        package = "Debian package linux-image-%s-dbg" % release
    elif "Ubuntu" in banner:
        package = "Ubuntu package linux-image-unsigned-%s-dbgsym (ddebs.ubuntu.com)" % release
    else:
        package = "your distribution's debug package with vmlinux-%s" % release
    return ["no ready-made ISF in the index: build one with dwarf2json from the kernel's debug image (%s):" % package,
            "  " + line]


def report(banners, index):
    """Printed lines for every banner; True when at least one has an ISF."""
    out, found = [], False
    for banner in banners:
        out.append("banner: %s" % banner)
        urls = index.get(banner.strip())
        if urls:
            found = True
            for url in urls:
                out += ["ISF: %s" % url, "  curl -LO %s" % url]
        else:
            out += build_hint(banner)
    return out, found


def main(argv):
    args = [a for a in argv if not a.startswith("--")]
    index_path = argv[argv.index("--index") + 1] if "--index" in argv and argv.index("--index") + 1 < len(argv) else None
    if index_path in args:
        args.remove(index_path)
    if len(args) != 1:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    target = args[0]
    banners = [target.strip()] if target.startswith("Linux version ") else banners_in(target) if os.path.isfile(target) else None
    if banners is None:
        print("find_isf: %s is neither a file nor a 'Linux version ...' banner" % target, file=sys.stderr)
        return 2
    if not banners:
        print("find_isf: no 'Linux version ...' banner in %s (is it a Linux memory image?)" % target)
        return 1
    if not index_path:
        index_path = CACHE
        if "--download" in argv:
            os.makedirs(os.path.dirname(CACHE), exist_ok=True)
            print("downloading %s" % INDEX_URL)
            urllib.request.urlretrieve(INDEX_URL, CACHE)
        elif not os.path.isfile(CACHE):
            print("find_isf: no index yet. Run again with --download (fetches %s, ~4 MB, once) or give "
                  "--index <banners_plain.json>." % INDEX_URL)
            print("banners found: %s" % "\n  ".join([""] + banners))
            return 2
    lines, found = report(banners, load_index(index_path))
    print("\n".join(lines))
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
