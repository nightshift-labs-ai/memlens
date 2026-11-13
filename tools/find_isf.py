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
Volatility's rule: "Linux version " and a version number like 6.12.115), most frequent first.

Exit status: 0 a ready-made ISF was found, 1 none was (or the image has no banner), 2 a usage error, a file or index
that cannot be read, a compressed image, or a failed download.
"""
import json
import mmap
import os
import re
import shutil
import sys
import urllib.request

INDEX_URL = "https://github.com/Abyss-W4tcher/volatility3-symbols/raw/master/banners/banners_plain.json"
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "memlens", "banners_plain.json")
BANNER = re.compile(rb"Linux version [0-9]+\.[0-9]+\.[0-9]+[ -~]{0,500}")  # Volatility's rule; printable ASCII up to the newline / NUL


def banners_in(path):
    """Distinct banners in a file, most frequent first (ties in file order)."""
    counts, order = {}, []
    with open(path, "rb") as handle:
        if os.fstat(handle.fileno()).st_size == 0:
            return []
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as data:
            for match in BANNER.finditer(data):
                text = match.group().decode("ascii").strip()  # the format string "Linux version %s" never matches
                if text not in counts:
                    order.append(text)
                counts[text] = counts.get(text, 0) + 1
    return sorted(order, key=lambda b: -counts[b])


COMPRESSED = ((b"\xfd7zXZ\x00", "xz", "xz -dk"), (b"\x1f\x8b", "gzip", "gzip -dk"), (b"BZh", "bzip2", "bzip2 -dk"))


def compression(path):
    """(kind, command) when the file starts like an xz, gzip or bzip2 file, else None (banners cannot be read there)."""
    with open(path, "rb") as handle:
        head = handle.read(6)
    return next(((kind, command) for magic, kind, command in COMPRESSED if head.startswith(magic)), None)


def load_index(path):
    with open(path, encoding="utf-8") as handle:
        return {key.strip(): urls for key, urls in json.load(handle).items()}


def download(url, dest):
    """Fetch the index to dest + ".part", check that it reads as an index, then move it into place: an interrupted or
    failed download never leaves a broken cache. Raises OSError (URLError is one) or ValueError."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    try:
        with urllib.request.urlopen(url, timeout=120) as response, open(part, "wb") as handle:
            shutil.copyfileobj(response, handle)
        try:
            load_index(part)
        except AttributeError:
            raise ValueError("not a banner -> URLs index")
        os.replace(part, dest)
    finally:
        if os.path.exists(part):
            os.remove(part)


def parse(argv):
    """(target, index path or None, download) or None on a usage error (unknown flag, --index without a file)."""
    args, index_path, fetch, i = [], None, False, 0
    while i < len(argv):
        arg = argv[i]
        if arg == "--index":
            if i + 1 >= len(argv) or argv[i + 1].startswith("--"):
                return None
            index_path, i = argv[i + 1], i + 2
            continue
        if arg == "--download":
            fetch = True
        elif arg.startswith("-"):
            return None
        else:
            args.append(arg)
        i += 1
    return (args[0], index_path, fetch) if len(args) == 1 else None


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
        urls = [u for u in urls if isinstance(u, str)] if isinstance(urls, list) else []  # a damaged index: a miss
        if urls:
            found = True
            for url in urls:
                out += ["ISF: %s" % url, "  curl -LO %s" % url]
        else:
            out += build_hint(banner)
    return out, found


def main(argv):
    if argv in (["-h"], ["--help"]):
        print(__doc__.strip())
        return 0
    parsed = parse(argv)
    if parsed is None:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    target, index_path, fetch = parsed
    banners = [target.strip()] if target.startswith("Linux version ") else banners_in(target) if os.path.isfile(target) else None
    if banners is None:
        print("find_isf: %s is neither a file nor a 'Linux version ...' banner" % target, file=sys.stderr)
        return 2
    packed = compression(target) if not banners and os.path.isfile(target) else None
    if packed:
        print("find_isf: %s is %s-compressed, so its banners cannot be read: decompress it first (%s %s), then run "
              "find_isf.py on the result" % (target, packed[0], packed[1], target))
        return 2
    if not banners:
        print("find_isf: no 'Linux version ...' banner in %s (is it a Linux memory image?)" % target)
        return 1
    if not index_path:
        index_path = CACHE
        if fetch:
            print("downloading %s" % INDEX_URL)
            try:
                download(INDEX_URL, CACHE)
            except (OSError, ValueError) as error:  # urllib.error.URLError is an OSError
                print("find_isf: the download failed (%s); nothing was cached. Try again, or download %s yourself and "
                      "give --index <file>." % (error, INDEX_URL))
                return 2
        elif not os.path.isfile(CACHE):
            print("find_isf: no index yet. Run again with --download (fetches %s, ~4 MB, once) or give "
                  "--index <banners_plain.json>." % INDEX_URL)
            print("banners found: %s" % "\n  ".join([""] + banners))
            return 2
    try:
        index = load_index(index_path)
    except (OSError, ValueError, AttributeError) as error:  # missing, not JSON, or JSON that is not banner -> URLs
        print("find_isf: cannot read the index %s (%s)" % (index_path, error))
        return 2
    lines, found = report(banners, index)
    print("\n".join(lines))
    return 0 if found else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
