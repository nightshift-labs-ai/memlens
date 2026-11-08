#!/usr/bin/env python3
"""Ask gcc to confirm the generated header matches the ISF: every struct size and member offset."""
import os, subprocess, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import isf2c

def main(path):
    gen = isf2c.Generator(isf2c.load_isf(path))
    header = gen.generate()
    checks, members = [], 0
    for name, info in gen.user.items():
        if name not in gen.done or not info.get("fields") or not info.get("size"):
            continue
        tag = "%s %s" % (info.get("kind", "struct"), isf2c.ident(name))
        checks.append("_Static_assert(sizeof(%s)==%d,\"size %s\");" % (tag, info["size"], name))
        if info.get("kind") == "union":
            continue
        for fname, field in info["fields"].items():
            typ = field["type"]
            label = isf2c.ident(fname)
            if label in isf2c.RESERVED:
                label += "_"
            if typ.get("kind") == "bitfield" or gen.size_of(typ) == 0:
                continue
            if fname not in gen.emitted.get(id(info), ()):
                continue
            checks.append("_Static_assert(__builtin_offsetof(%s,%s)==%d,\"off %s.%s\");" % (tag, label, field.get("offset", 0), name, fname))
            members += 1
    with tempfile.TemporaryDirectory() as tmp:
        src = os.path.join(tmp, "t.c")
        open(src, "w").write(header + "\n" + "\n".join(checks) + "\n")
        res = subprocess.run(["gcc", "-fsyntax-only", "-w", "-fmax-errors=25", src], capture_output=True, text=True)
    print(gen.stats, "size+offset asserts:", len(checks), "member offsets:", members, "header bytes:", len(header))
    real = sum(1 for n, i in gen.user.items() if i.get("kind") != "union" and i.get("size") for k, f in i.get("fields", {}).items()
               if f["type"].get("kind") != "bitfield" and gen.size_of(f["type"]) > 0 and k not in gen.emitted.get(id(i), ()))
    print("members dropped:", len(gen.dropped), "of which with size > 0:", real)
    print("gcc exit", res.returncode)
    print(res.stderr[:3000])
    return res.returncode

sys.exit(main(sys.argv[1]))
