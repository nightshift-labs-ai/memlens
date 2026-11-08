#!/usr/bin/env python3
"""Turn a Volatility 3 ISF symbol file into one C header that IDA can parse.

Every struct is emitted packed, with explicit padding, so its layout is exactly
what the ISF says and does not depend on the parsing compiler's alignment rules.
Standard library only.
"""
import argparse
import json
import lzma
import re
import sys

IDENT = re.compile(r"[^0-9A-Za-z_]")


def load_isf(path):
    opener = lzma.open if path.endswith(".xz") else open
    with opener(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


def ident(name):
    clean = IDENT.sub("_", name)
    return "_" + clean if clean[:1].isdigit() else clean


# C keywords and names that break a declaration when used as an identifier.
RESERVED = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "_Bool",
}


class Generator:
    def __init__(self, isf):
        self.base = isf.get("base_types", {})
        self.enums = isf.get("enums", {})
        self.user = isf.get("user_types", {})
        self.seen_constants = set()
        self.dropped = []
        self.emitted = {}
        self.done = set()
        self.active = set()
        self.body = []
        self.stats = {"structs": 0, "unions": 0, "enums": 0, "bitfields_as_storage": 0, "skipped": 0}

    def base_c(self, name):
        info = self.base.get(name, {})
        if name == "void" or info.get("kind") == "void":
            return "void"
        if name in ("pointer", "__ptr"):
            return "void *"
        size = info.get("size", 1)
        if info.get("kind") == "float":
            return {4: "float", 8: "double"}.get(size, "unsigned char /*float%d*/" % size)
        if info.get("kind") == "bool":
            return "unsigned char"
        if size == 16:
            return "unsigned __int128" if not info.get("signed") else "__int128"
        unsigned = "" if info.get("signed") else "unsigned "
        return unsigned + {1: "char", 2: "short", 4: "int", 8: "long long"}.get(size, "char")

    def enum_c(self, name):
        info = self.enums.get(name)
        if info is None:
            return "unsigned int"
        size = info.get("size", 4)
        if size == 4:
            return "enum " + self.enum_tag(name)
        return {1: "unsigned char", 2: "unsigned short", 8: "unsigned long long"}.get(size, "unsigned int")

    def enum_tag(self, name):
        """C has one tag namespace, so an enum may not share a name with a struct."""
        return ident(name) + "__enum" if name in self.user else ident(name)

    def size_of(self, typ):
        kind = typ.get("kind")
        if kind == "base":
            return self.base.get(typ["name"], {}).get("size", 1)
        if kind in ("struct", "union"):
            return self.user.get(typ["name"], {}).get("size", 0)
        if kind == "enum":
            return self.enums.get(typ["name"], {}).get("size", 4)
        if kind in ("pointer", "function"):
            return self.base.get("pointer", {}).get("size", 8)
        if kind == "array":
            return typ.get("count", 0) * self.size_of(typ["subtype"])
        if kind == "bitfield":
            return self.size_of(typ["type"])
        return 0

    def declarator(self, typ, name):
        """Return a C declaration of `name` with type `typ`."""
        kind = typ.get("kind")
        if kind == "array":
            count = typ.get("count", 0)
            return self.declarator(typ["subtype"], "%s[%d]" % (name, count))
        if kind == "pointer":
            sub = typ.get("subtype", {})
            if sub.get("kind") in ("function", "array"):
                return "void *" + name
            return self.declarator(sub, "*" + name)
        if kind == "function":
            return "void *" + name
        if kind == "base":
            base = self.base_c(typ["name"])
            sep = "" if base.endswith("*") else " "
            return base + sep + name
        if kind == "enum":
            return self.enum_c(typ["name"]) + " " + name
        if kind in ("struct", "union"):
            if typ["name"] not in self.user:
                return "void " + name if name.startswith("*") else "unsigned char " + name + "[0]"
            return "%s %s %s" % (self.user[typ["name"]].get("kind", kind), ident(typ["name"]), name)
        return "unsigned char " + name

    def deps(self, typ):
        """Types that must be complete before a member of type `typ`."""
        kind = typ.get("kind")
        if kind == "array":
            return self.deps(typ["subtype"])
        if kind in ("struct", "union"):
            return [typ["name"]]
        return []

    def emit_enum(self, name, info):
        if info.get("size", 4) != 4 or not info.get("constants"):
            return
        items = []
        for constant, value in sorted(info["constants"].items(), key=lambda kv: (kv[1], kv[0])):
            label = ident(constant)
            if label in self.seen_constants:
                label = "%s__%s" % (ident(name), label)
            if label in self.seen_constants:
                continue
            self.seen_constants.add(label)
            items.append("  %s = %d," % (label, value))
        if items:
            self.body.append("enum %s {\n%s\n};\n" % (self.enum_tag(name), "\n".join(items)))
            self.stats["enums"] += 1

    def members_struct(self, info):
        """Lay out a struct as ordered, padded, non-overlapping members."""
        out = []
        cursor = 0
        unknown = 0
        fields = sorted(info.get("fields", {}).items(), key=lambda kv: kv[1].get("offset", 0))
        index = 0
        while index < len(fields):
            name, field = fields[index]
            offset, typ = field.get("offset", 0), field["type"]
            if typ.get("kind") == "bitfield":
                # Merge every bitfield sharing this storage into a byte array.
                # The ISF gives each bitfield's real byte; its declared type is usually wider.
                end = offset
                labels = []
                while index < len(fields) and fields[index][1]["type"].get("kind") == "bitfield" and fields[index][1].get("offset", 0) <= end:
                    other = fields[index]
                    bits = other[1]["type"]
                    span = (bits.get("bit_position", 0) + bits.get("bit_length", 0) + 7) // 8
                    end = max(end, other[1].get("offset", 0) + span)
                    labels.append("%s:%d@%d" % (other[0], bits.get("bit_length", 0), bits.get("bit_position", 0)))
                    index += 1
                if offset >= cursor:
                    if offset > cursor:
                        out.append("  unsigned char __pad_%x[%d];" % (cursor, offset - cursor))
                    out.append("  unsigned char __bits_%x[%d]; /* %s */" % (offset, end - offset, ", ".join(labels)))
                    cursor = end
                    self.stats["bitfields_as_storage"] += len(labels)
                continue
            size = self.size_of(typ)
            index += 1
            if offset < cursor:
                # Overlap the ISF allows but a plain struct cannot express.
                unknown += 1
                self.dropped.append(name)
                continue
            if size == 0:
                # Flexible array or empty struct: it occupies no bytes, keep it as a comment.
                out.append("  /* +0x%x %s */" % (offset, name))
                continue
            if offset > cursor:
                out.append("  unsigned char __pad_%x[%d];" % (cursor, offset - cursor))
                cursor = offset
            label = ident(name)
            if label in RESERVED:
                label += "_"
            # ISFs keep one type per name, but the kernel has several same-named local
            # structs. Trust the member offsets: if the type cannot fit, keep raw bytes.
            limit = info.get("size", 0)
            for _, later in fields[index:]:
                if later.get("offset", 0) > offset:
                    limit = later["offset"]
                    break
            if offset + size > limit:
                out.append("  unsigned char %s[%d]; /* ISF type does not fit here: %s */" % (label, limit - offset, typ.get("name", typ.get("kind"))))
                self.stats["resized"] = self.stats.get("resized", 0) + 1
                size = limit - offset
            else:
                out.append("  %s;" % self.declarator(typ, label))
            self.emitted.setdefault(id(info), set()).add(name)
            cursor = offset + size
        size = info.get("size", 0)
        if cursor < size:
            out.append("  unsigned char __pad_%x[%d];" % (cursor, size - cursor))
        return out, unknown

    def members_union(self, info):
        out = []
        for name, field in sorted(info.get("fields", {}).items()):
            typ = field["type"]
            if typ.get("kind") == "bitfield" or self.size_of(typ) == 0:
                continue
            label = ident(name)
            if label in RESERVED:
                label += "_"
            out.append("  %s;" % self.declarator(typ, label))
        # Keeps the union's size right even when every member was a bitfield.
        out.append("  unsigned char __raw[%d];" % max(info.get("size", 0), 1))
        return out

    def emit_user(self, name):
        if name in self.done or name in self.active or name not in self.user:
            return
        self.active.add(name)
        info = self.user[name]
        for field in info.get("fields", {}).values():
            for dep in self.deps(field["type"]):
                self.emit_user(dep)
        self.active.discard(name)
        self.done.add(name)
        kind = info.get("kind", "struct")
        if not info.get("size"):
            # Occupies no bytes: forward-declared only, members of this type become comments.
            self.stats["skipped"] += 1
            return
        if not info.get("fields"):
            if info.get("size"):
                self.body.append("%s %s { unsigned char __raw[%d]; };\n" % (kind, ident(name), info["size"]))
            else:
                self.stats["skipped"] += 1
            return
        if kind == "union":
            members = self.members_union(info)
        else:
            members, _ = self.members_struct(info)
        self.stats["unions" if kind == "union" else "structs"] += 1
        self.body.append("%s %s {\n%s\n};\n" % (kind, ident(name), "\n".join(members)))

    def generate(self, only=None):
        names = sorted(self.user)
        for name, info in sorted(self.enums.items()):
            self.emit_enum(name, info)
        wanted = names if only is None else [n for n in names if n in only]
        for name in wanted:
            self.emit_user(name)
        head = ["/* Generated by isf2c from a Volatility 3 ISF. */", "#pragma pack(push, 1)", ""]
        for name in names:
            if name in self.done:
                head.append("%s %s;" % (self.user[name].get("kind", "struct"), ident(name)))
        return "\n".join(head) + "\n\n" + "\n".join(self.body) + "\n#pragma pack(pop)\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("isf")
    parser.add_argument("output")
    parser.add_argument("--only", nargs="*", help="only these types and what they need by value")
    args = parser.parse_args(argv)
    generator = Generator(load_isf(args.isf))
    text = generator.generate(set(args.only) if args.only else None)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(generator.stats, file=sys.stderr)


if __name__ == "__main__":
    main()
