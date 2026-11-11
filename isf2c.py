#!/usr/bin/env python3
"""Turn a Volatility 3 ISF symbol file into one C header that IDA can parse.

Every struct is emitted packed, with explicit padding, so its layout is exactly
what the ISF says and does not depend on the parsing compiler's alignment rules.
Standard library only.
"""
import argparse
import json
import os
import re
import sys

IDENT = re.compile(r"[^0-9A-Za-z_]")


class ISFError(Exception):
    """An ISF file that cannot be read here; the message says what to do."""


def load_isf(path):
    opener = open
    if path.endswith(".xz"):
        # Imported here, so a Python built without _lzma can still load the plugin and read plain .json ISFs.
        try:
            import lzma
        except ImportError:
            raise ISFError("this Python has no lzma module: decompress the ISF first "
                             "(xz -dk %s) and choose the .json file" % os.path.basename(path))
        opener = lzma.open
    with opener(path, "rt", encoding="utf-8") as handle:
        return json.load(handle)


# Names a C compiler accepts but IDA's parser may not: C keywords, C++ keywords (the kernel
# has members called private, new, class...) and IDA's own type keywords.
RESERVED = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum",
    "extern", "float", "for", "goto", "if", "inline", "int", "long", "register", "restrict", "return",
    "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union", "unsigned", "void",
    "volatile", "while", "_Bool", "__func__", "__FUNCTION__", "__PRETTY_FUNCTION__",
    "alignas", "alignof", "and", "and_eq", "asm", "bitand", "bitor", "bool", "catch", "char8_t", "char16_t",
    "char32_t", "class", "compl", "concept", "consteval", "constexpr", "constinit", "const_cast", "co_await",
    "co_return", "co_yield", "decltype", "delete", "dynamic_cast", "explicit", "export", "false", "friend",
    "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator", "or", "or_eq", "private",
    "protected", "public", "reinterpret_cast", "requires", "static_assert", "static_cast", "template", "this",
    "thread_local", "throw", "true", "try", "typeid", "typename", "using", "virtual", "wchar_t", "xor", "xor_eq",
    "__int8", "__int16", "__int32", "__int64", "__int128", "__cdecl", "__stdcall", "__fastcall", "__thiscall",
    "__pascal", "__usercall", "__userpurge", "__near", "__far", "__huge", "__hidden", "__return_ptr",
    "__struct_ptr", "__array_ptr", "__unused", "__noreturn", "__pure", "__cppobj", "__unaligned", "__ptr32",
    "__ptr64", "__seg", "__spoils", "__shifted", "__tuple", "__golang", "__swiftcall",
}

RESERVED |= {  # IDA's type keywords (docs: type-system-keywords)
    "_BOOL1", "_BOOL2", "_BOOL4", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_TBYTE", "_UNKNOWN",
    "__high", "__bitmask", "__invbf", "__bin", "__oct", "__hex", "__dec", "__sbin", "__soct", "__shex", "__udec",
    "__float", "__char", "__segm", "__enum", "__off", "__offset", "__strlit", "__stroff", "__custom",
    "__invsign", "__invbits", "__lzero", "__tabform",
    # Older calling-model words; gcc accepts them as names, IDA's parser is unproven on them.
    "near", "far", "huge", "interrupt", "cdecl", "pascal", "stdcall", "fastcall", "thiscall", "flat", "large", "small",
}


def ident(name):
    clean = IDENT.sub("_", name)
    if clean[:1].isdigit():
        clean = "_" + clean
    return clean + "_" if clean in RESERVED else clean


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

    def typed(self, typ):
        """True when `typ` is concrete enough to be worth applying to a global."""
        kind = typ.get("kind")
        if kind == "base":
            return self.base_c(typ["name"]) != "void"
        if kind == "pointer":
            return True
        if kind in ("struct", "union"):
            return typ["name"] in self.done
        if kind == "array":
            return typ.get("count", 0) > 0 and self.size_of(typ) > 0 and self.typed(typ["subtype"])
        return kind == "enum"

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

    def declarations(self, only=None):
        """Every declaration in the order it must be parsed: forward tags, enums, then bodies."""
        names = sorted(self.user)
        for name, info in sorted(self.enums.items()):
            self.emit_enum(name, info)
        wanted = names if only is None else [n for n in names if n in only]
        for name in wanted:
            self.emit_user(name)
        forward = ["%s %s;" % (self.user[n].get("kind", "struct"), ident(n)) for n in names if n in self.done]
        return forward + self.body

    def generate(self, only=None):
        head = "/* Generated by isf2c from a Volatility 3 ISF. */\n#pragma pack(push, 1)\n\n"
        return head + "\n".join(self.declarations(only)) + "\n#pragma pack(pop)\n"

    def expected_sizes(self):
        """{C tag: size} for every complete struct or union that was emitted."""
        return {ident(n): i["size"] for n, i in self.user.items() if n in self.done and i.get("size")}


def import_in_batches(declarations, parse, batch=1000, progress=None):
    """Feed declarations to parse(text) -> error count. Returns those that fail on their own.

    One declaration IDA rejects must not cost the other 60,000, so a failing batch is split in
    half until the bad declarations are isolated. parse_decls always ignores redeclarations,
    which is what makes parsing a batch again safe. progress(done, total) may return True to stop.
    """
    failed = []

    def run(items):
        if not parse("\n".join(items)):
            return
        if len(items) == 1:
            failed.append(items[0])
            return
        middle = len(items) // 2
        run(items[:middle])
        run(items[middle:])

    for start in range(0, len(declarations), batch):
        if progress and progress(start, len(declarations)):
            break
        run(declarations[start:start + batch])
    return failed


def global_decls(generator, isf):
    """C declarations for typed kernel globals: (symbol name, "struct task_struct init_task")."""
    decls = []
    for name, symbol in sorted(isf.get("symbols", {}).items()):
        typ = symbol.get("type")
        if not typ or ident(name) != name or name in RESERVED or not generator.typed(typ):
            continue
        decls.append((name, generator.declarator(typ, name)))
    return decls


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("isf")
    parser.add_argument("output")
    parser.add_argument("--only", nargs="*", help="only these types and what they need by value")
    args = parser.parse_args(argv)
    try:
        isf = load_isf(args.isf)
    except ISFError as error:
        print("isf2c: %s" % error, file=sys.stderr)
        return 1
    generator = Generator(isf)
    text = generator.generate(set(args.only) if args.only else None)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(generator.stats, file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
