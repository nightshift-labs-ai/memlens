#!/usr/bin/env python3
"""isf2c.load_isf reads the same ISF files Volatility does: .json, .json.xz, .json.gz, .json.bz2.
The compression is taken from the file's first bytes, so a misnamed file still loads. Pure Python, no IDA."""
import bz2, gzip, json, lzma, os, sys, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import isf2c

ISF = {"metadata": {}, "base_types": {}, "user_types": {}, "enums": {},
       "symbols": {"linux_banner": {"address": 0, "constant_data": "TGludXggdmVyc2lvbiA2LjEy"}}}
raw = json.dumps(ISF).encode()
d = tempfile.mkdtemp(prefix="memlens_isf_")
files = {
    "a.json": raw,
    "a.json.xz": lzma.compress(raw),
    "a.json.gz": gzip.compress(raw),
    "a.json.bz2": bz2.compress(raw),
    "gz-named.json": gzip.compress(raw),     # wrong extension: the magic bytes decide
    "xz-named.json.gz": lzma.compress(raw),
}
for name, data in files.items():
    with open(os.path.join(d, name), "wb") as f:
        f.write(data)
    assert isf2c.load_isf(os.path.join(d, name)) == ISF, name

expect = {"a.json": None, "a.json.xz": "xz", "a.json.gz": "gz", "a.json.bz2": "bz2", "gz-named.json": "gz",
          "xz-named.json.gz": "xz"}
for name, kind in expect.items():
    assert isf2c.isf_compression(os.path.join(d, name)) == kind, (name, isf2c.isf_compression(os.path.join(d, name)))
# A file that cannot be opened falls back on its extension (so a missing .xz still names the right tool).
assert isf2c.isf_compression("/nonexistent/x.json.xz") == "xz"
assert isf2c.isf_compression("/nonexistent/x.json") is None


def refused(name, data, words):
    p = os.path.join(d, name)
    with open(p, "wb") as f:
        f.write(data)
    try:
        isf2c.load_isf(p)
    except isf2c.ISFError as e:
        for w in words:
            assert w in str(e), (name, str(e))
        return
    raise AssertionError("%s was accepted" % name)


# Damaged streams and non-ISF JSON give one ISFError each (the plugin shows it as a one-line warning).
refused("cut.json.gz", gzip.compress(raw)[:40], ["not a readable Volatility ISF", ".json.gz"])
refused("cut.json.bz2", bz2.compress(raw)[:40], ["not a readable Volatility ISF"])
refused("cut.json.xz", lzma.compress(raw)[:40], ["not a readable Volatility ISF"])
bad = bytearray(gzip.compress(json.dumps({"user_types": {"s%d" % i: {"size": i} for i in range(400)}}).encode()))
bad[10] = 0xFF  # damaged deflate block: zlib.error, not OSError/ValueError
refused("damaged.json.gz", bytes(bad), ["not a readable Volatility ISF"])
refused("other.json.gz", gzip.compress(b'{"a": 1}'), ["not a Volatility ISF"])
refused("binary.json", b"\x7fELF\x02\x01\x01" + b"\0" * 64, ["not a readable Volatility ISF"])
print("ISF format test OK (.json, .json.xz, .json.gz, .json.bz2 by magic bytes; damaged and non-ISF files refused)")
