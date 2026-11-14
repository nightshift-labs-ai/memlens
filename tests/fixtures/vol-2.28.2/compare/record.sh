#!/bin/sh
# Re-record the Volatility 3 (2.28.2) outputs in this folder from the two public memory images.
# usage: record.sh <trace.elf> <testhook.elf> <symbols folder with linux/debian-6.12.115+deb13.1-amd64.json.xz> [vol]
# Writes into the current folder; tests/test_compare.py reads the files. Each run takes about 4 to 20 s.
set -e
trace=$1; testhook=$2; symbols=$3; vol=${4:-vol}
run() {  # run <output file> <image> <plugin> [options]
    out=$1; img=$2; shift 2
    "$vol" -q -s "$symbols" -f "$img" -r pretty "$@" > "$out"
}
run demo.ftrace.txt       "$trace"    linux.tracing.ftrace.CheckFtrace
run demo.ftrace-flags.txt "$trace"    linux.tracing.ftrace.CheckFtrace --show-ftrace-flags
run demo.ebpf.txt         "$trace"    linux.ebpf.EBPF
run th.ftrace.txt         "$testhook" linux.tracing.ftrace.CheckFtrace
run th.ftrace-flags.txt   "$testhook" linux.tracing.ftrace.CheckFtrace --show-ftrace-flags
run th.ebpf.txt           "$testhook" linux.ebpf.EBPF
run th.hidden_modules.txt "$testhook" linux.malware.hidden_modules.Hidden_modules
{ "$vol" -h | head -1; "$vol" -h | grep -o '^ *linux\.[A-Za-z_.]*' | tr -d ' '; } > plugins.txt
