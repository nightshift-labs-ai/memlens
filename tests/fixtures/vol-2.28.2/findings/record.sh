#!/bin/sh
# Re-record the Volatility 3 (2.28.2) JSON outputs in this folder from the two public memory images.
# usage: record.sh <trace.elf> <testhook.elf> <symbols folder with linux/debian-6.12.115+deb13.1-amd64.json.xz> [vol]
# Writes demo/*.json and testhook/*.json under the current folder; tests/test_volfind_stub.py reads them.
set -e
trace=$1; testhook=$2; symbols=$3; vol=${4:-vol}
run() {  # run <sample folder> <image> <output name> <plugin> [options]
    folder=$1; img=$2; name=$3; shift 3
    mkdir -p "$folder"
    "$vol" -q -s "$symbols" -f "$img" -r json "$@" > "$folder/$name.json"
}
for sample in demo testhook; do
    if [ $sample = demo ]; then img=$trace; else img=$testhook; fi
    run $sample "$img" tracepoints        linux.tracing.tracepoints.CheckTracepoints
    run $sample "$img" keyboard_notifiers linux.malware.keyboard_notifiers.Keyboard_notifiers
    run $sample "$img" check_idt          linux.malware.check_idt.Check_idt
    run $sample "$img" check_afinfo       linux.malware.check_afinfo.Check_afinfo
    run $sample "$img" netfilter          linux.malware.netfilter.Netfilter
    run $sample "$img" ftrace-flags       linux.tracing.ftrace.CheckFtrace --show-ftrace-flags
done
