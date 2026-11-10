#!/bin/bash
# usage: check_elf.sh <kernel.elf> : independent checks with binutils, awk and a short Python step.
E=$1; T=$(mktemp -d); readelf -sW "$E" 2>/dev/null > $T/s
readelf -lW "$E" | awk '$1=="LOAD"{n++; if ($3 !~ /^0xffff/) bad++} END{print "LOAD segments",n,"non-canonical",bad+0}'
readelf -lW "$E" | python3 -Ic 'import sys
rows=sorted((int(p[2],16),int(p[5],16)) for p in (l.split() for l in sys.stdin) if p and p[0]=="LOAD")
print("overlapping LOAD segments:",sum(a<b[0]+b[1] for b,(a,_) in zip(rows,rows[1:])))'
echo "symbols in symtab: $(($(wc -l < $T/s)-4))  module symbols: $(awk '$2 ~ /^ffffffff[c-f]/ && $8 ~ /\./' $T/s | wc -l)"
addr(){ awk -v n="$1" '$8==n{print $2; exit}' $T/s; }
for f in __x64_sys_read nf_hook_slow nf_tables.nft_do_chain; do A=$(addr $f); [ -z "$A" ] && { echo "MISSING $f"; continue; }
 echo "== $f $A"; objdump -d --start-address=0x$A --stop-address=0x$(python3 -Ic "print(hex(0x$A+24)[2:])") "$E" 2>&1 | grep -E '^ *[0-9a-f]+:' | head -7 | cut -c1-80; done
B=$(addr linux_banner); python3 -I - "$E" "$B" <<'PY'
import sys,struct
f=open(sys.argv[1],'rb'); a=int(sys.argv[2],16)
h=f.read(64); phoff,phnum=struct.unpack_from('<Q',h,32)[0],struct.unpack_from('<H',h,56)[0]
for i in range(phnum):
    f.seek(phoff+56*i); p=struct.unpack('<IIQQQQQQ',f.read(56))
    if p[3]<=a<p[3]+p[5]:
        f.seek(p[2]+a-p[3]); print('banner:',f.read(90).split(b'\0')[0].decode(errors='replace')); break
PY
rm -rf $T
