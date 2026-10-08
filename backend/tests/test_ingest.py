#!/usr/bin/env python3
import sys, subprocess, collections, glob, os
sys.path.insert(0, os.path.expanduser('~/ipsecscope/backend/app'))
from ingest import read_pcap

def tshark_L(path):
    out = subprocess.run(['tshark', '-r', path, '-Y', 'esp', '-T', 'fields', '-e', 'ip.len', '-e', 'ip.hdr_len',
                          '-e', 'udp.dstport', '-e', 'ipv6.plen'], capture_output=True, text=True).stdout
    c = collections.Counter()
    for line in out.splitlines():
        f = (line.split('\t') + [''] * 4)[:4]
        L = int(f[3]) if f[3] else int(f[0]) - int(f[1])
        c[L - (8 if f[2] else 0)] += 1
    return c

ok = True
for path in sorted(glob.glob(os.path.expanduser('~/ipsecscope/data/g1/*.pcap'))):
    pk = read_pcap(path)
    mine = collections.Counter(p.L for p in pk if p.kind == 'esp')
    ref = tshark_L(path)
    kinds = collections.Counter(p.kind for p in pk)
    good = mine == ref
    ok &= good
    print(f'{os.path.basename(path):24} esp {sum(mine.values()):3} (tshark {sum(ref.values()):3})  '
          f'ike {kinds["ike"]:2}  {"OK" if good else "DIFF"}')
print('ALL MATCH' if ok else 'MISMATCH')
