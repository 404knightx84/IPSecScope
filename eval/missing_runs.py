#!/usr/bin/env python3
"""List base runs that are missing a pcap or a label. Traffic names are read from existing files."""
import os, re, glob, collections
R = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
have = {os.path.basename(p)[:-5] for p in glob.glob(f'{R}/data/pcaps/c[1-8]_*_r[1-4].pcap')}
lab = {os.path.basename(p)[:-5] for p in glob.glob(f'{R}/data/labels/c[1-8]_*_r[1-4].json')}
traffic = sorted({re.match(r'c\d_(.+)_r\d', r).group(1) for r in have})
print('traffic types seen:', traffic)
done = have & lab
per = collections.Counter(re.search(r'_r(\d)$', r).group(1) for r in done)
print('complete runs per repeat (target 40):', dict(sorted(per.items())))
missing = [f'c{c}_{t}_r{r}' for r in range(1, 5) for c in range(1, 9) for t in traffic
           if f'c{c}_{t}_r{r}' not in done]
print(f'missing or unlabeled: {len(missing)}')
for m in missing:
    print(' ', m, '(pcap only, no label)' if m in have else '')
