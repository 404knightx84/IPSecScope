#!/usr/bin/env python3
import sys, os, json, glob
sys.path.insert(0, os.path.expanduser('~/ipsecscope/backend/app'))
from ingest import read_pcap
from ike import analyze, fmt, DH
HOME = os.path.expanduser('~/ipsecscope')
ok_all = True
for lf in sorted(glob.glob(f'{HOME}/data/labels/*.json')):
    d = json.load(open(lf))
    if not d.get('passed'):
        continue
    r = analyze(read_pcap(f"{HOME}/data/pcaps/{d['run_id']}.pcap"))
    ss, probs = r['sessions'], []
    if len(ss) != 1 or ss[0]['version'] != d['ike_version']:
        probs.append('session/version')
    if d['ike_version'] == 2 and ss:
        sel = ss[0].get('selected') or {}
        if not (sel.get('enc') == ['AES_CBC-128'] and sel.get('integ') == ['HMAC_SHA2_256_128']
                and sel.get('prf') == ['PRF_HMAC_SHA2_256'] and ss[0].get('dh_group') == d['dh_group']):
            probs.append('IKE suite/DH')
    if d['ike_version'] == 1 and r['aggressive'] != d.get('aggressive_mode_seen'):
        probs.append('aggressive flag')
    lab, mine = d['rekeys'], r['rekeys']
    if len(lab) != len(mine) or any(abs(a['t'] - b['t']) > 0.5 or b['type'] != 'child' for a, b in zip(lab, mine)):
        probs.append('rekeys')
    confirmed = sum(1 for k in mine if k['new_esp_spis'])
    if confirmed != len(mine):
        probs.append('no new ESP SPI')
    ok_all &= not probs
    suite = fmt(ss[0].get('selected')) if ss and 'selected' in ss[0] else ('IKEv1 aggressive' if r['aggressive'] else 'IKEv1')
    print(f"{d['run_id']:16} {suite:58} rekeys {len(mine)}/{len(lab)} esp-confirmed {confirmed}  {'OK' if not probs else 'DIFF ' + ','.join(probs)}")
print('ALL MATCH' if ok_all else 'MISMATCH')
