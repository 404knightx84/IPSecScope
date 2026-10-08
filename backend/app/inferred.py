#!/usr/bin/env python3
"""S5.6 / 5.8 / 5.9: one JSON with observed + inferred + not_determinable items and advisor notes."""
import sys, os, json, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest import read_pcap, build_flows
from ike import analyze
from observed import observed_findings, item
from esp import infer_cipher
from pfs import pfs_item
from mode_pfs import mode_item

def nd(key, label, reason, advice, min_capture=None, extra=None):
    d = {'reason': reason, 'advice': advice}
    if min_capture:
        d['min_capture'] = min_capture
    if extra:
        d.update(extra)
    return item(key, label, None, [], 'not_determinable', 0.0, d)

def lifetime_items(pkts, r, ike, esp):
    s = r['sessions'][0] if r['sessions'] else None
    if not s:
        return []
    dur = pkts[-1].t - pkts[0].t
    if s['version'] != 2:
        return [nd(k, lbl, 'IKEv1 Quick Mode rekeys are not parsed in the prototype',
                   'Read the lifetimes from the gateway configuration (status: provided)')
                for k, lbl in (('child_sa_lifetime', 'Child SA lifetime'), ('ike_sa_lifetime', 'IKE SA lifetime'))]
    out = []
    rk = sorted(r['rekeys'], key=lambda k: k['t'])
    child = [k['t'] for k in rk if k['type'] == 'child']
    ikes = [k['t'] for k in rk if k['type'] == 'ike']
    t_up = (min(fl[0].t for fl in esp.values()) - pkts[0].t) if esp else 0.0
    ev36 = [p.n for p in ike[s['ispi']] if p.exch == 36][:10]
    if not child:
        out.append(nd('child_sa_lifetime', 'Child SA lifetime (rekey interval)',
                      f'No child SA rekey seen in {dur:.0f} s of capture',
                      'Capture longer than the child SA lifetime, or trigger a rekey on a gateway you own',
                      'at least one full rekey (the rekey interval plus margin)'))
    else:
        ivs = [child[0] - t_up] + [b - a for a, b in zip(child, child[1:])]
        conf = min(0.9, 0.35 + 0.15 * len(ivs))      # heuristic: more intervals, more confidence
        out.append(item('child_sa_lifetime', 'Child SA lifetime (rekey interval)',
                        f'{statistics.median(ivs):.0f} s', ev36, 'inferred', round(conf, 2),
                        {'seconds': round(statistics.median(ivs), 1), 'intervals_s': [round(x, 1) for x in ivs],
                         'note': 'Soft lifetime (the moment the rekey starts). The hard lifetime is not visible.'}))
    if not ikes:
        out.append(nd('ike_sa_lifetime', 'IKE SA lifetime', f'No IKE SA rekey seen in {dur:.0f} s of capture',
                      'Capture longer than the IKE SA lifetime (often hours), or trigger an IKE rekey on a gateway you own',
                      'one full IKE SA lifetime'))
    else:
        out.append(item('ike_sa_lifetime', 'IKE SA lifetime', f'{ikes[0] - t_up:.0f} s', ev36, 'inferred', 0.5,
                        {'note': 'Measured from tunnel start to the first IKE rekey'}))
    return out

def build(path):
    pkts = read_pcap(path)
    ike, esp = build_flows(pkts)
    r = analyze(pkts)
    obs = observed_findings(path)
    items = list(obs['items'])
    items.append(infer_cipher(path))
    items += lifetime_items(pkts, r, ike, esp)
    items.append(nd('key_size', 'Cipher key size', 'Key length is not visible in ESP lengths (AES-128 and AES-256 look alike)',
                    'Read the key size from the gateway configuration (status: provided)'))
    items.append(mode_item(path))
    items.append(pfs_item(pkts))
    advisor = [{'item': i['key'], 'reason': i.get('reason'), 'advice': i.get('advice'), 'min_capture': i.get('min_capture')}
               for i in items if i['status'] == 'not_determinable' or i.get('low_confidence')]
    return {'items': items, 'advisor': advisor, 'sessions': obs['sessions'],
            'capture': {'packets': len(pkts), 'duration_s': round(pkts[-1].t - pkts[0].t, 1) if pkts else 0,
                        'esp_packets': sum(len(f) for f in esp.values())}}

if __name__ == '__main__':
    out = build(sys.argv[1])
    if len(sys.argv) > 2 and sys.argv[2] == '--short':
        for i in out['items']:
            print(f"{i['key']:18s} {i['status']:16s} {str(i['value'])[:34]:34s} conf={i['confidence']}")
        print('\nadvisor:')
        for a in out['advisor']:
            print(' -', a['item'], '|', a['reason'], '|', a['advice'])
    else:
        print(json.dumps(out, indent=1, default=str))
