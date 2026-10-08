#!/usr/bin/env python3
"""S4.7: observed findings from the IKE analysis, each with status, confidence and evidence packet numbers."""
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest import read_pcap, build_flows
from ike import analyze, fmt, DH

def item(key, label, value, evidence, status='observed', conf=1.0, extra=None):
    d = {'key': key, 'label': label, 'value': value, 'status': status,
         'confidence': conf, 'evidence': evidence[:10]}
    if extra:
        d.update(extra)
    return d

def observed_findings(path):
    pkts = read_pcap(path)
    r = analyze(pkts)
    ike, esp = build_flows(pkts)
    items = []
    if not r['sessions']:
        items.append(item('ike_version', 'IKE version', None, [], 'not_determinable', 0.0,
                          {'reason': 'No IKE handshake in this capture',
                           'advice': 'Capture from the start of the tunnel, or trigger a rekey on a gateway you own'}))
        return {'items': items, 'sessions': 0}
    s = r['sessions'][0]
    pk = ike[s['ispi']]
    ver = s['version']
    ev36 = [p.n for p in pk if p.exch == 36]
    ev36 = [p.n for p in pk if p.exch == 36]
    items.append(item('ike_version', 'IKE version', f'IKEv{ver}', [p.n for p in pk[:3]]))
    if ver == 2:
        sel = s.get('selected') or {}
        ev = [p.n for p in pk if p.exch == 34][:2]
        items.append(item('ike_encryption', 'IKE SA encryption', ' '.join(sel.get('enc', [])) or None, ev))
        items.append(item('ike_integrity', 'IKE SA integrity', ' '.join(sel.get('integ', [])) or None, ev))
        items.append(item('ike_prf', 'IKE SA PRF', ' '.join(sel.get('prf', [])) or None, ev))
        items.append(item('dh_group', 'Diffie-Hellman group', DH.get(s.get('dh_group'), s.get('dh_group')), ev))
        items.append(item('ike_offered', 'IKE proposals offered', [fmt(x) for x in (s.get('offered') or [])], ev))
    else:
        items.append(item('ike_mode', 'IKEv1 exchange mode',
                          'Aggressive Mode' if r['aggressive'] else ('Main Mode' if r['main_mode'] else 'unknown'),
                          [p.n for p in pk if p.exch in (2, 4)][:3],
                          extra={'note': 'Aggressive Mode exposes the peer identity and a hash in cleartext' if r['aggressive'] else ''}))
        for k, lbl in (('ike_encryption', 'IKE SA encryption'), ('dh_group', 'Diffie-Hellman group')):
            items.append(item(k, lbl, None, [], 'not_determinable', 0.0,
                              {'reason': 'IKEv1 payloads are not parsed in the prototype',
                               'advice': 'Read the algorithms from the gateway configuration (status: provided)'}))
    if ver == 2:
        items.append(item('child_rekeys', 'Child SA rekeys seen', len([k for k in r['rekeys'] if k['type'] == 'child']),
                          ev36, extra={'rekeys': r['rekeys']}))
        items.append(item('ike_rekeys', 'IKE SA rekeys seen', len([k for k in r['rekeys'] if k['type'] == 'ike']), []))
    else:
        for k, lbl in (('child_rekeys', 'Child SA rekeys seen'), ('ike_rekeys', 'IKE SA rekeys seen')):
            items.append(item(k, lbl, None, [], 'not_determinable', 0.0,
                              {'reason': 'IKEv1 Quick Mode exchanges are not parsed in the prototype',
                               'advice': 'Read the rekey and lifetime settings from the gateway configuration (status: provided)'}))
    items.append(item('ike_sessions', 'IKE SAs in capture', len(r['sessions']), []))
    return {'items': items, 'sessions': len(r['sessions'])}

if __name__ == '__main__':
    print(json.dumps(observed_findings(sys.argv[1]), indent=1))
