#!/usr/bin/env python3
"""S5.7: PFS from the size of child-rekey requests relative to the IKE_AUTH request of the same IKE SA.
IKE SA rekeys are excluded (type comes from SPIs in ike.analyze). Usage: pfs.py fit | eval [all]"""
import sys, os, json, statistics
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ingest import read_pcap, build_flows
from ike import analyze
from observed import item

ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
RULE = os.path.join(ROOT, 'backend', 'models', 'pfs_rule.json')
REPORTS = os.path.join(ROOT, 'data', 'reports')

def nd(reason, advice, min_capture=None):
    d = {'reason': reason, 'advice': advice}
    if min_capture:
        d['min_capture'] = min_capture
    return item('pfs', 'Perfect forward secrecy', None, [], 'not_determinable', 0.0, d)

def rekey_features(pkts):
    """Returns (features, None) or (None, nd item)."""
    if not pkts:
        return None, nd('No packets', 'Capture the IKE exchange')
    r = analyze(pkts)
    ike, _ = build_flows(pkts)
    s = next((x for x in r['sessions'] if x['version'] == 2), None)
    if not s:
        return None, nd('No IKEv2 session in this capture', 'PFS is only inferred for IKEv2 in the prototype')
    child = [k for k in r['rekeys'] if k['type'] == 'child']
    dur = pkts[-1].t - pkts[0].t
    if not child:
        return None, nd(f'No child SA rekey seen in {dur:.0f} s of capture',
                        'Capture longer than the child SA lifetime, or trigger a rekey on a gateway you own',
                        'at least one child SA rekey')
    v = ike[s['ispi']]
    auth = next((p.ike_len for p in v if p.exch == 35 and not p.flags & 0x20), None)
    if auth is None:
        return None, nd('The IKE_AUTH request is not in the capture, so there is no size baseline',
                        'Capture from the start of the tunnel, or wait for the next full handshake',
                        'the IKE_AUTH exchange')
    req = statistics.median(k['req_bytes'] for k in child)
    ev = [p.n for p in v if p.exch == 36 and not p.flags & 0x20][:10]
    return {'rel': req - auth, 'req': req, 'auth': auth, 'n_child': len(child), 'evidence': ev}, None

def decide(rel, rule):
    margin = (rule['on_min'] - rule['off_max']) / 4          # the middle band abstains
    if rel <= rule['off_max'] + margin:
        return 'off'
    if rel >= rule['on_min'] - margin:
        return 'on'
    return None

def fit_rule(rows):
    off = [r['rel'] for r in rows if not r['pfs']]
    on = [r['rel'] for r in rows if r['pfs']]
    return {'off_max': max(off), 'on_min': min(on), 'n_off': len(off), 'n_on': len(on)}

def pfs_item(pkts, rule=None):
    if rule is None:
        if not os.path.exists(RULE):
            return nd('PFS rule has not been fitted yet', 'Run: python3 backend/app/pfs.py fit')
        rule = json.load(open(RULE))
    f, miss = rekey_features(pkts)
    if miss:
        return miss
    v = decide(f['rel'], rule)
    if v is None:
        return nd(f"Rekey size ({f['rel']:+.0f} B vs IKE_AUTH) falls between the PFS-off and PFS-on groups seen in the lab",
                  'The DH group may differ from the lab (14); capture a rekey from a known configuration')
    conf = min(0.8, 0.5 + 0.1 * f['n_child'])     # heuristic, capped: moderate confidence by design
    return item('pfs', 'Perfect forward secrecy', v, f['evidence'], 'inferred', round(conf, 2),
                {'rekey_request_minus_ike_auth': f['rel'], 'child_rekeys_seen': f['n_child'],
                 'note': 'Moderate confidence: a key-exchange payload in the child rekey shows as extra bytes. '
                         'Rule learned on DH group 14 in the lab.'})

def collect(include_all=False):
    import traffic as T
    rows = []
    for lab in T.base_labels():
        if not include_all and int(lab['repeat']) > 2:
            continue
        pc = os.path.join(T.PCAPS, lab['run_id'] + '.pcap')
        if not os.path.exists(pc):
            continue
        f, miss = rekey_features(read_pcap(pc))
        rows.append({'run_id': lab['run_id'], 'config': lab['config'], 'mode': lab['mode'], 'cipher': lab['cipher'],
                     'pfs': bool(lab['pfs']), **(f or {'rel': None, 'n_child': 0})})
    return rows

def cmd_fit(include_all=False):
    rows = [r for r in collect(include_all) if r['rel'] is not None]
    rule = fit_rule(rows)
    os.makedirs(os.path.dirname(RULE), exist_ok=True)
    json.dump(rule, open(RULE, 'w'), indent=1)
    print('saved', RULE, rule)

def cmd_eval(include_all=False):
    import pandas as pd
    df = pd.DataFrame(collect(include_all))
    res = []
    for cfg in sorted(df.config.unique()):                               # leave-one-config-out
        tr = df[(df.config != cfg) & df.rel.notna()].to_dict('records')
        rule = fit_rule(tr)
        for r in df[df.config == cfg].itertuples():
            p = None if pd.isna(r.rel) else decide(r.rel, rule)
            res.append({'run_id': r.run_id, 'config': cfg, 'mode': r.mode, 'truth': 'on' if r.pfs else 'off',
                        'pred': p, 'rel': r.rel})
    R = pd.DataFrame(res)
    R['answered'] = R.pred.notna()
    R['correct'] = R.pred == R.truth
    def summ(g):
        a = int(g.answered.sum())
        return {'n': len(g), 'answered': a, 'coverage': round(a / len(g), 3),
                'acc_on_answered': round(float(g[g.answered].correct.mean()), 3) if a else None,
                'wrong': int((g.answered & ~g.correct).sum())}
    out = {'overall': summ(R), 'baseline_note': 'two balanced classes: majority baseline is 0.5',
           'by_config': {k: summ(g) for k, g in R.groupby('config')},
           'by_mode': {k: summ(g) for k, g in R.groupby('mode')},
           'rel_range_off': [float(R[R.truth == 'off'].rel.min()), float(R[R.truth == 'off'].rel.max())],
           'rel_range_on': [float(R[R.truth == 'on'].rel.min()), float(R[R.truth == 'on'].rel.max())]}
    os.makedirs(REPORTS, exist_ok=True)
    R.to_csv(os.path.join(REPORTS, 's5_pfs_runs.csv'), index=False)
    json.dump(out, open(os.path.join(REPORTS, 's5_pfs_eval.json'), 'w'), indent=1)
    print(json.dumps(out, indent=1))
    print('\nconfident-wrong runs:', R[R.answered & ~R.correct][['run_id', 'truth', 'pred']].to_dict('records'))

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    inc = len(sys.argv) > 2 and sys.argv[2] == 'all'
    if cmd == 'fit': cmd_fit(inc)
    elif cmd == 'eval': cmd_eval(inc)
    else: print(__doc__)
