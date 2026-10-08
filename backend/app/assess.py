#!/usr/bin/env python3
"""S6: rule engine, security score range, risk level with severity floor, threat matrix.
Usage: assess.py <pcap> [--json]    (runs the S4/S5 pipeline, then the rules)"""
import os, re, sys, json
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
RULES_PATH = os.path.join(HERE, '..', 'rules', 'rules.yaml')
SEV = ['none', 'informational', 'low', 'medium', 'high', 'critical']
LEVELS = ['Low', 'Medium', 'High', 'Critical']
LMH = {1: 'Low', 2: 'Medium', 3: 'High'}

def load_rules(path=RULES_PATH):
    with open(path) as f:
        return yaml.safe_load(f)

def check(when, item):
    v = item.get(when.get('field') or 'value')
    if v is None:
        return False
    op, t = when['op'], when.get('value')
    if op == 'eq': return v == t
    if op == 'neq': return v != t
    if op == 'in': return v in t
    if op == 'regex': return re.search(t, str(v)) is not None
    if op == 'any_regex': return any(re.search(t, str(x)) for x in (v if isinstance(v, list) else [v]))
    if op == 'gt': return float(v) > float(t)
    if op == 'lt': return float(v) < float(t)
    raise ValueError(f'unknown op {op}')

def band(score, cfg):
    for b in cfg['risk_bands']:
        if score >= b['min']:
            return b['level']
    return 'Critical'

def worse(a, b):
    return a if LEVELS.index(a) >= LEVELS.index(b) else b

def floor_level(sevs, cfg):
    lvl = 'Low'
    for s in sevs:
        f = cfg['floor'].get(s)
        if f:
            lvl = worse(lvl, f)
    return lvl

def _finding(r, it, status, conf, sev, impact, worst, worst_only=False):
    return {'rule_id': r['id'], 'name': r['name'], 'severity': sev, 'status': status,
            'confidence': round(conf, 3), 'evidence': (it or {}).get('evidence', []),
            'fix': r['fix'], 'reference': r['reference'], 'threat': r.get('threat'),
            'score_impact': round(impact, 2), 'worst_case_impact': round(worst, 2),
            'worst_case_only': worst_only}

def assess(items, cfg=None):
    cfg = cfg or load_rules()
    W = cfg['severity_weights']
    by_key = {i['key']: i for i in items}
    slots, findings = {}, []
    fired, worst_sevs = [], []
    found_t, possible_t = set(), set()
    for r in cfg['rules']:
        key, sev = r.get('item'), r['severity']
        wsev = r.get('worst_case_severity', 'none')
        if key is None:                                   # always-on informational rule (replay)
            findings.append(_finding(r, None, 'not_evidenced_passive', 1.0, sev, 0.0, 0.0))
            found_t.add(r['threat'])
            continue
        it = by_key.get(key)
        if it is None:                                    # item not present: rule does not apply
            continue
        status, conf = it['status'], float(it.get('confidence') or 0.0)
        if r.get('conf_field'):                           # rule-specific confidence (e.g. 3DES share)
            conf = float(it.get(r['conf_field']) or 0.0)
        nd, lowc = status == 'not_determinable', bool(it.get('low_confidence'))
        s = slots.setdefault(key, {'nominal': 0.0, 'full': 0.0, 'worst': 0.0, 'uncertain': False})
        s['uncertain'] = s['uncertain'] or nd or lowc
        if not nd and not lowc and check(r['when'], it):
            s['nominal'] = max(s['nominal'], W[sev] * conf)   # one item, one deduction: keep the worst rule
            s['full'] = max(s['full'], W[sev])
            fired.append(sev)
            findings.append(_finding(r, it, status, conf, sev, W[sev] * conf, W[sev]))
            found_t.add(r['threat'])
        elif (nd or lowc) and W[wsev] > 0:
            s['worst'] = max(s['worst'], W[wsev])
            worst_sevs.append(wsev)
            findings.append(_finding(r, it, 'not_determinable', 0.0, wsev, 0.0, W[wsev], True))
            possible_t.add(r['threat'])
    best = sum(s['nominal'] for s in slots.values())
    worst = sum(max(s['full'], s['worst']) if s['uncertain'] else s['nominal'] for s in slots.values())
    score_max, score_min = max(0.0, 100 - best), max(0.0, 100 - worst)
    risk_worst = worse(band(score_min, cfg), floor_level(fired + worst_sevs, cfg))
    risk_best = worse(band(score_max, cfg), floor_level(fired, cfg))
    cells = {}
    for tid in sorted(found_t | possible_t):
        t = cfg['threats'][tid]
        cells.setdefault(f"{t['likelihood']}-{t['impact']}", []).append(
            {'id': tid, 'name': t['name'], 'basis': 'found' if tid in found_t else 'possible'})
    findings.sort(key=lambda f: -SEV.index(f['severity']))
    return {'score': {'score_min': round(score_min), 'score_max': round(score_max),
                      'risk_level': risk_worst, 'risk_level_best_case': risk_best,
                      'floor': floor_level(fired + worst_sevs, cfg) if floor_level(fired + worst_sevs, cfg) != 'Low' else None},
            'findings': findings,
            'threat_matrix': {'likelihood_axis': LMH, 'impact_axis': LMH, 'cells': cells}}

if __name__ == '__main__':
    from inferred import build
    res = assess(build(sys.argv[1])['items'])
    if '--json' in sys.argv:
        print(json.dumps(res, indent=1))
    else:
        sc = res['score']
        print(f"score {sc['score_min']} to {sc['score_max']}   risk {sc['risk_level']} (best case {sc['risk_level_best_case']})   floor {sc['floor']}")
        for f in res['findings']:
            print(f"  {f['rule_id']} {f['severity']:13s} {f['status']:22s} conf={f['confidence']:<5} impact={f['score_impact']:<5} worst={f['worst_case_impact']:<5} {f['name']}")
        print('threat matrix (likelihood-impact):', {k: [t['id'] + ('?' if t['basis'] == 'possible' else '') for t in v]
                                                     for k, v in res['threat_matrix']['cells'].items()})
