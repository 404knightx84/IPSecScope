#!/usr/bin/env python3
"""S5.4/5.5: tunnel vs transport from the minimum-length anchor, with abstention.
Usage: mode_pfs.py features [all] | eval        (default: repeats 1-2 only; repeats 3-4 stay untouched)"""
import sys, os, json, collections
import numpy as np, pandas as pd
from sklearn.model_selection import GroupKFold
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import traffic as T

TCP_LIKE = {'web', 'video', 'email'}
SHARE = 0.02                      # anchor = smallest length carrying at least 2% of the packets
RUNS = os.path.join(T.FEATS, 'mode_runs.csv')

def run_features(path):
    rows = T.esp_rows(path)
    if not rows:
        return None
    c = collections.Counter(r[3] for r in rows)
    n = sum(c.values())
    odd = sum(k for l, k in c.items() if (l - 40) % 16)
    return {'n_pkts': n, 'distinct': len(c), 'anchor': min(l for l, k in c.items() if k >= SHARE * n),
            'non16_share': odd / n, 'all_mod4': all(l % 4 == 0 for l in c)}

def family(r):
    """Stand-in for the S5.2 length rules. None means ambiguous, so the mode step abstains."""
    if r.non16_share > 0.01:
        return 'GCM' if r.all_mod4 else None
    if r.non16_share == 0 and r.distinct >= 4:
        return 'CBC'
    return None

def cmd_features(include_all=False):
    out = []
    for lab in T.base_labels():
        if not include_all and int(lab['repeat']) > 2:
            continue
        pc = os.path.join(T.PCAPS, lab['run_id'] + '.pcap')
        if not os.path.exists(pc):
            continue
        f = run_features(pc)
        if f:
            out.append({'run_id': lab['run_id'], 'config': lab['config'], 'mode': lab['mode'],
                        'cipher': lab['cipher'], 'traffic': lab['traffic_type'], 'repeat': int(lab['repeat']), **f})
    df = pd.DataFrame(out)
    df.to_csv(RUNS, index=False)
    print('saved', RUNS, len(df), 'runs')

def pred_traffic(runs):
    """Predicted traffic per run from out-of-fold S7 predictions (the mode step must not see the true type)."""
    df = T.load_windows()
    df = df[df.run_id.isin(runs)]
    out = {}
    for a, b in GroupKFold(n_splits=5).split(df, df.traffic, df.run_id):
        m = T.rf(150).fit(df.iloc[a][T.FEATURES], df.iloc[a].traffic)
        te = df.iloc[b]
        pr = pd.DataFrame(m.predict_proba(te[T.FEATURES]), columns=m.classes_)
        pr['run_id'] = te.run_id.values
        out.update(pr.groupby('run_id')[list(m.classes_)].mean().idxmax(axis=1).to_dict())
    return out

def learn(tr):
    t = {}
    for (fam, mode), g in tr.groupby(['fam', 'mode']):
        t.setdefault(fam, {})[mode] = int(g.anchor.median())
    return t

def decide(r, table):
    if r.pred_traffic not in TCP_LIKE:
        return None, f'no TCP anchor (traffic {r.pred_traffic})'
    if r.fam is None or (isinstance(r.fam, float) and np.isnan(r.fam)):
        return None, 'cipher family ambiguous'
    exp = table.get(r.fam, {})
    if len(exp) < 2 or len(set(exp.values())) < 2:
        return None, 'no reference anchors for this family'
    for mode, a in exp.items():
        if r.anchor == a:
            return mode, 'ok'
    return None, 'anchor matches neither mode'

def cmd_eval():
    df = pd.read_csv(RUNS)
    df['fam'] = [family(r) for r in df.itertuples()]
    df['true_fam'] = np.where(df.cipher.str.contains('gcm'), 'GCM', 'CBC')
    pt = pred_traffic(set(df.run_id))
    df['pred_traffic'] = df.run_id.map(pt)
    res = []
    for cfg in sorted(df.config.unique()):                      # leave-one-config-out
        tr = df[(df.config != cfg) & df.traffic.isin(TCP_LIKE) & df.fam.notna()]
        table = learn(tr)
        for r in df[df.config == cfg].itertuples():
            pred, why = decide(r, table)
            res.append({'run_id': r.run_id, 'config': cfg, 'truth': r.mode, 'pred': pred, 'why': why,
                        'traffic': r.traffic, 'pred_traffic': r.pred_traffic, 'true_fam': r.true_fam,
                        'fam_hat': r.fam, 'anchor': r.anchor})
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
           'by_cipher_family': {k: summ(g) for k, g in R.groupby('true_fam')},
           'by_true_traffic': {k: summ(g) for k, g in R.groupby('traffic')},
           'abstain_reasons': R[~R.answered].why.value_counts().to_dict(),
           'family_stand_in_errors': int(((R.fam_hat != R.true_fam) & R.fam_hat.notna()).sum())}
    os.makedirs(T.REPORTS, exist_ok=True)
    R.to_csv(os.path.join(T.REPORTS, 's5_mode_runs.csv'), index=False)
    json.dump(out, open(os.path.join(T.REPORTS, 's5_mode_eval.json'), 'w'), indent=1)
    print(json.dumps(out, indent=1))
    print('\nconfident-wrong runs:', R[R.answered & ~R.correct][['run_id', 'truth', 'pred', 'pred_traffic']].to_dict('records'))


# ---- S5.4/5.5 runtime: mode item for the pipeline (family from esp.infer_cipher, traffic from S7) ----
RULE_MODE = os.path.join(T.MODELS, 'mode_rule.json')

def _fam_key(v):
    return 'GCM' if v and 'GCM' in v else ('CBC' if v and 'CBC' in v else None)

def cmd_fit_rule():
    from esp import infer_cipher
    df = pd.read_csv(RUNS)
    fams = {}
    for r in df.itertuples():
        if r.traffic not in TCP_LIKE:
            continue
        fams.setdefault(r.run_id, _fam_key(infer_cipher(os.path.join(T.PCAPS, r.run_id + '.pcap')).get('value')))
    df['fam'] = df.run_id.map(fams)
    table = learn(df[df.traffic.isin(TCP_LIKE) & df.fam.notna()])
    json.dump(table, open(RULE_MODE, 'w'), indent=1)
    print('saved', RULE_MODE, table)

def mode_item(path):
    from observed import item
    from esp import infer_cipher
    def nd(reason, advice):
        return item('tunnel_mode', 'Tunnel vs transport mode', None, [], 'not_determinable', 0.0,
                    {'reason': reason, 'advice': advice})
    if not os.path.exists(RULE_MODE):
        return nd('Mode rule has not been fitted yet', 'Run: python3 backend/app/mode_pfs.py fitrule')
    table = json.load(open(RULE_MODE))
    f = run_features(path)
    if not f:
        return nd('No ESP packets in this capture', 'Capture while traffic is flowing through the tunnel')
    fam = _fam_key(infer_cipher(path).get('value'))
    if fam is None:
        return nd('Cipher family is ambiguous, so the expected anchor is unknown', 'Capture traffic with varied packet sizes')
    b = __import__('joblib').load(T.MODEL if os.path.exists(T.MODEL) else T.SMOKE)
    w = T.window_features(T.esp_rows(path))
    if w.empty:
        return nd('Too few ESP packets to tell the traffic type', 'Capture for at least 15 seconds')
    pr = b['model'].predict_proba(w[b['features']].fillna(-1)).mean(axis=0)
    top = b['model'].classes_[int(pr.argmax())]
    if top not in TCP_LIKE:
        return nd(f'Traffic looks like {top}: no bare TCP ACK to anchor the length shift',
                  'Capture a window with TCP traffic (web or email)')
    exp = table.get(fam, {})
    for mode, a in exp.items():
        if f['anchor'] == a:
            return item('tunnel_mode', 'Tunnel vs transport mode', mode, [], 'inferred', round(min(0.85, float(pr.max())), 2),
                        {'anchor_len': f['anchor'], 'family': fam, 'predicted_traffic': top,
                         'note': 'Anchor lengths were learned from strongSwan in the lab; other gateways may differ.'})
    return nd(f"Smallest common ESP length ({f['anchor']}) matches neither mode for {fam}",
              'The gateway may use a different ICV or padding than the lab')

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'features': cmd_features(len(sys.argv) > 2 and sys.argv[2] == 'all')
    elif cmd == 'eval': cmd_eval()
    elif cmd == 'fitrule': cmd_fit_rule()
    else: print(__doc__)
