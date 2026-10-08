#!/usr/bin/env python3
"""S7: ESP windows -> shift-tolerant features -> Random Forest traffic classifier (ping, web, voip, video, email).
Usage: traffic.py splits | features | train | predict <pcap>"""
import sys, os, json, glob, itertools
import numpy as np, pandas as pd, joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
from sklearn.model_selection import GroupKFold
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ingest import read_pcap, build_flows

ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
DATA = os.path.join(ROOT, 'data')
PCAPS, LABELS = os.path.join(DATA, 'pcaps'), os.path.join(DATA, 'labels')
FEATS, REPORTS = os.path.join(DATA, 'features'), os.path.join(DATA, 'reports')
SPLITS = os.path.join(DATA, 'splits.csv')
MODELS = os.path.join(ROOT, 'backend', 'models')
MODEL, SMOKE = os.path.join(MODELS, 'traffic_rf.joblib'), os.path.join(MODELS, 'traffic_rf_smoke.joblib')
WIN = 5.0
META = ['run_id', 'config', 'mode', 'cipher', 'traffic', 'repeat', 'split', 'window']
# Mode-safe features only: magnitude features (r_*, b_*) leaked the tunnel/transport size shift (see S7 notes).
FEATURES = ['n_pkts', 'pps', 'gap_mean', 'gap_cv', 'gap_med', 'gap_p90', 'gap_max', 'n_bursts', 'burst_mean',
            'burst_max', 'd1_pkt_share', 'd1_byte_share', 'small_share', 'large_share', 'distinct_ratio']

def esp_rows(path):
    pkts = read_pcap(path)
    ike, esp = build_flows(pkts)
    rows = [(p.t, p.src, p.dst, p.L) for fl in esp.values() for p in fl if p.L and p.L > 0]
    rows.sort()
    return rows

def window_features(rows):
    """7.1/7.2: one row per full 5 s window of ESP packets. Sizes are ratios to the capture's minimum length (the anchor),
    so the ~20 byte tunnel shift largely cancels. Direction is 'dominant by bytes', not an IP address."""
    if len(rows) < 10:
        return pd.DataFrame()
    t = np.array([r[0] for r in rows]); L = np.array([r[3] for r in rows], dtype=float)
    pair = np.array([f'{r[1]}>{r[2]}' for r in rows])
    t0, Lmin, Lmax = t[0], L.min(), L.max()
    tot = {p: L[pair == p].sum() for p in set(pair)}
    d1 = pair == max(tot, key=tot.get)
    idx = ((t - t0) // WIN).astype(int)
    out = []
    for w in range(int((t[-1] - t0) // WIN)):             # the final partial window is dropped
        m = idx == w
        n = int(m.sum())
        if n < 3:
            continue
        tw, Lw, dw = t[m], L[m], d1[m]
        r, gaps, dl = Lw / Lmin, np.diff(tw), Lw - Lmin
        gm = float(gaps.mean())
        seg = np.diff(np.r_[0, np.where(gaps > 0.05)[0] + 1, n])      # bursts are split by gaps over 50 ms
        out.append({'window': w, 'n_pkts': n, 'pps': n / WIN,
                    'r_mean': r.mean(), 'r_std': r.std(), 'r_cv': r.std() / r.mean(),
                    'r_p50': np.percentile(r, 50), 'r_p90': np.percentile(r, 90), 'r_max': r.max(),
                    'small_share': float((Lw <= 1.25 * Lmin).mean()), 'large_share': float((Lw >= 0.9 * Lmax).mean()),
                    'distinct_ratio': len(np.unique(Lw)) / n,
                    'gap_mean': gm, 'gap_cv': float(gaps.std() / gm) if gm > 0 else 0.0,
                    'gap_med': float(np.median(gaps)), 'gap_p90': float(np.percentile(gaps, 90)), 'gap_max': float(gaps.max()),
                    'n_bursts': len(seg), 'burst_mean': n / len(seg), 'burst_max': int(seg.max()),
                    'd1_pkt_share': float(dw.mean()), 'd1_byte_share': float(Lw[dw].sum() / Lw.sum()),
                    'r_mean_d1': float(r[dw].mean()) if dw.any() else -1.0,
                    'r_mean_d2': float(r[~dw].mean()) if (~dw).any() else -1.0,
                    'b_mean': float(dl.mean()), 'b_std': float(dl.std()), 'b_p50': float(np.percentile(dl, 50)),
                    'b_p90': float(np.percentile(dl, 90)), 'b_max': float(dl.max()),
                    'b_mean_d1': float(dl[dw].mean()) if dw.any() else -1.0,
                    'b_mean_d2': float(dl[~dw].mean()) if (~dw).any() else -1.0})
    return pd.DataFrame(out)

def base_labels():
    for lp in sorted(glob.glob(os.path.join(LABELS, '*.json'))):
        lab = json.load(open(lp))
        if lab.get('block') == 'base':
            yield lab

def cmd_splits():
    """By run, never by window: repeats 1-2 train, 3 validation, 4 test. W1/W2 are outside every split."""
    rows = [{'run_id': l['run_id'], 'config': l['config'], 'traffic': l['traffic_type'], 'repeat': int(l['repeat']),
             'mode': l['mode'], 'cipher': l['cipher'],
             'split': 'train' if int(l['repeat']) in (1, 2) else ('val' if int(l['repeat']) == 3 else 'test')}
            for l in base_labels()]
    df = pd.DataFrame(rows)
    df.to_csv(SPLITS, index=False)
    print(f'splits.csv: {len(df)} base runs', dict(df.split.value_counts()))
    return df

def save_table(df, stem):
    try:
        df.to_parquet(stem + '.parquet', index=False)
        return stem + '.parquet'
    except Exception:
        df.to_csv(stem + '.csv', index=False)
        return stem + '.csv'

def load_windows():
    stem = os.path.join(FEATS, 'windows')
    return pd.read_parquet(stem + '.parquet') if os.path.exists(stem + '.parquet') else pd.read_csv(stem + '.csv')

def cmd_features():
    sp = cmd_splits()
    parts = []
    for i, row in enumerate(sp.itertuples(), 1):
        cache = os.path.join(FEATS, 'windows', row.run_id + '.csv')
        pc = os.path.join(PCAPS, row.run_id + '.pcap')
        if not (os.path.exists(cache) and os.path.getmtime(cache) > os.path.getmtime(pc)):
            window_features(esp_rows(pc)).to_csv(cache, index=False)
        f = pd.read_csv(cache)
        for c in ('run_id', 'config', 'mode', 'cipher', 'traffic', 'repeat', 'split'):
            f[c] = getattr(row, c)
        parts.append(f)
        if i % 10 == 0:
            print(f'  {i}/{len(sp)} runs', flush=True)
    df = pd.concat(parts, ignore_index=True).fillna(-1)
    print('windows saved to', save_table(df, os.path.join(FEATS, 'windows')))
    print(df.groupby(['split', 'traffic']).size().unstack(fill_value=0))

def metrics(y, p, labels):
    return {'n': int(len(y)), 'accuracy': round(float(accuracy_score(y, p)), 4),
            'macro_f1': round(float(f1_score(y, p, labels=labels, average='macro', zero_division=0)), 4),
            'confusion': {'labels': labels, 'matrix': confusion_matrix(y, p, labels=labels).tolist()}}

def evaluate(model, df, feats):
    """7.6: accuracy, macro F1 and confusion matrix overall, per mode and per cipher family, at window and run level."""
    cls = list(model.classes_)
    proba = model.predict_proba(df[feats])
    pred = np.array(cls)[proba.argmax(1)]
    y = df.traffic.values
    res = {'windows': metrics(y, pred, cls)}
    for m in sorted(df['mode'].unique()):
        k = (df['mode'] == m).values
        res[f'windows_{m}'] = metrics(y[k], pred[k], cls)
    fam = np.where(df.cipher.str.contains('gcm'), 'AEAD', 'CBC')
    for f in ('CBC', 'AEAD'):
        k = fam == f
        if k.any():
            res[f'windows_{f}'] = metrics(y[k], pred[k], cls)
    pr = pd.DataFrame(proba, columns=cls)
    pr['run_id'] = df.run_id.values
    g = pr.groupby('run_id')[cls].mean()
    truth = df.groupby('run_id').traffic.first().reindex(g.index)
    mode = df.groupby('run_id')['mode'].first().reindex(g.index)
    rp = g.idxmax(axis=1)
    res['runs'] = metrics(truth.values, rp.values, cls)
    for m in sorted(mode.unique()):
        k = (mode == m).values
        res[f'runs_{m}'] = metrics(truth.values[k], rp.values[k], cls)
    res['wrong_runs'] = [{'run_id': r, 'truth': truth[r], 'pred': rp[r], 'p_pred': round(float(g.loc[r].max()), 3)}
                         for r in g.index if truth[r] != rp[r]]
    return res

def rf(n=300, **kw):
    return RandomForestClassifier(n_estimators=n, class_weight='balanced', n_jobs=1, random_state=42, **kw)

def cmd_train():
    df = load_windows()
    feats = FEATURES
    tr, va, te = (df.split == s for s in ('train', 'val', 'test'))
    os.makedirs(MODELS, exist_ok=True)
    os.makedirs(REPORTS, exist_ok=True)
    if va.sum() == 0 or te.sum() == 0:
        print('SMOKE ONLY: repeats 3 and 4 are not finished yet. Group CV by run on what exists. Not reportable.')
        cv = GroupKFold(n_splits=min(5, df.run_id.nunique()))
        parts = []
        for a, b in cv.split(df, df.traffic, df.run_id):
            m = rf(150).fit(df.iloc[a][feats], df.iloc[a].traffic)
            parts.append(evaluate(m, df.iloc[b], feats)['runs'])
        acc = np.mean([p['accuracy'] for p in parts])
        print(f'smoke run-level accuracy over {len(parts)} folds: {acc:.3f}  ({df.run_id.nunique()} runs, {len(df)} windows)')
        joblib.dump({'model': rf().fit(df[feats], df.traffic), 'features': feats, 'smoke': True}, SMOKE)
        print('saved', SMOKE)
        return
    best = None
    for depth, leaf, mf in itertools.product([None, 12, 20], [1, 3, 5], ['sqrt', 0.5]):
        p = rf(200, max_depth=depth, min_samples_leaf=leaf, max_features=mf).fit(df[tr][feats], df[tr].traffic).predict(df[va][feats])
        sc = (f1_score(df[va].traffic, p, average='macro'), accuracy_score(df[va].traffic, p))
        if best is None or sc > best[0]:
            best = (sc, dict(max_depth=depth, min_samples_leaf=leaf, max_features=mf))
    print('best on validation (repeat 3): macro F1 %.3f acc %.3f' % best[0], best[1])
    final = rf(300, **best[1]).fit(df[tr | va][feats], df[tr | va].traffic)          # refit on train + validation
    res = evaluate(final, df[te], feats)                                               # test once (repeat 4)
    res['params'] = best[1]
    res['validation'] = {'macro_f1': round(best[0][0], 4), 'accuracy': round(best[0][1], 4)}
    json.dump(res, open(os.path.join(REPORTS, 's7_traffic_eval.json'), 'w'), indent=1)
    joblib.dump({'model': final, 'features': feats, 'smoke': False, 'params': best[1]}, MODEL)
    for k in [k for k in res if k.startswith(('windows', 'runs'))]:
        print(f"{k:16s} n={res[k]['n']:<5} acc={res[k]['accuracy']:<6} macroF1={res[k]['macro_f1']}")
    print('wrong runs:', res['wrong_runs'])
    print('saved', MODEL, 'and', os.path.join(REPORTS, 's7_traffic_eval.json'))

def predict_traffic(path):
    """7.7: class probabilities for one capture, shaped as an item for the S8 pipeline."""
    b = joblib.load(MODEL if os.path.exists(MODEL) else SMOKE)
    df = window_features(esp_rows(path))
    item = {'key': 'traffic_type', 'label': 'Traffic type'}
    if df.empty:
        item.update(status='not_determinable', value=None, confidence=0.0, evidence=[],
                    reason='Too few ESP packets to form a 5 s window', advice='Capture while traffic is flowing for at least 15 seconds')
        return item
    pr = b['model'].predict_proba(df[b['features']].fillna(-1)).mean(axis=0)
    probs = {c: round(float(p), 3) for c, p in zip(b['model'].classes_, pr)}
    top = max(probs, key=probs.get)
    low = len(df) < 3 or probs[top] < 0.5 or b.get('smoke', False)
    item.update(status='inferred', value=top, confidence=probs[top], probabilities=probs, windows=len(df),
                low_confidence=low, evidence=[], smoke_model=b.get('smoke', False))
    if low:
        item['reason'] = 'Few windows, a weak top class' + (' or a smoke-test model' if b.get('smoke') else '')
        item['advice'] = 'Capture longer so more 5 s windows are available'
    return item

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'splits': cmd_splits()
    elif cmd == 'features': cmd_features()
    elif cmd == 'train': cmd_train()
    elif cmd == 'predict': print(json.dumps(predict_traffic(sys.argv[2]), indent=1))
    else: print(__doc__)
