#!/usr/bin/env python3
"""S5.1-S5.3: per-SPI ESP features and Bayesian cipher-family inference (rules, nothing trained).
Usage: esp.py table <pcap> | infer <pcap> | eval [glob]"""
import sys, os, math, json, csv, glob, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ingest import read_pcap, build_flows
from ike import analyze

ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
PCAPS, LABELS, OUT = (os.path.join(ROOT, 'data', d) for d in ('pcaps', 'labels', 'reports'))

# L = ESP length (IP total length - outer IP header - 8 if UDP-encapsulated), as defined in gate G1.
# ESP = SPI(4) + seq(4) + IV + padded payload + ICV, so each suite gives a residue rule on L:
#   AES-CBC (IV 16, pad 16): L = 16n + 24 + ICV  -> SHA1-96: L%16=4, SHA256-128: 8, SHA384-192: 0, SHA512-256: 8
#   3DES-CBC (IV 8, pad 8):  L = 8n + 16 + ICV   -> SHA1-96: L%8=4, SHA256-128: 0
#   AES-GCM (IV 8, pad 4):   L = 4k              -> L%4=0 (any ICV of 8/12/16)
# (suite, modulus, residue, prior, family). Priors: GCM 0.4, AES-CBC 0.4 total, 3DES 0.2 total.
HYP = [
    ('AES-CBC + HMAC-SHA1-96',        16, 4, 0.10, 'CBC+HMAC'),
    ('AES-CBC + HMAC-SHA2-256-128',   16, 8, 0.10, 'CBC+HMAC'),
    ('AES-CBC + HMAC-SHA2-384-192',   16, 0, 0.10, 'CBC+HMAC'),
    ('AES-CBC + HMAC-SHA2-512-256',   16, 8, 0.10, 'CBC+HMAC'),
    ('AES-GCM (ICV 8/12/16)',          4, 0, 0.40, 'AEAD (GCM)'),
    ('3DES-CBC + HMAC-SHA1-96',        8, 4, 0.10, 'CBC+HMAC'),
    ('3DES-CBC + HMAC-SHA2-256-128',   8, 0, 0.10, 'CBC+HMAC'),
]
R = 1500.0          # range of possible ESP lengths
EPS = 0.01          # chance that a length breaks its own suite's rule (noise)
AMBIG_MIN = 0.15   # a family with at least this posterior mass is a candidate
MIN_DISTINCT = 6    # fewer distinct lengths than this -> low confidence, confidence capped
CONF_MIN = 0.95

def flow_table(esp):
    t0 = min(fl[0].t for fl in esp.values())
    rows = []
    for (src, dst, spi), fl in sorted(esp.items(), key=lambda kv: kv[1][0].t):
        Ls = [p.L for p in fl]
        rows.append({'flow': f'{src}->{dst}', 'spi': f'{spi:08x}', 'packets': len(fl),
                     'L_min': min(Ls), 'L_max': max(Ls), 'L_mean': round(sum(Ls) / len(Ls), 1),
                     'distinct_L': len(set(Ls)), 'seq_first': fl[0].seq, 'seq_last': fl[-1].seq,
                     't_first': round(fl[0].t - t0, 2), 't_last': round(fl[-1].t - t0, 2),
                     'udp_encap': any(p.udp_encap for p in fl)})
    return rows

def loglik(lengths, m, r):
    f = 1.0 / m
    hit, miss = math.log((1 - EPS) / (R * f)), math.log(EPS / (R * (1 - f)))
    return sum(hit if L % m == r else miss for L in lengths)

def posterior(lengths):
    lp = [math.log(h[3]) + loglik(lengths, h[1], h[2]) for h in HYP]
    mx = max(lp)
    w = [math.exp(x - mx) for x in lp]
    z = sum(w)
    return [x / z for x in w]

def infer_cipher(path):
    pkts = read_pcap(path)
    ike, esp = build_flows(pkts)
    nsa = len(analyze(pkts)['sessions'])
    pooled = collections.defaultdict(list)      # distinct L -> packet numbers (all SPIs, both directions)
    for fl in esp.values():
        for p in fl:
            if p.L and p.L > 0:
                pooled[p.L].append(p.n)
    out = {'key': 'cipher_family', 'label': 'Cipher family (from ESP lengths)', 'ike_sas': nsa,
           'esp_packets': sum(len(f) for f in esp.values()), 'distinct_lengths': len(pooled)}
    if not pooled:
        out.update(status='not_determinable', value=None, confidence=0.0, low_confidence=True, evidence=[],
                   reason='No ESP packets in this capture',
                   advice='Capture while traffic is flowing through the tunnel')
        return out
    Ls = sorted(pooled)
    bad = [L for L in Ls if L % 4]
    if bad:
        out.update(status='inferred', value='non-standard padding', group=[], confidence=0.3, low_confidence=True,
                   evidence=[pooled[L][0] for L in bad][:10],
                   reason='Some ESP lengths are not multiples of 4, which no standard suite produces',
                   advice='Check for offloads, fragmentation or extra encapsulation, then capture again')
        return out
    post = posterior(Ls)
    groups = {}
    for (name, m, r, _, fam), p in zip(HYP, post):
        g = groups.setdefault((m, r), {'suites': [], 'p': 0.0, 'family': fam})
        g['suites'].append(name)
        g['p'] += p
    ranked = sorted(groups.values(), key=lambda g: -g['p'])
    best = ranked[0]
    fam_p = sum(g['p'] for g in groups.values() if g['family'] == best['family'])
    p3 = sum(p for h, p in zip(HYP, post) if '3DES' in h[0])   # posterior mass on 3DES suites
    few = len(Ls) < MIN_DISTINCT
    fam_tot = collections.defaultdict(float)
    for g in groups.values():
        fam_tot[g['family']] += g['p']
    fit_fams = {h[4] for h in HYP if all(L % h[1] == h[2] for L in Ls)}
    amb = sorted(fit_fams, key=lambda f: -fam_tot.get(f, 0))
    mixed = few and len(amb) > 1
    conf = min(fam_p, 0.6) if few else fam_p
    low = few or fam_p < CONF_MIN or nsa > 1
    if mixed:
        value = ' or '.join(amb) + ' (not separable)'
        suites = [s for g in ranked if g['family'] in amb for s in g['suites']]
        conf = 0.5
    else:
        value, suites = best['family'], best['suites']
    out.update(status='inferred', value=value, families=(amb if mixed else [best['family']]), group=suites,
               group_confidence=round(best['p'], 3), p_3des=round(p3, 3),
               confidence=round(conf, 3), low_confidence=low,
               evidence=[pooled[L][0] for L in Ls][:10],
               alternatives=[{'suites': g['suites'], 'p': round(g['p'], 3)} for g in ranked[1:4]])
    why = []
    if few:
        why.append(f'only {len(Ls)} distinct ESP lengths seen (need {MIN_DISTINCT}+)')
    if fam_p < CONF_MIN:
        why.append('length rules do not separate the candidate suites well')
    if nsa > 1:
        why.append(f'ESP flows are pooled across {nsa} IKE SAs, which the prototype cannot separate')
    if why:
        out['reason'] = '; '.join(why)
        out['advice'] = 'Capture traffic with varied packet sizes (web, video) or a longer window'
    return out

def truth_family(lab):
    return 'AEAD (GCM)' if 'gcm' in lab['cipher'] else 'CBC+HMAC'

def truth_suite(lab):
    c, i = lab['cipher'], lab.get('integrity', '')
    if 'gcm' in c:
        return 'AES-GCM (ICV 8/12/16)'
    if c.startswith('3des'):
        return '3DES-CBC + HMAC-SHA1-96' if 'sha1' in i else '3DES-CBC + HMAC-SHA2-256-128'
    return {'hmac-sha1': 'AES-CBC + HMAC-SHA1-96', 'hmac-sha256': 'AES-CBC + HMAC-SHA2-256-128',
            'hmac-sha384': 'AES-CBC + HMAC-SHA2-384-192', 'hmac-sha512': 'AES-CBC + HMAC-SHA2-512-256'}.get(i)

def evaluate(pattern='*'):
    rows, cnt = [], collections.Counter()
    for pc in sorted(glob.glob(os.path.join(PCAPS, pattern + ('' if pattern.endswith('.pcap') else '.pcap')))):
        run = os.path.basename(pc)[:-5]
        lp = os.path.join(LABELS, run + '.json')
        if not os.path.exists(lp):
            continue
        lab = json.load(open(lp))
        r = infer_cipher(pc)
        t, ts = truth_family(lab), truth_suite(lab)
        fams = r.get('families') or [r['value']]
        ok = t in fams
        low = r.get('low_confidence', True)
        res = ('correct_low_conf' if low else 'correct') if ok else ('wrong_but_flagged' if low else 'CONFIDENTLY_WRONG')
        if ok and len(fams) > 1:
            res = 'group_correct'
        in_group = ts in (r.get('group') or [])
        cnt[res] += 1
        cnt['group_hit'] += in_group
        rows.append([run, lab['config'], lab['traffic_type'], t, r['value'], r['confidence'], low,
                     r['distinct_lengths'], in_group, res])
        print(f'{run:20s} truth={t:11s} pred={str(r["value"]):11s} conf={r["confidence"]:<5} '
              f'distinct={r["distinct_lengths"]:<3} group_ok={in_group!s:5s} {res}')
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, 's5_cipher_eval.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['run', 'config', 'traffic', 'truth', 'pred', 'confidence', 'low_conf', 'distinct_L', 'group_has_truth', 'result'])
        w.writerows(rows)
    n = len(rows)
    print(f'\nruns={n}  ' + '  '.join(f'{k}={v}' for k, v in sorted(cnt.items())))
    print('PASS' if n and not cnt['CONFIDENTLY_WRONG'] else 'FAIL', '(no confidently wrong verdict allowed)')
    print(f'report: {OUT}/s5_cipher_eval.csv')

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else ''
    if cmd == 'table':
        for r in flow_table(build_flows(read_pcap(sys.argv[2]))[1]):
            print(r)
    elif cmd == 'infer':
        print(json.dumps(infer_cipher(sys.argv[2]), indent=1))
    elif cmd == 'eval':
        evaluate(sys.argv[2] if len(sys.argv) > 2 else '*')
    else:
        print(__doc__)
