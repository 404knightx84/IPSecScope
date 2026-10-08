#!/usr/bin/env python3
"""S7.8: regenerate every metric table from the pcaps and labels. Nothing is typed by hand.
Usage: python3 eval/run_eval.py [all]      ('all' includes repeats 3-4 in the mode and PFS evals)"""
import sys, os, json, glob, subprocess, collections
ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
APP = os.path.join(ROOT, 'backend', 'app')
REP = os.path.join(ROOT, 'data', 'reports')
sys.path.insert(0, APP)
INC = ['all'] if 'all' in sys.argv else []

def run(script, *args):
    subprocess.run(['nice', '-n', '19', sys.executable, os.path.join(APP, script), *args],
                   check=True, cwd=ROOT, stdout=subprocess.DEVNULL)

rows = []
def add(check, goal, measured, passed):
    rows.append({'check': check, 'goal': goal, 'measured': measured, 'pass': passed})

# 1. regenerate inputs
run('validate_s4.py')
run('traffic.py', 'features')
run('traffic.py', 'train')
run('mode_pfs.py', 'features', *INC)
run('mode_pfs.py', 'eval')
run('pfs.py', 'eval', *INC)

# 2. parsing (S4): the validator writes its own table; the pass rule needs its columns
import csv
p = os.path.join(REP, 's4_validation.csv')
rows4 = list(csv.DictReader(open(p))) if os.path.exists(p) else []
fails = [r for r in rows4 if r['status'] == 'FAIL']
skips = [r for r in rows4 if r['status'] not in ('PASS', 'FAIL')]
nruns = len({r['run'] for r in rows4})
npass = sum(r['status'] == 'PASS' for r in rows4)
add('Parsing vs tshark/log/config', 'no check fails; skips listed',
    f"{npass} pass, {len(fails)} fail, {len(skips)} skipped over {nruns} runs", bool(rows4) and not fails)
for r in fails + skips:
    print(r['status'] + ':', r['run'], r['check'], r['detail'])

# 3. cipher family (S5.1-5.3)
import esp
cnt = collections.Counter()
for pc in sorted(glob.glob(os.path.join(ROOT, 'data', 'pcaps', '*.pcap'))):
    lp = os.path.join(ROOT, 'data', 'labels', os.path.basename(pc)[:-5] + '.json')
    if not os.path.exists(lp):
        continue
    lab = json.load(open(lp))
    if lab.get('block') != 'base':
        continue
    r = esp.infer_cipher(pc)
    ok, low = r['value'] == esp.truth_family(lab), r.get('low_confidence', True)
    cnt[('correct' if ok else 'wrong') + ('_low' if low else '_confident')] += 1
n = sum(cnt.values())
cw = cnt['wrong_confident']
add('Cipher family: confidently wrong runs', '0', f"{cw} of {n} base runs; wrong but flagged {cnt['wrong_low']}", cw == 0)
json.dump(dict(cnt), open(os.path.join(REP, 's5_cipher_summary.json'), 'w'), indent=1)

# 4. mode and PFS
m = json.load(open(os.path.join(REP, 's5_mode_eval.json')))['overall']
wrong_m = m['wrong']
add('Mode: wrong answers (leave-one-config-out)', '0 wrong', f"{m['acc_on_answered']} on {m['answered']}/{m['n']} answered, coverage {m['coverage']}, baseline 0.5", wrong_m == 0)
f = json.load(open(os.path.join(REP, 's5_pfs_eval.json')))['overall']
add('PFS: wrong answers (leave-one-config-out)', '0 wrong', f"{f['acc_on_answered']} on {f['answered']}/{f['n']} answered, coverage {f['coverage']}", f['wrong'] == 0)

# 5. traffic classifier (S7)
t = os.path.join(REP, 's7_traffic_eval.json')
if os.path.exists(t):
    s = json.load(open(t))
    add('Traffic: held-out repeat 4 (run level)', 'report accuracy per mode', f"acc {s['runs']['accuracy']}, macro F1 {s['runs']['macro_f1']}, wrong runs {len(s['wrong_runs'])}", None)
    for key, label in (('windows', 'all'), ('windows_tunnel', 'tunnel'), ('windows_transport', 'transport')):
        if key in s:
            add(f'Traffic: held-out repeat 4 (window level, {label})', 'report accuracy per mode', f"acc {s[key]['accuracy']}, macro F1 {s[key]['macro_f1']}, n {s[key]['n']}", None)
else:
    add('Traffic: held-out repeat 4', 'report accuracy per mode', 'traffic eval not run', None)

# 6. severity floor on the weak pair
from inferred import build
from assess import assess
for tag, ok_levels in (('w1', ('High', 'Critical')), ('w2', ('Low',))):
    pcs = sorted(glob.glob(os.path.join(ROOT, 'data', 'pcaps', tag + '_*.pcap')))
    lv = [assess(build(pc)['items'])['score']['risk_level'] for pc in pcs]
    add(f'Severity floor {tag.upper()}', ' or '.join(ok_levels), f"{collections.Counter(lv)} over {len(pcs)} runs", bool(lv) and all(x in ok_levels for x in lv))

os.makedirs(os.path.join(ROOT, 'eval'), exist_ok=True)
json.dump(rows, open(os.path.join(ROOT, 'eval', 'results.json'), 'w'), indent=1)
with open(os.path.join(ROOT, 'eval', 'results.md'), 'w') as fh:
    fh.write('| Check | Goal | Measured | Pass |\n|---|---|---|---|\n')
    for r in rows:
        fh.write(f"| {r['check']} | {r['goal']} | {r['measured']} | {'n/a' if r['pass'] is None else ('yes' if r['pass'] else 'NO')} |\n")
print(open(os.path.join(ROOT, 'eval', 'results.md')).read())
