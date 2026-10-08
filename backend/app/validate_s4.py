#!/usr/bin/env python3
"""S4.6: cross-check the parser against the lab label, the strongSwan log and tshark.
Usage: python3 validate_s4.py [glob]   e.g. 'c1_*' (default: every pcap that has a label)"""
import sys, os, re, json, csv, glob, shutil, subprocess, collections
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from ingest import read_pcap, build_flows
from ike import analyze

ROOT = os.path.abspath(os.path.join(HERE, '..', '..'))
PCAPS = os.path.join(ROOT, 'data', 'pcaps')
LABELS = os.path.join(ROOT, 'data', 'labels')
OUT = os.path.join(ROOT, 'data', 'reports')

def label_for(run):
    p = os.path.join(LABELS, run + '.json')
    return json.load(open(p)) if os.path.exists(p) else None

def log_counts(run):
    p = os.path.join(LABELS, run + '.strongswan.log')
    if not os.path.exists(p):
        return None
    if os.path.getsize(p) == 4096:
        return 'truncated'
    t = open(p, errors='replace').read()
    req = len(re.findall(r'(?:generating|parsed) CREATE_CHILD_SA request', t))
    ike = len(re.findall(r'rekeying IKE_SA|creating rekey job for IKE_SA|IKE_SA .*rekeyed', t))
    return {'child': max(req - ike, 0), 'ike': ike}

def tshark_counts(pcap):
    if not shutil.which('tshark'):
        return None
    for fld in ('isakmp.exchangetype', 'isakmp.exch_type'):
        out = subprocess.run(['tshark', '-r', pcap, '-Y', 'isakmp', '-T', 'fields', '-e', fld],
                             capture_output=True, text=True).stdout
        vals = [int(v) for l in out.splitlines() for v in l.split(',') if v.strip().isdigit()]
        if vals:
            return collections.Counter(vals)
    return collections.Counter()

def validate(pcap):
    run = os.path.basename(pcap)[:-5]
    res = []
    def add(name, ok, detail='', warn=False):
        res.append({'check': name, 'status': 'PASS' if ok else ('WARN' if warn else 'FAIL'), 'detail': detail})
    lab = label_for(run)
    if lab is None:
        return run, [{'check': 'label', 'status': 'SKIP', 'detail': 'no label yet (run not finished)'}]
    try:
        pkts = read_pcap(pcap)
        r = analyze(pkts)
        ike, esp = build_flows(pkts)
    except Exception as e:
        return run, [{'check': 'parse', 'status': 'FAIL', 'detail': repr(e)}]
    add('parse', True, f'{len(pkts)} packets, {len(r["sessions"])} IKE SA, {len(esp)} ESP flows')
    add('one_ike_sa', len(r['sessions']) == 1, f'{len(r["sessions"])} sessions')
    s = r['sessions'][0] if r['sessions'] else None
    if s:
        v = s['version']
        add('ike_version', v == lab.get('ike_version'), f'pcap {v} / label {lab.get("ike_version")}')
        if run.startswith('w1_'):
            add('aggressive_flag', bool(r['aggressive']), f'aggressive={r["aggressive"]}')
        if v == 2:
            if lab.get('dh_group') is not None:
                add('dh_group', s.get('dh_group') == lab['dh_group'],
                    f'pcap {s.get("dh_group")} / label {lab["dh_group"]}')
            want = sorted(lab.get('rekeys', []), key=lambda k: k['t'])
            got = sorted(r['rekeys'], key=lambda k: k['t'])
            wt, gt = [k['type'] for k in want], [k['type'] for k in got]
            add('rekey_types', sorted(wt) == sorted(gt), f'pcap {gt} / label {wt}')
            if len(want) == len(got) and want:
                dt = max(abs(a['t'] - b['t']) for a, b in zip(want, got))
                add('rekey_times', dt <= 3.0, f'max diff {dt:.1f}s', warn=True)
            lc = log_counts(run)
            if lc == 'truncated':
                res.append({'check': 'rekeys_vs_log', 'status': 'SKIP', 'detail': 'log truncated at 4096 bytes (run predates the stdbuf fix)'})
            elif lc is None:
                res.append({'check': 'rekeys_vs_log', 'status': 'SKIP', 'detail': 'no strongSwan log'})
            else:
                pc, pi = gt.count('child'), gt.count('ike')
                add('rekeys_vs_log', (pc, pi) == (lc['child'], lc['ike']),
                    f'pcap child/ike {pc}/{pi} / log {lc["child"]}/{lc["ike"]}')
    tc = tshark_counts(pcap)
    if tc is None:
        res.append({'check': 'tshark_exchange_types', 'status': 'SKIP', 'detail': 'tshark not installed'})
    else:
        mine = collections.Counter(p.exch for pk in ike.values() for p in pk)
        add('tshark_exchange_types', tc == mine,
            f'tshark {dict(sorted(tc.items()))} / mine {dict(sorted(mine.items()))}')
    return run, res

def main():
    pat = sys.argv[1] if len(sys.argv) > 1 else '*'
    pcaps = sorted(glob.glob(os.path.join(PCAPS, pat + ('' if pat.endswith('.pcap') else '.pcap'))))
    os.makedirs(OUT, exist_ok=True)
    allres, rows = {}, []
    tot = collections.Counter()
    for p in pcaps:
        run, res = validate(p)
        allres[run] = res
        st = [x['status'] for x in res]
        worst = 'FAIL' if 'FAIL' in st else ('SKIP' if st == ['SKIP'] else ('WARN' if 'WARN' in st else 'PASS'))
        tot[worst] += 1
        print(f'{run:28s} {worst}')
        for x in res:
            rows.append([run, x['check'], x['status'], x['detail']])
            if x['status'] in ('FAIL', 'WARN'):
                print(f'    {x["status"]} {x["check"]}: {x["detail"]}')
    json.dump(allres, open(os.path.join(OUT, 's4_validation.json'), 'w'), indent=1)
    with open(os.path.join(OUT, 's4_validation.csv'), 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['run', 'check', 'status', 'detail'])
        w.writerows(rows)
    print(f'\nruns: {len(pcaps)}  ' + '  '.join(f'{k}={v}' for k, v in sorted(tot.items())))
    print(f'report: {OUT}/s4_validation.csv and .json')
    sys.exit(1 if tot['FAIL'] else 0)

if __name__ == '__main__':
    main()
