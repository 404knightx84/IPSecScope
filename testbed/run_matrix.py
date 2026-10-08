#!/usr/bin/env python3
# usage: run_matrix.py [--block base|weak|all] [--repeats 1,2,3,4] [--duration 120]
#                      [--configs C1,C5] [--traffic ping,voip]
import os, sys, json, time, shutil, argparse, threading, subprocess, datetime

HOME = os.path.expanduser('~/ipsecscope')
TB, LABELS = f'{HOME}/testbed', f'{HOME}/data/labels'
LOG = f'{HOME}/data/matrix_log.txt'

ap = argparse.ArgumentParser()
ap.add_argument('--block', default='all')
ap.add_argument('--repeats', default='')
ap.add_argument('--duration', type=int, default=120)
ap.add_argument('--configs', default='')
ap.add_argument('--traffic', default='')
a = ap.parse_args()

jobs = []
if a.block in ('base', 'all'):
    reps = [int(x) for x in (a.repeats or '1,2,3,4').split(',')]
    cfgs = (a.configs or 'C1,C2,C3,C4,C5,C6,C7,C8').split(',')
    trs = (a.traffic or 'ping,web,voip,video,email').split(',')
    jobs += [(c, t, r) for r in reps for c in cfgs for t in trs]
if a.block in ('weak', 'all'):
    reps = [int(x) for x in (a.repeats or '1,2').split(',')]
    cfgs = (a.configs or 'W1,W2').split(',')
    trs = (a.traffic or 'ping,web,voip').split(',')
    jobs += [(c, t, r) for r in reps for c in cfgs for t in trs]

def log(msg):
    line = f'{datetime.datetime.now().isoformat(timespec="seconds")}  {msg}'
    print(line, flush=True)
    open(LOG, 'a').write(line + '\n')

def passed(run_id):
    try:
        return json.load(open(f'{LABELS}/{run_id}.json')).get('passed', False)
    except Exception:
        return False

free_gb = shutil.disk_usage(HOME).free / 1e9
if free_gb < 15:
    sys.exit(f'only {free_gb:.0f} GB free, need at least 15 GB')
subprocess.run(['sudo', '-v'], check=True)
threading.Thread(target=lambda: [(subprocess.run(['sudo', '-n', 'true']), time.sleep(60)) for _ in iter(int, 1)],
                 daemon=True).start()

todo = [j for j in jobs if not passed(f'{j[0].lower()}_{j[1]}_r{j[2]}')]
log(f'matrix start: {len(jobs)} runs planned, {len(todo)} to do, {a.duration}s each, {free_gb:.0f} GB free')
t0, failed = time.time(), []
for n, (c, t, r) in enumerate(todo, 1):
    rid = f'{c.lower()}_{t}_r{r}'
    ok = False
    for attempt in (1, 2):
        subprocess.run([f'{TB}/run_one.py', c, t, str(r), str(a.duration)])
        ok = passed(rid)
        log(f'{rid} attempt {attempt}: {"PASS" if ok else "FAIL"}')
        if ok:
            break
    if not ok:
        failed.append(rid)
    el = time.time() - t0
    log(f'progress {n}/{len(todo)}, elapsed {el/3600:.2f} h, eta {(el/n)*(len(todo)-n)/3600:.2f} h, failed so far {len(failed)}')
log(f'matrix done: {len(todo) - len(failed)} passed, {len(failed)} failed: {failed}')
