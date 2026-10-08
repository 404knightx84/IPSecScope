#!/usr/bin/env python3
# usage: run_one.py CONFIG TRAFFIC REPEAT [DURATION]
#   TRAFFIC = ping | web | voip | video | email
import os, sys, json, time, signal, getpass, subprocess, datetime, yaml

HOME = os.path.expanduser('~/ipsecscope')
TB = f'{HOME}/testbed'
PCAPS, LABELS = f'{HOME}/data/pcaps', f'{HOME}/data/labels'
os.makedirs(PCAPS, exist_ok=True)
os.makedirs(LABELS, exist_ok=True)

def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

def tsh(pcap, *args):
    r = subprocess.run(['tshark', '-r', pcap, *args], capture_output=True, text=True)
    return r.stdout.strip()

cid, traffic, rep = sys.argv[1], sys.argv[2], int(sys.argv[3])
dur = int(sys.argv[4]) if len(sys.argv) > 4 else 110
script = {'ping': 'ping', 'web': 'web', 'voip': 'voip', 'video': 'video', 'email': 'mail'}[traffic]
run_id = f'{cid.lower()}_{traffic}_r{rep}'
pcap, label = f'{PCAPS}/{run_id}.pcap', f'{LABELS}/{run_id}.json'
cfg = yaml.safe_load(open(f'{TB}/configs.yaml'))
d, c = cfg['defaults'], cfg['configs'][cid]

subprocess.run(['sudo', '-v'], check=True)

# 1. servers and cleanup
ports = sh('docker', 'exec', 'gw-b', 'ss', '-ltun')
if not all(p in ports for p in (':8080 ', ':2525 ', ':5004 ')):
    sh(f'{TB}/traffic/setup.sh')
    sh(f'{TB}/traffic/setup2.sh')
for gw in ('gw-a', 'gw-b'):
    for n in ('dset', 'g1', 'g1v6', 'gw-gw', 'gw-transport'):
        sh('docker', 'exec', gw, 'swanctl', '--terminate', '--ike', n)
time.sleep(3)

# 1b. network conditions by repeat (same in tunnel and transport runs)
NETEM = {1: '', 2: 'delay 20ms 5ms', 3: 'delay 50ms 10ms loss 1%', 4: 'delay 30ms 15ms loss 0.5%'}
prof = NETEM.get(rep, '')
def wan_if(gw):
    o = sh('docker', 'exec', gw, 'sh', '-c', "ip -o -4 addr show | grep ' 10.0.0.' | awk '{print $2}'")
    return o.split()[0] if o else None
for gw in ('gw-a', 'gw-b'):
    ifc = wan_if(gw)
    sh('docker', 'exec', gw, 'tc', 'qdisc', 'del', 'dev', ifc, 'root')
    if prof:
        print(gw, ifc, sh('docker', 'exec', gw, 'tc', 'qdisc', 'add', 'dev', ifc, 'root', 'netem', *prof.split()) or 'netem on')

# 2. capture and strongSwan log, both started before the tunnel
br = 'br-' + sh('docker', 'network', 'inspect', 'testbed_wan', '-f', '{{.Id}}')[:12]
capmsg = open(f'{LABELS}/{run_id}.tcpdump.txt', 'w')
cap = subprocess.Popen(
    ['sudo', 'tcpdump', '-i', br, '-s', '0', '-U', '-Z', getpass.getuser(), '-w', pcap,
     'udp port 500 or udp port 4500 or esp'],
    stdout=subprocess.DEVNULL, stderr=capmsg)
logpath = f'{LABELS}/{run_id}.strongswan.log'
logf = open(logpath, 'w')
lg = subprocess.Popen(['docker', 'exec', 'gw-a', 'timeout', '-s', 'INT', str(dur + 40),
                       'stdbuf', '-oL', 'swanctl', '--log'], stdout=logf, stderr=subprocess.STDOUT)
time.sleep(3)
if cap.poll() is not None or not os.path.exists(pcap):
    print('ERROR: tcpdump did not start. Its message:')
    print(open(f'{LABELS}/{run_id}.tcpdump.txt').read())
    sys.exit(1)
start = datetime.datetime.now().isoformat(timespec='seconds')

# 3. tunnel
out = sh(f'{TB}/apply_config.py', cid)
print(out)
tunnel_up = 'INSTALLED' in out

# 4. traffic
t_start = time.time()
subprocess.run([f'{TB}/traffic/{script}.sh', str(dur), str(rep)])
t_end = time.time()
time.sleep(2)
cap.send_signal(signal.SIGINT)
try:
    cap.wait(15)
except subprocess.TimeoutExpired:
    cap.kill()
lg.terminate()
logf.close()
end = datetime.datetime.now().isoformat(timespec='seconds')

for gw in ('gw-a', 'gw-b'):
    sh('docker', 'exec', gw, 'tc', 'qdisc', 'del', 'dev', wan_if(gw), 'root')

# 5. checks, from the pcap
off_ok = True
for gw in ('gw-a', 'gw-b'):
    for i in sh('docker', 'exec', gw, 'ls', '/sys/class/net').split():
        if not i.startswith('eth'):
            continue
        for line in sh('docker', 'exec', gw, 'ethtool', '-k', i).splitlines():
            if line.startswith(('generic-receive-offload:', 'tcp-segmentation-offload:',
                                'generic-segmentation-offload:')):
                if line.split(':')[1].split()[0] != 'off':
                    off_ok = False
rows = []   # (time, exchange type, flags, SPI pair as hex)
for l in tsh(pcap, '-Y', 'udp', '-T', 'fields', '-e', 'frame.time_relative', '-e', 'udp.payload').splitlines():
    t_, _, hx = l.partition('\t')
    try:
        b = bytes.fromhex(hx.replace(':', ''))
    except ValueError:
        continue
    if b[:4] == b'\x00\x00\x00\x00':      # NAT-T non-ESP marker: IKE follows
        b = b[4:]
    if len(b) < 28 or b[17] not in (0x10, 0x20):   # too short (keepalive) or not IKE
        continue
    rows.append((float(t_), b[18], b[19], b[:8].hex() + b[8:16].hex()))
esp_n = len(tsh(pcap, '-Y', 'esp', '-T', 'fields', '-e', 'frame.number').splitlines())
first = tsh(pcap, '-c', '1', '-T', 'fields', '-e', 'frame.time_epoch')
t0 = float(first) if first else t_start
rekeys = [{'type': 'child', 't': round(r[0], 1)} for r in rows
          if r[1] == 36 and (r[2] & 0x20) == 0]
ispis = {r[3] for r in rows if r[3][16:] != '0' * 16}
checks = {
    'tunnel_up': tunnel_up,
    'pcap_not_empty': os.path.getsize(pcap) > 1000,
    'ike_present': any(r[1] in (34, 4, 2) for r in rows),
    'esp_present': esp_n > 0,
    'child_rekeys_ge_2': len(rekeys) >= 2,
    'no_ike_rekey': len(ispis) == 1,
    'offloads_disabled': off_ok,
}
if c.get('block') == 'weak':   # IKEv1 has no IKEv2-style rekey exchanges
    checks.pop('child_rekeys_ge_2'); checks.pop('no_ike_rekey')
ver = next((l.split()[-1] for l in sh('docker', 'exec', 'gw-a', 'swanctl', '--version').splitlines()
            if 'strongSwan' in l), 'unknown')
logs = [l for l in open(logpath).read().splitlines() if 'CHILD_SA' in l or 'rekey' in l.lower()][:200]

# 6. label
json.dump({
    'run_id': run_id, 'block': c.get('block', 'base'), 'config': cid, 'ike_version': c.get('version', 2), 'mode': c['mode'],
    'cipher': c['cipher'], 'key_bits': c['key_bits'], 'integrity': c['integrity'],
    'dh_group': c.get('dh_group', 14), 'pfs': c['pfs'], 'ip_version': 4, 'topology': 'endpoints',
    'child_rekey_time_s': 40, 'ike_rekey_time_s': 14400, 'rekeys': rekeys,
    'offloads_disabled': off_ok, 'strongswan_version': ver, 'traffic_type': traffic,
    'repeat': rep, 'duration_s': dur, 'start': start, 'end': end,
    'traffic_start_s': round(t_start - t0, 1), 'traffic_end_s': round(t_end - t0, 1),
    'netem': prof or 'none', 'esp_packets': esp_n, 'aggressive_mode_seen': any(r[1] == 4 for r in rows), 'checks': checks, 'passed': all(checks.values()),
    'strongswan_log_lines': logs,
}, open(label, 'w'), indent=1)
print(f'\n{run_id}: passed={all(checks.values())}  esp_packets={esp_n}  child_rekeys={len(rekeys)}  ike_spis={len(ispis)}')
for k, v in checks.items():
    print(f'  {"ok  " if v else "FAIL"} {k}')
