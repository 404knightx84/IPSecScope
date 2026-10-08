#!/usr/bin/env python3
import os, sys, subprocess, yaml
from jinja2 import Template

here = os.path.expanduser('~/ipsecscope/testbed')
def sh(*a):
    r = subprocess.run(a, capture_output=True, text=True)
    return (r.stdout + r.stderr).strip()

cid = sys.argv[1]
cfg = yaml.safe_load(open(f'{here}/configs.yaml'))
d, c = cfg['defaults'], cfg['configs'][cid]
esp = c['esp_base'] + ('-' + d['dh'] if c['pfs'] else '')
tpl = Template(open(f'{here}/swanctl.conf.j2').read())
sides = {
  'gw-a': dict(local_ip='10.0.0.2', remote_ip='10.0.0.3', local_id='gw-a', remote_id='gw-b',
               child_rekey=d['child_rekey_a'], ike_rekey='4h'),
  'gw-b': dict(local_ip='10.0.0.3', remote_ip='10.0.0.2', local_id='gw-b', remote_id='gw-a',
               child_rekey=d['child_rekey_b'], ike_rekey='5h'),
}
for gw in sides:
    for n in ('dset', 'g1', 'g1v6', 'gw-gw', 'gw-transport'):
        sh('docker', 'exec', gw, 'swanctl', '--terminate', '--ike', n)
for gw, p in sides.items():
    path = f'/tmp/{cid}-{gw}.conf'
    open(path, 'w').write(tpl.render(mode=c['mode'], esp=esp, ike=c.get('ike', d['ike']), version=c.get('version', 2), aggressive=c.get('aggressive', False), **p))
    sh('docker', 'cp', path, f'{gw}:/tmp/dset.conf')
print(f"{cid}: mode={c['mode']} esp={esp} pfs={c['pfs']}")
for gw in sides:
    out = sh('docker', 'exec', gw, 'swanctl', '--load-all', '--file', '/tmp/dset.conf')
    print(gw, [l for l in out.splitlines() if 'successfully' in l or ('failed' in l and 'opening directory' not in l)])
print(sh('docker', 'exec', 'gw-a', 'swanctl', '--initiate', '--child', 'c').splitlines()[-1])
print(sh('docker', 'exec', 'gw-a', 'ping', '-c', '2', '10.0.0.3').splitlines()[-2])
for l in sh('docker', 'exec', 'gw-a', 'swanctl', '--list-sas').splitlines():
    if any(k in l for k in ('ESTABLISHED', 'INSTALLED', 'rekeying')):
        print(l)
