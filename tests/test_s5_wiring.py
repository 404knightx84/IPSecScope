import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'backend', 'app'))
from inferred import build
from assess import assess

def run(rid):
    items = build(os.path.join(ROOT, 'data', 'pcaps', rid + '.pcap'))['items']
    return {i['key']: i for i in items}, assess(items)

def test_pfs_and_mode_wired():
    it, _ = run('c3_web_r1')
    assert it['pfs']['value'] == 'on' and it['tunnel_mode']['value'] == 'tunnel'
    it, _ = run('c4_web_r1')
    assert it['pfs']['value'] == 'off'

def test_mode_abstains_on_voip():
    it, _ = run('c4_voip_r1')
    assert it['tunnel_mode']['status'] == 'not_determinable'

def test_low_confidence_cipher_is_not_a_finding():
    _, a = run('c4_voip_r1')                      # GCM, mislabelled CBC at low confidence
    assert not [f for f in a['findings'] if f['rule_id'] == 'R08' and not f['worst_case_only']]

def test_confident_cbc_still_a_finding():
    _, a = run('c1_ping_r1')
    assert [f for f in a['findings'] if f['rule_id'] == 'R08' and not f['worst_case_only']]
