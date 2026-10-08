import os, sys, pytest
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, os.path.join(ROOT, 'backend', 'app'))
from assess import assess

def it(key, value=None, status='observed', conf=1.0, **kw):
    d = {'key': key, 'value': value, 'status': status, 'confidence': conf, 'evidence': [1]}
    d.update(kw)
    return d

def nd(key):
    return it(key, None, 'not_determinable', 0.0, reason='x', advice='y')

STRONG = [it('ike_version', 'IKEv2'), it('ike_encryption', 'AES_CBC-256'), it('dh_group', 'MODP_2048'),
          it('cipher_family', 'AEAD (GCM)', group=['AES-GCM (ICV 8/12/16)']), it('pfs', 'on'),
          it('tunnel_mode', 'tunnel'), it('child_sa_lifetime', '3600 s', 'inferred', 0.8, seconds=3600)]
WEAK = [it('ike_version', 'IKEv1'), it('ike_mode', 'Aggressive Mode'), nd('ike_encryption'),
        it('dh_group', 'MODP_1024'), it('cipher_family', 'CBC+HMAC', group=['3DES-CBC + HMAC-SHA1-96']),
        it('pfs', 'off')]

def swap(items, key, new):
    return [new if i['key'] == key else i for i in items]

def test_strong_is_low_and_range_collapses():
    s = assess(STRONG)['score']
    assert s['risk_level'] == 'Low' and s['score_min'] == s['score_max'] == 100

def test_weak_is_high_or_critical():
    s = assess(WEAK)['score']
    assert s['risk_level'] in ('High', 'Critical') and s['risk_level_best_case'] in ('High', 'Critical')

def test_unknown_widens_range():
    s = assess(swap(STRONG, 'pfs', nd('pfs')))['score']
    assert s['score_min'] < s['score_max'] == 100

def test_replay_is_informational_with_no_score_impact():
    r = assess(STRONG)
    f = [x for x in r['findings'] if x['rule_id'] == 'R09'][0]
    assert f['status'] == 'not_evidenced_passive' and f['score_impact'] == 0 and r['score']['score_max'] == 100

def test_lifetime_rule_skipped_without_rekey():
    r = assess(swap(STRONG, 'child_sa_lifetime', nd('child_sa_lifetime')))
    assert not [x for x in r['findings'] if x['rule_id'] == 'R07'] and r['score']['score_min'] == 100

def test_long_lifetime_flagged():
    r = assess(swap(STRONG, 'child_sa_lifetime', it('child_sa_lifetime', '86400 s', 'inferred', 0.8, seconds=86400)))
    assert [x for x in r['findings'] if x['rule_id'] == 'R07'] and r['score']['score_max'] < 100

def test_severity_floor_beats_score_band():
    r = assess([it('ike_version', 'IKEv1')])          # score 85 would be Low, but one High finding forces High
    assert r['score']['score_max'] == 85 and r['score']['risk_level'] == 'High'

def test_low_confidence_family_widens_range():
    low = it('cipher_family', 'CBC+HMAC', 'inferred', 0.6, low_confidence=True, group=['AES-CBC + HMAC-SHA2-256-128'])
    s = assess(swap(STRONG, 'cipher_family', low))['score']
    assert s['score_min'] < s['score_max']

PCAPS = os.path.join(ROOT, 'data', 'pcaps')
@pytest.mark.skipif(not os.path.exists(os.path.join(PCAPS, 'w1_ping_r2.pcap')), reason='no W1/W2 pcaps here')
def test_real_w1_high_or_critical_and_w2_low():
    from inferred import build
    w1 = assess(build(os.path.join(PCAPS, 'w1_ping_r2.pcap'))['items'])['score']
    w2 = assess(build(os.path.join(PCAPS, 'w2_ping_r2.pcap'))['items'])['score']
    assert w1['risk_level'] in ('High', 'Critical') and w1['risk_level_best_case'] in ('High', 'Critical')
    assert w2['risk_level'] == 'Low'
