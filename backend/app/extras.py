import os, re, json, glob
from fastapi import APIRouter, HTTPException
from schemas import AnalyzeResponse

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
PCAPS = os.path.join(ROOT, 'data', 'pcaps')
EVAL = os.path.join(ROOT, 'eval', 'results.json')

CONFIGS = {
    'c1': 'Tunnel, AES-128-CBC + HMAC-SHA256, PFS on',
    'c2': 'Tunnel, AES-256-CBC + HMAC-SHA256, PFS off',
    'c3': 'Tunnel, AES-256-GCM, PFS on',
    'c4': 'Tunnel, AES-128-GCM, PFS off',
    'c5': 'Transport, AES-128-CBC + HMAC-SHA256, PFS on',
    'c6': 'Transport, AES-256-GCM, PFS on',
    'c7': 'Transport, AES-256-CBC + HMAC-SHA256, PFS off',
    'c8': 'Transport, AES-128-GCM, PFS off',
    'w1': 'Weak demo: IKEv1 Aggressive Mode, 3DES + SHA-1, no PFS',
    'w2': 'Clean control: IKEv2, AES-256-GCM, DH group 14, PFS on',
}
TRAFFIC = {'ping': 'ICMP ping', 'web': 'web browsing', 'voip': 'VoIP-like UDP',
           'video': 'video stream', 'email': 'email (SMTP)'}
FEATURED = ['c1_web_r1', 'c2_ping_r1', 'c3_voip_r1', 'c4_web_r1', 'c5_web_r1',
            'c6_voip_r1', 'c7_ping_r1', 'c8_web_r1', 'w1_web_r1', 'w2_web_r1']
ID_RE = re.compile(r'^[cw][1-8]_(ping|web|voip|video|email)_r[1-4]$')

def describe(rid):
    cfg, tr, rep = rid.split('_')
    return {'id': rid, 'config': cfg.upper(), 'traffic': tr, 'repeat': int(rep[1:]),
            'description': f"{CONFIGS.get(cfg, cfg)}; {TRAFFIC.get(tr, tr)}"}

def scenarios():
    return [describe(r) for r in FEATURED if os.path.exists(os.path.join(PCAPS, r + '.pcap'))]

def make_router(analyze_file):
    r = APIRouter()

    @r.get('/api/samples')
    def samples():
        return scenarios()

    @r.get('/api/scenarios')
    def scenarios_alias():
        return scenarios()

    @r.post('/api/samples/{rid}/analyze', response_model=AnalyzeResponse)
    def analyze_sample(rid: str):
        if not ID_RE.match(rid):
            raise HTTPException(404, 'Unknown scenario')
        path = os.path.join(PCAPS, rid + '.pcap')
        if not os.path.exists(path):
            raise HTTPException(404, 'Scenario pcap not found')
        try:
            return analyze_file(path, rid + '.pcap')
        except Exception as e:
            raise HTTPException(422, f'Could not analyze this capture: {e}')

    @r.get('/api/eval')
    def eval_results():
        if not os.path.exists(EVAL):
            raise HTTPException(404, 'No results yet. Run make eval.')
        return {'rows': json.load(open(EVAL)), 'generated': os.path.getmtime(EVAL)}

    return r
