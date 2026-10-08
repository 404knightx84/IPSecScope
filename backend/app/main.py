import os, sys, tempfile, functools, types
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from schemas import AnalyzeResponse, Item, Score, Finding, Traffic, ThreatMatrix
from inferred import build
from assess import assess
from main_mock import mock_response
import traffic as traffic_mod
import joblib

# 8.5: cache the model file so it is read once, not on every request
traffic_mod.joblib = types.SimpleNamespace(load=functools.lru_cache(maxsize=4)(joblib.load))

MAX_BYTES = 50 * 1024 * 1024

app = FastAPI(title="IPsecScope")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def warm():
    for p in (getattr(traffic_mod, "MODEL", None), getattr(traffic_mod, "SMOKE", None)):
        if p and os.path.exists(p):
            traffic_mod.joblib.load(p)

@app.get("/api/health")
def health():
    return {"ok": True}

def to_item(i):
    advice = i.get('advice')
    if i.get('min_capture'):
        advice = f"{advice or ''} Minimum capture: {i['min_capture']}".strip()
    v = i.get('value')
    return Item(id=i['key'], label=i.get('label', i['key']), value=None if v is None else str(v),
                status=i['status'], confidence=i.get('confidence'),
                evidence=[int(x) for x in i.get('evidence') or []],
                low_confidence=bool(i.get('low_confidence')),
                reason=i.get('reason'), advisor=advice)

def to_finding(f):
    return Finding(id=f['rule_id'], title=f['name'], severity=str(f['severity']).capitalize(),
                   status=f['status'], confidence=f.get('confidence'),
                   evidence=[int(x) for x in f.get('evidence') or []],
                   fix=f.get('fix', ''), reference=f.get('reference'), threat=f.get('threat'))

def get_traffic(path):
    try:
        t = traffic_mod.predict_traffic(path)
        return Traffic(status=t['status'], value=t.get('value'), confidence=t.get('confidence'),
                       probabilities=t.get('probabilities') or {}, windows=t.get('windows', 0),
                       low_confidence=bool(t.get('low_confidence')), smoke_model=bool(t.get('smoke_model')),
                       reason=t.get('reason'), advisor=t.get('advice'))
    except Exception as e:
        return Traffic(status="not_determinable", reason=f"Traffic classifier failed: {e}")

def to_matrix(m):
    return ThreatMatrix(
        likelihood_axis={str(k): str(v) for k, v in (m.get('likelihood_axis') or {}).items()},
        impact_axis={str(k): str(v) for k, v in (m.get('impact_axis') or {}).items()},
        cells={str(k): [dict(e) for e in v] for k, v in (m.get('cells') or {}).items()})

def analyze_file(path, name):
    b = build(path)
    a = assess(b['items'])
    s, cap = a['score'], b['capture']
    return AnalyzeResponse(
        file=name, duration_s=cap['duration_s'],
        ike_packets=cap['packets'] - cap['esp_packets'], esp_packets=cap['esp_packets'],
        items=[to_item(i) for i in b['items']],
        traffic=get_traffic(path),
        score=Score(score_min=s['score_min'], score_max=s['score_max'], risk_level=s['risk_level'],
                    risk_level_best_case=s.get('risk_level_best_case'), floor_applied=s.get('floor') is not None),
        findings=[to_finding(f) for f in a['findings']],
        threat_matrix=to_matrix(a['threat_matrix']))

@app.post("/api/analyze", response_model=AnalyzeResponse)
async def analyze(file: UploadFile = File(...), mock: bool = False):
    name = file.filename or "upload.pcap"
    if mock:
        return mock_response(name)
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    try:
        size = 0
        while chunk := await file.read(1024 * 1024):
            size += len(chunk)
            if size > MAX_BYTES:
                raise HTTPException(413, "File too large (limit 50 MB)")
            tmp.write(chunk)
        tmp.close()
        try:
            return analyze_file(tmp.name, name)
        except Exception as e:
            raise HTTPException(422, f"Could not analyze this capture: {e}")
    finally:
        tmp.close()
        os.unlink(tmp.name)

from extras import make_router
app.include_router(make_router(analyze_file))

from report import make_report_router
app.include_router(make_report_router(analyze_file))

# ---- S10: replay sessions ----
import asyncio
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from sessions import Session, SESSIONS

PCAP_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'pcaps'))

class SessionIn(BaseModel):
    scenario: str
    speed: float = 5.0

@app.post("/api/sessions")
def create_session(body: SessionIn):
    path = os.path.join(PCAP_DIR, os.path.basename(body.scenario) + '.pcap')
    if not os.path.exists(path):
        raise HTTPException(404, "unknown scenario")
    s = Session(path, os.path.basename(path), max(0.5, min(body.speed, 50.0)))
    SESSIONS[s.id] = s
    return {"id": s.id, "state": s.state, "speed": s.speed}

@app.post("/api/sessions/{sid}/start")
async def start_session(sid: str):
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(404, "no such session")
    await s.start(analyze_file)
    return {"id": s.id, "state": s.state}

@app.post("/api/sessions/{sid}/stop")
def stop_session(sid: str):
    s = SESSIONS.get(sid)
    if not s:
        raise HTTPException(404, "no such session")
    s.stop()
    return {"id": s.id, "state": s.state}

@app.websocket("/ws/sessions/{sid}")
async def ws_session(ws: WebSocket, sid: str):
    s = SESSIONS.get(sid)
    await ws.accept()
    if not s:
        await ws.close(code=4404)
        return
    q = asyncio.Queue()
    s.subscribers.add(q)
    try:
        if s.latest:
            await ws.send_json({'type': 'update', 'final': s.state == 'done', 'result': s.latest,
                                'history': s.history, 'events': s.events})
        while True:
            await ws.send_json(await q.get())
    except WebSocketDisconnect:
        pass
    finally:
        s.subscribers.discard(q)
