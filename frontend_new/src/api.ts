import type {
  AnalysisResponse, SamplePcap, EvalRow, EvidenceItem, Finding, Threat, Severity, TrafficData
} from './types/ipsec';

const DEFAULT_API_BASE = 'http://localhost:8000/api';

export function getApiBaseUrl(): string {
  try {
    return localStorage.getItem('ipsecscope_api_base') || DEFAULT_API_BASE;
  } catch {
    return DEFAULT_API_BASE;
  }
}

export function setApiBaseUrl(url: string): void {
  try {
    localStorage.setItem('ipsecscope_api_base', url.replace(/\/+$/, ''));
  } catch {
    // storage unavailable
  }
}

export interface ConnectionTestResult {
  healthy: boolean;
  status: string;
  service?: string;
  version?: string;
  latencyMs: number;
  corsOk: boolean;
  error?: string;
}

export async function testConnection(customUrl?: string): Promise<ConnectionTestResult> {
  const base = customUrl ? customUrl.replace(/\/+$/, '') : getApiBaseUrl();
  const start = performance.now();
  try {
    const res = await fetch(`${base}/health`, { signal: AbortSignal.timeout(3000) });
    const latencyMs = Math.round(performance.now() - start);
    if (!res.ok) {
      return { healthy: false, status: `HTTP ${res.status}`, latencyMs, corsOk: true, error: `Server returned HTTP ${res.status}` };
    }
    const data = await res.json();
    return { healthy: data.ok === true, status: data.ok ? 'healthy' : 'unexpected response', service: 'IPsecScope API', latencyMs, corsOk: true };
  } catch (err: unknown) {
    const latencyMs = Math.round(performance.now() - start);
    const msg = err instanceof Error ? err.message : String(err);
    const isCors = msg.includes('Failed to fetch') || msg.includes('NetworkError');
    return { healthy: false, status: 'offline', latencyMs, corsOk: !isCors, error: isCors ? 'Backend not reachable, or blocked by CORS' : msg };
  }
}

export async function fetchHealth(): Promise<{ status: string }> {
  const r = await testConnection();
  return { status: r.healthy ? 'healthy' : 'offline' };
}

async function errorFrom(res: Response): Promise<Error> {
  let detail = `HTTP ${res.status}`;
  try {
    const j = await res.json();
    if (j && j.detail) detail = String(j.detail);
  } catch {
    // not JSON
  }
  return new Error(detail);
}

export async function fetchScenarios(): Promise<SamplePcap[]> {
  const res = await fetch(`${getApiBaseUrl()}/scenarios`, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw await errorFrom(res);
  const rows = await res.json();
  return rows.map((r: { id: string; config: string; traffic: string; description: string }) => ({
    id: r.id, name: `${r.id}.pcap`, description: r.description, scenario: r.config, traffic: r.traffic
  }));
}

// ---- mapping the real API response onto what the components show ----

type ApiItem = {
  id: string; label: string; value: string | null; status: string; confidence: number | null;
  evidence: number[]; low_confidence: boolean; reason: string | null; advisor: string | null;
};
type ApiFinding = {
  id: string; title: string; severity: string; status: string; confidence: number | null;
  evidence: number[]; fix: string; reference: string | null;
};
interface ApiResponse {
  file: string; duration_s: number; ike_packets: number; esp_packets: number;
  items: ApiItem[];
  traffic: {
    status: string; value: string | null; confidence: number | null; probabilities: Record<string, number>;
    windows: number; low_confidence: boolean; smoke_model: boolean; reason: string | null;
  };
  score: { score_min: number; score_max: number; risk_level: string; risk_level_best_case: string | null; floor_applied: boolean };
  findings: ApiFinding[];
  threat_matrix: {
    likelihood_axis: Record<string, string>; impact_axis: Record<string, string>;
    cells: Record<string, { id: string; name: string; basis: string }[]>;
  };
}

function toEvidence(i: ApiItem): EvidenceItem {
  return {
    id: i.id, label: i.label, value: i.value ?? '-', confidence: i.confidence,
    evidence: i.evidence || [], lowConfidence: !!i.low_confidence
  };
}

function packets(ev: number[]): string {
  if (!ev || ev.length === 0) return 'No packet evidence recorded';
  const shown = ev.slice(0, 8).map(n => `#${n}`).join(', ');
  return `Packets ${shown}${ev.length > 8 ? ` (+${ev.length - 8} more)` : ''}`;
}

const SEVERITY: Record<string, Severity> = {
  critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational'
};

function toFinding(f: ApiFinding): Finding {
  const status = f.status === 'observed' ? 'Observed' : f.status === 'inferred' ? 'Inferred' : 'Not determinable';
  return {
    id: f.id, finding: f.title, severity: SEVERITY[f.severity.toLowerCase()] || 'Low', status,
    confidence: f.confidence == null ? 'n/a' : `${Math.round(f.confidence * 100)}%`,
    evidence: packets(f.evidence), recommended_fix: f.fix, reference: f.reference ?? undefined
  };
}

function toThreats(m: ApiResponse['threat_matrix']): Threat[] {
  const out: Threat[] = [];
  for (const [key, entries] of Object.entries(m.cells || {})) {
    const [l, i] = key.split('-').map(Number);
    const sc = l * i;
    const severity: Severity = sc >= 9 ? 'Critical' : sc >= 6 ? 'High' : sc >= 3 ? 'Medium' : 'Low';
    for (const e of entries) {
      out.push({
        id: e.id, name: e.name, likelihood: l, impact: i, severity,
        description: `Basis: ${e.basis || 'n/a'}. Likelihood ${m.likelihood_axis[String(l)] || l}, impact ${m.impact_axis[String(i)] || i}.`
      });
    }
  }
  return out;
}

function toTraffic(t: ApiResponse['traffic']): TrafficData {
  const probabilities = Object.entries(t.probabilities || {})
    .map(([type, probability]) => ({ type, probability }))
    .sort((a, b) => b.probability - a.probability);
  return {
    status: t.status, value: t.value, confidence: t.confidence, probabilities, windows: t.windows,
    smoke_model: t.smoke_model, low_confidence: t.low_confidence, reason: t.reason ?? undefined
  };
}

function adapt(a: ApiResponse, source: AnalysisResponse['source']): AnalysisResponse {
  const risk = (['Low', 'Medium', 'High', 'Critical'].includes(a.score.risk_level) ? a.score.risk_level : 'Medium') as AnalysisResponse['risk_level'];
  const min = a.score.score_min, max = a.score.score_max;
  return {
    id: source.scenarioId || a.file,
    source,
    summary: {
      filename: a.file, duration_sec: a.duration_s, ike_count: a.ike_packets,
      esp_count: a.esp_packets, total_packets: a.ike_packets + a.esp_packets
    },
    observed: { items: a.items.filter(i => i.status === 'observed').map(toEvidence) },
    inferred: { items: a.items.filter(i => i.status === 'inferred' || i.status === 'provided').map(toEvidence) },
    not_determinable: {
      items: a.items.filter(i => i.status === 'not_determinable').map(i => ({
        parameter: i.label, reason: i.reason || 'Not visible in a passive capture', advisor: i.advisor || undefined
      }))
    },
    traffic: toTraffic(a.traffic),
    score_range: { min, max, display: min === max ? String(min) : `${min} to ${max}` },
    risk_level: risk,
    best_case_risk: a.score.risk_level_best_case ?? undefined,
    floor_applied: a.score.floor_applied,
    findings: a.findings.map(toFinding),
    threat_matrix: toThreats(a.threat_matrix)
  };
}

// ---- analysis calls: no fallback data, failures are shown as errors ----

export async function analyzePcap(
  file: File | null,
  sampleId?: string,
  onProgress?: (pct: number) => void
): Promise<AnalysisResponse> {
  const base = getApiBaseUrl();
  if (sampleId) {
    onProgress?.(30);
    const res = await fetch(`${base}/samples/${encodeURIComponent(sampleId)}/analyze`, { method: 'POST' });
    if (!res.ok) throw await errorFrom(res);
    onProgress?.(100);
    return adapt(await res.json(), { kind: 'scenario', scenarioId: sampleId });
  }
  if (!file) throw new Error('No capture selected');
  const body = await new Promise<ApiResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${base}/analyze`);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress?.(Math.round((e.loaded / e.total) * 70));
    };
    xhr.onload = () => {
      onProgress?.(100);
      let j: unknown = null;
      try { j = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300 && j) resolve(j as ApiResponse);
      else reject(new Error(String((j && (j as { detail?: string }).detail) || `HTTP ${xhr.status}`)));
    };
    xhr.onerror = () => reject(new Error('Could not reach the backend. Check that it is running and the API URL in settings is right.'));
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
  return adapt(body, { kind: 'upload', file });
}

export async function fetchEval(): Promise<{ rows: EvalRow[]; generated: number }> {
  const res = await fetch(`${getApiBaseUrl()}/eval`, { signal: AbortSignal.timeout(4000) });
  if (!res.ok) throw await errorFrom(res);
  const j = await res.json();
  const rows: EvalRow[] = j.rows.map((r: { check: string; goal: string; measured: string; pass: boolean | null }) => ({
    check: r.check, goal: r.goal, measured: r.measured, pass: r.pass
  }));
  return { rows, generated: j.generated };
}

export async function downloadReport(a: AnalysisResponse, type: 'executive' | 'technical'): Promise<void> {
  const base = getApiBaseUrl();
  let res: Response;
  if (a.source.kind === 'scenario' && a.source.scenarioId) {
    res = await fetch(`${base}/report/${encodeURIComponent(a.source.scenarioId)}?type=${type}`);
  } else if (a.source.file) {
    const fd = new FormData();
    fd.append('file', a.source.file);
    res = await fetch(`${base}/report?type=${type}`, { method: 'POST', body: fd });
  } else {
    throw new Error('The original capture is no longer available. Analyze it again to export a report.');
  }
  if (!res.ok) throw await errorFrom(res);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const el = document.createElement('a');
  el.href = url;
  el.download = `ipsecscope-${type}-${a.id.replace(/\.pcap$/, '')}.pdf`;
  document.body.appendChild(el);
  el.click();
  document.body.removeChild(el);
  URL.revokeObjectURL(url);
}

// ---- S10: replay sessions ----

export function adaptResult(a: unknown, scenarioId: string): AnalysisResponse {
  return adapt(a as ApiResponse, { kind: 'scenario', scenarioId });
}

export async function createSession(scenario: string, speed: number): Promise<string> {
  const res = await fetch(`${getApiBaseUrl()}/sessions`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scenario, speed })
  });
  if (!res.ok) throw await errorFrom(res);
  return (await res.json()).id as string;
}

export async function startSession(id: string): Promise<void> {
  const res = await fetch(`${getApiBaseUrl()}/sessions/${id}/start`, { method: 'POST' });
  if (!res.ok) throw await errorFrom(res);
}

export async function stopSession(id: string): Promise<void> {
  await fetch(`${getApiBaseUrl()}/sessions/${id}/stop`, { method: 'POST' });
}

export interface SessionMessage {
  type: 'update' | 'state';
  final?: boolean;
  state?: string;
  result?: unknown;
  history?: { t: number; packets: number; confidence: Record<string, number | null> }[];
  events?: { t: number; text: string }[];
}

export function openSessionSocket(id: string, onMessage: (m: SessionMessage) => void, onClose: () => void): WebSocket {
  const wsBase = getApiBaseUrl().replace(/^http/, 'ws').replace(/\/api$/, '');
  const ws = new WebSocket(`${wsBase}/ws/sessions/${id}`);
  ws.onmessage = (e) => onMessage(JSON.parse(e.data));
  ws.onclose = onClose;
  return ws;
}

// chart points: an item that is not inferred yet counts as 0
export function toConfidencePoints(h: NonNullable<SessionMessage['history']>) {
  const pick = (c: Record<string, number | null>, part: string) => {
    const k = Object.keys(c).find(x => x.toLowerCase().includes(part));
    return k ? (c[k] ?? 0) : 0;
  };
  return h.map(p => ({
    packetCount: Math.max(p.packets, 1), timeSec: p.t,
    cipherConfidence: pick(p.confidence, 'cipher'),
    modeConfidence: pick(p.confidence, 'mode'),
    pfsConfidence: pick(p.confidence, 'pfs')
  }));
}

export function toTimelineEvents(ev: NonNullable<SessionMessage['events']>) {
  return ev.map(e => {
    const m = Math.floor(e.t / 60), s = (e.t % 60).toFixed(1).padStart(4, '0');
    const low = e.text.toLowerCase();
    const type = low.includes('rekey') || low.includes('forward') || low.includes('lifetime') ? 'REKEY'
      : low.includes('ike') || low.includes('diffie') ? 'IKE_INIT' : 'ESP';
    return { timestamp: `${String(m).padStart(2, '0')}:${s}`, offset_sec: e.t, type, message: e.text, details: '' };
  });
}
