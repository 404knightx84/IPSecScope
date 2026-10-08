import os
from datetime import datetime
from fastapi import APIRouter, HTTPException, UploadFile, File, Response
from jinja2 import Environment, DictLoader, select_autoescape
from extras import ID_RE, PCAPS

SEV = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}
STATUS = {'observed': 'Observed', 'inferred': 'Inferred', 'provided': 'Provided',
          'not_determinable': 'Not determinable'}

BASE = """<!doctype html><html><head><meta charset="utf-8"><title>{{ title }}</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;font-size:11pt;color:#1a1a1a;margin:28px}
h1{font-size:20pt;margin:0 0 4px} h2{font-size:13pt;margin:22px 0 6px;border-bottom:1px solid #bbb}
.sub{color:#555;margin-bottom:14px} table{border-collapse:collapse;width:100%;margin:6px 0}
th,td{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top;font-size:9.5pt}
th{background:#f0f0f0} .box{border:2px solid #444;padding:10px;margin:10px 0}
.Critical{background:#f8d0d0}.High{background:#fbe0c8}.Medium{background:#fff3c4}.Low{background:#dff0d8}.Informational{background:#e8eef7}
.nd{background:#f3f3f3;color:#444}.note{background:#fff8dc;border:1px solid #d9c36a;padding:6px;margin:8px 0;font-size:10pt}
.cell{height:56px;width:30%;font-size:8.5pt}
</style></head><body>
<h1>{{ title }}</h1>
<div class="sub">Capture: {{ d.file }} | {{ d.duration_s }} s | {{ d.ike_packets }} IKE packets (UDP 500/4500), {{ d.esp_packets }} ESP packets | Generated {{ now }}</div>
{% block body %}{% endblock %}
<p class="sub">IPsecScope is a passive analysis tool. Items marked Inferred are statistical or rule-based estimates, not readings of the gateway configuration. Items marked Not determinable could not be established from this capture.</p>
</body></html>"""

EXEC = """{% extends 'base' %}{% block body %}
<div class="box {{ d.score.risk_level }}"><b>Risk level: {{ d.score.risk_level }}</b><br>
Security score (higher is better): <b>{{ score_text }}</b> out of 100
{% if d.score.floor_applied %}<br>Severity floor applied: a serious finding sets the minimum risk level regardless of the numeric score.{% endif %}
{% if d.score.risk_level_best_case and d.score.risk_level_best_case != d.score.risk_level %}<br>Best case, if every undetermined item turned out fine: {{ d.score.risk_level_best_case }}.{% endif %}
</div>
{% if d.traffic.smoke_model %}<div class="note">Traffic-type result comes from a preliminary model and is low confidence.</div>{% endif %}
<h2>Findings</h2>
{% if findings %}<table><tr><th>Severity</th><th>Finding</th><th>Status</th><th>Recommended fix</th></tr>
{% for f in findings %}<tr><td class="{{ f.severity }}">{{ f.severity }}</td><td>{{ f.id }}: {{ f.title }}</td><td>{{ status.get(f.status) or ('Not evidenced (passive)' if f.status == 'not_evidenced_passive' else f.status) }}</td><td>{{ f.fix }}</td></tr>{% endfor %}</table>
{% else %}<p>No findings.</p>{% endif %}
<h2>What the capture shows</h2>
<table><tr><th>Item</th><th>Result</th><th>Evidence state</th></tr>
{% for i in key_items %}<tr><td>{{ i.label }}</td><td>{{ i.value if i.value else '-' }}</td><td>{{ status[i.status] }}{% if i.confidence is not none and i.status == 'inferred' %} ({{ (i.confidence*100)|round|int }}%){% endif %}</td></tr>{% endfor %}</table>
<p class="sub">IKE algorithms protect the control channel and are negotiated separately from the ESP data-plane cipher, so they can differ.</p>
<h2>What could not be determined</h2>
{% if nd %}<table><tr><th>Item</th><th>Why</th><th>What would help</th></tr>
{% for i in nd %}<tr class="nd"><td>{{ i.label }}</td><td>{{ i.reason or '-' }}</td><td>{{ i.advisor or '-' }}</td></tr>{% endfor %}</table>
{% else %}<p>Every item was determined.</p>{% endif %}
{% endblock %}"""

TECH = """{% extends 'base' %}{% block body %}
<p>Risk level <b>{{ d.score.risk_level }}</b>, score <b>{{ score_text }}</b>{% if d.score.floor_applied %} (severity floor applied){% endif %}.</p>
<h2>Items</h2>
<table><tr><th>Item</th><th>Value</th><th>Status</th><th>Conf.</th><th>Evidence packets</th><th>Reason / advice</th></tr>
{% for i in d['items'] %}<tr {% if i.status == 'not_determinable' %}class="nd"{% endif %}><td>{{ i.label }}</td><td>{{ i.value if i.value else '-' }}</td>
<td>{{ status[i.status] }}{% if i.low_confidence %} (low confidence){% endif %}</td>
<td>{{ i.confidence if i.confidence is not none else '-' }}</td><td>{{ i.evidence[:8]|join(', ') if i.evidence else '-' }}</td>
<td>{{ i.reason or '' }}{% if i.advisor %}<br><i>{{ i.advisor }}</i>{% endif %}</td></tr>{% endfor %}</table>
<p class="sub">IKE SA algorithms protect the control channel and are negotiated separately from the ESP data-plane cipher, so they can differ.</p>
<h2>Traffic type inside ESP</h2>
<p>Predicted: <b>{{ d.traffic.value or 'not determinable' }}</b>{% if d.traffic.confidence is not none %} ({{ d.traffic.confidence }}){% endif %}, {{ d.traffic.windows }} windows.
{% set ikev = (d['items']|selectattr('label','equalto','IKE version')|list|first) %}
{% if ikev and ikev.value and ikev.value != 'IKEv2' %}<br><i>The traffic model was trained on IKEv2 AES captures. Treat this prediction as indicative only.</i>{% endif %}
{% if d.traffic.smoke_model %}<br>Preliminary model: not yet evaluated on a held-out repeat.{% endif %}</p>
{% if d.traffic.probabilities %}<table><tr>{% for k in d.traffic.probabilities %}<th>{{ k }}</th>{% endfor %}</tr><tr>{% for v in d.traffic.probabilities.values() %}<td>{{ v }}</td>{% endfor %}</tr></table>{% endif %}
<h2>Findings</h2>
{% if findings %}<table><tr><th>Severity</th><th>Rule</th><th>Status</th><th>Conf.</th><th>Evidence</th><th>Fix</th><th>Reference</th></tr>
{% for f in findings %}<tr><td class="{{ f.severity }}">{{ f.severity }}</td><td>{{ f.id }}: {{ f.title }}</td><td>{{ status.get(f.status) or ('Not evidenced (passive)' if f.status == 'not_evidenced_passive' else f.status) }}</td><td>{{ f.confidence if f.confidence is not none else '-' }}</td>
<td>{{ f.evidence[:6]|join(', ') if f.evidence else '-' }}</td><td>{{ f.fix }}</td><td>{{ f.reference or '-' }}</td></tr>{% endfor %}</table>{% else %}<p>No findings.</p>{% endif %}
<h2>Threat matrix</h2>
<table><tr><th>Impact \\ Likelihood</th>{% for l in grid_cols %}<th>{{ l }}</th>{% endfor %}</tr>
{% for row in grid %}<tr><th>{{ row.label }}</th>{% for c in row.cells %}<td class="cell">{{ c|join('<br>')|safe if c else '' }}</td>{% endfor %}</tr>{% endfor %}</table>
<h2>Limits</h2>
<ul><li>Cipher family, mode and PFS rules were developed and tested on strongSwan captures with DH group 14. Other implementations may give lower confidence.</li>
<li>PFS and lifetime need a child rekey in the capture. Key size cannot be read from ESP lengths.</li>
<li>Replay protection is reported as Not evidenced (passive) with no score impact.</li></ul>
{% endblock %}"""

env = Environment(loader=DictLoader({'base': BASE, 'exec': EXEC, 'tech': TECH}),
                  autoescape=select_autoescape(default=True))

def context(d):
    s = d['score']
    score_text = str(s['score_min']) if s['score_min'] == s['score_max'] else f"{s['score_min']} to {s['score_max']}"
    findings = sorted(d['findings'], key=lambda f: SEV.get(f['severity'], 9))
    nd = [i for i in d['items'] if i['status'] == 'not_determinable']
    key_ids = ('ike_version', 'dh_group', 'cipher_family', 'tunnel_mode', 'pfs', 'child_sa_lifetime')
    key_items = [i for i in d['items'] if i['id'] in key_ids]
    m = d['threat_matrix']
    la, ia = m.get('likelihood_axis', {}), m.get('impact_axis', {})
    cols = sorted(la) or ['1', '2', '3']
    rows = []
    for imp in sorted(ia or {'1': 'Low', '2': 'Medium', '3': 'High'}, reverse=True):
        cells = []
        for lk in cols:
            ents = m.get('cells', {}).get(f'{lk}-{imp}', [])
            cells.append([f"{e['id']}: {e['name']}" for e in ents])
        rows.append({'label': ia.get(imp, imp), 'cells': cells})
    return dict(d=d, now=datetime.now().strftime('%Y-%m-%d %H:%M'), score_text=score_text,
                findings=findings, nd=nd, key_items=key_items, status=STATUS,
                grid=rows, grid_cols=[la.get(c, c) for c in cols])

def render(d, kind):
    if kind not in ('executive', 'technical'):
        raise HTTPException(400, 'type must be executive or technical')
    tpl = env.get_template('exec' if kind == 'executive' else 'tech')
    title = 'IPsecScope executive summary' if kind == 'executive' else 'IPsecScope technical report'
    return tpl.render(title=title, **context(d))

def output(html_text, fmt, name):
    if fmt == 'html':
        return Response(html_text, media_type='text/html')
    from weasyprint import HTML
    pdf = HTML(string=html_text).write_pdf()
    return Response(pdf, media_type='application/pdf',
                    headers={'Content-Disposition': f'attachment; filename="{name}.pdf"'})

def make_report_router(analyze_file):
    r = APIRouter()

    @r.get('/api/report/{rid}')
    def report_sample(rid: str, type: str = 'executive', format: str = 'pdf'):
        if not ID_RE.match(rid):
            raise HTTPException(404, 'Unknown scenario')
        path = os.path.join(PCAPS, rid + '.pcap')
        if not os.path.exists(path):
            raise HTTPException(404, 'Scenario pcap not found')
        d = analyze_file(path, rid + '.pcap').model_dump()
        return output(render(d, type), format, f'{rid}_{type}')

    @r.post('/api/report')
    async def report_upload(file: UploadFile = File(...), type: str = 'executive', format: str = 'pdf'):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        try:
            size = 0
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > 50 * 1024 * 1024:
                    raise HTTPException(413, 'File too large (limit 50 MB)')
                tmp.write(chunk)
            tmp.close()
            try:
                d = analyze_file(tmp.name, file.filename or 'upload.pcap').model_dump()
            except Exception as e:
                raise HTTPException(422, f'Could not analyze this capture: {e}')
            return output(render(d, type), format, f'report_{type}')
        finally:
            tmp.close()
            os.unlink(tmp.name)

    return r
