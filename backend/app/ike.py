#!/usr/bin/env python3
"""S4.3-4.5: IKE payload parsing, DH group, selected suite, rekey timeline (child vs IKE SA from SPIs)."""
import struct, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ingest import read_pcap, build_flows

ENC = {3: '3DES_CBC', 12: 'AES_CBC', 13: 'AES_CTR', 14: 'AES_CCM_8', 15: 'AES_CCM_12', 16: 'AES_CCM_16',
       18: 'AES_GCM_8', 19: 'AES_GCM_12', 20: 'AES_GCM_16'}
PRF = {1: 'PRF_HMAC_MD5', 2: 'PRF_HMAC_SHA1', 5: 'PRF_HMAC_SHA2_256', 6: 'PRF_HMAC_SHA2_384', 7: 'PRF_HMAC_SHA2_512'}
INTEG = {1: 'HMAC_MD5_96', 2: 'HMAC_SHA1_96', 12: 'HMAC_SHA2_256_128', 13: 'HMAC_SHA2_384_192', 14: 'HMAC_SHA2_512_256'}
DH = {1: 'MODP_768', 2: 'MODP_1024', 5: 'MODP_1536', 14: 'MODP_2048', 15: 'MODP_3072', 16: 'MODP_4096',
      19: 'ECP_256', 20: 'ECP_384', 21: 'ECP_521', 31: 'CURVE_25519'}

def parse_sa(body):
    props, off = [], 0
    while off + 8 <= len(body):
        last, plen = body[off], struct.unpack('!H', body[off + 2:off + 4])[0]
        spisz, ntr = body[off + 6], body[off + 7]
        toff = off + 8 + spisz
        prop = {'enc': [], 'prf': [], 'integ': [], 'dh': []}
        for _ in range(ntr):
            if toff + 8 > len(body):
                break
            tl = struct.unpack('!H', body[toff + 2:toff + 4])[0]
            ttype, tid = body[toff + 4], struct.unpack('!H', body[toff + 6:toff + 8])[0]
            keylen, a = None, toff + 8
            while a + 4 <= toff + tl:
                at, av = struct.unpack('!HH', body[a:a + 4])
                if at == 0x800E:
                    keylen = av
                a += 4
            if ttype == 1:
                prop['enc'].append(ENC.get(tid, f'ENC_{tid}') + (f'-{keylen}' if keylen else ''))
            elif ttype == 2:
                prop['prf'].append(PRF.get(tid, f'PRF_{tid}'))
            elif ttype == 3:
                prop['integ'].append(INTEG.get(tid, f'INTEG_{tid}'))
            elif ttype == 4:
                prop['dh'].append(DH.get(tid, f'DH_{tid}'))
            toff += max(tl, 8)
        props.append(prop)
        off += plen
        if last == 0 or plen < 8:
            break
    return props

def parse_ike_init(raw):
    sa, ke, np_, off = None, None, raw[16], 28
    while np_ and off + 4 <= len(raw):
        nxt, plen = raw[off], struct.unpack('!H', raw[off + 2:off + 4])[0]
        body = raw[off + 4:off + plen]
        if np_ == 33:
            sa = parse_sa(body)
        elif np_ == 34 and len(body) >= 2:
            ke = struct.unpack('!H', body[:2])[0]
        np_, off = nxt, off + plen
        if plen < 4:
            break
    return sa, ke

def fmt(prop):
    if not prop:
        return '-'
    return ' '.join('/'.join(prop[k]) for k in ('enc', 'prf', 'integ', 'dh') if prop[k])

def analyze(pkts):
    t0 = pkts[0].t
    ike, esp = build_flows(pkts)
    first_t = {k: v[0].t - t0 for k, v in ike.items()}
    out = {'sessions': [], 'rekeys': [], 'aggressive': False, 'main_mode': False}
    for k, v in ike.items():
        ver = v[0].ver >> 4
        s = {'ispi': k, 'version': ver, 'start': round(first_t[k], 2), 'packets': len(v),
             'exchanges': sorted({p.exch for p in v})}
        if ver == 1:
            out['aggressive'] |= any(p.exch == 4 for p in v)
            out['main_mode'] |= any(p.exch == 2 for p in v)
        else:
            for p in v:
                if p.exch == 34 and p.raw:
                    sa, ke = parse_ike_init(p.raw)
                    if p.flags & 0x20:
                        s['selected'], s['dh_group'] = (sa[0] if sa else None), ke
                    else:
                        s['offered'], s['offered_dh'] = sa, ke
        out['sessions'].append(s)
    esp_first = {}
    for (_, _, spi), v in esp.items():
        esp_first[spi] = min(esp_first.get(spi, 1e18), v[0].t - t0)
    for k, v in ike.items():
        if v[0].ver >> 4 != 2:
            continue
        resp = {p.msgid: p for p in v if p.exch == 36 and p.flags & 0x20}
        seen_req = set()
        for p in v:
            if p.exch == 36 and not p.flags & 0x20:
                if (p.msgid, p.src) in seen_req:
                    continue  # IKE retransmit of the same request, count once
                seen_req.add((p.msgid, p.src))
                r = resp.get(p.msgid)
                t_req = p.t - t0
                t_end = (r.t - t0) if r else t_req
                new_ike = [k2 for k2, f in first_t.items() if k2 != k and t_req <= f <= t_end + 6]
                new_esp = sorted(spi for spi, f in esp_first.items() if t_req <= f <= t_end + 6)
                out['rekeys'].append({'t': round(t_req, 1), 'type': 'ike' if new_ike else 'child',
                                      'initiator': p.src, 'req_bytes': p.ike_len,
                                      'resp_bytes': r.ike_len if r else None,
                                      'new_esp_spis': [f'{x:08x}' for x in new_esp], 'new_ike_spis': new_ike})
    out['rekeys'].sort(key=lambda r: r['t'])
    return out

if __name__ == '__main__':
    r = analyze(read_pcap(sys.argv[1]))
    for s in r['sessions']:
        print(f"IKE SA {s['ispi'][:8]}  IKEv{s['version']}  start {s['start']}s  exchanges {s['exchanges']}")
        if 'selected' in s:
            print(f"   selected: {fmt(s['selected'])}   DH group from KE: {DH.get(s['dh_group'], s['dh_group'])}")
            print(f"   offered : {' | '.join(fmt(p) for p in s.get('offered') or [])}")
    if r['aggressive'] or r['main_mode']:
        print('IKEv1 mode:', 'AGGRESSIVE (cleartext identity and hash)' if r['aggressive'] else 'Main')
    for k in r['rekeys']:
        print(f"rekey at {k['t']:6}s  {k['type']:5}  by {k['initiator']}  req {k['req_bytes']}B resp {k['resp_bytes']}B  new ESP SPIs {k['new_esp_spis']}")
