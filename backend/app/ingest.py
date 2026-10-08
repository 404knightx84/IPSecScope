#!/usr/bin/env python3
"""S4.1/4.2: classify packets (IKE, ESP, keepalive) and group them into IKE sessions and ESP flows."""
import socket, struct, sys, collections
from dataclasses import dataclass
from scapy.all import PcapReader, RawPcapReader

@dataclass
class Pkt:
    n: int
    t: float
    src: str
    dst: str
    kind: str                 # 'ike' | 'esp' | 'keepalive' | 'other'
    L: int = 0                # ESP length as defined in gate G1
    spi: int = 0
    seq: int = 0
    udp_encap: bool = False
    ispi: str = ''
    rspi: str = ''
    ver: int = 0
    exch: int = 0
    flags: int = 0
    msgid: int = 0
    ike_len: int = 0
    raw: bytes = b''

def parse_ike(data, p):
    if len(data) < 28:
        return False
    p.ispi, p.rspi = data[0:8].hex(), data[8:16].hex()
    p.ver, p.exch, p.flags = data[17], data[18], data[19]
    p.msgid, p.ike_len = struct.unpack('!II', data[20:28])
    if p.exch == 34:
        p.raw = bytes(data[:p.ike_len])
    p.kind = 'ike'
    return p.ver in (0x10, 0x20)

def parse_frame(n, t, b):
    if len(b) < 14:
        return None
    et, off = struct.unpack('!H', b[12:14])[0], 14
    if et == 0x8100:
        et, off = struct.unpack('!H', b[16:18])[0], 18
    ip = b[off:]
    if et == 0x0800 and len(ip) >= 20:
        ihl = (ip[0] & 0x0F) * 4
        tot = struct.unpack('!H', ip[2:4])[0]
        proto, src, dst = ip[9], socket.inet_ntop(socket.AF_INET, ip[12:16]), socket.inet_ntop(socket.AF_INET, ip[16:20])
        pay = ip[ihl:tot]
    elif et == 0x86DD and len(ip) >= 40:
        plen = struct.unpack('!H', ip[4:6])[0]
        proto, src, dst = ip[6], socket.inet_ntop(socket.AF_INET6, ip[8:24]), socket.inet_ntop(socket.AF_INET6, ip[24:40])
        pay = ip[40:40 + plen]
    else:
        return None
    p = Pkt(n, t, src, dst, 'other')
    if proto == 50 and len(pay) >= 8:                    # raw ESP
        p.kind, p.L = 'esp', len(pay)
        p.spi, p.seq = struct.unpack('!II', pay[:8])
    elif proto == 17 and len(pay) >= 8:
        sport, dport, ulen = struct.unpack('!HHH', pay[:6])
        data = pay[8:ulen]
        if 500 in (sport, dport):
            parse_ike(data, p)
        elif 4500 in (sport, dport):
            if len(data) == 1 and data[0] == 0xFF:        # NAT-T keepalive
                p.kind = 'keepalive'
            elif data[:4] == b'\x00\x00\x00\x00':         # non-ESP marker: IKE follows
                parse_ike(data[4:], p)
            elif len(data) >= 8:                          # ESP inside UDP
                p.kind, p.udp_encap, p.L = 'esp', True, len(data)
                p.spi, p.seq = struct.unpack('!II', data[:8])
    return p

def read_pcap(path):
    pkts = []
    try:
        for n, (raw, meta) in enumerate(RawPcapReader(path), 1):
            p = parse_frame(n, meta.sec + meta.usec / 1e6, bytes(raw))
            if p:
                pkts.append(p)
    except Exception:                      # pcapng and other formats: slower generic reader
        pkts = []
        for n, pk in enumerate(PcapReader(path), 1):
            p = parse_frame(n, float(pk.time), bytes(pk.original) if hasattr(pk, 'original') else bytes(pk))
            if p:
                pkts.append(p)
    return pkts

def build_flows(pkts):
    ike = collections.defaultdict(list)       # key: initiator SPI (stable for the life of one IKE SA)
    esp = collections.defaultdict(list)       # key: (src, dst, SPI)
    for p in pkts:
        if p.kind == 'ike':
            ike[p.ispi].append(p)
        elif p.kind == 'esp':
            esp[(p.src, p.dst, p.spi)].append(p)
    return ike, esp

if __name__ == '__main__':
    pkts = read_pcap(sys.argv[1])
    ike, esp = build_flows(pkts)
    print(collections.Counter(p.kind for p in pkts))
    for k, v in ike.items():
        print(f'IKE session {k[:8]}..  v{v[0].ver >> 4}  {len(v)} packets  exchanges {sorted({p.exch for p in v})}')
    for (s, d, spi), v in sorted(esp.items(), key=lambda x: x[1][0].t):
        print(f'ESP {s} -> {d}  spi {spi:08x}  {len(v)} packets  distinct L {len({p.L for p in v})}')
