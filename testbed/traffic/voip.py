#!/usr/bin/env python3
# usage: voip.py send DURATION SEED   |   voip.py echo
import socket, sys, time, random
PORT, SERVER = 5004, '10.0.0.3'
if sys.argv[1] == 'echo':
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('0.0.0.0', PORT))
    while True:
        data, addr = s.recvfrom(2048)
        s.sendto(data, addr)
else:
    dur, seed = float(sys.argv[2]), int(sys.argv[3])
    random.seed(seed)
    size = random.choice([80, 120, 160, 200])   # payload bytes, fixed within a run
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.001)
    end = time.time() + dur
    nxt, seq = time.time(), 0
    while time.time() < end:
        s.sendto(seq.to_bytes(4, 'big') + bytes(size - 4), (SERVER, PORT))
        seq += 1
        try:
            s.recvfrom(2048)
        except socket.timeout:
            pass
        nxt += 0.02                       # one packet every 20 ms
        d = nxt - time.time()
        if d > 0:
            time.sleep(d)
