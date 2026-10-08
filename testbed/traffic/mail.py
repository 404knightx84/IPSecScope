#!/usr/bin/env python3
# usage: mail.py server   |   mail.py send DURATION SEED
import sys, asyncio, smtplib, time, random
from email.message import EmailMessage

async def handle(r, w):
    w.write(b'220 lab ESMTP\r\n'); await w.drain()
    in_data = False
    while True:
        line = await r.readline()
        if not line:
            break
        if in_data:
            if line == b'.\r\n':
                in_data = False
                w.write(b'250 OK queued\r\n'); await w.drain()
            continue
        cmd = line[:4].upper()
        if cmd in (b'EHLO', b'HELO'):
            w.write(b'250 lab\r\n')
        elif cmd == b'DATA':
            in_data = True
            w.write(b'354 End data with <CR><LF>.<CR><LF>\r\n')
        elif cmd == b'QUIT':
            w.write(b'221 bye\r\n'); await w.drain(); break
        else:
            w.write(b'250 OK\r\n')
        await w.drain()
    w.close()

async def serve():
    srv = await asyncio.start_server(handle, '0.0.0.0', 2525)
    async with srv:
        await srv.serve_forever()

if sys.argv[1] == 'server':
    asyncio.run(serve())
else:
    dur, seed = float(sys.argv[2]), int(sys.argv[3])
    random.seed(seed)
    end = time.time() + dur
    while time.time() < end:
        m = EmailMessage()
        m['From'] = 'alice@lab'; m['To'] = 'bob@lab'
        m['Subject'] = 'report %d' % random.randint(1, 9999)
        m.set_content('x' * random.randint(200, 3000))
        if random.random() < 0.7:
            m.add_attachment(random.randbytes(random.choice([5000, 50000, 200000, 800000])),
                             maintype='application', subtype='octet-stream', filename='f.bin')
        with smtplib.SMTP('10.0.0.3', 2525, timeout=10) as s:
            s.send_message(m)
        time.sleep(random.uniform(0.5, 3))
