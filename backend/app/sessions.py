"""S10: replay source, rolling buffer and analysis loop. Re-runs the batch pipeline on the buffer so far."""
import asyncio, os, tempfile, time, uuid
from scapy.utils import PcapReader, PcapWriter

BUFFER_SECONDS = 600
ANALYZE_EVERY = 2.0

class Session:
    def __init__(self, path, name, speed=1.0):
        self.id = uuid.uuid4().hex[:12]
        self.path, self.name, self.speed = path, name, float(speed)
        self.state = 'created'
        self.packets = []
        self.history = []
        self.events = []
        self.latest = None
        self.subscribers = set()
        self._task = None
        self._seen = set()
        self.t_start = time.time()

    def log(self, text):
        self.events.append({'t': round(time.time() - self.t_start, 1), 'text': text})

    async def publish(self, msg):
        for q in list(self.subscribers):
            q.put_nowait(msg)

    async def start(self, analyze_file):
        if self._task:
            return
        self.state, self.t_start = 'running', time.time()
        self._task = asyncio.create_task(self._run(analyze_file))

    def stop(self):
        if self._task:
            self._task.cancel()
        self.state = 'stopped'

    async def _run(self, analyze_file):
        loop = asyncio.get_running_loop()
        first_t, wall0 = None, time.time()
        self._reading = True

        async def ticker():
            while self._reading:
                await asyncio.sleep(ANALYZE_EVERY)
                await self._analyze(loop, analyze_file, final=False)   # one at a time: awaited here

        tick = asyncio.create_task(ticker())
        try:
            with PcapReader(self.path) as rd:
                for pkt in rd:
                    t = float(pkt.time)
                    first_t = t if first_t is None else first_t
                    delay = (t - first_t) / self.speed - (time.time() - wall0)
                    if delay > 0:
                        await asyncio.sleep(delay)
                    elif self.packets and len(self.packets) % 200 == 0:
                        await asyncio.sleep(0)                          # let the event loop breathe
                    self.packets.append((t, pkt))
                    while self.packets and t - self.packets[0][0] > BUFFER_SECONDS:
                        self.packets.pop(0)
            self._reading = False
            tick.cancel()
            await asyncio.gather(tick, return_exceptions=True)
            await self._analyze(loop, analyze_file, final=True)
            self.state = 'done'
            await self.publish({'type': 'state', 'state': 'done'})
        except asyncio.CancelledError:
            self._reading = False
            tick.cancel()
            self.state = 'stopped'
            await self.publish({'type': 'state', 'state': 'stopped'})

    async def _analyze(self, loop, analyze_file, final):
        if len(self.packets) < 50 and not final:
            return
        if not self.packets:
            return
        fd, tmp = tempfile.mkstemp(suffix='.pcap')
        os.close(fd)
        try:
            w = PcapWriter(tmp)
            for _, p in self.packets:
                w.write(p)
            w.close()
            res = await loop.run_in_executor(None, analyze_file, tmp, self.name)
        except Exception as e:
            self.log(f'analysis skipped: {e}')
            return
        finally:
            os.unlink(tmp)
        data = res.model_dump()
        self.latest = data
        determined = sum(1 for i in data['items'] if i['status'] != 'not_determinable')
        self.history.append({'t': round(time.time() - self.t_start, 1), 'packets': len(self.packets),
                             'score_min': data['score']['score_min'], 'score_max': data['score']['score_max'],
                             'determined': determined, 'total': len(data['items']),
                             'confidence': {i['id']: i['confidence'] for i in data['items'] if i['status'] == 'inferred'}})
        for i in data['items']:
            key = (i['id'], i['status'], i['value'])
            if i['status'] != 'not_determinable' and key not in self._seen:
                self._seen.add(key)
                self.log(f"{i['label']}: {i['value']} ({i['status']})")
        await self.publish({'type': 'update', 'final': final, 'result': data,
                            'history': self.history, 'events': self.events})

SESSIONS = {}
