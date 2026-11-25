'use strict';
/*
 * relay.js - single-file, zero-dependency test relay (Node 22+/24).
 *
 *   Mac --HTTPS--> Render (node relay.js server) <--WSS-- AVD (node relay.js client)
 *
 * RENDER (Web Service, runtime Node):
 *   Build Command: echo ok        Start Command: node relay.js server
 *   Env vars: MAC_API_TOKEN, AVD_CLIENT_TOKEN  (each: openssl rand -hex 32)
 *
 * AVD (PowerShell):
 *   $env:RELAY_URL="wss://YOUR-SERVICE.onrender.com/ws"
 *   $env:AVD_CLIENT_TOKEN="<same as Render>"
 *   node relay.js client
 *
 * MAC:
 *   curl -H "Authorization: Bearer $MAC_API_TOKEN" https://YOUR-SERVICE.onrender.com/test
 */

const ts = () => new Date().toISOString();
const log = (...a) => console.log(`[${ts()}]`, ...a);

/* ============================ SERVER ============================ */
function runServer() {
  const http = require('node:http');
  const crypto = require('node:crypto');

  const PORT = Number(process.env.PORT) || 3000;
  const MAC = process.env.MAC_API_TOKEN;
  const AVD = process.env.AVD_CLIENT_TOKEN;
  if (!MAC || !AVD || MAC.length < 16 || AVD.length < 16) {
    console.error('Set MAC_API_TOKEN and AVD_CLIENT_TOKEN (min 16 chars each).');
    process.exit(1);
  }
  const REQUEST_TIMEOUT_MS = 10_000, HEARTBEAT_MS = 15_000, STALE_MS = 45_000, AUTH_TIMEOUT_MS = 5_000;
  const MAX_PAYLOAD = 4096;

  const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
  const eq = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

  let avd = null; // { socket, connectedAt, lastSeen }
  const pending = new Map();

  // --- minimal WebSocket framing (text frames, unfragmented, <=4KB) ---
  function wsSend(socket, text, opcode = 0x1) {
    const p = Buffer.from(text);
    const h = p.length < 126 ? Buffer.from([0x80 | opcode, p.length])
      : Buffer.from([0x80 | opcode, 126, p.length >> 8, p.length & 255]);
    socket.write(Buffer.concat([h, p]));
  }
  function wsClose(socket, code = 1000) {
    try { socket.end(Buffer.from([0x88, 2, code >> 8, code & 255])); } catch {}
    setTimeout(() => socket.destroy(), 500).unref();
  }
  function parseFrames(state, chunk, onText) {
    state.buf = Buffer.concat([state.buf, chunk]);
    for (;;) {
      const b = state.buf;
      if (b.length < 2) return;
      const fin = b[0] & 0x80, op = b[0] & 0x0f, masked = b[1] & 0x80;
      let len = b[1] & 0x7f, off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) return state.fail();
      if (!masked || !fin || len > MAX_PAYLOAD) return state.fail();
      if (b.length < off + 4 + len) return;
      const mask = b.subarray(off, off + 4);
      const data = Buffer.from(b.subarray(off + 4, off + 4 + len));
      for (let i = 0; i < len; i++) data[i] ^= mask[i & 3];
      state.buf = b.subarray(off + 4 + len);
      if (op === 0x1) onText(data.toString());
      else if (op === 0x8) return state.close();
      else if (op === 0x9) wsSend(state.socket, data.toString(), 0xA);
      else if (op !== 0xA) return state.fail();
    }
  }

  function failPending() {
    for (const [id, p] of pending) { clearTimeout(p.timer); p.reject(new Error('AVD_NOT_CONNECTED')); pending.delete(id); }
  }

  function requestTest() {
    return new Promise((resolve, reject) => {
      if (!avd) return reject(new Error('AVD_NOT_CONNECTED'));
      const id = crypto.randomUUID();
      const timer = setTimeout(() => { pending.delete(id); reject(new Error('AVD_TIMEOUT')); }, REQUEST_TIMEOUT_MS);
      pending.set(id, { resolve, reject, timer });
      wsSend(avd.socket, JSON.stringify({ type: 'test_request', id }));
    });
  }

  const json = (res, code, body) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(body));
  };

  const server = http.createServer(async (req, res) => {
    const path = (req.url || '').split('?')[0];
    if (req.method === 'GET' && path === '/health') return json(res, 200, { ok: true });
    if (path !== '/status' && path !== '/test') return json(res, 404, { error: 'not_found' });

    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    if (!m || !eq(m[1], MAC)) return json(res, 401, { error: 'unauthorized' });
    if (req.method !== 'GET') return json(res, 405, { error: 'method_not_allowed' });

    if (path === '/status') {
      return json(res, 200, {
        avdConnected: !!avd,
        connectedAt: avd ? new Date(avd.connectedAt).toISOString() : null,
        lastSeen: avd ? new Date(avd.lastSeen).toISOString() : null,
      });
    }
    const t0 = Date.now();
    try {
      const response = await requestTest();
      json(res, 200, { ok: true, response, roundTripMs: Date.now() - t0 });
    } catch (e) {
      if (e.message === 'AVD_TIMEOUT') json(res, 504, { ok: false, error: 'avd_timeout' });
      else json(res, 503, { ok: false, error: 'avd_not_connected' });
    }
  });

  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if ((req.url || '').split('?')[0] !== '/ws' || !key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') {
      return socket.destroy();
    }
    const accept = crypto.createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write('HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`);

    let authed = false;
    const state = { buf: Buffer.alloc(0), socket, fail: () => wsClose(socket, 1002), close: () => wsClose(socket) };
    const authTimer = setTimeout(() => { if (!authed) wsClose(socket, 4401); }, AUTH_TIMEOUT_MS);

    socket.on('data', (chunk) => parseFrames(state, chunk, (text) => {
      let msg; try { msg = JSON.parse(text); } catch { return state.fail(); }
      if (!msg || typeof msg !== 'object') return state.fail();
      if (!authed) {
        if (msg.type === 'auth' && typeof msg.token === 'string' && eq(msg.token, AVD)) {
          authed = true; clearTimeout(authTimer);
          if (avd) wsClose(avd.socket, 4000); // only one AVD client
          avd = { socket, connectedAt: Date.now(), lastSeen: Date.now() };
          wsSend(socket, JSON.stringify({ type: 'auth_ok' }));
          log('AVD connected');
        } else { log('AVD auth failed'); wsClose(socket, 4401); }
        return;
      }
      if (avd && avd.socket === socket) avd.lastSeen = Date.now();
      if (msg.type === 'test_response' && typeof msg.id === 'string' && typeof msg.message === 'string' && msg.message.length <= 200) {
        const p = pending.get(msg.id);
        if (p) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg.message); }
      }
    }));
    const gone = () => {
      clearTimeout(authTimer);
      if (avd && avd.socket === socket) { avd = null; failPending(); log('AVD disconnected'); }
    };
    socket.on('close', gone);
    socket.on('error', () => socket.destroy());
  });

  setInterval(() => {
    if (!avd) return;
    if (Date.now() - avd.lastSeen > STALE_MS) { log('AVD stale; dropping'); avd.socket.destroy(); return; }
    wsSend(avd.socket, JSON.stringify({ type: 'heartbeat' }));
  }, HEARTBEAT_MS).unref();

  server.listen(PORT, '0.0.0.0', () => log(`Relay listening on 0.0.0.0:${PORT}`));
  process.on('SIGTERM', () => { server.close(); process.exit(0); });
}

/* ============================ CLIENT ============================ */
function runClient() {
  const URL_ = process.env.RELAY_URL, TOKEN = process.env.AVD_CLIENT_TOKEN;
  if (!URL_ || !TOKEN) { console.error('Set RELAY_URL and AVD_CLIENT_TOKEN first.'); process.exit(1); }
  if (!/^wss:\/\/|^ws:\/\/(localhost|127\.0\.0\.1)/.test(URL_)) { console.error('RELAY_URL must start with wss://'); process.exit(1); }

  const REPLY = 'Hello from AVD', WATCHDOG_MS = 60_000;
  let attempt = 0, ws, watchdog, timer, stopping = false;

  const arm = () => { clearTimeout(watchdog); watchdog = setTimeout(() => { log('Server silent; reconnecting'); try { ws.close(); } catch {} }, WATCHDOG_MS); };

  function connect() {
    log('Connecting...');
    const sock = ws = new WebSocket(URL_);
    sock.addEventListener('open', () => { sock.send(JSON.stringify({ type: 'auth', token: TOKEN })); arm(); });
    sock.addEventListener('message', (ev) => {
      arm();
      let m; try { m = JSON.parse(String(ev.data)); } catch { return; }
      if (!m || typeof m !== 'object') return;
      if (m.type === 'auth_ok') { attempt = 0; log('CONNECTED and authenticated'); }
      else if (m.type === 'heartbeat') sock.send(JSON.stringify({ type: 'heartbeat_ack' }));
      else if (m.type === 'test_request' && typeof m.id === 'string' && /^[0-9a-f-]{36}$/i.test(m.id)) {
        log(`Test request ${m.id} received -> replying "${REPLY}"`);
        sock.send(JSON.stringify({ type: 'test_response', id: m.id, message: REPLY }));
      }
    });
    sock.addEventListener('error', () => log('Connection error'));
    sock.addEventListener('close', (ev) => {
      clearTimeout(watchdog);
      log(ev.code === 4401 ? 'Auth rejected - check AVD_CLIENT_TOKEN' : `DISCONNECTED (code ${ev.code})`);
      if (stopping) return;
      const base = Math.min(60_000, 1000 * 2 ** attempt++);
      const delay = Math.round(base / 2 + Math.random() * base / 2);
      log(`Reconnecting in ${(delay / 1000).toFixed(1)}s`);
      timer = setTimeout(connect, delay);
    });
  }
  const stop = () => { stopping = true; clearTimeout(timer); clearTimeout(watchdog); log('Stopping'); try { ws.close(1000); } catch {} setTimeout(() => process.exit(0), 300); };
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  connect();
}

/* ============================ MAIN ============================ */
const mode = process.argv[2];
if (mode === 'server') runServer();
else if (mode === 'client') runClient();
else { console.error('Usage: node relay.js server|client'); process.exit(1); }
