import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { config } from 'dotenv';
import express from 'express';
import QRCode from 'qrcode';
import { WebSocketServer } from 'ws';

config({ path: fileURLToPath(new URL('.env', import.meta.url)) });

const PORT = process.env.PORT || 3005;
const NODE_ENV = process.env.NODE_ENV || 'development';
const FRONTEND_ORIGINS = (process.env.FRONTEND_ORIGINS || process.env.FRONTEND_ORIGIN || 'http://localhost:3000')
  .split(',')
  .map((origin) => origin.trim().replace(/\/+$/, ''))
  .filter(Boolean);
const FRONTEND_ORIGIN = FRONTEND_ORIGINS[0];
const TTL_MS = 5 * 60 * 1000;
const WS_OPEN = 1;
const JSON_LIMIT = process.env.JSON_LIMIT || '32kb';
const MAX_WS_PAYLOAD_BYTES = Number(process.env.MAX_WS_PAYLOAD_BYTES || 16 * 1024);
const MAX_SDP_BYTES = Number(process.env.MAX_SDP_BYTES || 12 * 1024);
const MAX_ICE_BYTES = Number(process.env.MAX_ICE_BYTES || 2048);
const RATE_WINDOW_MS = Number(process.env.RATE_WINDOW_MS || 60 * 1000);
const CREATE_SESSION_LIMIT = Number(process.env.CREATE_SESSION_LIMIT || 20);
const JOIN_SESSION_LIMIT = Number(process.env.JOIN_SESSION_LIMIT || 60);
const WS_CONNECT_LIMIT = Number(process.env.WS_CONNECT_LIMIT || 30);
const SIGNAL_EVENT_LIMIT = Number(process.env.SIGNAL_EVENT_LIMIT || 120);
const sessions = new Map();
const pairings = new Map();
const rateBuckets = new Map();

const TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

if (NODE_ENV === 'production' && FRONTEND_ORIGINS.some((origin) => new URL(origin).protocol !== 'https:')) {
  throw new Error('Production FRONTEND_ORIGIN must use HTTPS.');
}

setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of rateBuckets) {
    if (now >= bucket.resetAt) rateBuckets.delete(key);
  }
}, RATE_WINDOW_MS).unref();

function hash(value) {
  return createHash('sha256').update(value).digest('hex');
}

function secret(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

function serverTime() {
  return new Date().toISOString();
}

function connectUrl(token) {
  return `${FRONTEND_ORIGIN}/connect/${encodeURIComponent(token)}`;
}

function remainingSeconds(session) {
  return Math.max(0, Math.ceil((session.expiresAt - Date.now()) / 1000));
}

function isAllowedOrigin(origin) {
  if (!origin) return true;
  try {
    return FRONTEND_ORIGINS.includes(new URL(origin).origin);
  } catch {
    return false;
  }
}

function clientIp(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const value = Array.isArray(forwarded) ? forwarded[0] : forwarded;
  return value?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
}

function hitRateLimit(bucket, key, limit, windowMs = RATE_WINDOW_MS) {
  const now = Date.now();
  const bucketKey = `${bucket}:${key}`;
  const entry = rateBuckets.get(bucketKey);
  if (!entry || now >= entry.resetAt) {
    rateBuckets.set(bucketKey, { count: 1, resetAt: now + windowMs });
    return false;
  }
  entry.count += 1;
  return entry.count > limit;
}

function validateSessionId(sessionId) {
  return typeof sessionId === 'string' && UUID_RE.test(sessionId);
}

function validateToken(token) {
  return typeof token === 'string' && TOKEN_RE.test(token);
}

function expireSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;

  for (const socket of [session.sender, session.receiver]) {
    if (socket?.readyState === WS_OPEN) {
      socket.send(JSON.stringify({ type: 'session-expired' }));
      socket.close(1008, 'Session expired');
    }
  }

  pairings.delete(session.tokenHash);
  sessions.delete(sessionId);
  return null;
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() >= session.expiresAt) return expireSession(sessionId);
  return session;
}

function validateSignal(sessionId, token, role) {
  if (!validateSessionId(sessionId)) return { ok: false, status: 400, message: 'Session tidak valid.' };
  if (!validateToken(token)) return { ok: false, status: 403, message: 'Token koneksi tidak valid.' };
  const session = getSession(sessionId);
  if (!session) return { ok: false, status: 404, message: 'Session tidak tersedia atau sudah kedaluwarsa.' };
  if (!['sender', 'receiver'].includes(role)) return { ok: false, status: 400, message: 'Role tidak valid.' };

  const expected = role === 'sender' ? session.senderSignalToken : session.receiverSignalToken;
  if (!expected || expected !== token) return { ok: false, status: 403, message: 'Token koneksi tidak valid.' };

  return { ok: true, session };
}

function isPlainObject(value) {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function validDescription(value) {
  return isPlainObject(value) && typeof value.type === 'string' && typeof value.sdp === 'string' && value.sdp.length <= MAX_SDP_BYTES;
}

function validIceCandidate(value) {
  if (!isPlainObject(value) || typeof value.candidate !== 'string' || value.candidate.length > MAX_ICE_BYTES) return false;
  if ('sdpMid' in value && typeof value.sdpMid !== 'string' && value.sdpMid !== null) return false;
  if ('sdpMLineIndex' in value && (!Number.isInteger(value.sdpMLineIndex) || value.sdpMLineIndex < 0 || value.sdpMLineIndex > 64)) return false;
  if ('usernameFragment' in value && typeof value.usernameFragment !== 'string' && value.usernameFragment !== null) return false;
  return true;
}

function validateSocketMessage(message, role) {
  if (!isPlainObject(message) || typeof message.type !== 'string') return false;
  if (message.type === 'offer') return role === 'sender' && validDescription(message.offer);
  if (message.type === 'answer') return role === 'receiver' && validDescription(message.answer);
  if (message.type === 'ice-candidate') return validIceCandidate(message.candidate);
  if (['transfer-start', 'transfer-complete', 'transfer-failed', 'peer-disconnected'].includes(message.type)) return true;
  return false;
}

const app = express();
app.set('trust proxy', true);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.set({
    'content-security-policy': "default-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), payment=()',
    'vary': 'Origin',
  });
  if (NODE_ENV === 'production') res.set('strict-transport-security', 'max-age=15552000; includeSubDomains');
  if (!isAllowedOrigin(origin)) return res.status(403).json({ error: 'ORIGIN_NOT_ALLOWED' });
  res.set({
    'access-control-allow-origin': origin || FRONTEND_ORIGIN,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: JSON_LIMIT }));

app.post('/api/sessions', (req, res) => {
  try {
    if (hitRateLimit('create-session', clientIp(req), CREATE_SESSION_LIMIT)) return res.status(429).json({ error: 'RATE_LIMITED' });
    const sessionId = randomUUID();
    const pairingToken = secret();
    const tokenHash = hash(pairingToken);
    const expiresAt = Date.now() + TTL_MS;
    const session = {
      sessionId,
      tokenHash,
      tokenUsed: false,
      senderSignalToken: secret(24),
      receiverSignalToken: null,
      sender: null,
      receiver: null,
      createdAt: Date.now(),
      expiresAt,
      status: 'WAITING_FOR_PEER',
    };

    sessions.set(sessionId, session);
    pairings.set(tokenHash, sessionId);
    setTimeout(() => expireSession(sessionId), TTL_MS + 1000).unref();

    res.status(201).json({
      sessionId,
      pairingToken,
      qrToken: pairingToken,
      pairingUrl: connectUrl(pairingToken),
      receiveUrl: connectUrl(pairingToken),
      expiresIn: TTL_MS / 1000,
      expiresAt: new Date(expiresAt).toISOString(),
      signalingToken: session.senderSignalToken,
      serverTime: serverTime(),
    });
  } catch (error) {
    console.error('create-session failed', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.post('/api/sessions/join', (req, res) => {
  try {
    const ip = clientIp(req);
    if (hitRateLimit('join-session', ip, JOIN_SESSION_LIMIT)) return res.status(429).json({ error: 'RATE_LIMITED' });
    const token = String(req.body.token || '').trim();
    if (!validateToken(token)) return res.status(400).json({ error: 'INVALID_PAIRING_CODE' });
    if (hitRateLimit('join-token', hash(token), 5)) return res.status(429).json({ error: 'RATE_LIMITED' });
    const tokenHash = hash(token);
    const sessionId = pairings.get(tokenHash);
    if (!sessionId) return res.status(409).json({ error: 'Pairing token sudah digunakan atau tidak valid.' });

    const session = getSession(sessionId);
    if (!session) return res.status(404).json({ error: 'Session tidak tersedia atau sudah kedaluwarsa.' });
    if (session.tokenUsed) return res.status(409).json({ error: 'Pairing token sudah digunakan.' });
    if (session.receiverSignalToken) return res.status(409).json({ error: 'SESSION_FULL' });

    pairings.delete(tokenHash);
    session.tokenUsed = true;
    session.status = 'PAIRING';
    session.receiverSignalToken = secret(24);

    res.status(200).json({
      sessionId: session.sessionId,
      peerId: `peer_${randomBytes(4).toString('hex')}`,
      expiresIn: remainingSeconds(session),
      expiresAt: new Date(session.expiresAt).toISOString(),
      signalingToken: session.receiverSignalToken,
      serverTime: serverTime(),
    });
  } catch (error) {
    console.error('join-session failed', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/sessions/:sessionId/qr', async (req, res) => {
  try {
    const token = String(req.query.token || '');
    if (!validateSessionId(req.params.sessionId) || !validateToken(token)) return res.status(400).json({ error: 'INVALID_QR_TOKEN' });
    const session = getSession(req.params.sessionId);
    if (!session) return res.status(404).json({ error: 'Session tidak tersedia atau sudah kedaluwarsa.' });
    if (session.tokenHash !== hash(token)) return res.status(403).json({ error: 'Token QR tidak valid.' });
    if (session.tokenUsed) return res.status(410).json({ error: 'Pairing token sudah digunakan.' });

    const svg = await QRCode.toString(connectUrl(token), { type: 'svg', margin: 1, width: 260 });
    res.type('svg').set('cache-control', 'no-store').send(svg);
  } catch (error) {
    console.error('qr generation failed', error);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.use((error, _req, res, next) => {
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: 'PAYLOAD_TOO_LARGE' });
  if (error instanceof SyntaxError) return res.status(400).json({ error: 'JSON request tidak valid.' });
  next(error);
});

app.use((error, _req, res, _next) => {
  console.error('request failed', error);
  res.status(500).json({ error: 'SERVER_ERROR' });
});

const server = createServer(app);
const wss = new WebSocketServer({
  server,
  path: '/signaling',
  maxPayload: MAX_WS_PAYLOAD_BYTES,
  verifyClient: ({ origin, req }, done) => {
    if (!isAllowedOrigin(origin)) return done(false, 403, 'Origin not allowed');
    if (hitRateLimit('ws-connect', clientIp(req), WS_CONNECT_LIMIT)) return done(false, 429, 'Rate limited');
    return done(true);
  },
});

wss.on('connection', (socket, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const sessionId = url.searchParams.get('sessionId');
  const token = url.searchParams.get('signalToken');
  const role = url.searchParams.get('role');
  const check = validateSignal(sessionId, token, role);

  if (!check.ok) {
    socket.close(1008, check.message);
    return;
  }

  const session = check.session;
  if (session[role]?.readyState === WS_OPEN) {
    socket.close(1008, 'Peer already connected');
    return;
  }
  session[role] = socket;
  socket.role = role;
  socket.sessionId = sessionId;
  socket.send(JSON.stringify({ type: 'session-ready', role, status: session.status, expiresAt: new Date(session.expiresAt).toISOString() }));

  const peer = role === 'sender' ? session.receiver : session.sender;
  if (peer?.readyState === WS_OPEN) {
    session.status = 'CONNECTED';
    peer.send(JSON.stringify({ type: 'peer-ready', role }));
    socket.send(JSON.stringify({ type: 'peer-ready', role: peer.role }));
  }

  socket.on('message', (raw) => {
    if (hitRateLimit('signal-event', `${sessionId}:${socket.role}`, SIGNAL_EVENT_LIMIT)) return socket.close(1008, 'Rate limited');
    const latest = getSession(sessionId);
    if (!latest) return socket.close(1008, 'Session expired');

    let message;
    try {
      message = JSON.parse(raw.toString());
    } catch {
      socket.close(1008, 'Malformed signaling message');
      return;
    }

    if (!validateSocketMessage(message, socket.role)) {
      socket.close(1008, 'Invalid signaling message');
      return;
    }

    if (message.type === 'transfer-start') latest.status = 'TRANSFERRING';
    if (message.type === 'transfer-complete') latest.status = 'CONNECTED';
    if (message.type === 'transfer-failed') latest.status = 'FAILED';
    if (message.type === 'peer-disconnected') {
      if (latest.status === 'TRANSFERRING') return;
      latest.status = 'DISCONNECTED';
      const target = socket.role === 'sender' ? latest.receiver : latest.sender;
      if (target?.readyState === WS_OPEN) target.send(JSON.stringify({ type: 'peer-disconnected' }));
      return;
    }

    if (['offer', 'answer', 'ice-candidate'].includes(message.type)) {
      const target = socket.role === 'sender' ? latest.receiver : latest.sender;
      if (target?.readyState === WS_OPEN) target.send(JSON.stringify(message));
    }
  });

  socket.on('close', () => {
    const latest = sessions.get(sessionId);
    if (!latest) return;
    if (latest.sender === socket) latest.sender = null;
    if (latest.receiver === socket) latest.receiver = null;
    if (latest.status === 'TRANSFERRING') latest.status = 'FAILED';
  });
});

server.listen(PORT, () => {
  console.log(`ShareMe API berjalan di http://localhost:${PORT}`);
});
