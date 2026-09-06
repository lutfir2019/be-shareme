import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { config } from 'dotenv';
import express from 'express';
import QRCode from 'qrcode';
import { WebSocketServer } from 'ws';

config({ path: fileURLToPath(new URL('.env', import.meta.url)) });

const PORT = process.env.PORT || 3005;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3005';
const TTL_MS = 5 * 60 * 1000;
const MAX_FILE_SIZE = 1024 * 1024 * 1024;
const WS_OPEN = 1;
const sessions = new Map();

function hash(value) {
  return createHash('sha256').update(value).digest('hex');
}

function publicUrl(req, sessionId, token) {
  return `${FRONTEND_ORIGIN}/receive/${sessionId}?token=${encodeURIComponent(token)}`;
}

function getSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function validateSession(sessionId, token, { join = false } = {}) {
  const session = getSession(sessionId);
  if (!session) return { ok: false, status: 404, message: 'Session tidak tersedia atau sudah kedaluwarsa.' };
  if (session.tokenHash !== hash(token || '')) return { ok: false, status: 403, message: 'Token QR tidak valid.' };
  if (join && !['WAITING_RECEIVER', 'CONNECTING'].includes(session.status)) {
    return { ok: false, status: 409, message: 'Session sudah dipakai, dibatalkan, atau selesai.' };
  }
  return { ok: true, session };
}

function safeMetadata(body) {
  const fileName = String(body.fileName || '').trim();
  const fileSize = Number(body.fileSize);
  const mimeType = String(body.mimeType || 'application/octet-stream').trim();
  if (!fileName || !Number.isFinite(fileSize) || fileSize <= 0) return null;
  if (fileSize > MAX_FILE_SIZE) return null;
  return { fileName, fileSize, mimeType };
}

const app = express();
app.set('trust proxy', true);
app.use((req, res, next) => {
  res.set({
    'access-control-allow-origin': FRONTEND_ORIGIN,
    'access-control-allow-methods': 'GET,POST,OPTIONS',
    'access-control-allow-headers': 'content-type',
  });
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.json({ limit: '32kb' }));

app.post('/api/transfers', (req, res) => {
  try {
    const metadata = safeMetadata(req.body);
    if (!metadata) return res.status(400).json({ error: 'Metadata file tidak valid.' });

    const sessionId = randomUUID();
    const token = randomBytes(32).toString('base64url');
    const expiresAt = Date.now() + TTL_MS;
    const session = {
      sessionId,
      tokenHash: hash(token),
      sender: null,
      receiver: null,
      attempts: 0,
      createdAt: Date.now(),
      expiresAt,
      status: 'WAITING_RECEIVER',
      ...metadata,
    };

    sessions.set(sessionId, session);
    setTimeout(() => {
      const latest = sessions.get(sessionId);
      if (latest && Date.now() >= latest.expiresAt) sessions.delete(sessionId);
    }, TTL_MS + 1000).unref();

    res.status(201).json({
      sessionId,
      qrToken: token,
      receiveUrl: publicUrl(req, sessionId, token),
      expiresIn: TTL_MS / 1000,
      expiresAt: new Date(expiresAt).toISOString(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

app.get('/api/transfers/:sessionId/qr', async (req, res) => {
  try {
    const token = String(req.query.token || '');
    const check = validateSession(req.params.sessionId, token);
    if (!check.ok) return res.status(check.status).json({ error: check.message });
    const svg = await QRCode.toString(publicUrl(req, req.params.sessionId, token), { type: 'svg', margin: 1, width: 260 });
    res.type('svg').set('cache-control', 'no-store').send(svg);
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

app.post('/api/transfers/:sessionId/join', (req, res) => {
  try {
    const token = String(req.body.token || '');
    const check = validateSession(req.params.sessionId, token, { join: true });
    if (!check.ok) return res.status(check.status).json({ error: check.message });
    const session = check.session;
    if (session.status !== 'WAITING_RECEIVER') {
      return res.status(409).json({ error: 'QR sudah digunakan.' });
    }
    session.attempts += 1;
    if (session.attempts > 5) {
      sessions.delete(session.sessionId);
      return res.status(429).json({ error: 'Terlalu banyak percobaan join.' });
    }
    session.status = 'CONNECTING';
    res.status(200).json({
      sessionId: session.sessionId,
      fileName: session.fileName,
      fileSize: session.fileSize,
      mimeType: session.mimeType,
      expiresAt: new Date(session.expiresAt).toISOString(),
    });
  } catch (error) {
    res.status(500).json({ error: error.message || 'Server error' });
  }
});

app.use((error, req, res, next) => {
  if (error instanceof SyntaxError) {
    return res.status(400).json({ error: 'JSON request tidak valid.' });
  }
  next(error);
});

const server = createServer(app);

const wss = new WebSocketServer({ server, path: '/signaling' });

wss.on('connection', (socket, req) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const sessionId = url.searchParams.get('sessionId');
  const token = url.searchParams.get('token');
  const role = url.searchParams.get('role');
  const check = validateSession(sessionId, token, { join: role === 'receiver' });

  if (!check.ok || !['sender', 'receiver'].includes(role)) {
    socket.close(1008, check.message || 'Invalid role');
    return;
  }

  const session = check.session;
  session[role] = socket;
  socket.role = role;
  socket.sessionId = sessionId;
  socket.send(JSON.stringify({ type: 'session-ready', role, status: session.status }));

  const peer = role === 'sender' ? session.receiver : session.sender;
  if (peer?.readyState === WS_OPEN) {
    session.status = 'CONNECTING';
    peer.send(JSON.stringify({ type: 'peer-ready', role }));
    socket.send(JSON.stringify({ type: 'peer-ready', role: peer.role }));
  }

  socket.on('message', (raw) => {
    const latest = getSession(sessionId);
    if (!latest) return socket.close(1008, 'Session expired');
    const target = socket.role === 'sender' ? latest.receiver : latest.sender;
    if (target?.readyState === WS_OPEN) target.send(raw.toString());

    try {
      const message = JSON.parse(raw);
      if (message.type === 'transfer-start') latest.status = 'TRANSFERRING';
      if (message.type === 'transfer-complete') {
        latest.status = 'COMPLETED';
        sessions.delete(sessionId);
      }
      if (message.type === 'transfer-failed') latest.status = 'FAILED';
    } catch {}
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
