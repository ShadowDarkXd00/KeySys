const express = require('express');
const crypto = require('crypto');
const path = require('path');
const store = require('./store');

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
if (!ADMIN_PASSWORD) {
  console.error('ADMIN_PASSWORD env var is required');
  process.exit(1);
}
const SESSION_SECRET =
  process.env.SESSION_SECRET || crypto.createHash('sha256').update('shadow-session:' + ADMIN_PASSWORD).digest('hex');
const IS_PROD = process.env.NODE_ENV === 'production';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));
app.use(express.text({ type: 'text/plain', limit: '1kb' }));
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  next();
});

/* ---------- helpers ---------- */
const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const ALPHA = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, no 0/O/1/I
function genKey() {
  const b = crypto.randomBytes(12);
  let s = '';
  for (let i = 0; i < 12; i++) s += ALPHA[b[i] % 32];
  return 'SHADOW-' + s;
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
function safeEqual(a, b) {
  return crypto.timingSafeEqual(sha(a), sha(b));
}
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const mac = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return body + '.' + mac;
}
function verify(token) {
  if (!token || typeof token !== 'string') return null;
  const [body, mac] = token.split('.');
  if (!body || !mac) return null;
  const exp = crypto.createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  if (mac.length !== exp.length || !crypto.timingSafeEqual(Buffer.from(mac), Buffer.from(exp))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) {
    return null;
  }
}
function getCookie(req, name) {
  const h = req.headers.cookie || '';
  for (const part of h.split(';')) {
    const i = part.indexOf('=');
    if (i > -1 && part.slice(0, i).trim() === name) return decodeURIComponent(part.slice(i + 1).trim());
  }
  return null;
}

// tiny in-memory rate limiter
const buckets = new Map();
function limit(name, max, windowMs) {
  return (req, res, next) => {
    const id = name + ':' + req.ip;
    const now = Date.now();
    let b = buckets.get(id);
    if (!b || b.reset < now) b = { n: 0, reset: now + windowMs };
    b.n++;
    buckets.set(id, b);
    if (b.n > max) {
      res.set('Retry-After', Math.ceil((b.reset - now) / 1000));
      return res.status(429).json({ ok: false, valid: false, status: 'rate_limited', message: 'Too many requests' });
    }
    next();
  };
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of buckets) if (v.reset < now) buckets.delete(k);
}, 60000).unref();

function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : getCookie(req, 'sks');
  if (!verify(token)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  next();
}

const UNIT_SECONDS = { minutes: 60, hours: 3600, days: 86400 };
function publicView(r) {
  return {
    key: r.key,
    note: r.note || '',
    created_at: r.created_at,
    duration_seconds: r.duration_seconds,
    start_on: r.start_on,
    expires_at: r.expires_at,
    max_uses: r.max_uses,
    uses: r.uses,
    revoked: !!r.revoked,
    first_used_at: r.first_used_at,
    last_used_at: r.last_used_at,
    last_ip: r.last_ip || null,
  };
}

/* ---------- admin auth ---------- */
app.post('/api/admin/login', limit('login', 8, 15 * 60 * 1000), (req, res) => {
  const pw = req.body && req.body.password;
  if (typeof pw !== 'string' || !safeEqual(pw, ADMIN_PASSWORD)) {
    return res.status(401).json({ ok: false, error: 'Wrong password' });
  }
  const token = sign({ exp: Date.now() + SESSION_TTL_MS });
  res.setHeader(
    'Set-Cookie',
    `sks=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_MS / 1000}${IS_PROD ? '; Secure' : ''}`
  );
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'sks=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');
  res.json({ ok: true });
});
app.get('/api/admin/me', requireAdmin, (req, res) => res.json({ ok: true }));

/* ---------- admin key management ---------- */
app.get('/api/admin/keys', requireAdmin, ah(async (req, res) => {
  const all = await store.all();
  all.sort((a, b) => b.created_at - a.created_at);
  res.json({ ok: true, keys: all.map(publicView) });
}));

app.post('/api/admin/keys', requireAdmin, ah(async (req, res) => {
  const b = req.body || {};
  const count = Math.min(Math.max(parseInt(b.count, 10) || 1, 1), 100);
  const unit = b.unit;
  let duration = null;
  if (unit && unit !== 'lifetime') {
    if (!UNIT_SECONDS[unit]) return res.status(400).json({ ok: false, error: 'Bad unit' });
    const amount = Number(b.amount);
    if (!(amount > 0) || amount > 36500 * 24 * 60) return res.status(400).json({ ok: false, error: 'Bad duration' });
    duration = Math.round(amount * UNIT_SECONDS[unit]);
  }
  let maxUses = null;
  if (b.max_uses !== undefined && b.max_uses !== null && b.max_uses !== '') {
    maxUses = parseInt(b.max_uses, 10);
    if (!(maxUses >= 1)) return res.status(400).json({ ok: false, error: 'Max uses must be 1 or more' });
  }
  const startOn = b.start_on === 'creation' ? 'creation' : 'first_use';
  const now = Date.now();
  const note = String(b.note || '').slice(0, 120);
  const recs = [];
  const seen = new Set();
  while (recs.length < count) {
    const k = genKey();
    if (seen.has(k)) continue;
    seen.add(k);
    recs.push({
      key: k,
      note,
      created_at: now,
      duration_seconds: duration,
      start_on: startOn,
      expires_at: duration && startOn === 'creation' ? now + duration * 1000 : null,
      max_uses: maxUses,
      uses: 0,
      revoked: false,
      first_used_at: null,
      last_used_at: null,
      last_ip: null,
    });
  }
  await store.insertMany(recs);
  res.json({ ok: true, keys: recs.map(publicView) });
}));

function keyAction(fn) {
  return ah(async (req, res) => {
    const key = String(req.params.key || '').toUpperCase();
    const result = await store.mutate(key, (rec) => {
      if (!rec) return { result: null };
      return fn(rec, req.body || {});
    });
    if (result === null) return res.status(404).json({ ok: false, error: 'Key not found' });
    if (result && result.error) return res.status(400).json({ ok: false, error: result.error });
    res.json({ ok: true, key: result });
  });
}

app.post(
  '/api/admin/keys/:key/reset',
  requireAdmin,
  keyAction((rec) => {
    rec.uses = 0;
    rec.first_used_at = null;
    rec.last_used_at = null;
    rec.last_ip = null;
    rec.expires_at = rec.duration_seconds && rec.start_on === 'creation' ? Date.now() + rec.duration_seconds * 1000 : null;
    return { rec, result: publicView(rec) };
  })
);
app.post(
  '/api/admin/keys/:key/revoke',
  requireAdmin,
  keyAction((rec, body) => {
    rec.revoked = body.revoked === false ? false : true;
    return { rec, result: publicView(rec) };
  })
);
app.patch(
  '/api/admin/keys/:key',
  requireAdmin,
  keyAction((rec, body) => {
    if (body.note !== undefined) rec.note = String(body.note).slice(0, 120);
    if (body.max_uses !== undefined) {
      if (body.max_uses === null || body.max_uses === '') rec.max_uses = null;
      else {
        const m = parseInt(body.max_uses, 10);
        if (!(m >= 1)) return { result: { error: 'Max uses must be 1 or more' } };
        rec.max_uses = m;
      }
    }
    if (body.add_days !== undefined) {
      const d = Number(body.add_days);
      if (!isFinite(d) || d === 0) return { result: { error: 'Bad days value' } };
      if (rec.expires_at) rec.expires_at += d * 86400000;
      else if (rec.duration_seconds) rec.duration_seconds = Math.max(60, rec.duration_seconds + d * 86400);
      else return { result: { error: 'Lifetime keys have no expiry to extend' } };
    }
    return { rec, result: publicView(rec) };
  })
);
app.delete(
  '/api/admin/keys/:key',
  requireAdmin,
  keyAction((rec) => ({ rec: null, result: publicView(rec) }))
);

/* ---------- public key check (put this URL in your app) ---------- */
// Type 1: GET /api/check?key=SHADOW-XXXXXXXXXXXX
// Type 2: POST /api/check with the key in the body (JSON or plain text) or an X-License-Key header, nothing in the URL
// consume=0 only looks at the key without using a use or starting the timer.
const cors = (req, res, next) => {
  res.set('Access-Control-Allow-Origin', '*');
  res.set('Access-Control-Allow-Headers', 'Content-Type, X-License-Key');
  res.set('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
};

function evaluate(rec, consume, ip) {
  const now = Date.now();
  const fail = (status, message) => ({
    rec: undefined,
    result: { ok: true, valid: false, status, message },
  });
  if (!rec) return fail('invalid', 'Key not found');
  if (rec.revoked) return fail('revoked', 'Key has been revoked');
  if (rec.expires_at && now > rec.expires_at) return fail('expired', 'Key has expired');
  if (rec.max_uses !== null && rec.uses >= rec.max_uses) {
    return fail('max_uses', 'Key has no uses left');
  }
  if (consume) {
    rec.uses += 1;
    if (!rec.first_used_at) {
      rec.first_used_at = now;
      if (rec.duration_seconds && !rec.expires_at) rec.expires_at = now + rec.duration_seconds * 1000;
    }
    rec.last_used_at = now;
    rec.last_ip = ip;
  }
  const expiresAt = rec.expires_at || null;
  return {
    rec: consume ? rec : undefined,
    result: {
      ok: true,
      valid: true,
      status: 'valid',
      message: 'Key is valid',
      expires_at: expiresAt ? Math.floor(expiresAt / 1000) : null,
      seconds_left: expiresAt ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : null,
      duration_seconds: rec.duration_seconds,
      lifetime: !rec.duration_seconds && !rec.expires_at,
      uses: rec.uses,
      max_uses: rec.max_uses,
      uses_left: rec.max_uses === null ? null : Math.max(0, rec.max_uses - rec.uses),
    },
  };
}

async function handleCheck(req, res) {
  // Key can come from: ?key= (GET), JSON/form body {"key":...}, a plain-text body, or the X-License-Key header.
  const body = req.body && typeof req.body === 'object' ? req.body : {};
  const src = req.method === 'POST' ? Object.assign({}, req.query, body) : req.query;
  let rawKey = src.key || req.headers['x-license-key'] || (typeof req.body === 'string' ? req.body : '');
  const key = String(rawKey).trim().toUpperCase();
  const consume = !(src.consume === '0' || src.consume === 0 || src.consume === false || src.consume === 'false');
  if (!/^SHADOW-[A-Z0-9]{12}$/.test(key)) {
    return res.json({ ok: true, valid: false, status: 'invalid', message: 'Key not found' });
  }
  const result = await store.mutate(key, (rec) => evaluate(rec, consume, req.ip));
  res.json(result);
}
app.options('/api/check', cors);
app.get('/api/check', cors, limit('check', 60, 60 * 1000), ah(handleCheck));
app.post('/api/check', cors, limit('check', 60, 60 * 1000), ah(handleCheck));

app.get('/healthz', (req, res) => res.send('ok'));

/* ---------- static admin site ---------- */
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', maxAge: 0 }));

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ ok: false, error: 'Server error' });
});

const PORT = process.env.PORT || 3000;
store
  .init()
  .then(() => app.listen(PORT, () => console.log(`Shadow Key System on :${PORT} (${store.kind})`)))
  .catch((e) => {
    console.error('Storage init failed', e);
    process.exit(1);
  });
