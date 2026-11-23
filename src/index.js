const COOKIE = 'otp_session';
const ENTRIES_KEY_DEFAULT = 'otp:entries';

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json', ...headers } });
}

function parseCookies(req) {
  const out = {};
  const c = req.headers.get('Cookie') || '';
  for (const part of c.split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k] = decodeURIComponent(v.join('='));
  }
  return out;
}

function isSecure(req) {
  const url = new URL(req.url);
  return url.protocol === 'https:';
}

function setCookieHeader(token, req, maxAge = 60 * 60 * 24 * 7) {
  const secure = isSecure(req) ? '; Secure' : '';
  return `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=${maxAge}`;
}

function clearCookieHeader(req) {
  const secure = isSecure(req) ? '; Secure' : '';
  return `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict${secure}; Max-Age=0`;
}

async function getSession(req, env) {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE];
  if (!token) return null;
  const val = await env.OTP_KV.get(`session:${token}`);
  return val ? token : null;
}

async function requireAuth(req, env) {
  const token = await getSession(req, env);
  if (!token) return null;
  return token;
}

function uid() {
  return crypto.randomUUID();
}

function entriesKey(env) {
  return env.KV_KEY || ENTRIES_KEY_DEFAULT;
}

async function getEntries(env) {
  const raw = await env.OTP_KV.get(entriesKey(env), 'json');
  return Array.isArray(raw) ? raw : [];
}

async function saveEntries(env, entries) {
  await env.OTP_KV.put(entriesKey(env), JSON.stringify(entries));
}

function normalizeAlgo(a) {
  const m = { 'SHA1': 'SHA-1', 'SHA-1': 'SHA-1', 'SHA256': 'SHA-256', 'SHA-256': 'SHA-256', 'SHA512': 'SHA-512', 'SHA-512': 'SHA-512' };
  return m[(a || '').toUpperCase().replace(/\s/g, '')] || 'SHA-1';
}

function parseOtpAuth(uri) {
  const url = new URL(uri.trim());
  if (url.protocol !== 'otpauth:') throw new Error('not otpauth uri');
  const label = decodeURIComponent(url.pathname.replace(/^\/+/, ''));
  const params = url.searchParams;
  const secret = params.get('secret');
  if (!secret) throw new Error('missing secret');
  let issuer = params.get('issuer');
  const parts = label.split(':');
  if (!issuer && parts.length > 1) issuer = parts[0].trim();
  const account = parts.length > 1 ? parts.slice(1).join(':').trim() : label;
  const algorithm = normalizeAlgo(params.get('algorithm') || 'SHA-1');
  const digits = parseInt(params.get('digits') || '6', 10);
  const period = parseInt(params.get('period') || '30', 10);
  return {
    name: account || label,
    issuer: issuer || '',
    secret: secret.replace(/\s/g, ''),
    algorithm,
    digits: isNaN(digits) ? 6 : digits,
    period: isNaN(period) ? 30 : period,
  };
}

async function handleApi(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // login
  if (path === '/api/login' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const pw = env.PASSWORD;
    if (!pw) return json({ error: 'PASSWORD not configured' }, 500);
    if (body.password !== pw) return json({ error: 'Password salah' }, 401);
    const token = crypto.randomUUID();
    await env.OTP_KV.put(`session:${token}`, '1', { expirationTtl: 60 * 60 * 24 * 7 });
    return json({ ok: true }, 200, { 'Set-Cookie': setCookieHeader(token, request) });
  }

  if (path === '/api/logout' && method === 'POST') {
    const token = await requireAuth(request, env);
    if (token) await env.OTP_KV.delete(`session:${token}`);
    return json({ ok: true }, 200, { 'Set-Cookie': clearCookieHeader(request) });
  }

  if (path === '/api/me' && method === 'GET') {
    const token = await getSession(request, env);
    return json({ authenticated: !!token });
  }

  // require auth below
  const token = await requireAuth(request, env);
  if (!token) return json({ error: 'Unauthorized' }, 401);

  if (path === '/api/entries' && method === 'GET') {
    const entries = await getEntries(env);
    return json({ entries });
  }

  if (path === '/api/entries' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const entries = await getEntries(env);
    let newEntry;
    if (body.uri) {
      const parsed = parseOtpAuth(body.uri);
      newEntry = { id: uid(), createdAt: Date.now(), pinned: false, category: '', ...parsed };
    } else {
      if (!body.secret) return json({ error: 'secret required' }, 400);
      newEntry = {
        id: uid(),
        createdAt: Date.now(),
        name: body.name || 'OTP',
        issuer: body.issuer || '',
        secret: String(body.secret).replace(/\s/g, ''),
        algorithm: normalizeAlgo(body.algorithm || 'SHA-1'),
        digits: parseInt(body.digits || 6, 10),
        period: parseInt(body.period || 30, 10),
        pinned: !!body.pinned,
      };
    }
    entries.push(newEntry);
    await saveEntries(env, entries);
    return json({ ok: true, entry: newEntry });
  }

  if (path === '/api/import' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const text = body.text || '';
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    const entries = await getEntries(env);
    let added = 0;
    let updated = 0;
    let skipped = 0;
    for (const line of lines) {
      try {
        const parsed = parseOtpAuth(line);
        const keySecret = (parsed.secret || '').toUpperCase();
        const keyName = ((parsed.issuer || '') + '|' + (parsed.name || '')).toLowerCase();
        const idxByName = entries.findIndex(e => (((e.issuer || '') + '|' + (e.name || '')).toLowerCase() === keyName));
        const idxBySecret = keySecret ? entries.findIndex(e => (e.secret || '').toUpperCase() === keySecret) : -1;
        const idx = idxByName >= 0 ? idxByName : idxBySecret;
        if (idx >= 0) {
          const e = entries[idx];
          // Timpa secret saja: pertahankan nama/penerbit/algoritma/digit/periode lama,
          // perbarui secret (dan hanya secret) dari data import.
          const changed = e.secret !== parsed.secret;
          e.secret = parsed.secret;
          if (changed) updated++;
          else skipped++;
        } else {
          entries.push({ id: uid(), createdAt: Date.now(), pinned: false, category: '', ...parsed });
          added++;
        }
      } catch (e) {
        // skip non-otp lines
      }
    }
    await saveEntries(env, entries);
    return json({ ok: true, added, updated, skipped });
  }

  // PUT or DELETE /api/entries/:id
  const m = path.match(/^\/api\/entries\/(.+)$/);
  if (m && method === 'PUT') {
    const id = decodeURIComponent(m[1]);
    const body = await request.json().catch(() => ({}));
    const entries = await getEntries(env);
    const idx = entries.findIndex(e => e.id === id);
    if (idx < 0) return json({ error: 'not found' }, 404);
    const e = entries[idx];
    if (body.uri) {
      const parsed = parseOtpAuth(body.uri);
      Object.assign(e, parsed);
    } else {
      if (body.name !== undefined) e.name = String(body.name).trim() || e.name;
      if (body.issuer !== undefined) e.issuer = String(body.issuer).trim();
      if (body.secret) e.secret = String(body.secret).replace(/\s/g, '');
      if (body.algorithm) e.algorithm = normalizeAlgo(body.algorithm);
      if (body.digits) e.digits = parseInt(body.digits, 10);
      if (body.period) e.period = parseInt(body.period, 10);
      if (body.pinned !== undefined) e.pinned = !!body.pinned;
      if (body.category !== undefined) e.category = String(body.category).trim();
    }
    await saveEntries(env, entries);
    return json({ ok: true, entry: e });
  }
  if (m && method === 'DELETE') {
    const id = decodeURIComponent(m[1]);
    const entries = await getEntries(env);
    const next = entries.filter(e => e.id !== id);
    await saveEntries(env, next);
    return json({ ok: true });
  }

  // POST /api/reorder
  if (path === '/api/reorder' && method === 'POST') {
    const body = await request.json().catch(() => ({}));
    const ids = Array.isArray(body.ids) ? body.ids : [];
    const entries = await getEntries(env);
    const map = new Map(entries.map(e => [e.id, e]));
    const next = [];
    for (const id of ids) { if (map.has(id)) { next.push(map.get(id)); map.delete(id); } }
    for (const e of entries) { if (map.has(e.id)) next.push(e); }
    await saveEntries(env, next);
    return json({ ok: true });
  }

  return json({ error: 'Not found' }, 404);
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname.startsWith('/api/')) {
      try {
        return await handleApi(request, env);
      } catch (e) {
        return json({ error: e.message || 'Server error' }, 500);
      }
    }
    // serve static assets
    if (env.ASSETS && typeof env.ASSETS.fetch === 'function') {
      const res = await env.ASSETS.fetch(request);
      if (res.status !== 404) return res;
    }
    return new Response('Not found', { status: 404 });
  },
};
