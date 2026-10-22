'use strict';
// StockFlow server: accounts, password reset by email, per-user data stored in SQLite,
// JSON export/import. Uses only Node.js built-in modules (Node 22.5+).
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const { DatabaseSync } = require('node:sqlite');
const { sendMail } = require('./smtp');

const PORT = Number(process.env.PORT || 8080);
const BASE_URL = (process.env.BASE_URL || 'http://localhost:' + PORT).replace(/\/$/, '');
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data', 'stockflow.db');
if (process.env.RENDER && !process.env.DB_FILE) console.warn('WARNING: Render is using the default local SQLite path. Configure a persistent disk and set DB_FILE to its mounted path to prevent data loss on redeploy/restart.');
const COOKIE_SECURE = process.env.COOKIE_SECURE === '1' || BASE_URL.startsWith('https://');
const MAX_BODY = Number(process.env.MAX_BODY_MB || 200) * 1024 * 1024;
const SESSION_DAYS = 14;
const TRUST_PROXY = process.env.TRUST_PROXY === '1'; // set to 1 only when behind your own reverse proxy
const REG_PER_HOUR = Number(process.env.RATE_REGISTER_PER_HOUR || 50);
const LOGIN_PER_15MIN = Number(process.env.RATE_LOGIN_PER_15MIN || 10);
const RESET_MINUTES = 60;
const SAFETY_KEYS = ['sf_pre_restore', 'sf_pre_drive_restore', 'before_import'];
const SMTP = process.env.SMTP_HOST ? {
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: process.env.SMTP_SECURE === '1',
  user: process.env.SMTP_USER || '',
  pass: process.env.SMTP_PASS || '',
  from: process.env.SMTP_FROM || process.env.SMTP_USER || 'StockFlow <no-reply@localhost>',
  rejectUnauthorized: process.env.SMTP_REJECT_UNAUTHORIZED !== '0',
} : null;

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });
const db = new DatabaseSync(DB_FILE);
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE, pass_hash TEXT NOT NULL, created_at TEXT NOT NULL, store_name TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reset_tokens(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS user_data(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, rev INTEGER NOT NULL, json TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS safety(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, key TEXT NOT NULL, json TEXT NOT NULL, saved_at TEXT NOT NULL, PRIMARY KEY(user_id,key));
`);

try { if (!db.prepare('PRAGMA table_info(users)').all().some(c => c.name === 'store_name')) db.exec("ALTER TABLE users ADD COLUMN store_name TEXT NOT NULL DEFAULT ''"); } catch (e) { console.error('Could not migrate users.store_name:', e.message); }

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const now = () => Date.now();
const nowIso = () => new Date().toISOString();

async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64, SCRYPT);
  return 'scrypt$' + salt.toString('hex') + '$' + key.toString('hex');
}
async function verifyPassword(pw, stored) {
  const [, saltHex, keyHex] = String(stored).split('$');
  const key = await scrypt(pw, Buffer.from(saltHex, 'hex'), 64, SCRYPT);
  const want = Buffer.from(keyHex, 'hex');
  return want.length === key.length && crypto.timingSafeEqual(want, key);
}
// Used when an email is not registered, so login timing does not reveal accounts.
const DUMMY_HASH = null;
let dummyHashPromise = null;
function dummy() { return dummyHashPromise || (dummyHashPromise = hashPassword('not-a-real-password-' + crypto.randomUUID())); }

function httpErr(status, message) { const e = new Error(message); e.status = status; return e; }

function validName(n) { const t = String(n || '').trim(); return t.length >= 2 && t.length <= 80 ? t : null; }
function validEmail(e) { const t = String(e || '').trim().toLowerCase(); return t.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t) ? t : null; }
function validPassword(p) {
  if (typeof p !== 'string' || p.length < 8) throw httpErr(400, 'Password must be at least 8 characters.');
  if (p.length > 200) throw httpErr(400, 'Password is too long.');
  return p;
}

// Simple in-memory rate limiter (per key, sliding window).
const hits = new Map();
function limited(key, max, windowMs) {
  const t = now();
  const arr = (hits.get(key) || []).filter(x => t - x < windowMs);
  arr.push(t); hits.set(key, arr);
  return arr.length > max;
}

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('='); if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const tok = parseCookies(req).sf_session;
  if (!tok) return null;
  const row = db.prepare(`SELECT u.id, u.name, u.email, u.store_name AS storeName FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`).get(sha(tok), now());
  return row ? { id: row.id, name: row.name, email: row.email, storeName: row.storeName || '' } : null;
}
function setSessionCookie(res, token) {
  const parts = ['sf_session=' + encodeURIComponent(token), 'Path=/', 'HttpOnly', 'SameSite=Lax', 'Max-Age=' + SESSION_DAYS * 86400];
  if (COOKIE_SECURE) parts.push('Secure');
  res.setHeader('Set-Cookie', parts.join('; '));
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'sf_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0' + (COOKIE_SECURE ? '; Secure' : ''));
}
function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  db.prepare('INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token), userId, now() + SESSION_DAYS * 86400000);
  return token;
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(httpErr(413, 'File is too large.')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJSON(req) {
  if (!String(req.headers['content-type'] || '').includes('application/json')) throw httpErr(415, 'Request must be JSON.');
  const buf = await readBody(req);
  try { return buf.length ? JSON.parse(buf.toString('utf8')) : {}; }
  catch (_) { throw httpErr(400, 'That file is not valid JSON.'); }
}

function send(res, status, obj, extra) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, Object.assign({ 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }, extra || {}));
  res.end(body);
}
function sendFile(res, file, type) {
  fs.readFile(path.join(__dirname, 'public', file), (err, data) => {
    if (err) { res.writeHead(404); return res.end('Not found'); }
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

function isRecord(value) { return !!value && typeof value === 'object' && !Array.isArray(value); }
function validDataDoc(d) {
  return isRecord(d) && Array.isArray(d.items) && d.items.every(isRecord) &&
    Array.isArray(d.tx) && d.tx.every(isRecord) && isRecord(d.settings) &&
    Array.isArray(d.suppliers) && d.suppliers.every(isRecord);
}
function validBackup(d) {
  return isRecord(d) && d.backupFormat === 'StockFlow' &&
    (Number(d.backupFormatVersion) === 1 || Number(d.backupFormatVersion) === 2) &&
    Array.isArray(d.items) && d.items.every(isRecord) && Array.isArray(d.tx) && d.tx.every(isRecord) &&
    isRecord(d.settings) && (d.suppliers === undefined || Array.isArray(d.suppliers) && d.suppliers.every(isRecord));
}

// Writes a user's data. The If-Match revision must equal the stored revision, so two
// windows cannot overwrite each other. BEGIN IMMEDIATE serialises concurrent writers.
function writeUserData(userId, doc, expectedRev) {
  db.exec('BEGIN IMMEDIATE');
  try {
    const cur = db.prepare('SELECT rev FROM user_data WHERE user_id=?').get(userId);
    const curRev = cur ? cur.rev : 0;
    if (expectedRev !== null && curRev !== expectedRev) {
      db.exec('ROLLBACK');
      return { conflict: true, rev: curRev };
    }
    const newRev = curRev + 1;
    db.prepare(`INSERT INTO user_data(user_id,rev,json,updated_at) VALUES(?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET rev=excluded.rev, json=excluded.json, updated_at=excluded.updated_at`)
      .run(userId, newRev, JSON.stringify(doc), nowIso());
    db.exec('COMMIT');
    return { rev: newRev };
  } catch (e) {
    try { db.exec('ROLLBACK'); } catch (_) {}
    throw e;
  }
}

async function sendReset(user, token) {
  const link = BASE_URL + '/auth.html?token=' + encodeURIComponent(token);
  const text = 'Hello ' + user.name + ',\n\nUse this link to choose a new StockFlow password. It works for ' + RESET_MINUTES +
    ' minutes and can be used once:\n\n' + link + '\n\nIf you did not ask for this, you can ignore this email. Your password will not change.\n';
  if (!SMTP) {
    console.warn('[email not configured] Password reset link for ' + user.email + ': ' + link);
    return;
  }
  await sendMail(SMTP, { to: user.email, subject: 'Reset your StockFlow password', text });
}

async function handle(req, res) {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname, m = req.method;
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'same-origin');
  const ip = (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || 'unknown';

  if (m === 'GET' && p === '/') return sendFile(res, 'index.html', 'text/html; charset=utf-8');
  if (m === 'GET' && (p === '/dashboard' || p === '/dashboard.html')) {
    if (!currentUser(req)) { res.writeHead(302, { Location: '/auth.html' }); return res.end(); }
    return sendFile(res, 'dashboard.html', 'text/html; charset=utf-8');
  }
  if (m === 'GET' && p === '/auth.html') return sendFile(res, 'auth.html', 'text/html; charset=utf-8');
  if (m === 'GET' && p === '/manifest.webmanifest') return sendFile(res, 'manifest.webmanifest', 'application/manifest+json; charset=utf-8');
  if (m === 'GET' && p === '/favicon.svg') return sendFile(res, 'favicon.svg', 'image/svg+xml');
  if (m === 'GET' && p === '/favicon.ico') { res.writeHead(204, { 'Cache-Control': 'public, max-age=86400' }); return res.end(); }

  if (m === 'GET' && p === '/api/me') {
    const u = currentUser(req);
    return u ? send(res, 200, { user: u }) : send(res, 401, { error: 'Not signed in.' });
  }

  if (m === 'POST' && p === '/api/profile') {
    const sessionUser = currentUser(req);
    if (!sessionUser) return send(res, 401, { error: 'Sign in to continue.' });
    if (limited('profile:' + sessionUser.id, 12, 3600000)) throw httpErr(429, 'Too many account changes. Try again later.');
    const b = await readJSON(req);
    const currentPassword = String(b.currentPassword || '');
    if (!currentPassword || currentPassword.length > 200) throw httpErr(400, 'Enter your current password to confirm these changes.');
    const stored = db.prepare('SELECT pass_hash FROM users WHERE id=?').get(sessionUser.id);
    if (!stored || !(await verifyPassword(currentPassword, stored.pass_hash))) throw httpErr(403, 'Your current password is incorrect.');
    const name = validName(b.name); if (!name) throw httpErr(400, 'Name must be 2 to 80 characters.');
    const email = validEmail(b.email); if (!email) throw httpErr(400, 'Enter a valid email address.');
    const storeName = String(b.storeName || '').trim();
    if (storeName.length > 100) throw httpErr(400, 'Store name must be 100 characters or fewer.');
    let nextHash = stored.pass_hash;
    if (b.newPassword) {
      validPassword(b.newPassword);
      if (b.newPassword === currentPassword) throw httpErr(400, 'Choose a new password different from your current password.');
      nextHash = await hashPassword(b.newPassword);
    }
    try {
      db.prepare('UPDATE users SET name=?, email=?, store_name=?, pass_hash=? WHERE id=?').run(name, email, storeName, nextHash, sessionUser.id);
    } catch (e) {
      if (String(e.message || '').includes('UNIQUE')) throw httpErr(409, 'That email address is already in use.');
      throw e;
    }
    if (b.newPassword) {
      const token = parseCookies(req).sf_session;
      db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(sessionUser.id, sha(token || ''));
    }
    return send(res, 200, { ok: true, user: { id: sessionUser.id, name, email, storeName } });
  }

  if (m === 'POST' && p === '/api/register') {
    if (limited('reg:' + ip, REG_PER_HOUR, 3600000)) throw httpErr(429, 'Too many attempts. Try again later.');
    const b = await readJSON(req);
    const name = validName(b.name); if (!name) throw httpErr(400, 'Enter your name (2 to 80 characters).');
    const email = validEmail(b.email); if (!email) throw httpErr(400, 'Enter a valid email address.');
    const pw = validPassword(b.password);
    if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) throw httpErr(409, 'An account with this email already exists. Sign in instead.');
    const hash = await hashPassword(pw);
    const info = db.prepare('INSERT INTO users(name,email,pass_hash,created_at) VALUES(?,?,?,?)').run(name, email, hash, nowIso());
    setSessionCookie(res, createSession(Number(info.lastInsertRowid)));
    return send(res, 201, { user: { id: Number(info.lastInsertRowid), name, email } });
  }

  if (m === 'POST' && p === '/api/login') {
    const b = await readJSON(req);
    const email = validEmail(b.email) || '';
    if (limited('login:' + ip + ':' + email, LOGIN_PER_15MIN, 900000) || limited('loginip:' + ip, LOGIN_PER_15MIN * 6, 900000)) throw httpErr(429, 'Too many sign-in attempts. Wait 15 minutes and try again.');
    const u = email ? db.prepare('SELECT id,name,email,pass_hash FROM users WHERE email=?').get(email) : null;
    const ok = await verifyPassword(String(b.password || ''), u ? u.pass_hash : await dummy());
    if (!u || !ok) throw httpErr(401, 'Email or password is incorrect.');
    setSessionCookie(res, createSession(u.id));
    return send(res, 200, { user: { id: u.id, name: u.name, email: u.email } });
  }

  if (m === 'POST' && p === '/api/logout') {
    const tok = parseCookies(req).sf_session;
    if (tok) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(tok));
    clearSessionCookie(res);
    return send(res, 200, { ok: true });
  }

  if (m === 'POST' && p === '/api/forgot') {
    const b = await readJSON(req);
    const email = validEmail(b.email);
    const generic = { ok: true, message: 'If an account exists for that email, a reset link has been sent. Check your inbox and spam folder.' };
    if (!email || limited('forgot:' + email, 5, 3600000) || limited('forgotip:' + ip, 30, 3600000)) return send(res, 200, generic);
    const u = db.prepare('SELECT id,name,email FROM users WHERE email=?').get(email);
    if (u) {
      db.prepare('DELETE FROM reset_tokens WHERE user_id=? AND used=0').run(u.id);
      const token = crypto.randomBytes(32).toString('base64url');
      db.prepare('INSERT INTO reset_tokens(token_hash,user_id,expires_at) VALUES(?,?,?)').run(sha(token), u.id, now() + RESET_MINUTES * 60000);
      try { await sendReset(u, token); }
      catch (e) { console.error('Reset email failed for ' + email + ': ' + e.message); }
    }
    return send(res, 200, generic);
  }

  if (m === 'POST' && p === '/api/reset') {
    if (limited('reset:' + ip, 20, 3600000)) throw httpErr(429, 'Too many attempts. Try again later.');
    const b = await readJSON(req);
    const pw = validPassword(b.password);
    const row = db.prepare('SELECT user_id, expires_at, used FROM reset_tokens WHERE token_hash=?').get(sha(String(b.token || '')));
    if (!row || row.used || row.expires_at < now()) throw httpErr(400, 'This reset link is invalid or has expired. Request a new one.');
    const hash = await hashPassword(pw);
    db.exec('BEGIN IMMEDIATE');
    db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(hash, row.user_id);
    db.prepare('UPDATE reset_tokens SET used=1 WHERE token_hash=?').run(sha(String(b.token)));
    db.prepare('DELETE FROM sessions WHERE user_id=?').run(row.user_id);
    db.exec('COMMIT');
    return send(res, 200, { ok: true, message: 'Your password has been changed. Sign in with the new password.' });
  }

  if (p === '/api/data' || p === '/api/export' || p === '/api/import' || p.startsWith('/api/safety/')) {
    const u = currentUser(req);
    if (!u) return send(res, 401, { error: 'Sign in to continue.' });

    if (m === 'GET' && p === '/api/data') {
      const row = db.prepare('SELECT rev, json FROM user_data WHERE user_id=?').get(u.id);
      return send(res, 200, row ? '{"rev":' + row.rev + ',"data":' + row.json + '}' : '{"rev":0,"data":null}');
    }
    if (m === 'PUT' && p === '/api/data') {
      const ifMatch = req.headers['if-match'];
      if (ifMatch === undefined || !/^\d+$/.test(String(ifMatch))) throw httpErr(428, 'Missing revision.');
      const doc = await readJSON(req);
      if (!validDataDoc(doc)) throw httpErr(400, 'Data is not in the StockFlow format.');
      const r = writeUserData(u.id, doc, Number(ifMatch));
      if (r.conflict) return send(res, 409, { error: 'Your data was changed in another window or device.', rev: r.rev });
      return send(res, 200, { rev: r.rev });
    }
    if (m === 'GET' && p === '/api/export') {
      const row = db.prepare('SELECT rev, json FROM user_data WHERE user_id=?').get(u.id);
      const d = row ? JSON.parse(row.json) : { items: [], tx: [], settings: {}, suppliers: [] };
      const file = Object.assign({ backupFormat: 'StockFlow', backupFormatVersion: 2, exportedAt: nowIso() }, d);
      const name = 'stockflow-backup-' + new Date().toISOString().slice(0, 10) + '.json';
      return send(res, 200, JSON.stringify(file, null, 2), { 'Content-Disposition': 'attachment; filename="' + name + '"', 'Content-Type': 'application/json' });
    }
    if (m === 'POST' && p === '/api/import') {
      const b = await readJSON(req);
      if (!validBackup(b)) throw httpErr(400, 'This is not a valid StockFlow backup file.');
      const doc = { items: b.items, tx: b.tx, settings: b.settings, suppliers: Array.isArray(b.suppliers) ? b.suppliers : [] };
      const ifMatch = req.headers['if-match'];
      if (ifMatch !== undefined && !/^\d+$/.test(String(ifMatch))) throw httpErr(428, 'Invalid revision. Reload your data and try again.');
      const cur = db.prepare('SELECT json FROM user_data WHERE user_id=?').get(u.id);
      if (cur) db.prepare(`INSERT INTO safety(user_id,key,json,saved_at) VALUES(?,?,?,?) ON CONFLICT(user_id,key) DO UPDATE SET json=excluded.json, saved_at=excluded.saved_at`).run(u.id, 'before_import', cur.json, nowIso());
      const r = writeUserData(u.id, doc, ifMatch === undefined ? null : Number(ifMatch));
      if (r.conflict) return send(res, 409, { error: 'Your data changed before the restore completed. Reload and try again.', rev: r.rev });
      return send(res, 200, { ok: true, rev: r.rev, items: doc.items.length, tx: doc.tx.length });
    }
    if (m === 'PUT' && p.startsWith('/api/safety/')) {
      const key = decodeURIComponent(p.slice('/api/safety/'.length));
      if (!SAFETY_KEYS.includes(key)) throw httpErr(400, 'Unknown safety copy.');
      const body = await readJSON(req);
      db.prepare(`INSERT INTO safety(user_id,key,json,saved_at) VALUES(?,?,?,?) ON CONFLICT(user_id,key) DO UPDATE SET json=excluded.json, saved_at=excluded.saved_at`).run(u.id, key, JSON.stringify(body), nowIso());
      return send(res, 200, { ok: true });
    }
  }

  return send(res, 404, { error: 'Not found.' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(err => {
    const status = err.status || 500;
    if (status === 500) console.error(new Date().toISOString(), err);
    if (!res.headersSent) send(res, status, { error: status === 500 ? 'Something went wrong on the server. Try again.' : err.message });
    else res.end();
  });
});

// Remove expired sessions and reset links once an hour.
setInterval(() => {
  db.prepare('DELETE FROM sessions WHERE expires_at<?').run(now());
  db.prepare('DELETE FROM reset_tokens WHERE expires_at<? OR used=1').run(now());
}, 3600000).unref();

server.listen(PORT, () => {
  console.log('StockFlow server listening on port ' + PORT + ' (' + BASE_URL + ')');
  console.log(SMTP ? 'Email: SMTP via ' + SMTP.host + ':' + SMTP.port : 'Email: NOT configured. Reset links will be printed to the console only.');
});
module.exports = { server, db };
