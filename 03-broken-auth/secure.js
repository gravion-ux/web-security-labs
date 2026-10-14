'use strict';

/**
 * Lab 03 — Broken authentication (secure variant).
 *
 * Fix
 * ---
 *   - Sessions are server-side, stored out-of-band.
 *   - The cookie carries an opaque session id that the attacker cannot
 *     guess (≥128 bits of entropy).
 *   - Privileged pages require both an authenticated session AND a
 *     server-side role check.
 *
 * Run
 * ---
 *   node secure.js
 *
 *   # Server boots and seeds three users:
 *   #   alice (user) gets session id 'sess_alice'
 *   #   bob   (user) gets session id 'sess_bob'
 *   #   eve   (admin) gets session id 'sess_eve'
 *
 *   curl -b 'sid=sess_bob'   http://127.0.0.1:4302/admin  # 403 (not admin)
 *   curl -b 'sid=sess_eve'   http://127.0.0.1:4302/admin  # 200 admin console
 *   curl -b 'sid=evil'       http://127.0.0.1:4302/admin  # 401
 */

const http = require('node:http');
const crypto = require('node:crypto');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4302', 10);

const users = {
  alice: { name: 'alice', role: 'user'  },
  bob:   { name: 'bob',   role: 'user'  },
  eve:   { name: 'eve',   role: 'admin' },
};

// server-side session table (in production: signed cookies or Redis)
const sessions = new Map();
for (const u of Object.values(users)) {
  // 32 random bytes hex = 256 bits, served over /login in reality
  const sid = `sess_${crypto.randomBytes(16).toString('hex')}`;
  sessions.set(sid, u);
}

function sessionFor(cookies) {
  const sid = cookies.sid;
  if (!sid || !sessions.has(sid)) return null;
  return sessions.get(sid);
}

function parseCookies(header = '') {
  const out = {};
  for (const part of header.split(/;\s*/)) {
    if (!part) continue;
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i)] = decodeURIComponent(part.slice(i + 1));
  }
  return out;
}

const ADMIN_PAGE = `<h1>admin console</h1><p>privileged actions live here</p>`;

const server = http.createServer((req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const user = sessionFor(cookies);

  if (req.url === '/admin') {
    if (!user) {
      res.writeHead(401, { 'content-type': 'text/plain' });
      res.end('who are you?');
      return;
    }
    // FIX: explicit role-based authorization on the privileged endpoint
    if (user.role !== 'admin') {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(ADMIN_PAGE);
    return;
  }

  if (req.url === '/whoami') {
    if (!user) {
      res.writeHead(401, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_authenticated' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ name: user.name, role: user.role }));
    return;
  }

  res.writeHead(404).end('not found');
});

server.listen(PORT, HOST, () => {
  console.log(`[lab-03-secure] http://${HOST}:${PORT}/admin`);
  console.log('[lab-03-secure] (dev only) sessions seeded for alice, bob, eve:');
  for (const [sid, u] of sessions) {
    console.log(`  ${u.name.padEnd(6)} ${sid}  (role=${u.role})`);
  }
});

module.exports = { server, sessions };
