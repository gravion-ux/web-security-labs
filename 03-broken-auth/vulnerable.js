'use strict';

/**
 * Lab 03 — Broken authentication (vulnerable variant).
 *
 * Scenario
 * --------
 *   A "remember me" feature is implemented by trusting a `uid` cookie
 *   as the authenticated identity. A request to /admin only checks
 *   that *some* `uid` cookie is present and that the corresponding
 *   user exists. Anyone can set the cookie to 1 (alice) and reach
 *   the admin page — there's no signed token, no signature, no
 *   server-side session validation.
 *
 * Why vulnerable
 * --------------
 *   Authentication state must be unforgeable. A user-supplied cookie
 *   value alone cannot prove identity. The classic fix is a signed,
 *   server-issued session token (HttpOnly cookie holding an opaque id
 *   that the server maps to a session).
 *
 * Run
 * ---
 *   node vulnerable.js
 *   curl -b 'uid=2' http://127.0.0.1:4301/admin      # bob hits admin (bug)
 *   curl -b 'uid=9999' http://127.0.0.1:4301/admin   # unknown user blocked
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4301', 10);

const users = {
  1: { id: 1, name: 'alice', role: 'user'  },
  2: { id: 2, name: 'bob',   role: 'user'  },
  3: { id: 3, name: 'eve',   role: 'admin' },
};

const ADMIN_PAGE = `<h1>admin console</h1><p>privileged actions live here</p>`;

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

const server = http.createServer((req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const uid = cookies.uid;
  const user = uid ? users[Number.parseInt(uid, 10)] : null;

  if (req.url === '/admin') {
    // BUG: trusting a raw cookie value as identity
    if (!user) {
      res.writeHead(401, { 'content-type': 'text/plain' });
      res.end('who are you?');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(ADMIN_PAGE);
    return;
  }

  res.writeHead(404).end('not found');
});

server.listen(PORT, HOST, () => {
  console.log(`[lab-03-vulnerable] http://${HOST}:${PORT}/admin`);
});

module.exports = { server };
