'use strict';

/**
 * Lab 01 — Secure counterpart.
 *
 * Fix
 * ---
 *   Enforce ownership server-side: the requested profile's id must equal
 *   the session's authenticated userId (or be in the same tenant for
 *   multi-tenant systems).
 *
 *   Beyond identity checks, prefer opaque, non-enumerable IDs (UUID v4)
 *   so guessing is harder — but the real defense is the authorization
 *   rule, not the secrecy of the ID.
 *
 * Run
 * ---
 *   node secure.js
 *   curl -s http://127.0.0.1:4102/profile/2 ; echo
 *   # → 403 forbidden (alice's session tries to read bob's profile)
 *   curl -s http://127.0.0.1:4102/profile/1 ; echo
 *   # → 200 with alice's profile
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4102', 10);

const users = {
  1: { id: 1, name: 'alice', email: 'alice@example.test' },
  2: { id: 2, name: 'bob',   email: 'bob@example.test'   },
  3: { id: 3, name: 'carol', email: 'carol@example.test' },
};

const session = { userId: 1 };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  const idMatch = /^\/profile\/(\d+)\/?$/.exec(url.pathname);
  if (idMatch) {
    const requestedId = Number.parseInt(idMatch[1], 10);

    // FIX: server-side authorization check before serving the record
    if (requestedId !== session.userId) {
      res.writeHead(403, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'forbidden' }));
      return;
    }

    const record = users[requestedId];
    if (!record) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(record));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(PORT, HOST, () => {
  console.log(`[lab-01-secure] http://${HOST}:${PORT}/ (session userId=${session.userId})`);
});

module.exports = { server, session };
