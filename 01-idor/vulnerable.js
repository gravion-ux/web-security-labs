'use strict';

/**
 * Lab 01 — Insecure Direct Object Reference (IDOR)
 *
 * Educational vulnerable server.
 *
 * Scenario
 * --------
 *   A naive profile API exposes GET /profile/:id which returns the profile
 *   record for any numeric ID — without checking that the requesting user
 *   owns the profile. A user who logs in as alice (id=1) can request
 *   /profile/2 and read bob's data.
 *
 * Why it's vulnerable
 * -------------------
 *   The handler trusts client-supplied IDs without an authorization check.
 *   This is the textbook OWASP A01:2021 Broken Access Control case.
 *
 * How to run
 * ----------
 *   node vulnerable.js
 *   curl http://127.0.0.1:4101/profile/1
 *   # alice's profile leaks
 *   curl http://127.0.0.1:4101/profile/2
 *   # bob's profile also leaks (the bug)
 *
 * Compare with: secure.js
 *
 * Do NOT expose this on a routable network. Bind to 127.0.0.1 only.
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4101', 10);

const users = {
  1: { id: 1, name: 'alice', email: 'alice@example.test' },
  2: { id: 2, name: 'bob',   email: 'bob@example.test'   },
  3: { id: 3, name: 'carol', email: 'carol@example.test' },
};

// pretend "session" — in a real app this comes from a signed cookie or token.
const session = { userId: 1 };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  // GET /profile/:id — VULNERABLE: no ownership check
  const idMatch = /^\/profile\/(\d+)\/?$/.exec(url.pathname);
  if (idMatch) {
    const id = Number.parseInt(idMatch[1], 10);
    const record = users[id];
    if (!record) {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
      return;
    }
    // BUG: any caller may request any id; should compare id to session.userId
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(record));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(PORT, HOST, () => {
  console.log(`[lab-01-vulnerable] http://${HOST}:${PORT}/ (session userId=${session.userId})`);
});

module.exports = { server, session };
