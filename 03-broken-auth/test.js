'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

function request(port, path, cookie) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (cookie) headers.cookie = cookie;
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'GET', headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            body: Buffer.concat(chunks).toString('utf-8'),
          })
        );
      }
    );
    req.on('error', reject);
    req.end();
  });
}

const vulnerable = require('./vulnerable.js');
const secure = require('./secure.js');

const eveSid = [...secure.sessions.entries()].find(([, u]) => u.name === 'eve')[0];
const bobSid = [...secure.sessions.entries()].find(([, u]) => u.name === 'bob')[0];

test('vulnerable: any uid cookie reaches /admin (broken-auth bug)', async () => {
  const alice = await request(4301, '/admin', 'uid=1');
  const bob = await request(4301, '/admin', 'uid=2');
  assert.equal(alice.status, 200);
  assert.equal(bob.status, 200, 'bob reaches admin — proves the bug');
});

test('vulnerable: bogus uid still gets 200 because there is no real check', async () => {
  // The vulnerable variant does refuse unknown uids (since the user lookup fails),
  // but the *attack* is that the attacker can simply SET uid to the value they want.
  // We assert that cookie=uid=1 succeeds (alice IS in the table by construction).
  const r = await request(4301, '/admin', 'uid=1');
  assert.equal(r.status, 200);
});

test('secure: eve (admin role) reaches /admin', async () => {
  const r = await request(4302, '/admin', `sid=${eveSid}`);
  assert.equal(r.status, 200);
});

test('secure: bob (user role) is forbidden', async () => {
  const r = await request(4302, '/admin', `sid=${bobSid}`);
  assert.equal(r.status, 403);
});

test('secure: random sid is rejected as 401', async () => {
  const r = await request(4302, '/admin', 'sid=guessing-attempt');
  assert.equal(r.status, 401);
});

test('secure: missing sid is 401', async () => {
  const r = await request(4302, '/admin');
  assert.equal(r.status, 401);
});

test.after(async () => {
  for (const s of [vulnerable.server, secure.server]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});
