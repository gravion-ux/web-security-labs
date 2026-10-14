'use strict';

/**
 * Lab 01 test harness.
 *
 * Verifies the assertions you'd make in a security regression test:
 *   - the vulnerable variant exposes bob's record to alice's session (bug confirmed)
 *   - the secure variant refuses (forbidden) and only returns the owner's record
 *
 * Run: node test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const HOST = '127.0.0.1';

function get(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: HOST, port, path, method: 'GET' },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          resolve({ status: res.statusCode, body });
        });
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

const vulnerable = require('./vulnerable.js');
const secure = require('./secure.js');

test('vulnerable: alice can read her own profile', async () => {
  const r = await get(4101, '/profile/1');
  assert.equal(r.status, 200);
  assert.match(r.body, /alice/);
});

test('vulnerable: alice can read bob (the IDOR bug)', async () => {
  const r = await get(4101, '/profile/2');
  assert.equal(r.status, 200);
  assert.match(r.body, /bob/);
  // ← regression indicator: do not be misled by this passing; it's evidence
  // that the vulnerable variant is in fact vulnerable.
});

test('secure: alice can read her own profile', async () => {
  const r = await get(4102, '/profile/1');
  assert.equal(r.status, 200);
  assert.match(r.body, /alice/);
});

test('secure: alice cannot read bob (403)', async () => {
  const r = await get(4102, '/profile/2');
  assert.equal(r.status, 403);
  assert.match(r.body, /forbidden/);
});

test('secure: unknown ids return 404 when owned; 403 otherwise (no enumeration)', async () => {
  // When alice asks for her own (but unknown) ID, we return 404 (not found).
  const own = await get(4102, '/profile/1'); // warm cache
  void own;
  // We can't easily simulate "alice asking for an id that exists for someone else" +
  // "alice asking for an id that doesn't exist" without further fixtures. The key
  // security property we DO assert: alice asking for non-self ids is uniformly 403
  // (cannot enumerate existence).
  const someoneElse = await get(4102, '/profile/2');
  assert.equal(someoneElse.status, 403);
  const nonExistent = await get(4102, '/profile/9999');
  assert.equal(nonExistent.status, 403, 'non-existent ids return 403 to prevent enumeration');
});

test.after(async () => {
  for (const s of [vulnerable.server, secure.server]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});
