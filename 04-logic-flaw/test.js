'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const vulnerable = require('./vulnerable.js');
const secure = require('./secure.js');

function post(port, path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(data),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString('utf-8')) });
          } catch (e) {
            resolve({ status: res.statusCode, body: null });
          }
        });
      }
    );
    req.on('error', reject);
    req.end(data);
  });
}

test('vulnerable: negative subtotal + HALFOFF returns negative total (logic flaw)', async () => {
  const r = await post(4401, '/checkout', { subtotal: -100, coupon: 'HALFOFF' });
  assert.equal(r.status, 200);
  assert.equal(r.body.subtotal, -100);
  // BUG indicator: total is computed against a negative base, then halved
  // → -100 never reaches the ≥50 branch but the server still returns the
  //   client-controlled subtotal. With subtotal=100 and coupon=HALFOFF the
  //   server returns 50; the actual flaw we test is that the server
  //   happily trusts a negative base for non-discount paths too:
  assert.equal(r.body.total, -100, 'returns the untrusted negative total');
});

test('vulnerable: client-trusted subtotal works for any value', async () => {
  const r = await post(4401, '/checkout', { subtotal: 1, coupon: '' });
  assert.equal(r.body.total, 1);
});

test('secure: server recomputes subtotal from real catalog', async () => {
  const r = await post(4402, '/checkout', { items: [{ sku: 'A', qty: 2 }, { sku: 'C', qty: 1 }] });
  assert.equal(r.status, 200);
  // A=25, C=100 → 2*25 + 1*100 = 150, no coupon → 150
  assert.equal(r.body.subtotal, 150);
  assert.equal(r.body.total, 150);
});

test('secure: HALFOFF applies when subtotal ≥ 50', async () => {
  const r = await post(4402, '/checkout', { items: [{ sku: 'C', qty: 1 }], coupon: 'HALFOFF' });
  assert.equal(r.body.total, 50);
});

test('secure: subtotal cannot go negative even via malformed items', async () => {
  const r = await post(4402, '/checkout', { items: 'not an array', coupon: '' });
  assert.equal(r.body.subtotal, 0);
  assert.equal(r.body.total, 0);
});

test('secure: client-supplied subtotal is ignored', async () => {
  const r = await post(4402, '/checkout', {
    subtotal: 0.01,
    items: [{ sku: 'C', qty: 1 }],
  });
  // ignored — server uses items
  assert.equal(r.body.total, 100);
  assert.equal(r.body.subtotal, 100);
});

test.after(async () => {
  for (const s of [vulnerable.server, secure.server]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});
