'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const vulnerable = require('./vulnerable.js');
const secure = require('./secure.js');

function get(port, path) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: 'GET' },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString('utf-8'),
          })
        );
      }
    );
    req.on('error', reject);
    req.end();
  });
}

const payload = '%3Cscript%3Ealert(1)%3C%2Fscript%3E'; // <script>alert(1)</script> url-encoded
const path = `/search?q=${payload}`;

test('vulnerable: raw <script> reaches the response', async () => {
  const r = await get(4201, path);
  assert.equal(r.status, 200);
  assert.ok(r.body.includes('<script>alert(1)</script>'),
    'response should contain the unsanitized script tag — the bug');
});

test('vulnerable: no Content-Security-Policy is set', async () => {
  const r = await get(4201, path);
  assert.equal(r.headers['content-security-policy'], undefined);
});

test('secure: <script> tags are HTML-encoded', async () => {
  const r = await get(4202, path);
  assert.equal(r.status, 200);
  assert.equal(r.body.includes('<script>alert(1)</script>'), false,
    'response must not contain a raw script tag');
  assert.ok(r.body.includes('&lt;script&gt;'));
});

test('secure: a strict CSP is set', async () => {
  const r = await get(4202, path);
  const csp = r.headers['content-security-policy'];
  assert.ok(csp);
  assert.ok(/default-src 'self'/.test(csp));
  assert.ok(/object-src 'none'/.test(csp));
});

test('secure: X-Content-Type-Options: nosniff is set', async () => {
  const r = await get(4202, path);
  assert.equal(r.headers['x-content-type-options'], 'nosniff');
});

test.after(async () => {
  for (const s of [vulnerable.server, secure.server]) {
    if (s && s.listening) await new Promise((r) => s.close(() => r()));
  }
});
