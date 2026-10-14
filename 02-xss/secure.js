'use strict';

/**
 * Lab 02 — Reflected XSS, secure variant.
 *
 * Fix
 * ---
 *   - HTML-encode every untrusted value before it reaches the response.
 *   - Set a Content-Security-Policy that disallows inline scripts.
 *   - Set `X-Content-Type-Options: nosniff` and a strong Content-Type.
 *
 * Run
 * ---
 *   node secure.js
 *   curl -s 'http://127.0.0.1:4202/search?q=<script>alert(1)</script>'
 *   # → body contains the literal &lt;script&gt; ... no script tag
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4202', 10);

function encode(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function renderSearch(query) {
  // FIX: encode before interpolation
  return `<!doctype html><html><body>
    <h1>Search</h1>
    <p>You searched for: <strong>${encode(query)}</strong></p>
  </body></html>`;
}

const secureServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/search') {
    const q = url.searchParams.get('q') ?? '';
    res.writeHead(200, {
      'content-type': 'text/html; charset=utf-8',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'",
    });
    res.end(renderSearch(q));
    return;
  }
  res.writeHead(404).end('not found');
});
secureServer.listen(PORT, HOST, () => console.log(`[lab-02-secure] http://${HOST}:${PORT}/search`));

module.exports = { server: secureServer };
