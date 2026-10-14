'use strict';

/**
 * Lab 02 — Reflected XSS (vulnerable variant).
 *
 * A search endpoint echoes whatever the user typed back into the HTML
 * response without escaping. A crafted query (`?q=<script>alert(1)</script>`)
 * will execute in any browser that renders the response.
 *
 * Why vulnerable
 * --------------
 *   The response builds HTML by template-string interpolation with
 *   attacker-controlled input.
 *
 * Run
 * ---
 *   node vulnerable.js
 *   curl 'http://127.0.0.1:4201/search?q=<script>alert(1)</script>'
 *   # → 200 OK with raw <script> in the body
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4201', 10);

function renderSearch(query) {
  // BUG: query is concatenated into HTML without encoding
  return `<!doctype html><html><body>
    <h1>Search</h1>
    <p>You searched for: <strong>${query}</strong></p>
  </body></html>`;
}

const vulnerableServer = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/search') {
    const q = url.searchParams.get('q') ?? '';
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(renderSearch(q));
    return;
  }
  res.writeHead(404).end('not found');
});
vulnerableServer.listen(PORT, HOST, () => console.log(`[lab-02-vulnerable] http://${HOST}:${PORT}/search`));

module.exports = { server: vulnerableServer };
