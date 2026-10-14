'use strict';

/**
 * Lab 04 — Business-logic flaw (vulnerable variant).
 *
 * Scenario
 * --------
 *   A coupon "HALFOFF" should give 50% off a cart with subtotal ≥ $50.
 *   The vulnerable implementation reapplies HALFOFF to *negative* numbers,
 *   so a user can submit an order with a negative subtotal and the server
 *   will *subtract* the discount, charging the customer.
 *
 *   A simpler variant is also embedded: the total is computed in the
 *   client and trusted. By sending a custom `total` field the attacker
 *   picks the final price.
 *
 * Why vulnerable
 * --------------
 *   The server trusts client-supplied prices or accepts discounts on
 *   invalid domain values. The fix moves all monetary calculations
 *   server-side and clamps the inputs.
 *
 * Run
 * ---
 *   node vulnerable.js
 *
 *   curl -X POST http://127.0.0.1:4401/checkout -H 'content-type: application/json' \
 *     -d '{"subtotal":-100,"coupon":"HALFOFF"}'
 *     # → returns total = -50 (negative!) and "SOLD"
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4401', 10);

function applyCoupon(subtotal, code) {
  if (code === 'HALFOFF' && subtotal >= 50) return subtotal * 0.5;
  return subtotal;
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf-8') || '{}')); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

const vulnerableServer = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/checkout') {
    let body;
    try { body = await readJsonBody(req); }
    catch { res.writeHead(400).end('bad json'); return; }

    let subtotal = Number(body.subtotal);
    const coupon = String(body.coupon || '');

    // BUG (1) no upper bound on subtotal — negative values flip the sign of the discount
    // BUG (2) no clamping on the discounted amount
    const discounted = applyCoupon(subtotal, coupon);

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      status: 'SOLD',
      subtotal,
      coupon,
      total: discounted,
    }));
    return;
  }
  res.writeHead(404).end('not found');
});
vulnerableServer.listen(PORT, HOST, () => console.log(`[lab-04-vulnerable] POST http://${HOST}:${PORT}/checkout`));

module.exports = { server: vulnerableServer };
