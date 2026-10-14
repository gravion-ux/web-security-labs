'use strict';

/**
 * Lab 04 — Business-logic flaw (secure variant).
 *
 * Fix
 * ---
 *   1. Subtotal is recomputed from the actual product catalog — never
 *      trusted from the request body.
 *   2. Coupon application has explicit pre-conditions and clamps the result
 *      to [0, subtotal] (a discount cannot make the total negative).
 *   3. The server returns the authoritative total; the client never picks it.
 *
 * Run
 * ---
 *   node secure.js
 *
 *   curl -X POST http://127.0.0.1:4402/checkout -H 'content-type: application/json' \
 *     -d '{"items":[{"sku":"A","qty":1},{"sku":"B","qty":1}],"coupon":"HALFOFF"}'
 *     # subtotal server-side is recomputed; discount applied; total >= 0
 */

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.PORT || '4402', 10);

const PRICES = {
  A: 25,
  B: 30,
  C: 100,
};

function clampNonNegative(n) {
  if (!Number.isFinite(n) || n < 0) return 0;
  return n;
}

function computeSubtotal(items) {
  if (!Array.isArray(items)) return 0;
  let sum = 0;
  for (const item of items) {
    if (!item || typeof item !== 'object') continue;
    const sku = String(item.sku || '');
    const qty = Number(item.qty);
    if (!Number.isFinite(qty) || qty <= 0) continue;
    if (!(sku in PRICES)) continue;
    sum += PRICES[sku] * qty;
  }
  return clampNonNegative(sum);
}

function applyCoupon(subtotal, code) {
  if (code === 'HALFOFF' && subtotal >= 50) return subtotal * 0.5;
  return subtotal;
}

function checkoutTotal(subtotal, couponCode) {
  // Defense in depth: clamp the result so a discount cannot produce a
  // negative total. This protects against any future coupon that *adds*
  // (e.g. a "5% extra" promotion) and against fractional rounding errors.
  const discounted = applyCoupon(subtotal, couponCode);
  return Math.max(0, discounted);
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

const secureServer = http.createServer(async (req, res) => {
  if (req.method === 'POST' && req.url === '/checkout') {
    let body;
    try { body = await readJsonBody(req); }
    catch { res.writeHead(400, { 'content-type': 'application/json' }); res.end('{"error":"bad_json"}'); return; }

    // FIX: never trust client-supplied subtotal — recompute it server-side.
    const subtotal = computeSubtotal(body.items);
    const couponCode = String(body.coupon || '');
    const total = checkoutTotal(subtotal, couponCode);

    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({
      status: 'SOLD',
      subtotal,
      coupon: couponCode || null,
      total,
    }));
    return;
  }
  res.writeHead(404).end('not found');
});
secureServer.listen(PORT, HOST, () => console.log(`[lab-04-secure] POST http://${HOST}:${PORT}/checkout`));

module.exports = { server: secureServer };
