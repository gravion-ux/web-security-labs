# Lab 04 — Business Logic Flaw

## What it is

Logic flaws live in the application's own rules — not in escaping,
parsing, or cryptography. They are the reason you cannot "securely"
test an API by fuzzing fields: the bug is in the **state machine the
server believes it is operating in** versus the one the attacker
forces.

OWASP **A04:2021 — Insecure Design**. (Sometimes miscategorized under
A01 — both apply.)

## The vulnerable code (`vulnerable.js`)

```js
let subtotal = Number(body.subtotal);                  // trusted!
const coupon = String(body.coupon || '');
const discounted = applyCoupon(subtotal, coupon);
res.end(JSON.stringify({ status: 'SOLD', total: discounted }));
```

Two flaws:

1. **`subtotal` comes from the client.** A user picks their own price.
2. **No clamping** on the discounted amount. With a `HALFOFF` coupon
   plus a manipulated subtotal, an attacker can drive the price to
   whatever they want — including a negative number that flips the sign
   of any follow-up "refund" or stored balance.

## Confirming the bug

```bash
node vulnerable.js &
curl -X POST http://127.0.0.1:4401/checkout -H 'content-type: application/json' \
     -d '{"subtotal":-100,"coupon":""}'
# → {"status":"SOLD","subtotal":-100,"coupon":"","total":-100}

curl -X POST http://127.0.0.1:4401/checkout -H 'content-type: application/json' \
     -d '{"subtotal":0.01,"coupon":""}'
# → {"status":"SOLD","total":0.01}
```

## The secure code (`secure.js`)

Three changes:

1. **Subtotal is recomputed** from the actual product catalog — never
   read from the request.
2. The coupon's pre-conditions are explicit (`subtotal ≥ 50` for HALFOFF).
3. The result is clamped: `Math.max(0, discounted)` so a malformed
   promotion can never make the total negative.

```js
function checkoutTotal(subtotal, couponCode) {
  const discounted = applyCoupon(subtotal, couponCode);
  return Math.max(0, discounted);
}
```

## Confirming the fix

```bash
node secure.js &
curl -X POST http://127.0.0.1:4402/checkout -H 'content-type: application/json' \
     -d '{"items":[{"sku":"C","qty":1}],"coupon":"HALFOFF"}'
# → {"status":"SOLD","subtotal":100,"coupon":"HALFOFF","total":50}

curl -X POST http://127.0.0.1:4402/checkout -H 'content-type: application/json' \
     -d '{"subtotal":-1000,"items":[{"sku":"C","qty":1}],"coupon":""}'
# → {"status":"SOLD","subtotal":100,"coupon":null,"total":100}
# (the bogus subtotal is ignored)
```

## Remediation checklist

- [x] Server-side recomputation of all monetary values.
- [x] Numeric clamping on every output that reaches billing.
- [x] Explicit pre-conditions on every promotion.
- [ ] Threat model the unhappy paths (race conditions, concurrent
      coupon stacking, negative-balance playthrough).
- [ ] Idempotency keys on checkout to prevent double-charge on retry.
- [ ] Audit trail with integrity (signed events) for high-value flows.
- [ ] Unit tests for every coupon combination.

## Ethics

Use these lab servers only on `127.0.0.1`. Logic flaws are often
specific to one business; do not assume the pattern transfers without
explicit test coverage on the targeted system.
