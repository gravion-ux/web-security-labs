# Lab 01 — Insecure Direct Object Reference (IDOR)

## What it is

An IDOR (also written BOLA — Broken Object Level Authorization) is what happens
when a server uses a client-supplied identifier to look up a record **without
checking that the caller is allowed to access that record**.

OWASP classifies this under **A01:2021 — Broken Access Control**.

## The vulnerable code

`vulnerable.js` exposes `GET /profile/:id` which simply returns whatever record
matches the id. There is no ownership check.

```js
const id = Number.parseInt(idMatch[1], 10);
const record = users[id];           // any caller can ask for any id
res.end(JSON.stringify(record));
```

## How to confirm the bug

```bash
node vulnerable.js &
node -e "
  const http = require('http');
  for (const id of [1, 2, 3]) {
    http.get('http://127.0.0.1:4101/profile/' + id, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => console.log('profile', id, '→', body));
    });
  }
"
```

You'll see `alice`, `bob`, and `carol` returned regardless of who is asking.

## The secure code

`secure.js` adds a single server-side check:

```js
if (requestedId !== session.userId) {
  res.writeHead(403); res.end('{"error":"forbidden"}'); return;
}
```

## How to confirm the fix

```bash
node secure.js &
curl -s http://127.0.0.1:4102/profile/1 ; echo   # 200 + alice's profile
curl -s http://127.0.0.1:4102/profile/2 ; echo   # 403 forbidden
curl -s http://127.0.0.1:4102/profile/999 ; echo # 404 not found
```

## Why the test suite matters

`test.js` codifies the regression check: the vulnerable variant *must* expose
bob's record when alice's session is asking (this proves the test is actually
exercising the bug), and the secure variant *must* refuse with a 403.

If a future refactor accidentally reintroduces the IDOR, the `secure: alice
cannot read bob (403)` test will fail loudly.

## Remediation checklist

- [x] Enforce ownership **server-side**, not in the client.
- [x] Return `403 Forbidden`, never `404`, when the requester is authenticated
      but lacks permission — this avoids leaking the existence of resources
      they aren't allowed to see.
- [ ] For multi-tenant systems, also verify the resource is in the same
      tenant as the requester.
- [ ] Prefer opaque, non-enumerable IDs (`UUID v4`) so guessing ids is harder.
      (Defence in depth — never the primary control.)
- [ ] Log authorization failures for monitoring and incident response.

## Files

| file | purpose |
| --- | --- |
| `vulnerable.js` | intentionally vulnerable server |
| `secure.js`     | hardened server with ownership check |
| `test.js`       | regression suite proving bug + fix |

## Ethics

These lab servers bind to `127.0.0.1`. Do not change the bind address to
`0.0.0.0`. Do not point these tests at production systems.
