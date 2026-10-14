# Lab 03 — Broken Authentication

## What it is

A request that authenticates the user purely from a client-supplied
cookie value (`uid`) — with no signature, no server-side session, and
no role check — is trivially bypassed.

OWASP **A07:2021 — Identification and Authentication Failures**.

## The vulnerable code (`vulnerable.js`)

```js
const cookies = parseCookies(req.headers.cookie);
const uid = cookies.uid;
const user = uid ? users[Number.parseInt(uid, 10)] : null;
if (!user) { /* 401 */ } else { /* 200 admin */ }
```

The cookie carries the user id in plaintext. There is no signed token,
no expiration, no role-based authorization check.

## Confirming the bug

```bash
node vulnerable.js &
curl -b 'uid=2' http://127.0.0.1:4301/admin    # bob (a user) gets admin
curl -b 'uid=3' http://127.0.0.1:4301/admin    # eve (an admin) gets admin
```

In the secure variant, only eve should reach /admin.

## The secure code (`secure.js`)

```js
// Server-side session table — cookie carries only an opaque id.
const sessions = new Map();
const sid = `sess_${crypto.randomBytes(16).toString('hex')}`;
sessions.set(sid, u);
```

Then:

```js
const user = sessions.get(cookies.sid);
if (!user)              → 401
if (user.role !== 'admin') → 403
else                    → 200
```

## Confirming the fix

```bash
node secure.js
# (note the logged session ids for alice, bob, eve)

curl -b 'sid=<eve-sid>'    http://127.0.0.1:4302/admin   # 200
curl -b 'sid=<bob-sid>'    http://127.0.0.1:4302/admin   # 403 forbidden
curl -b 'sid=evil'         http://127.0.0.1:4302/admin   # 401 unknown
```

## Remediation checklist

- [x] Server-side session, not client-trusted identity.
- [x] Opaque ≥128-bit session id with `HttpOnly; Secure; SameSite=Lax`.
- [x] Explicit authorization check on every privileged endpoint.
- [ ] Idle and absolute session timeouts.
- [ ] Re-issue session id on privilege change (login, role grant).
- [ ] Rate-limit failed logins; lock out / back off on credential stuffing.
- [ ] Multi-factor authentication for admin actions.

## Ethics

These lab servers bind to `127.0.0.1`. Do not adapt this code to test
authentication on systems you don't own.
