# Web Security Labs

Hands-on OWASP-style web application security labs. Every lab ships in
**two variants** — `vulnerable.js` (intentionally exploitable, to study the
bug) and `secure.js` (the hardened counterpart) — plus an automated
test suite that proves both behaviors exist and stay separated.

> **Scope statement.** These labs are designed for systems you own or have
> written authorization to test. Every server binds to `127.0.0.1`. Do not
> deploy the vulnerable variant against production, partner, or third-party
> environments. Do not chain these patterns together to attack anything
> beyond the local loopback.

## What's in here

| # | Lab | OWASP | Variants | Test file |
| --- | --- | --- | --- | --- |
| 01 | **IDOR** (Insecure Direct Object Reference)         | A01 Broken Access Control | `01-idor/vulnerable.js`, `01-idor/secure.js` | `01-idor/test.js` |
| 02 | **Reflected XSS** (search endpoint echoes user input) | A03 Injection             | `02-xss/vulnerable.js`, `02-xss/secure.js`     | `02-xss/test.js`     |
| 03 | **Broken Authentication** (`uid` cookie as identity)  | A07 Identification & Auth Failures | `03-broken-auth/vulnerable.js`, `03-broken-auth/secure.js` | `03-broken-auth/test.js` |
| 04 | **Business Logic Flaw** (client-trusted checkout total) | A04 Insecure Design      | `04-logic-flaw/vulnerable.js`, `04-logic-flaw/secure.js` | `04-logic-flaw/test.js` |

Each lab directory also includes an `explain.md` with payloads, evidence,
remediation checklist, and ethical guidance.

## Quick start

You need Node.js 18+ (the test suite uses the built-in `node:test` runner).
Clone this repository and run the whole suite:

```bash
npm install         # not required — no external dependencies
npm test            # runs every lab's test.js in sequence
```

To run a single lab interactively, in two terminals:

```bash
# terminal 1
node 01-idor/vulnerable.js
node 01-idor/secure.js

# terminal 2
node 01-idor/test.js
```

## Why two variants

Each lab ships both a **vulnerable** and a **secure** server. The test
suite asserts:

1. The vulnerable variant exhibits the bug (e.g., bob's profile leaks
   when alice asks for it).
2. The secure variant rejects the same attack with the correct status
   and message.

That pattern means a future refactor that accidentally re-introduces the
bug trips a clearly named test failure that says exactly which assertion
broke — instead of just "the build is red somewhere."

## Project layout

```text
web-security-labs/
├── 01-idor/
│   ├── vulnerable.js
│   ├── secure.js
│   ├── test.js
│   └── explain.md
├── 02-xss/
│   ├── vulnerable.js
│   ├── secure.js
│   ├── test.js
│   └── explain.md
├── 03-broken-auth/
│   ├── vulnerable.js
│   ├── secure.js
│   ├── test.js
│   └── explain.md
├── 04-logic-flaw/
│   ├── vulnerable.js
│   ├── secure.js
│   ├── test.js
│   └── explain.md
├── package.json
└── README.md
```

## Sample run

```text
$ npm test

> web-security-labs@1.0.0 test
> node scripts/run-all-tests.js

[lab-01] PASS (5/5)
[lab-02] PASS (5/5)
[lab-03] PASS (6/6)
[lab-04] PASS (6/6)

22 tests passed, 0 failed, 0 skipped.
```

## What this is **not**

- It is not an exploit pack. There are no exploit scripts, no fuzzers,
  no payload libraries. The vulnerable variants are deliberately small
  and exist only to make the bug reproducible.
- It is not a substitute for manual testing on a real assessment.
  Especially for logic flaws (lab 04), the same pattern reads
  completely differently in the context of a specific product.
- It is not production code. Do not copy `vulnerable.js` into a real
  service.

## Ethics

Use these labs to study how vulnerabilities work and how to fix them.
Apply the patterns to systems you own or are explicitly authorized to
test. When reporting a vulnerability you find elsewhere, follow
coordinated disclosure timelines and avoid any action that could harm
users.

## License

MIT — see [`LICENSE`](./LICENSE).
