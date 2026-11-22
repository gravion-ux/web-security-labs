# Contributing to web-security-labs

Thanks for helping! `web-security-labs` is a set of hands-on OWASP-style
labs. Every lab ships a deliberately **vulnerable** implementation, a
**secure** implementation of the same feature, an explanation, and a
test that proves the vulnerable version is exploitable in the lab and
the secure version is not.

## Ground rules

- **Local-only — hard rule.** The vulnerable code exists to be run on
  your own machine for learning. Never deploy a vulnerable lab to a
  public server, and never point lab payloads at a real website.
- **Pairs, always.** A lab is only complete with both implementations:
  `vulnerable.js` and `secure.js`, differing only in the fix, so the
  lesson is the diff.
- **Zero runtime dependencies.** Node.js standard library only.

## Development setup

Requires Node.js 18 or newer. There is nothing to install.

```bash
git clone https://github.com/gravion-ux/web-security-labs.git
cd web-security-labs
npm test
```

## Running the tests

```bash
npm test          # all labs via scripts/run-all-tests.js
npm run test:01   # a single lab (01-idor, 02-xss, 03-broken-auth, 04-logic-flaw)
npm run run:01-vulnerable   # run a lab app locally to explore it by hand
npm run run:01-secure
```

## Adding a lab

1. Create `NN-name/` with `vulnerable.js`, `secure.js`, `test.js` and a
   `README.md` that explains the vulnerability class, the attack the
   test performs, and the fix — in the style of the existing labs.
2. The test must show the exploit succeeding against the vulnerable
   version and failing against the secure version.
3. Wire the lab into `scripts/run-all-tests.js`, add the `test:NN` and
   `run:NN-*` scripts to `package.json`, and list the lab in the
   top-level README.

## Pull request workflow

1. Fork and branch from `main`: `lab/<lab-name>` or `fix/<short-name>`.
2. Run `npm test` locally — every lab must pass.
3. Open the PR against `main` with: the vulnerability class, what the
   test proves, and what the secure version changes.
4. CI must be green (Node 18, 20 and 22).
5. One lab (or one fix) per PR.
