#!/usr/bin/env node
'use strict';

/**
 * Aggregate test runner for web-security-labs.
 *
 * Runs every lab's test file in sequence. Each lab test boots its own
 * servers (vulnerable + secure on different ports) and shuts them down
 * in `test.after()`, so this runner waits synchronously between labs
 * to avoid port collisions.
 *
 * Exit code: 0 if every lab passes, 1 otherwise.
 */

const { spawnSync } = require('node:child_process');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const labs = [
  { id: 'lab-01-idor',          script: '01-idor/test.js' },
  { id: 'lab-02-xss',           script: '02-xss/test.js' },
  { id: 'lab-03-broken-auth',   script: '03-broken-auth/test.js' },
  { id: 'lab-04-logic-flaw',    script: '04-logic-flaw/test.js' },
];

let passed = 0;
let failed = 0;

for (const lab of labs) {
  const t0 = Date.now();
  const result = spawnSync(
    process.execPath,
    [path.join(root, lab.script)],
    { encoding: 'utf-8', timeout: 30_000 }
  );

  const ms = Date.now() - t0;
  const summary = parseSummary(result.stdout + result.stderr);

  if (result.status === 0) {
    passed += 1;
    console.log(
      `[${lab.id}] PASS (${summary.passed}/${summary.total})${
        summary.failed > 0 ? '  with warnings' : ''
      } — ${ms}ms`
    );
  } else {
    failed += 1;
    console.log(`[${lab.id}] FAIL — ${ms}ms`);
    if (summary.failed > 0) {
      console.log(`  → ${summary.failed} failed assertion(s) out of ${summary.total}`);
    }
    if (result.stderr) {
      const trimmed = result.stderr.split(/\r?\n/).slice(0, 6).join('\n');
      console.log(trimmed);
    }
  }
}

console.log('');
console.log(`${labs.length} labs: ${passed - 0} passed, ${failed} failed.`);

process.exit(failed > 0 ? 1 : 0);

// crude parser — looks for the "tests N pass N fail N" line that
// node --test prints
function parseSummary(out) {
  let total = 0,
    passed = 0,
    failed = 0;
  const m = /ℹ tests\s+(\d+)[\s\S]*?ℹ pass\s+(\d+)[\s\S]*?ℹ fail\s+(\d+)/.exec(out);
  if (m) {
    total = Number(m[1]);
    passed = Number(m[2]);
    failed = Number(m[3]);
  } else {
    const m2 = /tests\s+(\d+)[\s\S]*?pass\s+(\d+)[\s\S]*?fail\s+(\d+)/.exec(out);
    if (m2) {
      total = Number(m2[1]);
      passed = Number(m2[2]);
      failed = Number(m2[3]);
    }
  }
  return { total, passed, failed };
}
