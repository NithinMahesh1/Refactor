import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runProcess } from '../skills/rea/scripts/lib/run.mjs';

test('Exit code 0 and output', async () => {
  const script = 'process.stdout.write("hello"); process.stderr.write("warn")';
  const r = await runProcess(process.execPath, ['-e', script]);
  assert.strictEqual(r.exitCode, 0);
  assert.strictEqual(r.stdout, 'hello');
  assert.strictEqual(r.stderr, 'warn');
  assert.strictEqual(r.timedOut, false);
  assert.strictEqual(r.stdoutTruncated, false);
  assert.strictEqual(r.stderrTruncated, false);
  assert.strictEqual(typeof r.durationMs, 'number');
});

test('Exit code 3 is returned, not thrown', async () => {
  const r = await runProcess(process.execPath, ['-e', 'process.exit(3)']);
  assert.strictEqual(r.exitCode, 3);
  assert.strictEqual(r.timedOut, false);
});

test('A sleeping child is stopped at the timeout', async () => {
  const script = 'setTimeout(() => {}, 60000)';
  const r = await runProcess(process.execPath, ['-e', script], { timeoutMs: 500 });
  assert.strictEqual(r.timedOut, true);
  assert.notStrictEqual(r.exitCode, 0);
  assert.ok(r.durationMs < 15000);
});

test('A child that starts its own child is stopped as a tree', async () => {
  const script = [
    'const { spawn } = require("node:child_process");',
    'spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"], { stdio: "inherit" });',
    'setTimeout(() => {}, 60000);',
  ].join(' ');
  const r = await runProcess(process.execPath, ['-e', script], { timeoutMs: 500 });
  assert.strictEqual(r.timedOut, true);
  assert.ok(r.durationMs < 15000);
}, { timeout: 20000 });

test('Output over the limit is cut and flagged', async () => {
  const script = 'process.stdout.write("x".repeat(5000))';
  const r = await runProcess(process.execPath, ['-e', script], { maxOutputBytes: 1000 });
  assert.strictEqual(r.stdout.length, 1000);
  assert.strictEqual(r.stdout, 'x'.repeat(1000));
  assert.strictEqual(r.stdoutTruncated, true);
  assert.strictEqual(r.stderrTruncated, false);
});

test('Output at exactly the limit is not flagged', async () => {
  const script = 'process.stdout.write("y".repeat(1000))';
  const r = await runProcess(process.execPath, ['-e', script], { maxOutputBytes: 1000 });
  assert.strictEqual(r.stdout.length, 1000);
  assert.strictEqual(r.stdoutTruncated, false);
});

test('A program that does not exist rejects', async () => {
  await assert.rejects(runProcess('refactor-no-such-program-0000', []), { code: 'spawn_failed' });
});

test('Arguments are passed as an array without a shell', async () => {
  const script = 'process.stdout.write(JSON.stringify(process.argv.slice(1)))';
  const r = await runProcess(process.execPath, [
    '-e',
    script,
    'a b',
    '&',
    '%PATH%',
    '$HOME',
  ]);
  const args = JSON.parse(r.stdout);
  assert.deepStrictEqual(args, ['a b', '&', '%PATH%', '$HOME']);
});
