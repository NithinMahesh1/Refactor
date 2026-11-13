import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runProcess, windowsSystemProgram } from '../skills/rea/scripts/lib/run.mjs';

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

test('A child that starts its own child is stopped as a tree', { timeout: 20000 }, async () => {
  const script = [
    'const { spawn } = require("node:child_process");',
    'spawn(process.execPath, ["-e", "setTimeout(() => {}, 60000)"],',
    '{ stdio: "inherit", windowsHide: true, detached: process.platform === "win32" });',
    'setTimeout(() => {}, 60000);',
  ].join(' ');
  const r = await runProcess(process.execPath, ['-e', script], { timeoutMs: 500 });
  assert.strictEqual(r.timedOut, true);
  assert.ok(r.durationMs < 15000);
});

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

test('windowsSystemProgram builds the path', async () => {
  assert.strictEqual(
    windowsSystemProgram('cmd.exe', { SystemRoot: 'D:\\Win' }),
    'D:\\Win\\System32\\cmd.exe'
  );
  assert.strictEqual(
    windowsSystemProgram('cmd.exe', { windir: 'E:\\W' }),
    'E:\\W\\System32\\cmd.exe'
  );
  assert.strictEqual(
    windowsSystemProgram('cmd.exe', {}),
    'C:\\Windows\\System32\\cmd.exe'
  );
});

test('Bad options reject with code usage', async () => {
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { timeoutMs: 3_000_000_000 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { timeoutMs: 0 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { timeoutMs: 1.5 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { maxOutputBytes: -1 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { maxOutputBytes: 1.5 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { timeoutMs: 2147483648 }),
    { code: 'usage' }
  );
  const atLimit = await runProcess(process.execPath, ['-e', ''], { timeoutMs: 2147483647 });
  assert.strictEqual(atLimit.exitCode, 0);
});

test('The spawn_failed message holds no path', async () => {
  const missing = path.join(os.tmpdir(), 'refactor-missing-folder', 'nope.exe');
  await assert.rejects(runProcess(missing, []), (e) =>
    e.code === 'spawn_failed' && !e.message.includes('refactor-missing-folder')
  );
  const withZeroByte = ['-e', '', 'refactor-secret-text' + String.fromCharCode(0) + 'tail'];
  await assert.rejects(runProcess(process.execPath, withZeroByte), (e) =>
    e.code === 'spawn_failed' && !e.message.includes('refactor-secret-text')
  );
});

test('The time limit starts taskkill by its full path and has a fallback', {
  skip: process.platform !== 'win32',
  timeout: 30000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const savedRoot = process.env.SystemRoot;
  try {
    const pending = runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 12000)'],
      { timeoutMs: 500 });
    // From here on <SystemRoot>/System32/taskkill.exe does not exist.
    process.env.SystemRoot = dir;
    const r = await pending;
    assert.strictEqual(r.timedOut, true);
    assert.strictEqual(r.signal, 'SIGTERM');
    assert.ok(r.durationMs < 10000);
  } finally {
    process.env.SystemRoot = savedRoot;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('The child gets NoDefaultCurrentDirectoryInExePath when the caller passes env', {
  skip: process.platform !== 'win32',
}, async () => {
  const env = Object.freeze({ SystemRoot: process.env.SystemRoot, PATH: process.env.PATH });
  const script = 'process.stdout.write(String(process.env.NoDefaultCurrentDirectoryInExePath))';
  const r = await runProcess(process.execPath, ['-e', script], { env });
  assert.strictEqual(r.stdout, '1');
  assert.deepStrictEqual(Object.keys(env), ['SystemRoot', 'PATH']);
});

test('A program in the current folder is not started by its bare name on Windows', {
  skip: process.platform !== 'win32',
  timeout: 30000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    fs.copyFileSync(process.execPath, path.join(dir, 'refactor-probe.exe'));
    delete process.env.NoDefaultCurrentDirectoryInExePath;
    await assert.rejects(
      runProcess('refactor-probe', ['-e', ''], { cwd: dir }),
      { code: 'spawn_failed' }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
