import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runProcess, windowsSystemProgram, STOP_WAIT_MS } from '../skills/rea/scripts/lib/run.mjs';
import { buildWindowsBatCommand } from '../skills/rea/scripts/lib/args.mjs';

// Each case uses a time limit of 500 ms and a program that would run 8 s.
const LIMIT_MS = 500;
const MOST_MS = LIMIT_MS + STOP_WAIT_MS + 1500;

/**
 * Stops a left-over test process; it may have ended already.
 * @param {number} pid
 */
function stopPid(pid) {
  try {
    process.kill(pid);
  } catch {
    // already gone
  }
}

test('The wait ends when taskkill cannot start and a grandchild holds the pipes', {
  skip: process.platform !== 'win32',
  timeout: 20000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const savedRoot = process.env.SystemRoot;
  const pidFile = path.join(dir, 'sleeper.pid');
  try {
    const sleeper = path.join(dir, 'sleeper.cjs');
    fs.writeFileSync(sleeper, 'require("node:fs").writeFileSync(process.argv[2], '
      + 'String(process.pid)); setTimeout(() => {}, 8000);\n');
    const bat = path.join(dir, 'launch.bat');
    fs.writeFileSync(bat, '@echo off\r\n"%~1" "%~2" "%~3"\r\n');
    const pending = runProcess(windowsSystemProgram('cmd.exe'),
      buildWindowsBatCommand(bat, [process.execPath, sleeper, pidFile]),
      { timeoutMs: LIMIT_MS, windowsVerbatimArguments: true });
    // From here on <SystemRoot>/System32/taskkill.exe does not exist.
    process.env.SystemRoot = dir;
    const r = await pending;
    process.env.SystemRoot = savedRoot;
    assert.strictEqual(r.timedOut, true);
    assert.ok(r.durationMs < MOST_MS, 'durationMs ' + r.durationMs);
  } finally {
    process.env.SystemRoot = savedRoot;
    if (fs.existsSync(pidFile)) {
      stopPid(Number(fs.readFileSync(pidFile, 'utf8')));
    }
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('A taskkill that starts but fails is followed by child.kill()', {
  skip: process.platform !== 'win32',
  timeout: 30000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const savedRoot = process.env.SystemRoot;
  const savedWindir = process.env.windir;
  try {
    // A stand-in taskkill.exe: a copy of the Node.js program. It ends with exit code 1 for
    // the taskkill arguments (it finds no script with the name /pid).
    fs.mkdirSync(path.join(dir, 'System32'));
    fs.copyFileSync(process.execPath, path.join(dir, 'System32', 'taskkill.exe'));
    const pending = runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 8000)'],
      { timeoutMs: LIMIT_MS });
    // windowsSystemProgram refuses this SystemRoot (no drive letter at its start) and takes
    // windir. Windows accepts it, so the stand-in can start (Node.js needs the real folder).
    process.env.SystemRoot = '\\\\?\\' + savedRoot;
    process.env.windir = dir;
    const r = await pending;
    assert.strictEqual(r.timedOut, true);
    assert.strictEqual(r.exitCode, null);
    assert.strictEqual(r.signal, 'SIGTERM');
    // The first start of a new copy of a large program can take some seconds.
    assert.ok(r.durationMs < MOST_MS + 8000, 'durationMs ' + r.durationMs);
  } finally {
    process.env.SystemRoot = savedRoot;
    process.env.windir = savedWindir;
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
});

test('A taskkill file that is not a program is followed by child.kill()', {
  skip: process.platform !== 'win32',
  timeout: 20000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const savedRoot = process.env.SystemRoot;
  try {
    fs.mkdirSync(path.join(dir, 'System32'));
    fs.writeFileSync(path.join(dir, 'System32', 'taskkill.exe'), 'this is not a program\n');
    const pending = runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 8000)'],
      { timeoutMs: LIMIT_MS });
    process.env.SystemRoot = dir;
    const r = await pending;
    process.env.SystemRoot = savedRoot;
    assert.strictEqual(r.timedOut, true);
    assert.strictEqual(r.signal, 'SIGTERM');
    assert.ok(r.durationMs < MOST_MS, 'durationMs ' + r.durationMs);
  } finally {
    process.env.SystemRoot = savedRoot;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('A child that ended is not stopped, and a grandchild cannot hold the wait', {
  timeout: 30000,
}, async () => {
  // The child starts a detached grandchild that keeps the output pipes for 15 s, prints
  // the grandchild's process number and ends at a fixed clock time, 1000 ms before the time
  // limit. A slow start of the child does not move that time. So the time limit comes after
  // the end of the child and before the end of the stop wait.
  const limitMs = 5000;
  const endAt = Date.now() + limitMs - 1000;
  const script = 'const { spawn } = require("node:child_process");'
    + 'const g = spawn(process.execPath, ["-e", "setTimeout(() => {}, 15000)"],'
    + ' { stdio: "inherit", detached: true });'
    + 'g.unref(); process.stdout.write(String(g.pid));'
    + 'setTimeout(() => process.exit(0), Math.max(100, ' + endAt + ' - Date.now()));';
  const r = await runProcess(process.execPath, ['-e', script], { timeoutMs: limitMs });
  if (/^[0-9]+$/.test(r.stdout)) {
    stopPid(Number(r.stdout));
  }
  assert.match(r.stdout, /^[0-9]+$/);
  assert.strictEqual(r.timedOut, false);
  assert.strictEqual(r.exitCode, 0);
  assert.strictEqual(r.signal, null);
  assert.ok(r.durationMs >= limitMs, 'the result came before the time limit: ' + r.durationMs);
  assert.ok(r.durationMs < limitMs + STOP_WAIT_MS + 1500, 'durationMs ' + r.durationMs);
});

test('The time limit starts taskkill by its full path, not through PATH', {
  skip: process.platform !== 'win32',
  timeout: 20000,
}, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const savedPath = process.env.PATH;
  try {
    const pending = runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 8000)'],
      { timeoutMs: LIMIT_MS });
    // From here on a program with a bare name cannot be found.
    process.env.PATH = dir;
    const r = await pending;
    process.env.PATH = savedPath;
    assert.strictEqual(r.timedOut, true);
    // The real taskkill stopped the child: no signal name. A start by a bare name fails
    // here, and child.kill() would give SIGTERM.
    assert.strictEqual(r.signal, null);
    assert.ok(r.durationMs < MOST_MS, 'durationMs ' + r.durationMs);
  } finally {
    process.env.PATH = savedPath;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
