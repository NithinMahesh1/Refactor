import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { runProcess } from '../skills/rea/scripts/lib/run.mjs';

const RUN_URL = new URL('../skills/rea/scripts/lib/run.mjs', import.meta.url).href;
const ARGS_URL = new URL('../skills/rea/scripts/lib/args.mjs', import.meta.url).href;

// A stand-in for a helper script. It starts a long program as a grandchild (on Windows
// through cmd.exe and a batch file, elsewhere through a Node.js launcher), waits until the
// program has written its process number, and then ends in the way that argv[2] names:
// 'exit', 'SIGTERM', 'SIGINT', or 'own' (SIGINT, and the script has its own listener).
// The script has other work (an interval that never ends), so nothing but that way ends it.
const SCRIPT = [
  `import { runProcess, windowsSystemProgram } from ${JSON.stringify(RUN_URL)};`,
  `import { buildWindowsBatCommand } from ${JSON.stringify(ARGS_URL)};`,
  'import fs from \'node:fs\';',
  'import path from \'node:path\';',
  'const [mode, dir] = process.argv.slice(2);',
  'const engine = path.join(dir, \'engine.cjs\');',
  'const pidFile = path.join(dir, \'engine.pid\');',
  'let calls = 0;',
  'if (mode === \'own\') {',
  '  process.on(\'SIGINT\', () => {',
  '    calls += 1;',
  '    if (calls === 1) {',
  '      setTimeout(() => process.exit(40 + calls), 500);',
  '    }',
  '  });',
  '}',
  'if (process.platform === \'win32\') {',
  '  const bat = path.join(dir, \'launch.bat\');',
  '  runProcess(windowsSystemProgram(\'cmd.exe\'),',
  '    buildWindowsBatCommand(bat, [process.execPath, engine, pidFile]),',
  '    { windowsVerbatimArguments: true, timeoutMs: 60000 });',
  '} else {',
  '  runProcess(process.execPath, [path.join(dir, \'launcher.cjs\'), engine, pidFile],',
  '    { timeoutMs: 60000 });',
  '}',
  'setInterval(() => {}, 1000);',
  'const timer = setInterval(() => {',
  '  if (!fs.existsSync(pidFile) || fs.readFileSync(pidFile, \'utf8\') === \'\') {',
  '    return;',
  '  }',
  '  clearInterval(timer);',
  '  // From here on a program with a bare name cannot be found.',
  '  process.env.PATH = dir;',
  '  const signal = mode === \'own\' ? \'SIGINT\' : mode;',
  '  if (mode === \'exit\') {',
  '    process.exit(0);',
  '  } else if (process.platform === \'win32\') {',
  '    process.emit(signal, signal);',
  '  } else {',
  '    process.kill(process.pid, signal);',
  '  }',
  '}, 50);',
  '',
].join('\n');

/**
 * True when a process with this number runs.
 * @param {number} pid
 * @returns {boolean}
 */
function alive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/**
 * Runs the stand-in script in `mode`. Returns how the script ended and if its grandchild
 * still runs after that.
 * @param {string} mode
 * @returns {Promise<{enginePid: number, stillAlive: boolean, exitCode: number | null,
 *   signal: string | null, timedOut: boolean}>}
 */
async function runScript(mode) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  let enginePid = 0;
  try {
    fs.writeFileSync(path.join(dir, 'script.mjs'), SCRIPT);
    fs.writeFileSync(path.join(dir, 'engine.cjs'), 'require("node:fs").writeFileSync('
      + 'process.argv[2], String(process.pid)); setTimeout(() => {}, 30000);\n');
    fs.writeFileSync(path.join(dir, 'launch.bat'), '@echo off\r\n"%~1" "%~2" "%~3"\r\n');
    fs.writeFileSync(path.join(dir, 'launcher.cjs'), 'require("node:child_process").spawn('
      + 'process.execPath, process.argv.slice(2), { stdio: "inherit" });'
      + ' setTimeout(() => {}, 30000);\n');
    const r = await runProcess(process.execPath, [path.join(dir, 'script.mjs'), mode, dir],
      { timeoutMs: 10000 });
    enginePid = Number(fs.readFileSync(path.join(dir, 'engine.pid'), 'utf8'));
    let stillAlive = alive(enginePid);
    for (let i = 0; i < 20 && stillAlive; i++) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      stillAlive = alive(enginePid);
    }
    return { enginePid, stillAlive, exitCode: r.exitCode, signal: r.signal, timedOut: r.timedOut };
  } finally {
    if (enginePid > 0 && alive(enginePid)) {
      process.kill(enginePid);
    }
    fs.rmSync(dir, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  }
}

test('The child tree stops when the script ends', { timeout: 30000 }, async () => {
  const r = await runScript('exit');
  assert.ok(r.enginePid > 0);
  assert.strictEqual(r.stillAlive, false);
  assert.strictEqual(r.timedOut, false);
  assert.strictEqual(r.exitCode, 0);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  test(`The child tree stops when the script gets ${signal}, and the signal ends the script`, {
    timeout: 30000,
  }, async () => {
    const r = await runScript(signal);
    assert.ok(r.enginePid > 0);
    assert.strictEqual(r.stillAlive, false);
    assert.strictEqual(r.timedOut, false);
    if (process.platform === 'win32') {
      // Node.js ends a Windows process that sends itself a signal with exit code 1.
      assert.strictEqual(r.exitCode, 1);
    } else {
      assert.strictEqual(r.signal, signal);
    }
  });
}

test('A script with its own signal listener is not ended by the listener of runProcess', {
  timeout: 30000,
}, async () => {
  const r = await runScript('own');
  assert.ok(r.enginePid > 0);
  assert.strictEqual(r.stillAlive, false);
  assert.strictEqual(r.timedOut, false);
  // The own listener ran one time and ended the script 500 ms later with 40 + 1.
  assert.strictEqual(r.exitCode, 41);
});

test('The listeners are added with the first running child and removed with the last', {
  timeout: 30000,
}, async () => {
  const count = () => ['exit', 'SIGINT', 'SIGTERM'].map((name) => process.listenerCount(name));
  const before = count();
  const more = before.map((n) => n + 1);
  const quick = runProcess(process.execPath, ['-e', '']);
  assert.deepStrictEqual(count(), more);
  const long = runProcess(process.execPath, ['-e', 'setTimeout(() => {}, 60000)'],
    { timeoutMs: 2500 });
  assert.deepStrictEqual(count(), more);
  await quick;
  assert.deepStrictEqual(count(), more);
  await long;
  assert.deepStrictEqual(count(), before);
  await assert.rejects(runProcess('refactor-no-such-program-0000', []), { code: 'spawn_failed' });
  assert.deepStrictEqual(count(), before);
});
