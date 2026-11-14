import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runProcess,
  windowsSystemProgram,
  MAX_OUTPUT_BYTES_LIMIT,
} from '../skills/rea/scripts/lib/run.mjs';

test('windowsSystemProgram reads the names in any letter case', () => {
  assert.strictEqual(windowsSystemProgram('taskkill.exe', { SYSTEMROOT: 'D:\\Win' }),
    'D:\\Win\\System32\\taskkill.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { WINDIR: 'E:\\W' }),
    'E:\\W\\System32\\cmd.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { WINDIR: 'E:\\W', systemroot: 'D:\\Win' }),
    'D:\\Win\\System32\\cmd.exe');
});

test('windowsSystemProgram uses only an absolute root with a drive letter', () => {
  assert.strictEqual(windowsSystemProgram('cmd.exe', { SystemRoot: '.' }),
    'C:\\Windows\\System32\\cmd.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { SystemRoot: '\\Win' }),
    'C:\\Windows\\System32\\cmd.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { SystemRoot: 'D:Win' }),
    'C:\\Windows\\System32\\cmd.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { SystemRoot: '.', windir: 'E:\\W' }),
    'E:\\W\\System32\\cmd.exe');
  assert.strictEqual(windowsSystemProgram('cmd.exe', { SystemRoot: 'D:/Win' }),
    'D:\\Win\\System32\\cmd.exe');
  const env = Object.freeze({ SystemRoot: '.' });
  windowsSystemProgram('cmd.exe', env);
  assert.deepStrictEqual(env, { SystemRoot: '.' });
});

test('maxOutputBytes has an upper limit', async () => {
  assert.strictEqual(MAX_OUTPUT_BYTES_LIMIT, 1073741824);
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { maxOutputBytes: MAX_OUTPUT_BYTES_LIMIT + 1 }),
    { code: 'usage' }
  );
  await assert.rejects(
    runProcess(process.execPath, ['-e', ''], { maxOutputBytes: 1e300 }),
    { code: 'usage' }
  );
  const atLimit = await runProcess(process.execPath, ['-e', ''],
    { maxOutputBytes: MAX_OUTPUT_BYTES_LIMIT });
  assert.strictEqual(atLimit.exitCode, 0);
});

test('A cut inside a character leaves that character out', async () => {
  // The euro sign is 3 bytes in UTF-8; the face is 4 bytes.
  const euros = 'process.stdout.write("\\u20ac".repeat(10))';
  for (const limit of [3, 4, 5]) {
    const r = await runProcess(process.execPath, ['-e', euros], { maxOutputBytes: limit });
    assert.strictEqual(r.stdout, '\u20ac', 'limit ' + limit);
    assert.strictEqual(r.stdoutTruncated, true);
  }
  const faces = 'process.stderr.write("\\u{1F600}".repeat(3))';
  const r = await runProcess(process.execPath, ['-e', faces], { maxOutputBytes: 7 });
  assert.strictEqual(r.stderr, '\u{1F600}');
  assert.strictEqual(r.stderrTruncated, true);
  const none = await runProcess(process.execPath, ['-e', euros], { maxOutputBytes: 2 });
  assert.strictEqual(none.stdout, '');
});
