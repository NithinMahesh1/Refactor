import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, buildWindowsBatCommand } from '../skills/rea/scripts/lib/args.mjs';

const spec = { flags: ['show-path', 'pretty'], values: ['limit', 'filter'] };

test('parseArgs positionals and options', () => {
  const res = parseArgs(['a.bin', '--pretty', '--limit', '5'], spec);
  assert.deepEqual(res, { positionals: ['a.bin'], options: { pretty: true, limit: '5' } });
});

test('parseArgs = form', () => {
  const res = parseArgs(['--filter=main'], spec);
  assert.strictEqual(res.options.filter, 'main');
});

test('parseArgs -- ends options', () => {
  const res = parseArgs(['--', '--pretty'], spec);
  assert.deepEqual(res, { positionals: ['--pretty'], options: {} });
});

test('parseArgs errors', () => {
  assert.throws(() => parseArgs(['--nope'], spec), { code: 'usage' });
  assert.throws(() => parseArgs(['--limit'], spec), { code: 'usage' });
  assert.throws(() => parseArgs(['--pretty=1'], spec), { code: 'usage' });
  assert.throws(() => parseArgs(['--pretty', '--pretty'], spec), { code: 'usage' });
});

test('buildWindowsBatCommand quotes each argument', () => {
  const res = buildWindowsBatCommand('C:\\tools\\run.bat', ['a', 'b c']);
  assert.deepEqual(res, ['/d', '/s', '/c', '""C:\\tools\\run.bat" "a" "b c""']);
});

test('A path with spaces is accepted', () => {
  const res = buildWindowsBatCommand(
    'C:\\Program Files\\tool\\run.bat',
    ['C:\\My Files\\sample file.bin'],
  );
  assert.strictEqual(
    res[3],
    '""C:\\Program Files\\tool\\run.bat" "C:\\My Files\\sample file.bin""',
  );

});

test('Each unsafe character is refused', () => {
  const chars = ['"', '%', '^', '&', '|', '<', '>', '!', '\n', '\r', '\t', '\u0000', '\u001b'];
  for (const ch of chars) {
    assert.throws(
      () => buildWindowsBatCommand('run.bat', ['a' + ch + 'b']),
      { code: 'unsafe_path' },
    );
  }
});

test('An unsafe batPath is refused', () => {
  assert.throws(() => buildWindowsBatCommand('run&.bat', []), { code: 'unsafe_path' });
});

test('The error message does not repeat the bad text', () => {
  try {
    buildWindowsBatCommand('run.bat', ['secret%value']);
    assert.fail('Should have thrown');
  } catch (e) {
    assert.strictEqual(e.code, 'unsafe_path');
    assert.strictEqual(e.message.includes('secret'), false);
    assert.strictEqual(e.message.includes('1'), true);
  }
});

test('No arguments', () => {
  const res = buildWindowsBatCommand('run.bat', []);
  assert.deepEqual(res, ['/d', '/s', '/c', '""run.bat""']);
});
