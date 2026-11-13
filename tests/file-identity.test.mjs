import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { main } from '../skills/rea/scripts/file-identity.mjs';

const SCRIPT = fileURLToPath(new URL('../skills/rea/scripts/file-identity.mjs', import.meta.url));

/**
 * Runs the script as a child process.
 * @param {string[]} args Arguments to pass to the script.
 * @returns {{status: number, stdout: string, stderr: string}}
 */
function runScript(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8' });
}

test('text file', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'sample.txt');
    const content = 'hello, world\n';
    fs.writeFileSync(filePath, content);

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);
    assert.strictEqual(r.stderr, '');
    const out = JSON.parse(r.stdout);
    const expectedHash = crypto.createHash('sha256').update(content).digest('hex');

    assert.strictEqual(out.schema, 'refactor.evidence/1');
    assert.strictEqual(out.subject.name, 'sample.txt');
    assert.strictEqual(out.subject.sha256, expectedHash);
    assert.strictEqual(out.subject.size_bytes, content.length);
    assert.strictEqual(out.result.type, 'text');
    assert.strictEqual(out.result.size_bytes, content.length);
    assert.strictEqual(out.tool.name, 'file-identity');
    assert.strictEqual(out.operation, 'identify');
    assert.strictEqual(out.confidence, 'observed');
    assert.strictEqual(out.tool.engine, null);
    assert.deepStrictEqual(out.parameters, {});
    assert.deepStrictEqual(out.coverage, {
      examined: 'first 4096 bytes for the type; all bytes for the digest',
      not_examined: ['content after the header was not interpreted'],
      truncated: false,
      next_cursor: null,
    });
    assert.deepStrictEqual(out.limits,
      ['The type comes from the first bytes only. A file can carry a misleading header.']);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('elf file', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'prog.bin');
    const buffer = Buffer.alloc(64);
    buffer.writeUInt8(0x7f, 0);
    buffer.writeUInt8(0x45, 1);
    buffer.writeUInt8(0x4c, 2);
    buffer.writeUInt8(0x46, 3);
    buffer.writeUInt8(0x02, 4); // bits 64
    buffer.writeUInt8(0x01, 5); // endian little
    buffer.writeUInt16LE(2, 16); // kind executable
    buffer.writeUInt16LE(62, 18); // machine x86-64

    fs.writeFileSync(filePath, buffer);

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.result.type, 'elf');
    assert.deepStrictEqual(out.result.details, {
      bits: 64,
      endian: 'little',
      kind: 'executable',
      machine: 'x86-64',
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('no folder path by default', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'sample.txt');
    fs.writeFileSync(filePath, 'hello, world\n');

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    assert.strictEqual('path' in out.subject, false);
    assert.strictEqual(r.stdout.includes(dir), false);
    assert.strictEqual(r.stdout.includes(dir.replaceAll('\\', '\\\\')), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('--show-path adds the path', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'sample.txt');
    fs.writeFileSync(filePath, 'hello, world\n');

    const r = runScript([filePath, '--show-path']);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.subject.path, path.resolve(filePath));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('not_found', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'non-existent.txt');

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 2);

    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.schema, 'refactor.error/1');
    assert.strictEqual(out.error.code, 'not_found');
    assert.strictEqual(r.stdout.includes(path.basename(dir)), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('is_directory', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const r = runScript([dir]);
    assert.strictEqual(r.status, 2);

    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.error.code, 'is_directory');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('usage', async (t) => {
  // no argument
  const r1 = runScript([]);
  assert.strictEqual(r1.status, 2);
  const out1 = JSON.parse(r1.stdout);
  assert.strictEqual(out1.error.code, 'usage');

  // two arguments
  const r2 = runScript(['arg1', 'arg2']);
  assert.strictEqual(r2.status, 2);
  const out2 = JSON.parse(r2.stdout);
  assert.strictEqual(out2.error.code, 'usage');

  // --nope
  const r3 = runScript(['--nope']);
  assert.strictEqual(r3.status, 2);
  const out3 = JSON.parse(r3.stdout);
  assert.strictEqual(out3.error.code, 'usage');
});

test('--pretty prints more than one line', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'sample.txt');
    fs.writeFileSync(filePath, 'hello, world\n');

    const rPretty = runScript([filePath, '--pretty']);
    assert.strictEqual(rPretty.status, 0);
    assert.ok(rPretty.stdout.trim().split('\n').length > 1);

    const rNormal = runScript([filePath]);
    assert.strictEqual(rNormal.status, 0);
    assert.strictEqual(rNormal.stdout.trim().split('\n').length, 1);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('large file hashing', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'big.bin');
    const size = 5 * 1024 * 1024;
    const buffer = Buffer.alloc(size, 0x61);
    fs.writeFileSync(filePath, buffer);

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    const expectedHash = crypto.createHash('sha256').update(buffer).digest('hex');

    assert.strictEqual(out.subject.sha256, expectedHash);
    assert.strictEqual(out.subject.size_bytes, size);
    assert.strictEqual(out.result.type, 'text');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('empty file', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'empty.txt');
    fs.writeFileSync(filePath, '');

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    assert.strictEqual(out.result.type, 'empty');
    assert.strictEqual(out.subject.sha256,
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('--help', async (t) => {
  const r = runScript(['--help']);
  assert.strictEqual(r.status, 0);
  assert.ok(r.stdout.startsWith('Use: node file-identity.mjs'));
});

test('id is stable', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'stable.txt');
    fs.writeFileSync(filePath, 'stable content');

    const r1 = runScript([filePath]);
    const r2 = runScript([filePath]);
    assert.strictEqual(r1.status, 0);
    assert.strictEqual(r2.status, 0);

    const out1 = JSON.parse(r1.stdout);
    const out2 = JSON.parse(r2.stdout);
    assert.match(out1.id, /^ev_[0-9a-f]{32}$/);
    assert.strictEqual(out1.id, out2.id);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('unreadable', () => {
  // The null device is there on every system and is not a regular file.
  const r = runScript([os.devNull]);
  assert.strictEqual(r.status, 2);
  assert.strictEqual(r.stderr, '');

  const out = JSON.parse(r.stdout);
  assert.strictEqual(out.schema, 'refactor.error/1');
  assert.strictEqual(out.error.code, 'unreadable');
});

test('an error prints no folder path on stdout or stderr', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const folderName = path.basename(dir);
    for (const target of [dir, path.join(dir, 'non-existent.txt')]) {
      const r = runScript([target]);
      assert.strictEqual(r.status, 2);
      assert.strictEqual(r.stderr, '');
      assert.strictEqual(r.stdout.includes(folderName), false);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a file that changes after its size was read gives no wrong record', async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'growing.bin');
    fs.writeFileSync(filePath, 'hello, world\n');

    // main() asks for the file size at once. The loop below keeps this thread busy, so the
    // answer (13 bytes) is ready before the file grows and main() reads the bytes after it.
    const pending = main([filePath]);
    const end = Date.now() + 300;
    while (Date.now() < end) {
      // wait
    }
    fs.appendFileSync(filePath, 'more');

    const { exitCode, output } = await pending;
    const out = JSON.parse(output);
    if (exitCode === 0) {
      // Only when the size request was very slow and saw the new file: the record must then
      // describe the 17 bytes that were read.
      const newHash = crypto.createHash('sha256').update('hello, world\nmore').digest('hex');
      assert.strictEqual(out.subject.size_bytes, 17);
      assert.strictEqual(out.result.size_bytes, 17);
      assert.strictEqual(out.subject.sha256, newHash);
    } else {
      assert.strictEqual(exitCode, 2);
      assert.strictEqual(out.error.code, 'unreadable');
      assert.strictEqual(out.error.message, 'the file changed while it was read');
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
