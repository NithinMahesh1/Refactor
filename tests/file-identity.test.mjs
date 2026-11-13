import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { main } from '../skills/rea/scripts/file-identity.mjs';

const SCRIPT = fileURLToPath(new URL('../skills/rea/scripts/file-identity.mjs', import.meta.url));
const PACKAGE = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const BS = '\\';
const UNSAFE_MESSAGE =
  'network and device paths are not allowed; copy the file to a local folder';

/**
 * Runs the script as a child process. A run that takes longer than 60 seconds is stopped (its
 * status is then null).
 * @param {string[]} args Arguments to pass to the script.
 * @returns {{status: number, stdout: string, stderr: string}}
 */
function runScript(args) {
  return spawnSync(process.execPath, [SCRIPT, ...args], { encoding: 'utf8', timeout: 60000 });
}

test('text file', () => {
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
    assert.strictEqual(out.tool.version, PACKAGE.version);
    // One line of JSON, then one line end.
    assert.strictEqual(r.stdout.endsWith('}\n'), true);
    assert.strictEqual(r.stdout.split('\n').length, 2);
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

test('elf file', () => {
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

test('no folder path by default', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'sample.txt');
    fs.writeFileSync(filePath, 'hello, world\n');

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);

    const out = JSON.parse(r.stdout);
    assert.strictEqual('path' in out.subject, false);
    // The folder name finds the path with every kind of separator.
    assert.strictEqual(r.stdout.includes(path.basename(dir)), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('--show-path adds the path', () => {
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

test('not_found', () => {
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

test('is_directory', () => {
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

test('usage', () => {
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

  // an empty path
  const r4 = runScript(['']);
  assert.strictEqual(r4.status, 2);
  assert.strictEqual(r4.stderr, '');
  assert.deepStrictEqual(JSON.parse(r4.stdout).error,
    { code: 'usage', message: 'the file path is empty' });
});

test('--pretty prints more than one line', () => {
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

test('large file hashing', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const filePath = path.join(dir, 'big.bin');
    const size = 5 * 1024 * 1024;
    // Letters in a counting pattern: the file is text, and the order of the read chunks
    // matters for the digest.
    const buffer = Buffer.alloc(size);
    for (let i = 0; i < size; i++) {
      buffer[i] = 0x61 + (i % 26);
    }
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

test('empty file', () => {
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

test('--help', () => {
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

test('unreadable', async () => {
  // No system accepts a zero byte in a file path. A command line cannot hold one, so this
  // case calls main() directly.
  const { exitCode, output } = await main(['sample' + String.fromCharCode(0) + '.bin']);
  assert.strictEqual(exitCode, 2);
  assert.deepStrictEqual(JSON.parse(output), {
    schema: 'refactor.error/1',
    error: { code: 'unreadable', message: 'the file cannot be read' },
  });
});

test('the null device is refused', () => {
  // On Windows the null device has the device path \\.\nul. On other systems it is a
  // character device, not a regular file.
  const r = runScript([os.devNull]);
  assert.strictEqual(r.status, 2);
  assert.strictEqual(r.stderr, '');

  const out = JSON.parse(r.stdout);
  assert.strictEqual(out.schema, 'refactor.error/1');
  assert.strictEqual(out.error.code, process.platform === 'win32' ? 'unsafe_path' : 'unreadable');
});

test('a network or device path gives unsafe_path', () => {
  const targets = [BS + BS + 'host' + BS + 'share' + BS + 'sample.bin', '//host/share/sample.bin'];
  for (const target of targets) {
    const r = runScript([target]);
    assert.strictEqual(r.status, 2);
    assert.strictEqual(r.stderr, '');
    assert.deepStrictEqual(JSON.parse(r.stdout).error,
      { code: 'unsafe_path', message: UNSAFE_MESSAGE });
  }
});

test('--pretty also prints an error record on more than one line', () => {
  // A usage error after the options were read, and one while they were read.
  for (const args of [['--pretty'], ['--nope', '--pretty']]) {
    const r = runScript(args);
    assert.strictEqual(r.status, 2);
    assert.ok(r.stdout.trim().split('\n').length > 1);
    assert.strictEqual(JSON.parse(r.stdout).error.code, 'usage');
  }
  // After a lone -- the word --pretty is a path, not an option.
  const r = runScript(['--nope', '--', '--pretty']);
  assert.strictEqual(r.status, 2);
  assert.strictEqual(r.stdout.trim().split('\n').length, 1);
  assert.strictEqual(JSON.parse(r.stdout).error.code, 'usage');
});

test('the type comes from exactly the first 4096 bytes', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    // An MZ file names the place of its PE signature at offset 0x3c. The signature has
    // 4 bytes. At offset 4092 its last byte is byte 4096 of the file: inside the first bytes.
    // At offset 4093 one byte is outside the first bytes, but inside the file.
    const cases = [
      [4092, { type: 'pe', details: { incomplete: true } }],
      [4093, { type: 'mz', details: { pe_header: 'outside the bytes read' } }],
    ];
    for (const [offset, expected] of cases) {
      const buffer = Buffer.alloc(8192);
      buffer.write('MZ', 0, 'latin1');
      buffer.writeUInt32LE(offset, 0x3c);
      buffer.write('PE', offset, 'latin1');
      const filePath = path.join(dir, 'head-' + offset + '.bin');
      fs.writeFileSync(filePath, buffer);

      const r = runScript([filePath]);
      assert.strictEqual(r.status, 0);
      const out = JSON.parse(r.stdout);
      assert.deepStrictEqual({ type: out.result.type, details: out.result.details }, expected);
    }
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a text file whose first 4096 bytes end inside a character is text', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    // Byte 4096 is the first of the 2 bytes of the letter e with an acute accent. The type
    // check must know that the file goes on after the bytes that it got.
    const filePath = path.join(dir, 'letters.txt');
    fs.writeFileSync(filePath,
      Buffer.concat([Buffer.alloc(4095, 0x61), Buffer.from([0xc3, 0xa9, 0x62])]));

    const r = runScript([filePath]);
    assert.strictEqual(r.status, 0);
    assert.strictEqual(JSON.parse(r.stdout).result.type, 'text');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a reader that closes stdout early gets no stack trace on stderr', { timeout: 60000 },
  async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
    try {
      const filePath = path.join(dir, 'sample.txt');
      fs.writeFileSync(filePath, 'hello, world\n');
      const child = spawn(process.execPath, [SCRIPT, filePath],
        { stdio: ['ignore', 'pipe', 'pipe'] });
      // Close the reading end at once: the script then writes into a closed pipe.
      child.stdout.destroy();
      let stderr = '';
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (text) => {
        stderr += text;
      });
      const exitCode = await new Promise((resolve) => {
        child.on('close', (code) => {
          resolve(code);
        });
      });
      assert.strictEqual(stderr, '');
      assert.strictEqual(exitCode, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

test('main() answers only after the file is closed', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const realClose = fs.close;
  try {
    const filePath = path.join(dir, 'sample.txt');
    fs.writeFileSync(filePath, 'hello, world\n');
    // The read stream closes the file with fs.close: count the calls that started and ended.
    let started = 0;
    let ended = 0;
    fs.close = (fd, callback) => {
      started += 1;
      realClose(fd, (err) => {
        ended += 1;
        callback(err);
      });
    };
    const { exitCode } = await main([filePath]);
    assert.strictEqual(exitCode, 0);
    assert.strictEqual(started, 1);
    assert.strictEqual(ended, 1);
  } finally {
    fs.close = realClose;
    fs.rmSync(dir, { recursive: true, force: true });
  }
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

test('a file that changes after its size was read gives no wrong record', async () => {
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
