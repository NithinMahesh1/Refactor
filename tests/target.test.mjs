import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { resolveTarget, sha256File } from '../skills/rea/scripts/lib/target.mjs';

const BS = '\\';
const UNSAFE = {
  code: 'unsafe_path',
  message: 'network and device paths are not allowed; copy the file to a local folder',
};

// Paths that start with two slashes or backslashes in any mix. The last three have no share
// part, so on Windows their absolute form is a local path: only the first check refuses them.
const UNSAFE_PATHS = [
  BS + BS + 'host' + BS + 'share' + BS + 'sample.bin',
  '//host/share/sample.bin',
  BS + BS + '?' + BS + 'C:' + BS + 'sample.bin',
  BS + BS + '.' + BS + 'sample.bin',
  BS + '/host/share/sample.bin',
  '/' + BS + 'host' + BS + 'share' + BS + 'sample.bin',
  '//host',
  BS + BS + 'host',
  '/' + BS + 'host',
];

/**
 * Makes a temporary folder, runs `fn` with it, and removes the folder again.
 * @param {(dir: string) => Promise<void>} fn
 * @returns {Promise<void>}
 */
async function withTempDir(fn) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    await fn(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('resolveTarget returns the absolute path, the base name and the size', async () => {
  await withTempDir(async (dir) => {
    const filePath = path.join(dir, 'sample.bin');
    fs.writeFileSync(filePath, Buffer.from([1, 2, 3, 4, 5]));
    assert.deepStrictEqual(await resolveTarget(filePath),
      { absPath: path.resolve(filePath), name: 'sample.bin', size: 5 });
  });
});

test('resolveTarget accepts a path that starts with one separator', async () => {
  await withTempDir(async (dir) => {
    const filePath = path.join(dir, 'sample.bin');
    fs.writeFileSync(filePath, 'abc');
    // The path from the root (on Windows: from the root of the drive of the folder).
    const rootRelative = path.sep + path.relative(path.parse(filePath).root, filePath);
    const before = process.cwd();
    process.chdir(dir);
    try {
      assert.deepStrictEqual(await resolveTarget(rootRelative),
        { absPath: path.resolve(filePath), name: 'sample.bin', size: 3 });
    } finally {
      process.chdir(before);
    }
  });
});

test('resolveTarget gives not_found for a missing file', async () => {
  await withTempDir(async (dir) => {
    await assert.rejects(resolveTarget(path.join(dir, 'missing.bin')),
      { code: 'not_found', message: 'no file at the given path' });
    fs.writeFileSync(path.join(dir, 'sample.bin'), 'x');
    await assert.rejects(resolveTarget(path.join(dir, 'sample.bin', 'inner.bin')),
      { code: 'not_found', message: 'no file at the given path' });
  });
});

test('resolveTarget gives is_directory for a folder', async () => {
  await withTempDir(async (dir) => {
    await assert.rejects(resolveTarget(dir),
      { code: 'is_directory', message: 'the path is a folder, not a file' });
  });
});

test('resolveTarget refuses the null device', async () => {
  // On Windows the null device has the device path \\.\nul. On other systems it is a
  // character device: there, it is not a regular file.
  if (process.platform === 'win32') {
    await assert.rejects(resolveTarget(os.devNull), UNSAFE);
  } else {
    await assert.rejects(resolveTarget(os.devNull),
      { code: 'unreadable', message: 'the path is not a regular file' });
  }
});

test('resolveTarget gives unreadable for a path that the system refuses', async () => {
  // No system accepts a zero byte in a file path.
  await assert.rejects(resolveTarget('sample' + String.fromCharCode(0) + '.bin'),
    { code: 'unreadable', message: 'the file cannot be read' });
});

test('resolveTarget gives usage for an empty path', async () => {
  await assert.rejects(resolveTarget(''), { code: 'usage', message: 'the file path is empty' });
});

test('resolveTarget refuses network and device paths on every system', async () => {
  for (const unsafePath of UNSAFE_PATHS) {
    await assert.rejects(resolveTarget(unsafePath), UNSAFE);
  }
});

test('resolveTarget refuses them before any file system call', async () => {
  await withTempDir(async (dir) => {
    const realStat = fsPromises.stat;
    let calls = 0;
    fsPromises.stat = (...args) => {
      calls += 1;
      return realStat(...args);
    };
    syncBuiltinESMExports();
    try {
      for (const unsafePath of UNSAFE_PATHS) {
        await assert.rejects(resolveTarget(unsafePath), UNSAFE);
      }
      assert.strictEqual(calls, 0);
      // The counter works: a local path takes one call.
      await assert.rejects(resolveTarget(path.join(dir, 'missing.bin')), { code: 'not_found' });
      assert.strictEqual(calls, 1);
    } finally {
      fsPromises.stat = realStat;
      syncBuiltinESMExports();
    }
  });
});

test('resolveTarget refuses a relative path when the current folder is a device path',
  { skip: process.platform !== 'win32' }, async () => {
    await withTempDir(async (dir) => {
      fs.writeFileSync(path.join(dir, 'sample.bin'), 'x');
      const before = process.cwd();
      process.chdir(BS + BS + '?' + BS + dir);
      try {
        await assert.rejects(resolveTarget('sample.bin'), UNSAFE);
      } finally {
        process.chdir(before);
      }
    });
  });

test('sha256File gives the digest of a small file and of an empty file', async () => {
  await withTempDir(async (dir) => {
    const small = path.join(dir, 'small.bin');
    fs.writeFileSync(small, 'hello, world\n');
    assert.strictEqual(await sha256File(small),
      crypto.createHash('sha256').update('hello, world\n').digest('hex'));
    const empty = path.join(dir, 'empty.bin');
    fs.writeFileSync(empty, '');
    assert.strictEqual(await sha256File(empty),
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });
});

test('sha256File gives the digest of a file of several read chunks', async () => {
  await withTempDir(async (dir) => {
    // 300007 bytes are more than 4 chunks of the default read size (64 KiB). The counting
    // pattern makes the order of the chunks matter.
    const data = Buffer.alloc(300007);
    for (let i = 0; i < data.length; i++) {
      data[i] = i % 251;
    }
    const filePath = path.join(dir, 'chunks.bin');
    fs.writeFileSync(filePath, data);
    assert.strictEqual(await sha256File(filePath),
      crypto.createHash('sha256').update(data).digest('hex'));
  });
});

test('sha256File gives unreadable for a missing file and for a folder', async () => {
  await withTempDir(async (dir) => {
    for (const target of [path.join(dir, 'missing.bin'), dir]) {
      await assert.rejects(sha256File(target),
        { code: 'unreadable', message: 'the file cannot be read' });
    }
  });
});

test('sha256File answers only after the file is closed', async () => {
  await withTempDir(async (dir) => {
    const filePath = path.join(dir, 'small.bin');
    fs.writeFileSync(filePath, 'hello, world\n');
    // The read stream closes the file with fs.close: count the calls that started and ended.
    const realClose = fs.close;
    let started = 0;
    let ended = 0;
    fs.close = (fd, callback) => {
      started += 1;
      realClose(fd, (err) => {
        ended += 1;
        callback(err);
      });
    };
    try {
      await sha256File(filePath);
      assert.strictEqual(started, 1);
      assert.strictEqual(ended, 1);
    } finally {
      fs.close = realClose;
    }
  });
});
