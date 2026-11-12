// Read-only access to the target file: checks, first bytes and digest.
// Nothing here runs, changes or deletes the target.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { open, stat } from 'node:fs/promises';
import path from 'node:path';
import { codedError } from './evidence.mjs';

/**
 * Checks that `filePath` names a readable file.
 * Throws codedError with code `not_found`, `is_directory` or `unreadable`.
 * @param {string} filePath
 * @returns {Promise<{absPath: string, name: string, size: number}>}
 */
export async function resolveTarget(filePath) {
  const absPath = path.resolve(filePath);
  let info;
  try {
    info = await stat(absPath);
  } catch (err) {
    if (err.code === 'ENOENT' || err.code === 'ENOTDIR') {
      throw codedError('not_found', 'no file at the given path');
    }
    throw codedError('unreadable', 'the file cannot be read');
  }
  if (info.isDirectory()) {
    throw codedError('is_directory', 'the path is a folder, not a file');
  }
  if (!info.isFile()) {
    throw codedError('unreadable', 'the path is not a regular file');
  }
  return { absPath, name: path.basename(absPath), size: info.size };
}

/**
 * Reads at most `maxBytes` bytes from the start of the file.
 * Throws codedError('unreadable', ...) when the file cannot be read.
 * @param {string} absPath
 * @param {number} maxBytes
 * @returns {Promise<Buffer>}
 */
export async function readHead(absPath, maxBytes) {
  let handle;
  try {
    handle = await open(absPath, 'r');
    const buffer = Buffer.alloc(maxBytes);
    const { bytesRead } = await handle.read(buffer, 0, maxBytes, 0);
    return buffer.subarray(0, bytesRead);
  } catch {
    throw codedError('unreadable', 'the file cannot be read');
  } finally {
    if (handle) {
      await handle.close();
    }
  }
}

/**
 * Streams the whole file through SHA-256. Never loads the whole file into memory.
 * Throws codedError('unreadable', ...) when the file cannot be read.
 * @param {string} absPath
 * @returns {Promise<string>}  64 lower-case hex characters
 */
export function sha256File(absPath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(absPath);
    stream.on('error', () => {
      reject(codedError('unreadable', 'the file cannot be read'));
    });
    stream.on('data', (chunk) => {
      hash.update(chunk);
    });
    stream.on('end', () => {
      resolve(hash.digest('hex'));
    });
  });
}
