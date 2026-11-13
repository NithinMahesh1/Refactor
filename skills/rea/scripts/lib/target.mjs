// Read-only access to the target file: checks and digest.
// Nothing here runs, changes or deletes the target.

import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import path from 'node:path';
import { codedError } from './evidence.mjs';

// Two slashes or backslashes in any mix at the start: a network path (\\host\share\file,
// //host/share/file) or a device path (\\?\..., \\.\...). On Windows a network path makes the
// system connect to another computer and log in there with the user's account.
const NETWORK_OR_DEVICE_START = /^[\\/]{2}/;

const UNSAFE_PATH_MESSAGE =
  'network and device paths are not allowed; copy the file to a local folder';

/**
 * Checks that `filePath` names a readable file.
 * Throws codedError with code `usage` (an empty path), `unsafe_path` (a network or device
 * path), `not_found`, `is_directory` or `unreadable`.
 * A path that starts with two slashes or backslashes in any mix is refused on every system
 * before any file system call, and so is a path whose absolute form starts that way (for
 * example a relative path while the current folder is on a network share). Not covered: a
 * drive letter that is mapped to a network share, and a link or junction that points to one.
 * No message repeats the path.
 * @param {string} filePath
 * @returns {Promise<{absPath: string, name: string, size: number}>}
 */
export async function resolveTarget(filePath) {
  if (filePath === '') {
    throw codedError('usage', 'the file path is empty');
  }
  if (NETWORK_OR_DEVICE_START.test(filePath)) {
    throw codedError('unsafe_path', UNSAFE_PATH_MESSAGE);
  }
  const absPath = path.resolve(filePath);
  if (NETWORK_OR_DEVICE_START.test(absPath)) {
    throw codedError('unsafe_path', UNSAFE_PATH_MESSAGE);
  }
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
 * Streams the whole file through SHA-256. Never loads the whole file into memory.
 * The promise settles only after the file is closed again.
 * Throws codedError('unreadable', ...) when the file cannot be read.
 * @param {string} absPath
 * @returns {Promise<string>}  64 lower-case hex characters
 */
export function sha256File(absPath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const stream = createReadStream(absPath);
    let digest = null;
    stream.on('error', () => {
      reject(codedError('unreadable', 'the file cannot be read'));
    });
    stream.on('data', (chunk) => {
      hash.update(chunk);
    });
    stream.on('end', () => {
      digest = hash.digest('hex');
    });
    stream.on('close', () => {
      if (digest === null) {
        reject(codedError('unreadable', 'the file cannot be read'));
      } else {
        resolve(digest);
      }
    });
  });
}
