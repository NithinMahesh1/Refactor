#!/usr/bin/env node
// Identifies one file: its SHA-256 digest, its size and its type from the first bytes.
// Prints one JSON document: an Evidence record on success, an error record on failure.
// Use: node file-identity.mjs <path> [--show-path] [--pretty]
// It never runs, changes or deletes the file.

import { createHash } from 'node:crypto';
import { createReadStream, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from './lib/args.mjs';
import { makeEvidence, makeError, TOOL_VERSION, codedError } from './lib/evidence.mjs';
import { identifyBytes, HEAD_BYTES } from './lib/magic.mjs';
import { resolveTarget } from './lib/target.mjs';

const HELP_TEXT = `Use: node file-identity.mjs <path> [--show-path] [--pretty]
Prints one JSON document: an Evidence record with the SHA-256 digest, the size and the type
of the file, or an error record.
  --show-path  also print the full path of the file (by default only its base name)
  --pretty     print the JSON on several lines
Exit codes: 0 success, 2 error.`;

/**
 * Reads the file once. The same bytes give the digest, the size and the first bytes, so the
 * three values always describe the same content. The promise settles only after the file is
 * closed again, so that the caller can remove the file at once.
 * Throws codedError('unreadable', ...) when the file cannot be read.
 * @param {string} absPath
 * @returns {Promise<{sha256: string, size: number, head: Buffer}>}
 */
function readOnce(absPath) {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    const headParts = [];
    let headLength = 0;
    let size = 0;
    let result = null;
    const stream = createReadStream(absPath);
    stream.on('error', () => {
      reject(codedError('unreadable', 'the file cannot be read'));
    });
    stream.on('data', (chunk) => {
      hash.update(chunk);
      size += chunk.length;
      if (headLength < HEAD_BYTES) {
        const part = chunk.subarray(0, HEAD_BYTES - headLength);
        headParts.push(part);
        headLength += part.length;
      }
    });
    stream.on('end', () => {
      result = { sha256: hash.digest('hex'), size, head: Buffer.concat(headParts) };
    });
    stream.on('close', () => {
      if (result === null) {
        reject(codedError('unreadable', 'the file cannot be read'));
      } else {
        resolve(result);
      }
    });
  });
}

/**
 * Runs the command line and returns { exitCode, output } where output is the text to print
 * (JSON, or the help text for --help). Never calls process.exit and never writes to stdout.
 * @param {string[]} argv  arguments after the script name
 * @returns {Promise<{exitCode: number, output: string}>}
 */
export async function main(argv) {
  let positionals;
  let options;
  try {
    ({ positionals, options } = parseArgs(argv,
      { flags: ['show-path', 'pretty', 'help'], values: [] }));
  } catch (err) {
    // The options were not parsed: look for --pretty in the arguments as typed, before a
    // lone -- (which ends the options).
    const end = argv.indexOf('--');
    const pretty = (end === -1 ? argv : argv.slice(0, end)).includes('--pretty');
    const out = makeError('usage', err.message);
    return {
      exitCode: 2,
      output: pretty ? JSON.stringify(out, null, 2) : JSON.stringify(out),
    };
  }

  if (options.help) {
    return { exitCode: 0, output: HELP_TEXT };
  }

  try {
    if (positionals.length !== 1) {
      throw codedError('usage', 'give exactly one file path');
    }

    const target = await resolveTarget(positionals[0]);
    const { sha256, size, head } = await readOnce(target.absPath);
    if (size !== target.size) {
      throw codedError('unreadable', 'the file changed while it was read');
    }
    const { type, details } = identifyBytes(head, size);

    const subject = {
      name: target.name,
      sha256,
      size_bytes: size,
      ...(options['show-path'] ? { path: target.absPath } : {}),
    };

    const record = makeEvidence({
      subject,
      tool: { name: 'file-identity', version: TOOL_VERSION, engine: null },
      operation: 'identify',
      parameters: {},
      confidence: 'observed',
      result: { type, details, size_bytes: size },
      coverage: {
        examined: 'first 4096 bytes for the type; all bytes for the digest',
        not_examined: ['content after the header was not interpreted'],
        truncated: false,
        next_cursor: null,
      },
      limits: ['The type comes from the first bytes only. A file can carry a misleading header.'],
    });

    return {
      exitCode: 0,
      output: options.pretty ? JSON.stringify(record, null, 2) : JSON.stringify(record),
    };
  } catch (err) {
    let code = err.code;
    let msg = err.message;
    if (!['usage', 'not_found', 'is_directory', 'unreadable', 'unsafe_path'].includes(code)) {
      code = 'unreadable';
      msg = 'the file cannot be read';
    }
    const out = makeError(code, msg);
    return {
      exitCode: 2,
      output: options.pretty ? JSON.stringify(out, null, 2) : JSON.stringify(out),
    };
  }
}

/**
 * True when this file is the script that Node.js started (not imported by a test).
 * @returns {boolean}
 */
function isMainModule() {
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  const { exitCode, output } = await main(process.argv.slice(2));
  // A reader that closes stdout early (for example `| head -c 0`) makes the write fail. That
  // is not an error of this script: print nothing on stderr (no stack trace with the path of
  // this script) and keep the exit code.
  process.stdout.on('error', () => {});
  process.stdout.write(output + '\n');
  process.exitCode = exitCode;
}
