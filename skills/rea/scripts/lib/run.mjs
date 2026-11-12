// Runs a child process with a time limit and an output limit.

import { spawn } from 'node:child_process';
import path from 'node:path';
import { codedError } from './evidence.mjs';

export const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 600_000;

/**
 * Returns the path to a system program on Windows.
 * @param {string} name
 * @param {{SystemRoot?: string, windir?: string}} [env]
 * @returns {string}
 */
export function windowsSystemProgram(name, env = process.env) {
  return path.win32.join(env.SystemRoot || env.windir || 'C:\\Windows', 'System32', name);
}

/**
 * Starts `file` with `args` (an array; `shell` is always false) and waits for it to end.
 * - timeoutMs: when reached, stops the whole process tree: on Windows
 *   `taskkill /pid <pid> /T /F`; elsewhere the child starts with `detached: true` (its own
 *   process group) and `process.kill(-pid, 'SIGKILL')` is sent. timedOut is then true.
 *   Must be a whole number from 1 to 2147483647.
 * - maxOutputBytes: each of stdout and stderr keeps only its first maxOutputBytes bytes;
 *   the matching ...Truncated flag is then true. stdout and stderr are returned as UTF-8 text.
 *   Must be a whole number of 0 or more.
 * - cwd, env: passed to spawn. windowsVerbatimArguments: passed to spawn (used for cmd.exe).
 * - On Windows, `NoDefaultCurrentDirectoryInExePath` is set to '1' to avoid searching the
 *   current directory for executables.
 * - A non-zero exit code is a normal result. Only a failed start rejects, with
 *   codedError('spawn_failed', 'could not start the program (<err_code>)').
 *   Bad options reject with codedError('usage', ...).
 * stdin is ignored ('ignore'). windowsHide is true.
 * @param {string} file
 * @param {string[]} args
 * @param {{timeoutMs?: number, maxOutputBytes?: number, cwd?: string,
 *   env?: NodeJS.ProcessEnv, windowsVerbatimArguments?: boolean}} [options]
 * @returns {Promise<{exitCode: number | null, signal: string | null, stdout: string,
 *   stderr: string, timedOut: boolean, stdoutTruncated: boolean, stderrTruncated: boolean,
 *   durationMs: number}>}
 */
export function runProcess(file, args, { timeoutMs = DEFAULT_TIMEOUT_MS,
  maxOutputBytes = DEFAULT_MAX_OUTPUT_BYTES, cwd, env, windowsVerbatimArguments } = {}) {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 2147483647) {
    return Promise.reject(codedError('usage',
      'timeoutMs must be a whole number from 1 to 2147483647'));
  }
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 0) {
    return Promise.reject(codedError('usage',
      'maxOutputBytes must be a whole number of 0 or more'));
  }

  const started = Date.now();
  return new Promise((resolve, reject) => {
    const isWindows = process.platform === 'win32';
    if (isWindows) {
      // On Windows, prevent the current directory from being searched for executables.
      process.env.NoDefaultCurrentDirectoryInExePath = '1';
    }

    let settled = false;
    let timedOut = false;
    let stdoutTruncated = false;
    let stderrTruncated = false;

    let outChunks = [];
    let outCount = 0;
    let errChunks = [];
    let errCount = 0;

    let child;
    const spawnEnv = (isWindows && env) ? { ...env, NoDefaultCurrentDirectoryInExePath: '1' } : env;

    try {
      child = spawn(file, args, {
        cwd,
        env: spawnEnv,
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
        detached: !isWindows,
        windowsVerbatimArguments: windowsVerbatimArguments === true,
      });
    } catch (err) {
      return reject(codedError('spawn_failed',
        'could not start the program (' + (err.code ?? 'error') + ')'));
    }

    const killTree = (pid) => {
      if (pid === undefined || pid === null) {
        return;
      }
      if (isWindows) {
        const taskkill = spawn(windowsSystemProgram('taskkill.exe'),
          ['/pid', String(pid), '/T', '/F'], {
          stdio: 'ignore',
          windowsHide: true,
        });
        taskkill.on('error', () => {
          child.kill();
        });
      } else {
        try {
          process.kill(-pid, 'SIGKILL');
        } catch {
          try {
            process.kill(pid, 'SIGKILL');
          } catch {
            // already gone
          }
        }
      }
    };

    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child.pid);
    }, timeoutMs);

    child.stdout.on('data', (chunk) => {
      if (outCount < maxOutputBytes) {
        const remaining = maxOutputBytes - outCount;
        const take = Math.min(chunk.length, remaining);
        outChunks.push(chunk.subarray(0, take));
        outCount += take;
        if (take < chunk.length) {
          stdoutTruncated = true;
        }
      } else {
        stdoutTruncated = true;
      }
    });

    child.stderr.on('data', (chunk) => {
      if (errCount < maxOutputBytes) {
        const remaining = maxOutputBytes - errCount;
        const take = Math.min(chunk.length, remaining);
        errChunks.push(chunk.subarray(0, take));
        errCount += take;
        if (take < chunk.length) {
          stderrTruncated = true;
        }
      } else {
        stderrTruncated = true;
      }
    });

    child.on('error', (err) => {
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(codedError('spawn_failed',
          'could not start the program (' + (err.code ?? 'error') + ')'));
      }
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (settled) {
        return;
      }
      settled = true;
      resolve({
        exitCode: code,
        signal: signal ?? null,
        stdout: Buffer.concat(outChunks).toString('utf8'),
        stderr: Buffer.concat(errChunks).toString('utf8'),
        timedOut,
        stdoutTruncated,
        stderrTruncated,
        durationMs: Date.now() - started,
      });
    });
  });
}
