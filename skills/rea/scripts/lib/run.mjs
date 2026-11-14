// Runs a child process with a time limit and an output limit.

import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import { codedError } from './evidence.mjs';

export const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;
export const DEFAULT_TIMEOUT_MS = 600_000;
export const STOP_WAIT_MS = 2000;
export const MAX_OUTPUT_BYTES_LIMIT = 1024 * 1024 * 1024;

/**
 * Returns the path to a system program on Windows: `<root>\System32\<name>`.
 * The root is the value of the first variable in `env` whose name is `SystemRoot`, or else
 * `windir`, in any letter case, and whose value is an absolute path with a drive letter
 * (for example `C:\Windows`). Without such a value the root is `C:\Windows`.
 * @param {string} name
 * @param {Record<string, string | undefined>} [env]
 * @returns {string}
 */
export function windowsSystemProgram(name, env = process.env) {
  return path.win32.join(windowsRoot(env), 'System32', name);
}

/**
 * The Windows folder named in `env`, or `C:\Windows`.
 * @param {Record<string, string | undefined>} env
 * @returns {string}
 */
function windowsRoot(env) {
  const keys = Object.keys(env);
  for (const wanted of ['systemroot', 'windir']) {
    for (const key of keys) {
      const value = env[key];
      if (key.toLowerCase() === wanted && typeof value === 'string'
        && /^[A-Za-z]:[\\/]/.test(value)) {
        return value;
      }
    }
  }
  return 'C:\\Windows';
}

// The children that run now. Their trees stop when the script ends or gets SIGINT or SIGTERM.
const runningChildren = new Set();

/**
 * Stops the process tree of `child` at once, with synchronous calls only.
 * @param {import('node:child_process').ChildProcess} child
 */
function stopTreeNow(child) {
  if (process.platform === 'win32') {
    try {
      spawnSync(windowsSystemProgram('taskkill.exe'), ['/pid', String(child.pid), '/T', '/F'],
        { stdio: 'ignore', windowsHide: true, timeout: 5000 });
    } catch {
      // child.kill() below still runs
    }
    try {
      child.kill();
    } catch {
      // already gone
    }
    return;
  }
  try {
    process.kill(-child.pid, 'SIGKILL');
  } catch {
    try {
      process.kill(child.pid, 'SIGKILL');
    } catch {
      // already gone
    }
  }
}

/** Stops the trees of all running children (the listener for the `exit` event). */
function stopAllNow() {
  for (const child of runningChildren) {
    stopTreeNow(child);
  }
}

/**
 * Stops the trees of all running children; then the signal ends the script as it would
 * without this listener, unless the script has its own listener for that signal.
 * @param {string} signal
 */
function stopAllOnSignal(signal) {
  stopAllNow();
  runningChildren.clear();
  removeStopListeners();
  if (process.listenerCount(signal) === 0) {
    process.kill(process.pid, signal);
  }
}

const onSigint = () => stopAllOnSignal('SIGINT');
const onSigterm = () => stopAllOnSignal('SIGTERM');

/** Adds the listeners that stop the child trees. */
function addStopListeners() {
  process.on('exit', stopAllNow);
  process.on('SIGINT', onSigint);
  process.on('SIGTERM', onSigterm);
}

/** Removes the listeners that stop the child trees. */
function removeStopListeners() {
  process.removeListener('exit', stopAllNow);
  process.removeListener('SIGINT', onSigint);
  process.removeListener('SIGTERM', onSigterm);
}

/**
 * Notes a child that runs; the first one adds the listeners.
 * @param {import('node:child_process').ChildProcess} child
 */
function trackChild(child) {
  runningChildren.add(child);
  if (runningChildren.size === 1) {
    addStopListeners();
  }
}

/**
 * Forgets a child that ended; the last one removes the listeners.
 * @param {import('node:child_process').ChildProcess} child
 */
function untrackChild(child) {
  if (runningChildren.delete(child) && runningChildren.size === 0) {
    removeStopListeners();
  }
}

/**
 * Joins the kept output bytes into UTF-8 text. After a cut, an incomplete character at the
 * end is left out (it would become U+FFFD).
 * @param {Buffer[]} chunks
 * @param {boolean} truncated
 * @returns {string}
 */
function outputText(chunks, truncated) {
  const buf = Buffer.concat(chunks);
  if (!truncated) {
    return buf.toString('utf8');
  }
  for (let back = 1; back <= Math.min(3, buf.length); back++) {
    const byte = buf[buf.length - back];
    if ((byte & 0xc0) !== 0x80) {
      // The lead byte of the last character: 110xxxxx needs 2 bytes, 1110xxxx 3, 11110xxx 4.
      let needed = 1;
      if ((byte & 0xe0) === 0xc0) {
        needed = 2;
      } else if ((byte & 0xf0) === 0xe0) {
        needed = 3;
      } else if ((byte & 0xf8) === 0xf0) {
        needed = 4;
      }
      return buf.subarray(0, back < needed ? buf.length - back : buf.length).toString('utf8');
    }
  }
  return buf.toString('utf8');
}

/**
 * Starts `file` with `args` (an array; `shell` is always false) and waits for it to end.
 * - timeoutMs: when reached and the child has not ended, stops the whole process tree:
 *   on Windows `taskkill /pid <pid> /T /F` by its full path (windowsSystemProgram); when
 *   taskkill cannot start, throws, or ends with an exit code that is not 0, `child.kill()`
 *   follows. Elsewhere the child starts with `detached: true` (its own process group) and
 *   `process.kill(-pid, 'SIGKILL')` is sent. timedOut is then true.
 *   Must be a whole number from 1 to 2147483647.
 * - The wait always ends: when the output pipes are still open STOP_WAIT_MS after the child
 *   ended, or after the stop at the time limit, both pipes are destroyed and the result comes
 *   with the output read so far. A child that ended before the time limit is never stopped.
 * - While the child runs, its tree is stopped in the same way (synchronous calls) when the
 *   script ends (`exit` event) or gets SIGINT or SIGTERM. After the signal the script ends
 *   as it would without the listener, unless it has its own listener for that signal.
 * - maxOutputBytes: each of stdout and stderr keeps only its first maxOutputBytes bytes;
 *   the matching ...Truncated flag is then true, and a character that the cut splits is
 *   left out. stdout and stderr are returned as UTF-8 text. A missing pipe gives ''.
 *   Must be a whole number from 0 to MAX_OUTPUT_BYTES_LIMIT (1 GiB).
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
  if (!Number.isInteger(maxOutputBytes) || maxOutputBytes < 0
    || maxOutputBytes > MAX_OUTPUT_BYTES_LIMIT) {
    return Promise.reject(codedError('usage',
      'maxOutputBytes must be a whole number from 0 to ' + MAX_OUTPUT_BYTES_LIMIT));
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
    let exited = false;
    let exitCode = null;
    let exitSignal = null;
    let stopTimer = null;
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

    const killChild = () => {
      try {
        child.kill();
      } catch {
        // already gone
      }
    };

    const killTree = (pid) => {
      if (pid === undefined || pid === null) {
        return;
      }
      if (isWindows) {
        let taskkill;
        try {
          taskkill = spawn(windowsSystemProgram('taskkill.exe'),
            ['/pid', String(pid), '/T', '/F'], {
            stdio: 'ignore',
            windowsHide: true,
          });
        } catch {
          killChild();
          return;
        }
        taskkill.on('error', killChild);
        taskkill.on('exit', (code) => {
          if (code !== 0) {
            killChild();
          }
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

    // Ends the wait once: also when a grandchild still holds the output pipes open.
    const finish = (code, signal) => {
      clearTimeout(timer);
      clearTimeout(stopTimer);
      if (settled) {
        return;
      }
      settled = true;
      child.stdout?.destroy();
      child.stderr?.destroy();
      resolve({
        exitCode: code,
        signal: signal ?? null,
        stdout: outputText(outChunks, stdoutTruncated),
        stderr: outputText(errChunks, stderrTruncated),
        timedOut,
        stdoutTruncated,
        stderrTruncated,
        durationMs: Date.now() - started,
      });
    };

    const finishLater = () => {
      clearTimeout(stopTimer);
      stopTimer = setTimeout(() => finish(exitCode, exitSignal), STOP_WAIT_MS);
    };

    const timer = setTimeout(() => {
      if (exited) {
        return;
      }
      timedOut = true;
      killTree(child.pid);
      finishLater();
    }, timeoutMs);

    child.stdout?.on('data', (chunk) => {
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

    child.stderr?.on('data', (chunk) => {
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
      if (child.pid !== undefined) {
        // A stop that failed; the exit event or the stop wait ends the wait.
        return;
      }
      clearTimeout(timer);
      if (!settled) {
        settled = true;
        reject(codedError('spawn_failed',
          'could not start the program (' + (err.code ?? 'error') + ')'));
      }
    });

    child.on('exit', (code, signal) => {
      exited = true;
      exitCode = code;
      exitSignal = signal;
      clearTimeout(timer);
      untrackChild(child);
      finishLater();
    });

    child.on('close', (code, signal) => {
      finish(code, signal);
    });

    if (child.pid !== undefined) {
      trackChild(child);
    }
  });
}
