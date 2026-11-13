// Shared helpers for the ghidra-query tests: a temporary folder with a target file, an
// environment that starts the stand-in program in place of Ghidra, and readers for its log.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProcess } from '../../skills/rea/scripts/lib/run.mjs';

export const SCRIPT = fileURLToPath(
  new URL('../../skills/rea/scripts/ghidra-query.mjs', import.meta.url));
export const FAKE = fileURLToPath(new URL('./fake-analyze-headless.mjs', import.meta.url));
export const JAVA_NAME = process.platform === 'win32' ? 'java.exe' : 'java';

// Variables that a test run must not take from the computer that runs the tests.
const CLEARED = ['GHIDRA_INSTALL_DIR', 'REFACTOR_ENGINE_COMMAND', 'REFACTOR_CACHE_DIR',
  'FAKE_GHIDRA_MODE', 'FAKE_GHIDRA_ARGS_LOG', 'JAVA_HOME'];

/**
 * Makes a temporary folder `tmp` that holds a 64-byte target file `sample.bin`, and an
 * environment `env` that starts the stand-in in place of Ghidra:
 * REFACTOR_ENGINE_COMMAND = [process.execPath, FAKE], REFACTOR_CACHE_DIR = <tmp>/cache and
 * FAKE_GHIDRA_ARGS_LOG = <tmp>/args.log. Then each entry of `extra` is set (a value of
 * undefined removes the variable). Call cleanup() in a finally block.
 * @param {Record<string, string | undefined>} [extra]
 * @returns {{tmp: string, target: string, log: string, env: NodeJS.ProcessEnv,
 *   cleanup: () => void}}
 */
export function setup(extra = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  const target = path.join(tmp, 'sample.bin');
  fs.writeFileSync(target, Buffer.alloc(64, 0x41));
  const log = path.join(tmp, 'args.log');
  const env = { ...process.env };
  for (const name of CLEARED) {
    delete env[name];
  }
  env.REFACTOR_ENGINE_COMMAND = JSON.stringify([process.execPath, FAKE]);
  env.REFACTOR_CACHE_DIR = path.join(tmp, 'cache');
  env.FAKE_GHIDRA_ARGS_LOG = log;
  for (const [name, value] of Object.entries(extra)) {
    if (value === undefined) {
      delete env[name];
    } else {
      env[name] = value;
    }
  }
  const cleanup = () => {
    fs.rmSync(tmp, { recursive: true, force: true });
  };
  return { tmp, target, log, env, cleanup };
}

/**
 * Runs the script with `args` and `env`, in the folder `cwd` (default: this process's
 * folder), through runProcess with a time limit of 120 seconds. `json` is the parsed stdout,
 * or null when stdout is not JSON.
 * @param {string[]} args
 * @param {NodeJS.ProcessEnv} env
 * @param {string} [cwd]
 * @returns {Promise<{status: number | null, stdout: string, stderr: string, json: any}>}
 */
export async function run(args, env, cwd) {
  const r = await runProcess(process.execPath, [SCRIPT, ...args], {
    env,
    cwd,
    timeoutMs: 120000,
  });
  let json = null;
  try {
    json = JSON.parse(r.stdout);
  } catch {
    json = null;
  }
  return { status: r.exitCode, stdout: r.stdout, stderr: r.stderr, json };
}

/**
 * The runs of the stand-in, one entry for each run, in order: { args, cwd_is_query_dir, query }.
 * An empty array when the stand-in never ran.
 * @param {string} log  the FAKE_GHIDRA_ARGS_LOG file
 * @returns {{args: string[], cwd_is_query_dir: boolean, query: object | null}[]}
 */
export function readLog(log) {
  if (!fs.existsSync(log)) {
    return [];
  }
  return fs.readFileSync(log, 'utf8').split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line));
}

/**
 * The value that follows `name` in an argument list, or undefined.
 * @param {string[]} args
 * @param {string} name
 * @returns {string | undefined}
 */
export function argAfter(args, name) {
  const i = args.indexOf(name);
  return i === -1 ? undefined : args[i + 1];
}

/**
 * True when `text` holds `folder`, as it is or in its JSON form (each backslash doubled).
 * @param {string} text
 * @param {string} folder
 * @returns {boolean}
 */
export function holdsPath(text, folder) {
  return text.includes(folder) || text.includes(JSON.stringify(folder).slice(1, -1));
}

/**
 * Makes a stand-in Ghidra folder `<tmp>/g`: support/analyzeHeadless and
 * support/analyzeHeadless.bat (empty files) and Ghidra/application.properties with the
 * given version. Returns the folder (an absolute path).
 * @param {string} tmp
 * @param {string} [version]
 * @returns {string}
 */
export function makeGhidraFolder(tmp, version = '11.0.3') {
  const g = path.join(tmp, 'g');
  fs.mkdirSync(path.join(g, 'support'), { recursive: true });
  fs.mkdirSync(path.join(g, 'Ghidra'), { recursive: true });
  fs.writeFileSync(path.join(g, 'support', 'analyzeHeadless'), '');
  fs.writeFileSync(path.join(g, 'support', 'analyzeHeadless.bat'), '');
  fs.writeFileSync(path.join(g, 'Ghidra', 'application.properties'),
    `application.name=Ghidra\napplication.version=${version}\n`);
  return g;
}

/**
 * Windows only: makes the folder of makeGhidraFolder(tmp, '11.0-test'), whose
 * support/analyzeHeadless.bat starts the stand-in with node, so that a test runs the real
 * .bat path through cmd.exe. Returns the folder.
 * @param {string} tmp
 * @returns {string}
 */
export function makeBatGhidraFolder(tmp) {
  const g = makeGhidraFolder(tmp, '11.0-test');
  fs.writeFileSync(path.join(g, 'support', 'analyzeHeadless.bat'),
    `@echo off\r\n"${process.execPath}" "${FAKE}" %*\r\n`);
  return g;
}
