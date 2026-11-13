#!/usr/bin/env node
// Asks Ghidra (in headless mode) about one program file and prints one JSON document:
// an Evidence record on success, an error record on failure.
// Use: node ghidra-query.mjs <check|functions|strings|decompile> [<path>] [options]
// It never downloads or installs anything, and it never runs the target.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildWindowsBatCommand, parseArgs } from './lib/args.mjs';
import { codedError, makeError, makeEvidence, TOOL_VERSION } from './lib/evidence.mjs';
import { parseCursor, parseLimit } from './lib/limits.mjs';
import { runProcess, windowsSystemProgram } from './lib/run.mjs';
import { resolveTarget, sha256File } from './lib/target.mjs';

export const COMMANDS = Object.freeze(['check', 'functions', 'strings', 'decompile']);
export const SCRIPT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'ghidra');
export const QUERY_SCRIPT = 'RefactorQuery.java';
export const MAX_RESULT_BYTES = 5 * 1024 * 1024;
export const ENGINE_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
export const DEFAULT_MAX_CHARS = 20000;
export const MAX_MAX_CHARS = 200000;
export const DEFAULT_TIMEOUT_SEC = 600;
export const MAX_TIMEOUT_SEC = 86400;
export const ERROR_TAIL_CHARS = 2000;
// A cause is named only when a line of the engine output names the script: a message of the
// Java compiler ("RefactorQuery.java:12: error: ...") or a stack frame
// ("at RefactorQuery.run("). Single words do not count: the normal log of an import holds
// "Compiler", "Decompiler" and "Exception Handlers".
const SCRIPT_COMPILE_ERROR = /RefactorQuery\.java:\d+:\s*error\b/;
const SCRIPT_STACK_FRAME = /\bat RefactorQuery\.[\w$<>]+\(/;
const USAGE_REFACTOR_ENGINE_COMMAND = 'REFACTOR_ENGINE_COMMAND must be a JSON array of texts '
  + 'that starts with an absolute program path';
const ENGINE_NOT_FOUND_GHIDRA = 'Ghidra was not found: pass --ghidra <folder> or set '
  + 'GHIDRA_INSTALL_DIR';

// Error codes that this script prints. USAGE_CODES mean "change the command or the file" and
// give exit code 2; ENGINE_CODES give exit code 3. Any other error becomes internal_error.
const USAGE_CODES = Object.freeze(['usage', 'not_found', 'is_directory', 'unreadable',
  'unsafe_path', 'function_not_found', 'bad_address']);
const ENGINE_CODES = Object.freeze(['engine_not_found', 'engine_failed', 'engine_timeout',
  'bad_engine_output', 'decompile_failed']);

const HELP_TEXT = [
  'Use: node ghidra-query.mjs <check|functions|strings|decompile> [<path>] [options]',
  'Asks Ghidra (in headless mode) about one program file and prints one JSON document.',
  '  check               report whether Ghidra and Java are found (starts no program)',
  '  functions <path>    list the functions, in address order',
  '  strings <path>      list the defined strings, in address order',
  '  decompile <path>    decompile one function (give --name or --address)',
  'Options:',
  '  --ghidra <folder>   the Ghidra folder (else the variable GHIDRA_INSTALL_DIR)',
  '  --limit <n>         items on one page, 1 to 1000 (default 100)',
  '  --cursor <c>        start at this item: the next_cursor value of the page before',
  '  --filter <text>     only names or texts that hold this text (case ignored)',
  '  --name <name>       decompile: the exact name of the function',
  '  --address <hex>     decompile: an address inside the function, for example 0x401000',
  '  --max-chars <n>     decompile: most characters of code, 1 to 200000 (default 20000)',
  '  --timeout-sec <n>   time limit for Ghidra, 1 to 86400 seconds (default 600)',
  '  --no-cache          use a new project folder and remove it at the end',
  '  --show-path         also print full paths (by default only base names)',
  '  --pretty            print the JSON on several lines',
  'Exit codes: 0 success, 2 command or file error, 3 Ghidra error.',
].join('\n');

/**
 * Returns the cache root folder (main makes it absolute with path.resolve).
 * - env.REFACTOR_CACHE_DIR when it is a non-empty string;
 * - win32: path.win32.join(env.LOCALAPPDATA || path.win32.join(home, 'AppData', 'Local'),
 *   'refactor', 'cache');
 * - darwin: path.posix.join(home, 'Library', 'Caches', 'refactor');
 * - other: path.posix.join(env.XDG_CACHE_HOME || path.posix.join(home, '.cache'), 'refactor').
 * @param {NodeJS.ProcessEnv} env
 * @param {string} platform  a value of process.platform
 * @param {string} home  the user's home folder
 * @returns {string}
 */
export function cacheRoot(env, platform, home) {
  if (env.REFACTOR_CACHE_DIR && env.REFACTOR_CACHE_DIR.length > 0) {
    return env.REFACTOR_CACHE_DIR;
  }
  if (platform === 'win32') {
    return path.win32.join(
      env.LOCALAPPDATA || path.win32.join(home, 'AppData', 'Local'),
      'refactor',
      'cache'
    );
  }
  if (platform === 'darwin') {
    return path.posix.join(home, 'Library', 'Caches', 'refactor');
  }
  return path.posix.join(env.XDG_CACHE_HOME || path.posix.join(home, '.cache'), 'refactor');
}

/**
 * The file name of the Ghidra launcher: 'analyzeHeadless.bat' when platform is 'win32',
 * else 'analyzeHeadless'.
 * @param {string} platform  a value of process.platform
 * @returns {string}
 */
export function launcherName(platform) {
  return platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless';
}

/**
 * Builds the analyzeHeadless argument list (without the launcher itself).
 * mode 'import':  [projectDir, 'p', '-import', targetPath, ...tail]
 * mode 'process': [projectDir, 'p', '-process', targetName, '-noanalysis', '-readOnly',
 *   ...tail] (-readOnly: Ghidra never saves the project after a later query)
 * tail: ['-scriptPath', scriptDir, '-postScript', QUERY_SCRIPT, queryFile,
 *   '-analysisTimeoutPerFile', String(timeoutSec)]
 * Throws codedError('unsafe_path', 'the file name starts with "-", so Ghidra would read it as
 * an option: copy the file to a name that does not start with "-"') when targetName starts
 * with '-' (in both modes). Also throws unsafe_path when scriptDir holds ';' (Ghidra
 * reads it as a separator of folders). The messages never repeat the name or the folder.
 * @param {{mode: 'import' | 'process', projectDir: string, targetPath: string,
 *   targetName: string, scriptDir: string, queryFile: string, timeoutSec: number}} input
 * @returns {string[]}
 */
export function buildEngineArgs({ mode, projectDir, targetPath, targetName, scriptDir,
  queryFile, timeoutSec }) {
  if (targetName.startsWith('-')) {
    throw codedError(
      'unsafe_path',
      'the file name starts with "-", so Ghidra would read it as an option: ' +
        'copy the file to a name that does not start with "-"'
    );
  }
  if (scriptDir.includes(';')) {
    throw codedError('unsafe_path', 'the skill folder path holds ";", which Ghidra reads as '
      + 'a separator: move the skill to a folder without ";"');
  }
  const tail = ['-scriptPath', scriptDir, '-postScript', QUERY_SCRIPT, queryFile,
    '-analysisTimeoutPerFile', String(timeoutSec)];
  if (mode === 'import') {
    return [projectDir, 'p', '-import', targetPath, ...tail];
  } else {
    return [projectDir, 'p', '-process', targetName, '-noanalysis', '-readOnly', ...tail];
  }
}

/**
 * Makes engine output safe to show, then keeps its end.
 * 1. The replacements, in this order: names.home -> '~', names.home with every '\'
 *    changed to '/' -> '~', names.home with every '/' changed to '\' -> '~',
 *    names.user -> '<user>', names.host -> '<host>', and the part of names.host before
 *    its first '.' (only when the host holds a '.') -> '<host>'. Skip a value that is
 *    not a string or is shorter than 2 characters, and skip a value that is already in
 *    the list (case ignored).
 * 2. Sort them by the length of the value, longest first (a stable sort, so equal lengths
 *    keep the order of step 1). Replace each value in turn, case ignored. A home value is
 *    replaced wherever it is. A user or host value is replaced only where the character
 *    before it and the character after it (when there is one) is not one of [A-Za-z0-9].
 *    Build each pattern from the value with every character of .*+?^${}()|[]\ escaped.
 * 3. Return the last maxChars characters of the result (all of it when it is shorter).
 * @param {string} text
 * @param {{home?: string, user?: string, host?: string}} names
 * @param {number} [maxChars]
 * @returns {string}
 */
export function scrubTail(text, names, maxChars = ERROR_TAIL_CHARS) {
  const { home, homeShort, user, host } = names;
  const replacements = [];

  const addRepl = (v, type) => {
    if (typeof v !== 'string' || v.length < 2) {
      return;
    }
    if (replacements.some(r => r.v.toLowerCase() === v.toLowerCase())) {
      return;
    }
    replacements.push({ v, type });
  };

  if (home) {
    addRepl(home, 'home');
    addRepl(home.replace(/\\/g, '/'), 'home');
    addRepl(home.replace(/\//g, '\\'), 'home');
  }
  if (homeShort) {
    addRepl(homeShort, 'home');
    addRepl(homeShort.replace(/\\/g, '/'), 'home');
  }
  addRepl(user, 'user');
  addRepl(host, 'host');
  if (host && typeof host === 'string' && host.includes('.')) {
    addRepl(host.split('.')[0], 'host');
  }

  replacements.sort((a, b) => b.v.length - a.v.length);

  let result = text;
  for (const { v, type } of replacements) {
    const escaped = v.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (type === 'home') {
      const re = new RegExp(escaped, 'gi');
      result = result.replace(re, () => '~');
    } else {
      const pattern = '(?<![A-Za-z0-9])' + escaped + '(?![A-Za-z0-9])';
      const re = new RegExp(pattern, 'gi');
      const replacement = (type === 'user') ? '<user>' : '<host>';
      result = result.replace(re, () => replacement);
    }
  }

  return result.slice(-maxChars);
}

/**
 * Reads the Ghidra version from path.join(ghidraDir, 'Ghidra', 'application.properties'):
 * the value of the first line (lines split on /\r?\n/) that matches
 * /^application\.version\s*=\s*(.*)$/, trimmed. Returns null when ghidraDir is null, when
 * the file cannot be read, when no line matches, or when the value is empty.
 * @param {string | null} ghidraDir
 * @returns {string | null}
 */
export function readGhidraVersion(ghidraDir) {
  if (!ghidraDir) {
    return null;
  }
  try {
    const file = path.join(ghidraDir, 'Ghidra', 'application.properties');
    const content = fs.readFileSync(file, 'utf8');
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const match = line.match(/^application\.version\s*=\s*(.*)$/);
      if (match) {
        const val = match[1].trim();
        return val === '' ? null : val;
      }
    }
    return null;
  } catch (err) {
    return null;
  }
}

/**
 * Looks for a java program without starting it. The name is 'java.exe' when platform is
 * 'win32', else 'java'. A candidate counts only when it is a file
 * (fs.statSync(candidate, { throwIfNoEntry: false })?.isFile() === true).
 * 1. When env.JAVA_HOME is a non-empty string: path.join(env.JAVA_HOME, 'bin', name); when it
 *    counts, return { found: true, source: 'JAVA_HOME', path: candidate }.
 * 2. Else each non-empty folder of (env.PATH ?? env.Path ?? '').split(path.delimiter), in
 *    order: path.join(folder, name); the first that counts gives
 *    { found: true, source: 'PATH', path: candidate }.
 * 3. Else { found: false, source: null, path: null }.
 * @param {NodeJS.ProcessEnv} env
 * @param {string} platform  a value of process.platform
 * @returns {{found: boolean, source: 'JAVA_HOME' | 'PATH' | null, path: string | null}}
 */
export function findJava(env, platform) {
  const name = platform === 'win32' ? 'java.exe' : 'java';
  if (env.JAVA_HOME && env.JAVA_HOME.length > 0) {
    const candidate = path.join(env.JAVA_HOME, 'bin', name);
    if (fs.statSync(candidate, { throwIfNoEntry: false })?.isFile() === true) {
      return { found: true, source: 'JAVA_HOME', path: candidate };
    }
  }

  const pathStr = env.PATH || env.Path || '';
  const folders = pathStr.split(path.delimiter);
  for (const folder of folders) {
    if (folder.length > 0) {
      const candidate = path.join(folder, name);
      if (fs.statSync(candidate, { throwIfNoEntry: false })?.isFile() === true) {
        return { found: true, source: 'PATH', path: candidate };
      }
    }
  }

  return { found: false, source: null, path: null };
}

/**
 * Checks the options of functions, strings and decompile. Every failure throws
 * codedError('usage', message).
 * - limit = parseLimit(options.limit); cursor = String(parseCursor(options.cursor)). Their
 *   errors (codes bad_limit and bad_cursor) become usage errors with the same message.
 * - filter = options.filter, or null when not given.
 * - maxChars: DEFAULT_MAX_CHARS when options['max-chars'] is not given; else it must match
 *   /^[0-9]+$/ and be from 1 to MAX_MAX_CHARS; message
 *   'max-chars must be a whole number from 1 to 200000'.
 * - timeoutSec: DEFAULT_TIMEOUT_SEC when options['timeout-sec'] is not given; else it must match
 *   /^[0-9]+$/ and be from 1 to MAX_TIMEOUT_SEC; message
 *   'timeout-sec must be a whole number from 1 to 86400'.
 * - name = options.name and address = options.address, each null when not given or ''.
 *   decompile: exactly one of them must be set; message
 *   'decompile needs exactly one of --name and --address'. address must match
 *   /^(0[xX])?[0-9a-fA-F]{1,16}$/; message 'address must be hex digits, for example 0x401000'.
 *   functions and strings: neither may be set; message
 *   '--name and --address are only for decompile'.
 * @param {string} command  'functions', 'strings' or 'decompile'
 * @param {Record<string, string | boolean>} options  the options object from parseArgs
 * @returns {{limit: number, cursor: string, filter: string | null, name: string | null,
 *   address: string | null, maxChars: number, timeoutSec: number}}
 */
export function parseQueryOptions(command, options) {
  let limit, cursor, filter, maxChars, timeoutSec;

  try {
    limit = parseLimit(options.limit);
  } catch (err) {
    if (err.code === 'bad_limit') {
      throw codedError('usage', err.message);
    }
    throw err;
  }

  try {
    cursor = String(parseCursor(options.cursor));
  } catch (err) {
    if (err.code === 'bad_cursor') {
      throw codedError('usage', err.message);
    }
    throw err;
  }

  filter = options.filter || null;

  if (options['max-chars'] === undefined || options['max-chars'] === '') {
    maxChars = DEFAULT_MAX_CHARS;
  } else {
    const s = String(options['max-chars']);
    if (!/^[0-9]+$/.test(s) || parseInt(s, 10) < 1 || parseInt(s, 10) > MAX_MAX_CHARS) {
      throw codedError('usage', 'max-chars must be a whole number from 1 to 200000');
    }
    maxChars = parseInt(s, 10);
  }

  if (options['timeout-sec'] === undefined || options['timeout-sec'] === '') {
    timeoutSec = DEFAULT_TIMEOUT_SEC;
  } else {
    const s = String(options['timeout-sec']);
    if (!/^[0-9]+$/.test(s) || parseInt(s, 10) < 1 || parseInt(s, 10) > MAX_TIMEOUT_SEC) {
      throw codedError('usage', 'timeout-sec must be a whole number from 1 to 86400');
    }
    timeoutSec = parseInt(s, 10);
  }

  let name = options.name || null;
  let address = options.address || null;

  if (command === 'decompile') {
    if ((name && address) || (!name && !address)) {
      throw codedError('usage', 'decompile needs exactly one of --name and --address');
    }
    if (address && !/^(0[xX])?[0-9a-fA-F]{1,16}$/.test(address)) {
      throw codedError('usage', 'address must be hex digits, for example 0x401000');
    }
  } else {
    if (name || address) {
      throw codedError('usage', '--name and --address are only for decompile');
    }
  }

  return { limit, cursor, filter, name, address, maxChars, timeoutSec };
}

/**
 * Chooses how analyzeHeadless opens the target. Returns 'process' when all of these hold:
 * marker is an object (not null, not an array); marker.sha256 === sha256;
 * marker.program_name is a non-empty string; and ghidraVersion is null or
 * marker.ghidra_version === ghidraVersion. Else returns 'import'.
 * @param {unknown} marker  the parsed imported.json of the project folder, or null
 * @param {string} sha256  the digest of the target
 * @param {string | null} ghidraVersion  the version of the Ghidra folder, when known
 * @returns {'import' | 'process'}
 */
export function chooseMode(marker, sha256, ghidraVersion) {
  if (marker && typeof marker === 'object' && !Array.isArray(marker)) {
    if (marker.sha256 === sha256 &&
        typeof marker.program_name === 'string' && marker.program_name.length > 0 &&
        (ghidraVersion === null || marker.ghidra_version === ghidraVersion)) {
      return 'process';
    }
  }
  return 'import';
}

/**
 * The user's home folder, user name and machine name, for scrubTail. Never throws: each value
 * that cannot be read (os.homedir(), os.userInfo().username, os.hostname()) is ''.
 * @returns {{home: string, user: string, host: string}}
 */
function localNames() {
  let home = '';
  try {
    home = os.homedir() || '';
  } catch {
  }
  let user = '';
  try {
    user = os.userInfo().username || '';
  } catch {
  }
  let host = '';
  try {
    host = os.hostname() || '';
  } catch {
  }
  let tmpGiven = '';
  let tmpReal = '';
  try {
    tmpGiven = path.resolve(os.tmpdir());
    tmpReal = fs.realpathSync.native(tmpGiven);
  } catch {
  }
  return { home, homeShort: shortHome(home, tmpGiven, tmpReal), user, host };
}

/**
 * The short (8.3) spelling of the home folder on Windows, or '' when there is none to find.
 * tmpGiven is os.tmpdir() and tmpReal is its real path: when tmpReal is below home and
 * tmpGiven ends with the same folders, the start of tmpGiven is the other spelling of the
 * home folder (a folder name such as LONGNA~1 in place of the long name).
 * @param {string} home
 * @param {string} tmpGiven
 * @param {string} tmpReal
 * @returns {string}
 */
export function shortHome(home, tmpGiven, tmpReal) {
  if (typeof home !== 'string' || home.length < 2 ||
      !tmpReal.toLowerCase().startsWith(home.toLowerCase())) {
    return '';
  }
  const tail = tmpReal.slice(home.length);
  if (!/^[\\/]/.test(tail) || tmpGiven.length <= tail.length ||
      !tmpGiven.toLowerCase().endsWith(tail.toLowerCase())) {
    return '';
  }
  return tmpGiven.slice(0, tmpGiven.length - tail.length);
}

/**
 * Runs `check`. Starts no process. Returns, with the keys in this order:
 * { schema: 'refactor.check/1', ghidra: { found, version }, java: { found, source }, ready }.
 * - ghidra.found: ghidraDir is not null and path.join(ghidraDir, 'support',
 *   launcherName(process.platform)) is a file. ghidra.version: readGhidraVersion(ghidraDir).
 * - java: found and source from findJava(env, process.platform).
 * - ready: ghidra.found && java.found.
 * - showPath: also ghidra.path = ghidraDir (only when ghidraDir is not null) and
 *   java.path = the path from findJava (only when found), each as the last key of its object.
 * @param {string | null} ghidraDir  an absolute folder, or null when none was given
 * @param {NodeJS.ProcessEnv} env
 * @param {boolean} showPath
 * @returns {object}
 */
function checkReport(ghidraDir, env, showPath) {
  const launcher = ghidraDir
    ? path.join(ghidraDir, 'support', launcherName(process.platform))
    : null;
  const ghidraFound = ghidraDir !== null &&
    fs.statSync(launcher, { throwIfNoEntry: false })?.isFile() === true;
  const ghidraVersion = readGhidraVersion(ghidraDir);
  const ghidra = { found: ghidraFound, version: ghidraVersion };
  if (showPath && ghidraDir !== null) {
    ghidra.path = ghidraDir;
  }

  const java = findJava(env, process.platform);
  const javaObj = { found: java.found, source: java.source };
  if (showPath && java.found) {
    javaObj.path = java.path;
  }

  const ready = ghidra.found && java.found;

  return {
    schema: 'refactor.check/1',
    ghidra,
    java: javaObj,
    ready,
  };
}

/**
 * Finds the program that runs the engine.
 * - When env.REFACTOR_ENGINE_COMMAND is a non-empty string (TEST ONLY: the tests use it to
 *   start a stand-in program in place of Ghidra; it is not a user setting): JSON.parse it.
 *   It must be a non-empty array of strings whose first item is an absolute path
 *   (path.isAbsolute), else codedError('usage', 'REFACTOR_ENGINE_COMMAND must be a JSON array
 *   of texts that starts with an absolute program path'). Return
 *   { program: arr[0], prefix: arr.slice(1), useBat: false }.
 * - Else ghidraDir must not be null and the launcher path.join(ghidraDir, 'support',
 *   launcherName(platform)) must be a file, else codedError('engine_not_found', 'Ghidra was
 *   not found: pass --ghidra <folder> or set GHIDRA_INSTALL_DIR'). Return
 *   { program: <the launcher path>, prefix: [], useBat: platform === 'win32' }.
 * @param {NodeJS.ProcessEnv} env
 * @param {string | null} ghidraDir  an absolute folder, or null
 * @param {string} platform  a value of process.platform
 * @returns {{program: string, prefix: string[], useBat: boolean}}
 */
function engineCommand(env, ghidraDir, platform) {
  if (env.REFACTOR_ENGINE_COMMAND && env.REFACTOR_ENGINE_COMMAND.length > 0) {
    let arr;
    try {
      arr = JSON.parse(env.REFACTOR_ENGINE_COMMAND);
    } catch {
      throw codedError('usage', USAGE_REFACTOR_ENGINE_COMMAND);
    }
    if (!Array.isArray(arr) || arr.length === 0
      || !arr.every((item) => typeof item === 'string') || !path.isAbsolute(arr[0])) {
      throw codedError('usage', USAGE_REFACTOR_ENGINE_COMMAND);
    }
    return { program: arr[0], prefix: arr.slice(1), useBat: false };
  }

  if (!ghidraDir) {
    throw codedError('engine_not_found', ENGINE_NOT_FOUND_GHIDRA);
  }
  const launcher = path.join(ghidraDir, 'support', launcherName(platform));
  if (fs.statSync(launcher, { throwIfNoEntry: false })?.isFile() !== true) {
    throw codedError('engine_not_found', ENGINE_NOT_FOUND_GHIDRA);
  }
  return { program: launcher, prefix: [], useBat: platform === 'win32' };
}

/**
 * Starts the engine with the arguments [...engine.prefix, ...args] and waits for it.
 * - engine.useBat: runProcess(windowsSystemProgram('cmd.exe', env),
 *   buildWindowsBatCommand(engine.program, [...engine.prefix, ...args]),
 *   { timeoutMs, maxOutputBytes: ENGINE_MAX_OUTPUT_BYTES, cwd, env,
 *   windowsVerbatimArguments: true }). Node.js cannot start a .bat file without cmd.exe, and
 *   cmd.exe is started by its full path only. An unsafe_path error from
 *   buildWindowsBatCommand is thrown as it is.
 * - Else: runProcess(engine.program, [...engine.prefix, ...args],
 *   { timeoutMs, maxOutputBytes: ENGINE_MAX_OUTPUT_BYTES, cwd, env }).
 * - timeoutMs is timeoutSec * 1000.
 * - A rejection with code spawn_failed becomes codedError('engine_not_found',
 *   'Ghidra could not be started'). Any other rejection is thrown as it is.
 * - result.timedOut: throw codedError('engine_timeout',
 *   `Ghidra did not finish within ${timeoutSec} seconds`).
 * - result.exitCode !== 0: throw codedError('engine_failed',
 *   `Ghidra ended with exit code ${result.exitCode}`, { exit_code: result.exitCode,
 *   output: scrubTail(result.stdout + '\n' + result.stderr, names) }).
 * - Else return scrubTail(result.stdout + '\n' + result.stderr, names, ENGINE_MAX_OUTPUT_BYTES)
 *   (all of the engine's output, scrubbed; runQuery looks for messages in it).
 * @param {{program: string, prefix: string[], useBat: boolean}} engine
 * @param {string[]} args  from buildEngineArgs
 * @param {{timeoutSec: number, cwd: string, env: NodeJS.ProcessEnv,
 *   names: {home: string, user: string, host: string}}} options
 * @returns {Promise<string>}
 */
async function startEngine(engine, args, { timeoutSec, cwd, env, names }) {
  const timeoutMs = timeoutSec * 1000;
  let result;
  try {
    if (engine.useBat) {
      result = await runProcess(windowsSystemProgram('cmd.exe', env),
        buildWindowsBatCommand(engine.program, [...engine.prefix, ...args]),
        { timeoutMs, maxOutputBytes: ENGINE_MAX_OUTPUT_BYTES, cwd, env,
          windowsVerbatimArguments: true });
    } else {
      result = await runProcess(engine.program, [...engine.prefix, ...args],
        { timeoutMs, maxOutputBytes: ENGINE_MAX_OUTPUT_BYTES, cwd, env });
    }
  } catch (err) {
    if (err.code === 'spawn_failed') {
      throw codedError('engine_not_found', 'Ghidra could not be started');
    }
    throw err;
  }

  if (result.timedOut) {
    throw codedError('engine_timeout', `Ghidra did not finish within ${timeoutSec} seconds`);
  }

  if (result.exitCode !== 0) {
    throw codedError('engine_failed',
      `Ghidra ended with exit code ${result.exitCode}`, { exit_code: result.exitCode,
      output: scrubTail(result.stdout + '\n' + result.stderr, names) });
  }

  return scrubTail(result.stdout + '\n' + result.stderr, names, ENGINE_MAX_OUTPUT_BYTES);
}

/**
 * Reads the imported.json marker of a project folder. Returns the parsed value, or null when
 * the file is missing or is not JSON.
 * @param {string} projectDir
 * @returns {unknown}
 */
function readMarker(projectDir) {
  const markerFile = path.join(projectDir, 'imported.json');
  if (!fs.existsSync(markerFile)) {
    return null;
  }
  try {
    const content = fs.readFileSync(markerFile, 'utf8');
    return JSON.parse(content);
  } catch {
    return null;
  }
}

/**
 * Reads and checks the result file that the Ghidra script wrote. Throws
 * codedError('bad_engine_output', 'Ghidra did not write a valid result file') when the file is
 * larger than MAX_RESULT_BYTES (check the size with fs.statSync before reading), is not JSON,
 * is not an object (null and arrays do not count), or has no boolean `ok`; and also when ok
 * is true and `result` is not an object (null and arrays do not count).
 * When the file is missing, the message names the cause found in engineOutput (the scrubbed
 * output of the engine): when /compil/i matches it, 'Ghidra did not write a result file: the
 * Ghidra script did not compile'; else when /Exception|Error:/ matches it, 'Ghidra did not
 * write a result file: the Ghidra script stopped with an exception'; else 'Ghidra did not
 * write a valid result file'. The code is always bad_engine_output and there are no details.
 * @param {string} outFile
 * @param {string} engineOutput
 * @returns {object}
 */
function readResultFile(outFile, engineOutput) {
  if (!fs.existsSync(outFile)) {
    let message = 'Ghidra did not write a valid result file';
    if (SCRIPT_COMPILE_ERROR.test(engineOutput)) {
      message = 'Ghidra did not write a result file: the Ghidra script did not compile';
    } else if (SCRIPT_STACK_FRAME.test(engineOutput)) {
      message = 'Ghidra did not write a result file: the Ghidra script stopped with an exception';
    }
    throw codedError('bad_engine_output', message);
  }

  if (fs.statSync(outFile).size > MAX_RESULT_BYTES) {
    throw codedError('bad_engine_output', 'Ghidra did not write a valid result file');
  }

  let file;
  try {
    file = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  } catch {
    throw codedError('bad_engine_output', 'Ghidra did not write a valid result file');
  }

  if (file === null || typeof file !== 'object' || Array.isArray(file)) {
    throw codedError('bad_engine_output', 'Ghidra did not write a valid result file');
  }

  if (file.ok === undefined || typeof file.ok !== 'boolean') {
    throw codedError('bad_engine_output', 'Ghidra did not write a valid result file');
  }

  const result = file.result;
  if (file.ok === true
    && (result === null || typeof result !== 'object' || Array.isArray(result))) {
    throw codedError('bad_engine_output', 'Ghidra did not write a valid result file');
  }

  return file;
}

/**
 * Builds the Evidence record (makeEvidence) for a result file with ok === true.
 * - subject: { name: target.name, sha256, size_bytes: target.size }, plus
 *   path: target.absPath only when showPath.
 * - tool: { name: 'ghidra-query', version: TOOL_VERSION,
 *   engine: { name: 'ghidra', version: String(file.ghidra_version ?? 'unknown') } }.
 * - operation: command. confidence: 'derived' for decompile, else 'observed'.
 * - parameters: functions and strings { limit, cursor, filter }; decompile
 *   { name, address, max_chars: maxChars } (from query).
 * - result: { program: file.program ?? null, ...file.result }; for decompile also
 *   code: file.result.code ?? null (a missing key reads as null).
 * - coverage, functions and strings: next = file.result.next_cursor == null ? null :
 *   String(file.result.next_cursor); { examined: <text below>, not_examined: <list below>,
 *   truncated: next !== null, next_cursor: next }. examined: functions 'functions that
 *   Ghidra found in its analysis, in address order'; strings 'strings that Ghidra defined,
 *   in address order'. not_examined, in this order: for strings first 'strings inside
 *   structures and arrays are not listed'; then 'items after this page' when next !== null.
 * - coverage, decompile: { examined: 'one function, decompiled by Ghidra',
 *   not_examined: ['all other functions'], truncated: file.result.truncated === true,
 *   next_cursor: null }.
 * - For every command, when analysisTimedOut is true: add 'the analysis timed out, so the
 *   program is only partly analysed' as the last item of not_examined.
 * - limits: functions ['Ghidra finds functions by its own analysis. It can miss a function or
 *   split one in two.']; strings ['Only strings that Ghidra defined are listed. A text longer
 *   than 200 characters is cut and flagged.']; decompile ['Decompiler output is a
 *   reconstruction. It is not the original source code.', 'Names and types that the program
 *   does not hold are guessed by Ghidra.'].
 * @param {{command: string, target: {absPath: string, name: string, size: number},
 *   sha256: string, showPath: boolean, query: ReturnType<typeof parseQueryOptions>,
 *   file: object, analysisTimedOut: boolean}} input
 * @returns {Readonly<object>}
 */
function buildRecord({ command, target, sha256, showPath, query, file, analysisTimedOut }) {
  const subject = { name: target.name, sha256, size_bytes: target.size };
  if (showPath) {
    subject.path = target.absPath;
  }

  const tool = {
    name: 'ghidra-query',
    version: TOOL_VERSION,
    engine: { name: 'ghidra', version: String(file.ghidra_version ?? 'unknown') },
  };

  const operation = command;
  const confidence = command === 'decompile' ? 'derived' : 'observed';

  let parameters;
  if (command === 'functions' || command === 'strings') {
    parameters = { limit: query.limit, cursor: query.cursor, filter: query.filter };
  } else {
    parameters = { name: query.name, address: query.address, max_chars: query.maxChars };
  }

  const result = { program: file.program ?? null, ...file.result };
  if (command === 'decompile') {
    result.code = file.result.code ?? null;
  }

  let coverage;
  if (command === 'functions' || command === 'strings') {
    const next = file.result.next_cursor == null ? null : String(file.result.next_cursor);
    const examined = command === 'functions'
      ? 'functions that Ghidra found in its analysis, in address order'
      : 'strings that Ghidra defined, in address order';
    const not_examined = [];
    if (command === 'strings') {
      not_examined.push('strings inside structures and arrays are not listed');
    }
    if (next !== null) {
      not_examined.push('items after this page');
    }
    coverage = {
      examined,
      not_examined,
      truncated: next !== null,
      next_cursor: next,
    };
  } else if (Array.isArray(file.result.candidates)) {
    coverage = {
      examined: 'function names only: several functions have the given name',
      not_examined: ['the code of every candidate: no function was decompiled'],
      truncated: file.result.candidates.length < Number(file.result.candidates_total),
      next_cursor: null,
    };
  } else {
    coverage = {
      examined: 'one function, decompiled by Ghidra',
      not_examined: ['all other functions'],
      truncated: file.result.truncated === true,
      next_cursor: null,
    };
  }

  if (analysisTimedOut) {
    if (Array.isArray(coverage.not_examined)) {
      coverage.not_examined.push(
        'the analysis timed out, so the program is only partly analysed');
    }
  }

  const limits = [];
  if (command === 'functions') {
    limits.push('Ghidra finds functions by its own analysis. '
      + 'It can miss a function or split one in two.');
  } else if (command === 'strings') {
    limits.push('Only strings that Ghidra defined are listed. '
      + 'A text longer than 200 characters is cut and flagged.');
  } else if (command === 'decompile') {
    limits.push('Decompiler output is a reconstruction. It is not the original source code.');
    limits.push('Names and types that the program does not hold are guessed by Ghidra.');
  }

  return makeEvidence({
    subject, tool, operation, parameters, confidence, result, coverage, limits,
  });
}

/**
 * Runs functions, strings or decompile and returns the Evidence record. Steps:
 * 1. query = parseQueryOptions(command, options). Then each of query.filter, query.name and
 *    query.address that is a string longer than 500 characters gives codedError('usage',
 *    '--filter, --name and --address hold at most 500 characters').
 * 2. target = await resolveTarget(targetArg); sha256 = await sha256File(target.absPath).
 * 3. engine = engineCommand(env, ghidraDir, process.platform);
 *    ghidraVersion = readGhidraVersion(ghidraDir); names = localNames().
 * 4. Project folder. With options['no-cache']: projectDir = fs.mkdtempSync(path.join(
 *    path.resolve(os.tmpdir()), 'refactor-ghidra-')), marker = null, mode = 'import'.
 *    Else: projectDir = path.join(path.resolve(cacheRoot(env, process.platform,
 *    os.homedir())), 'ghidra', sha256.slice(0, 16)); marker = readMarker(projectDir);
 *    mode = chooseMode(marker, sha256, ghidraVersion); in mode 'import' first remove
 *    projectDir (fs.rmSync with recursive and force: it can only hold an earlier import that
 *    did not finish), then fs.mkdirSync(projectDir, { recursive: true }).
 * 5. queryDir = fs.mkdtempSync(path.join(path.resolve(os.tmpdir()), 'refactor-query-'));
 *    queryFile = path.join(queryDir, 'query.json'); outFile = path.join(queryDir,
 *    'result.json'). Write queryFile: JSON.stringify({ op: command, out: outFile, limit,
 *    cursor, filter, name, address, max_chars: maxChars }) (values from query). The filter,
 *    the name and the address reach the engine ONLY through this file.
 * 6. In try, with finally (always remove queryDir; with options['no-cache'] also remove
 *    projectDir; fs.rmSync with recursive and force):
 *    a. args = buildEngineArgs({ mode, projectDir, targetPath: target.absPath,
 *       targetName: mode === 'process' ? marker.program_name : target.name,
 *       scriptDir: SCRIPT_DIR, queryFile, timeoutSec: query.timeoutSec }).
 *    b. output = await startEngine(engine, args, { timeoutSec: query.timeoutSec,
 *       cwd: queryDir, env, names }). The engine starts in queryDir, a new empty folder.
 *    c. file = readResultFile(outFile, output).
 *    d. In mode 'import' without options['no-cache']: write path.join(projectDir,
 *       'imported.json') with JSON.stringify({ sha256, ghidra_version:
 *       String(file.ghidra_version ?? 'unknown'), program_name: target.name }). (A valid
 *       result file proves that the import worked, also when ok is false.)
 *    e. file.ok === false: engineCode = String(file.error?.code ?? 'unknown'); throw
 *       codedError(<code>, 'the Ghidra script reported an error', { engine_error: {
 *       code: engineCode, message: scrubTail(String(file.error?.message ?? ''), names,
 *       500) } }), where <code> is 'usage' for engineCode 'bad_query'; engineCode itself
 *       for 'function_not_found', 'bad_address' and 'decompile_failed'; else
 *       'engine_failed' (also for 'script_error').
 *    f. Return buildRecord({ command, target, sha256, showPath: options['show-path'] ===
 *       true, query, file, analysisTimedOut: output.includes('Analysis timed out') }).
 * @param {string} command  'functions', 'strings' or 'decompile'
 * @param {string} targetArg  the path that the user gave
 * @param {Record<string, string | boolean>} options  the options object from parseArgs
 * @param {string | null} ghidraDir  an absolute folder, or null
 * @param {NodeJS.ProcessEnv} env
 * @returns {Promise<Readonly<object>>}
 */
async function runQuery(command, targetArg, options, ghidraDir, env) {
  const query = parseQueryOptions(command, options);
  if (query.filter?.length > 500 || query.name?.length > 500 || query.address?.length > 500) {
    throw codedError('usage', '--filter, --name and --address hold at most 500 characters');
  }

  const target = await resolveTarget(targetArg);
  const sha256 = await sha256File(target.absPath);
  const engine = engineCommand(env, ghidraDir, process.platform);
  const ghidraVersion = readGhidraVersion(ghidraDir);
  const names = localNames();

  let projectDir;
  let marker = null;
  let mode;

  if (options['no-cache']) {
    projectDir = fs.mkdtempSync(path.join(path.resolve(os.tmpdir()), 'refactor-ghidra-'));
    mode = 'import';
  } else {
    const root = path.resolve(cacheRoot(env, process.platform, os.homedir()));
    projectDir = path.join(root, 'ghidra', sha256.slice(0, 16));
    marker = readMarker(projectDir);
    mode = chooseMode(marker, sha256, ghidraVersion);
    if (mode === 'import') {
      fs.rmSync(projectDir, { recursive: true, force: true });
      fs.mkdirSync(projectDir, { recursive: true });
    }
  }

  const queryDir = fs.mkdtempSync(path.join(path.resolve(os.tmpdir()), 'refactor-query-'));
  const queryFile = path.join(queryDir, 'query.json');
  const outFile = path.join(queryDir, 'result.json');

  try {
    fs.writeFileSync(queryFile, JSON.stringify({
      op: command,
      out: outFile,
      limit: query.limit,
      cursor: query.cursor,
      filter: query.filter,
      name: query.name,
      address: query.address,
      max_chars: query.maxChars,
    }));

    const args = buildEngineArgs({
      mode,
      projectDir,
      targetPath: target.absPath,
      targetName: mode === 'process' ? marker.program_name : target.name,
      scriptDir: SCRIPT_DIR,
      queryFile,
      timeoutSec: query.timeoutSec,
    });

    const output = await startEngine(engine, args, {
      timeoutSec: query.timeoutSec,
      cwd: queryDir,
      env,
      names,
    });

    const file = readResultFile(outFile, output);

    if (mode === 'import' && !options['no-cache']) {
      fs.writeFileSync(path.join(projectDir, 'imported.json'), JSON.stringify({
        sha256,
        ghidra_version: String(file.ghidra_version ?? 'unknown'),
        program_name: target.name,
      }));
    }

    if (file.ok === false) {
      const engineCode = String(file.error?.code ?? 'unknown');
      let code;
      if (engineCode === 'bad_query') {
        code = 'usage';
      } else if (['function_not_found', 'bad_address', 'decompile_failed'].includes(engineCode)) {
        code = engineCode;
      } else {
        code = 'engine_failed';
      }
      throw codedError(code, 'the Ghidra script reported an error', {
        engine_error: {
          code: engineCode,
          message: scrubTail(String(file.error?.message ?? ''), names, 500),
        },
      });
    }

    return buildRecord({
      command,
      target,
      sha256,
      showPath: options['show-path'] === true,
      query,
      file,
      analysisTimedOut: output.includes('Analysis timed out'),
    });
  } finally {
    fs.rmSync(queryDir, { recursive: true, force: true });
    if (options['no-cache']) {
      fs.rmSync(projectDir, { recursive: true, force: true });
    }
  }
}


/**
 * Turns an error into { exitCode, output }. When err.code is in USAGE_CODES or ENGINE_CODES:
 * record = makeError(err.code, err.message, err.details), exit code 2 for USAGE_CODES and 3
 * for ENGINE_CODES. Any other error (a bug, or a file system error whose message can hold a
 * path): record = makeError('internal_error', 'an unexpected error stopped the script'), exit
 * code 3; err.message is never shown. output: JSON.stringify(record), or
 * JSON.stringify(record, null, 2) when pretty.
 * @param {unknown} err
 * @param {boolean} pretty
 * @returns {{exitCode: number, output: string}}
 */
function errorOutput(err, pretty) {
  let code = 'internal_error';
  let message = 'an unexpected error stopped the script';
  let details;

  if (err && typeof err === 'object' && typeof err.code === 'string' &&
      (USAGE_CODES.includes(err.code) || ENGINE_CODES.includes(err.code))) {
    code = err.code;
    message = err.message;
    details = err.details;
  }

  let exitCode = 3;
  if (USAGE_CODES.includes(code)) {
    exitCode = 2;
  }

  const errorRecord = makeError(code, message, details);
  const output = pretty ? JSON.stringify(errorRecord, null, 2) : JSON.stringify(errorRecord);
  return { exitCode, output };
}

/**
 * Runs the command line and returns { exitCode, output }; output is the text to print.
 * Never calls process.exit and never writes to stdout itself. Steps:
 * 1. { positionals, options } = parseArgs(argv, { flags: ['show-path', 'pretty', 'no-cache',
 *    'help'], values: ['ghidra', 'limit', 'cursor', 'filter', 'name', 'address', 'max-chars',
 *    'timeout-sec'] }). When it throws: return errorOutput(err, false).
 * 2. options.help: return { exitCode: 0, output: HELP_TEXT }.
 * 3. pretty = options.pretty === true. Steps 4 to 7 run in try; catch (err) returns
 *    errorOutput(err, pretty).
 * 4. command = positionals[0]; it must be in COMMANDS, else codedError('usage',
 *    'give one of: check, functions, strings, decompile').
 * 5. ghidraDir = options.ghidra, else env.GHIDRA_INSTALL_DIR; an empty text or a missing value
 *    gives null; a folder that is given is made absolute with path.resolve.
 * 6. check: more than 2 positionals gives codedError('usage', 'too many arguments for check')
 *    (a second positional, a file path, is ignored). Return { exitCode: 0,
 *    output: JSON.stringify(checkReport(ghidraDir, env, options['show-path'] === true)) }
 *    (with JSON.stringify(value, null, 2) when pretty).
 * 7. functions, strings, decompile: no positionals[1] gives codedError('usage', 'give the path
 *    of the program file'); more than 2 positionals gives codedError('usage', 'give only one
 *    program file'). record = await runQuery(command, positionals[1], options, ghidraDir,
 *    env). Return { exitCode: 0, output: JSON.stringify(record) } (with
 *    JSON.stringify(record, null, 2) when pretty).
 * @param {string[]} argv  the arguments after the script name
 * @param {NodeJS.ProcessEnv} env
 * @returns {Promise<{exitCode: number, output: string}>}
 */
export async function main(argv, env) {
  let positionals, options;
  try {
    ({ positionals, options } = parseArgs(argv, {
      flags: ['show-path', 'pretty', 'no-cache', 'help'],
      values: ['ghidra', 'limit', 'cursor', 'filter', 'name', 'address', 'max-chars',
        'timeout-sec'],
    }));
  } catch (err) {
    return errorOutput(err, false);
  }

  if (options.help) {
    return { exitCode: 0, output: HELP_TEXT };
  }

  const pretty = options.pretty === true;

  try {
    const command = positionals[0];
    if (!COMMANDS.includes(command)) {
      throw codedError('usage', 'give one of: check, functions, strings, decompile');
    }

    let ghidraDir = options.ghidra || env.GHIDRA_INSTALL_DIR || null;
    if (typeof ghidraDir === 'string' && ghidraDir.length > 0) {
      ghidraDir = path.resolve(ghidraDir);
    }

    if (command === 'check') {
      if (positionals.length > 2) {
        throw codedError('usage', 'too many arguments for check');
      }
      const report = checkReport(ghidraDir, env, options['show-path'] === true);
      const output = pretty ? JSON.stringify(report, null, 2) : JSON.stringify(report);
      return { exitCode: 0, output };
    } else {
      if (positionals.length < 2) {
        throw codedError('usage', 'give the path of the program file');
      }
      if (positionals.length > 2) {
        throw codedError('usage', 'give only one program file');
      }
      const result = await runQuery(command, positionals[1], options, ghidraDir, env);
      const output = pretty ? JSON.stringify(result, null, 2) : JSON.stringify(result);
      return { exitCode: 0, output };
    }
  } catch (err) {
    return errorOutput(err, pretty);
  }
}

/**
 * True when this file is the script that Node.js started (not imported by a test).
 * @returns {boolean}
 */
function isMainModule() {
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch (err) {
    return false;
  }
}

if (isMainModule()) {
  const { exitCode, output } = await main(process.argv.slice(2), process.env);
  // A reader that closes stdout early (for example a pager) is not an error of this script.
  process.stdout.on('error', () => {});
  process.stdout.write(output + '\n');
  process.exitCode = exitCode;
}
