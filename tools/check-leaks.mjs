#!/usr/bin/env node
// Scans the repository for private data before it is made public.
// Use: node tools/check-leaks.mjs [--root DIR] [--staged] [--history] [--private-terms FILE]
//   [--json]
// Exit codes: 0 no finding, 1 findings or content that could not be checked, 2 usage error.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { codedError } from '../skills/rea/scripts/lib/evidence.mjs';
import { runProcess } from '../skills/rea/scripts/lib/run.mjs';

/**
 * Checks one line of text against every rule.
 * Returns the findings for this line: [{ rule, message }], in rule order, at most one finding
 * for each rule. A line that holds the text `leak-check: allow` gives [].
 * @param {string} line
 * @param {string[]} privateTerms  terms in lower case; finding message 'private term #<n>'
 *   where n is the 1-based position of the term in this array
 * @returns {{rule: string, message: string}[]}
 */
export function checkLine(line, privateTerms) {
  if (line.includes(ALLOW_MARKER)) {
    return [];
  }

  const findings = [];

  // email
  const emailMatches = line.matchAll(EMAIL_PATTERN);
  for (const match of emailMatches) {
    const domain = match[1].toLowerCase();
    if (!ALLOWED_EMAIL_DOMAINS.includes(domain)) {
      findings.push({ rule: 'email', message: 'email address' });
      break;
    }
  }

  // user-path
  let userPathFound = false;
  for (const pattern of USER_PATH_PATTERNS) {
    if (userPathFound) {
      break;
    }
    const matches = line.matchAll(pattern);
    for (const match of matches) {
      // Full stops at the end are not part of the name (the end of a sentence); a name of
      // full stops only is a placeholder, not a user name.
      const name = match[1].replace(/(?<![.])[.]+$/, '');
      if (name.length > 0 && !ALLOWED_USER_NAMES.includes(name)) {
        findings.push({ rule: 'user-path', message: 'home-folder path with a user name' });
        userPathFound = true;
        break;
      }
    }
  }

  // private-ip
  const ipMatches = line.matchAll(IPV4_PATTERN);
  for (const match of ipMatches) {
    const a = parseInt(match[1], 10);
    const b = parseInt(match[2], 10);
    const c = parseInt(match[3], 10);
    const d = parseInt(match[4], 10);

    if (
      a <= 255 && b <= 255 && c <= 255 && d <= 255 &&
      ((a === 10) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        (a === 169 && b === 254))
    ) {
      findings.push({ rule: 'private-ip', message: 'private network address' });
      break;
    }
  }

  // mac-address
  if (line.match(MAC_PATTERN) !== null) {
    findings.push({ rule: 'mac-address', message: 'hardware address' });
  }

  // local-hostname
  const hostMatches = line.matchAll(LOCAL_HOST_PATTERN);
  for (const match of hostMatches) {
    const host = match[0].toLowerCase();
    if (!ALLOWED_LOCAL_HOSTS.includes(host)) {
      findings.push({ rule: 'local-hostname', message: 'local host name' });
      break;
    }
  }

  // secret
  for (const pattern of SECRET_PATTERNS) {
    if (pattern.test(line)) {
      findings.push({ rule: 'secret', message: 'possible secret' });
      break;
    }
  }

  // private-term
  const lowerLine = line.toLowerCase();
  for (let i = 0; i < privateTerms.length; i++) {
    if (lowerLine.includes(privateTerms[i])) {
      findings.push({ rule: 'private-term', message: `private term #${i + 1}` });
      break;
    }
  }

  return findings;
}

/**
 * Reads a private-terms file: one term for each line; trims each line; skips empty lines and
 * lines that start with '#'; returns the terms in lower case.
 * Throws codedError('usage', ...) when the file cannot be read, when it is not UTF-8 text (it
 * starts with the bytes FF FE or FE FF, holds a zero byte or holds bytes that are not UTF-8),
 * and when it holds no term: a named terms file never gives an empty list.
 * @param {string} filePath
 * @returns {string[]}
 */
export function readPrivateTerms(filePath) {
  let bytes;
  try {
    bytes = fs.readFileSync(filePath);
  } catch {
    throw codedError('usage', 'cannot read the private-terms file');
  }
  const utf16 = bytes.length >= 2 &&
    ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff));
  const content = utf16 || bytes.includes(0) ? null : decodeUtf8Strict(bytes);
  if (content === null) {
    throw codedError('usage', 'the private-terms file must be UTF-8 text');
  }
  const terms = content
    .split(LINE_BREAK)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'))
    .map((line) => line.toLowerCase());
  if (terms.length === 0) {
    throw codedError('usage', 'the private-terms file holds no term');
  }
  return terms;
}

/**
 * The text of `bytes` when they are valid UTF-8 (a byte order mark is removed), else null.
 * @param {Buffer} bytes
 * @returns {string | null}
 */
function decodeUtf8Strict(bytes) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

/**
 * Runs the command line and returns { exitCode, output } where output is the text to print.
 * Never calls process.exit and never writes to stdout itself.
 * `env` gives LEAK_CHECK_PRIVATE_TERMS. git gets the environment of this process; with --root,
 * without GIT_LOCATION_VARIABLES, so that git uses the folder of --root.
 * @param {string[]} argv  arguments after the script name
 * @param {NodeJS.ProcessEnv} env
 * @param {{readFile?: (file: string) => Buffer}} [io]  for tests: the function that reads a
 *   file of the work tree (default fs.readFileSync)
 * @returns {Promise<{exitCode: number, output: string}>}
 */
export async function main(argv, env, { readFile = fs.readFileSync } = {}) {
  const usageError = (msg) => ({ exitCode: 2, output: 'usage: ' + msg });

  let root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  let staged = false;
  let history = false;
  let json = false;
  let privateTermsPath = null;
  let rootSet = false;
  let stagedSet = false;
  let historySet = false;
  let jsonSet = false;
  let privateTermsPathSet = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--help') {
      return { exitCode: 0, output: HELP };
    } else if (arg === '--json') {
      if (jsonSet) {
        return usageError('--json given twice');
      }
      jsonSet = true;
      json = true;
    } else if (arg === '--staged') {
      if (stagedSet) {
        return usageError('--staged given twice');
      }
      stagedSet = true;
      staged = true;
    } else if (arg === '--history') {
      if (historySet) {
        return usageError('--history given twice');
      }
      historySet = true;
      history = true;
    } else if (arg === '--root') {
      if (rootSet) {
        return usageError('--root given twice');
      }
      rootSet = true;
      const val = argv[++i];
      if (!val || val.startsWith('--')) {
        return usageError('--root needs a value');
      }
      root = path.resolve(val);
    } else if (arg === '--private-terms') {
      if (privateTermsPathSet) {
        return usageError('--private-terms given twice');
      }
      privateTermsPathSet = true;
      const val = argv[++i];
      if (!val || val.startsWith('--')) {
        return usageError('--private-terms needs a value');
      }
      privateTermsPath = val;
    } else {
      return usageError('unknown argument');
    }
  }

  let privateTerms = [];
  try {
    if (privateTermsPath) {
      privateTerms = readPrivateTerms(privateTermsPath);
    } else if (env.LEAK_CHECK_PRIVATE_TERMS) {
      privateTerms = readPrivateTerms(env.LEAK_CHECK_PRIVATE_TERMS);
    }
  } catch (err) {
    if (err.code === 'usage') {
      return usageError(err.message);
    }
    throw err;
  }

  const gitEnv = rootSet ? withoutGitLocation(process.env) : undefined;

  // git gives a hook the index of the running commit in GIT_INDEX_FILE, and --root removes
  // that variable: the tool would read an older index and report nothing.
  if (staged && rootSet
    && Object.keys(env).some((key) => key.toUpperCase() === 'GIT_INDEX_FILE')) {
    return usageError('--staged with --root cannot be used in a git hook: leave out --root');
  }

  async function git(root, args, maxOutputBytes) {
    try {
      return await runProcess('git', ['-C', root, ...args],
        { timeoutMs: 120_000, maxOutputBytes, env: gitEnv });
    } catch (err) {
      if (err.code === 'spawn_failed') {
        return { exitCode: 2, output: 'usage: git was not found' };
      }
      throw err;
    }
  }

  const findings = [];
  const skipped = [];
  const unchecked = [];
  let files_checked = 0;

  if (history) {
    // A zero byte ends each field and each commit: a commit message cannot hold one.
    const res = await git(root, [
      'log', '--all', '-z', '--encoding=UTF-8', '--no-show-signature',
      '--format=%H%x00%an%x00%ae%x00%cn%x00%ce%x00%B'
    ], 64 * 1024 * 1024);
    if (res.exitCode !== 0 || res.stdoutTruncated) {
      if (res.output && res.output.startsWith('usage: git was not found')) {
        return res;
      }
      return usageError('could not read the commit history');
    }

    const values = res.stdout.split('\0');
    for (let r = 0; r + 5 < values.length; r += 6) {
      const [hash, authorName, authorEmail, committerName, committerEmail, message] =
        values.slice(r, r + 6);
      const label = `commit-${hash.substring(0, 12)}`;

      const fields = [
        { name: 'author-name', value: authorName },
        { name: 'author-email', value: authorEmail },
        { name: 'committer-name', value: committerName },
        { name: 'committer-email', value: committerEmail },
      ];

      for (const field of fields) {
        const resLine = checkLine(field.value, privateTerms);
        for (const f of resLine) {
          findings.push({ ...f, file: label, line: field.name });
        }
      }

      const messageLines = message.split(LINE_BREAK);
      for (let i = 0; i < messageLines.length; i++) {
        const resLine = checkLine(messageLines[i], privateTerms);
        for (const f of resLine) {
          findings.push({ ...f, file: label, line: `message-${i + 1}` });
        }
      }
    }
  }

  // The file check always runs: --history only adds the commit check above.
  {
    const gitArgs = staged
      ? ['diff', '--cached', '--raw', '-z', '--no-renames', '--diff-filter=ACMT']
      : ['ls-files', '-z', '-c', '-o', '--exclude-standard'];
    const res = await git(root, gitArgs, 64 * 1024 * 1024);
    if (res.exitCode !== 0 || res.stdoutTruncated) {
      if (res.output && res.output.startsWith('usage: git was not found')) {
        return res;
      }
      return usageError('not a git repository: pass --root with the top folder of the repository');
    }

    // Each path with its mode in the index (staged mode), or with null (default mode).
    const listed = staged ? parseStagedList(res.stdout) : parseFileList(res.stdout);
    const uniquePaths = [...listed.keys()].sort();

    for (let i = 0; i < uniquePaths.length; i++) {
      const p = uniquePaths[i];
      const k = i + 1;
      let label = p;
      let privateTermIndex = -1;

      const lowerP = p.toLowerCase();
      for (let j = 0; j < privateTerms.length; j++) {
        if (lowerP.includes(privateTerms[j])) {
          label = `file#${k}`;
          privateTermIndex = j + 1;
          break;
        }
      }

      if (privateTermIndex !== -1) {
        findings.push({
          rule: 'private-term',
          file: label,
          line: 0,
          message: `private term #${privateTermIndex} in the file name`,
        });
      }

      const content = staged
        ? await readStagedContent((args) => git(root, args, MAX_FILE_BYTES), p, listed.get(p))
        : readWorkTreeContent(path.join(root, p), readFile);
      if (content === null) {
        continue; // gone from the work tree
      }
      if (content.unchecked) {
        unchecked.push({ file: label, reason: content.unchecked });
        continue;
      }
      const skipReason = content.skipped ?? null;
      const text = content.text ?? '';

      if (skipReason) {
        skipped.push({ file: label, reason: skipReason });
      } else {
        files_checked++;
        const lines = text.split(LINE_BREAK);
        for (let j = 0; j < lines.length; j++) {
          const resLine = checkLine(lines[j], privateTerms);
          for (const f of resLine) {
            findings.push({ ...f, file: label, line: j + 1 });
          }
        }
      }
    }
  }

  const exitCode = findings.length > 0 || unchecked.length > 0 ? 1 : 0;
  if (json) {
    return {
      exitCode,
      output: JSON.stringify({ findings, skipped, unchecked, files_checked }),
    };
  } else {
    const lines = [];
    for (const f of findings) {
      lines.push(`${f.rule} ${f.file}:${f.line}: ${f.message}`);
    }
    for (const s of skipped) {
      lines.push(`skipped ${s.file}: ${s.reason}`);
    }
    for (const u of unchecked) {
      lines.push(`unchecked ${u.file}: ${u.reason}`);
    }
    lines.push(`checked ${files_checked} files, ${findings.length} findings`);
    return { exitCode, output: lines.join('\n') };
  }
}

const HELP = [
  'Use: node tools/check-leaks.mjs [--root DIR] [--staged] [--history] [--private-terms FILE]',
  '  [--json] [--help]',
  '  --root DIR            the repository folder (default: the folder above tools)',
  '  --staged              check the staged content of the staged files',
  '  --history             also check the names, email addresses and messages of all commits',
  '  --private-terms FILE  one term for each line (default: LEAK_CHECK_PRIVATE_TERMS)',
  '  --json                print the result as JSON',
  '  --help                print this text',
  'Exit codes: 0 no finding, 1 findings or content that could not be checked, 2 usage error.',
].join('\n');
const ALLOW_MARKER = 'leak-check: allow'; // leak-check: allow
// The email and host patterns start only at the first character of a run (the look-behind),
// so the time for a line grows only with its length, not with its square.
const EMAIL_PATTERN = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})/g;
const ALLOWED_EMAIL_DOMAINS = ['example.com', 'example.org', 'example.net'];
const USER_PATH_PATTERNS = [
  /[A-Za-z]:[\\/]+Users[\\/]+([^\\/\s"'`<>|*?]+)/gi,
  /\/home\/([^/\\\s"'`:;,()[\]{}]+)/g,
  /(?<![A-Za-z]:)\/Users\/([^/\\\s"'`:;,()[\]{}]+)/g,
  /(?:\/mnt)?\/[A-Za-z]\/users\/([^/\\\s"'`:;,()[\]{}]+)/gi,
];
const ALLOWED_USER_NAMES = ['you', '<you>', 'USERNAME', 'user', 'example', 'Public', 'runner'];
const IPV4_PATTERN = /(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.]*\d)/g;
const MAC_PATTERN = /\b[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}\b/g;
const LOCAL_HOST_PATTERN = new RegExp(
  '(?<![A-Za-z0-9.-])[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\\.[A-Za-z0-9-]+)*' +
  '\\.local\\b(?!-|\\.[A-Za-z0-9])',
  'gi'
);
const ALLOWED_LOCAL_HOSTS = ['my-pc.local', 'example.local'];
const SECRET_PATTERNS = [
  /-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----/,
  // A name that ends in a key word (DB_PASSWORD, dbPassword), then : or =, then a quoted value.
  new RegExp(
    '(?<![A-Za-z0-9_.-])[A-Za-z0-9_.-]*' +
    '(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|' +
    'private[_-]?key)["\']?\\s*[:=]\\s*["\'][^"\'\\s]{8,}["\']',
    'i'
  ),
  // The environment-file form with no quotes: a whole line NAME=value or export NAME=value,
  // where NAME is upper case and the value has 8 or more characters, no space, no quote and
  // no $ at the start.
  new RegExp(
    '^\\s*(?:export\\s+)?(?=[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|APIKEY|' +
    'ACCESS_KEY|PRIVATE_KEY))[A-Z0-9_]+=[^\\s"\'$][^\\s"\']{7,}\\s*$'
  ),
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{22,}/,
  /\bsk-[A-Za-z0-9_-]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/,
  /\bAIza[0-9A-Za-z_-]{35}\b/,
  /\bnpm_[A-Za-z0-9]{36}\b/,
];
// Line ends: CR LF, LF, CR, and the line and paragraph separators U+2028 and U+2029.
const LINE_BREAK = new RegExp('\\r\\n|[\\n\\r' + String.fromCharCode(0x2028, 0x2029) + ']');
const MAX_FILE_BYTES = 2 * 1024 * 1024;
const BINARY_CHECK_BYTES = 8000;
// The variables that make git use another repository, work tree or index than --root.
const GIT_LOCATION_VARIABLES = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
  'GIT_OBJECT_DIRECTORY', 'GIT_NAMESPACE', 'GIT_PREFIX'];
// UTF-16 text in git output that was read as UTF-8: the byte order mark (FF FE or FE FF) becomes
// two U+FFFD characters, then an ASCII character comes with its zero byte. A JPEG file, which
// also starts with two such characters, does not match.
const UTF16_TEXT_START = new RegExp('^' + String.fromCharCode(0xfffd, 0xfffd)
  + '(?:[\\t\\n\\r\\x20-\\x7e]\\x00|\\x00[\\t\\n\\r\\x20-\\x7e])');

/**
 * A copy of `env` without GIT_LOCATION_VARIABLES (names compared without letter case, as
 * Windows does).
 * @param {NodeJS.ProcessEnv} env
 * @returns {NodeJS.ProcessEnv}
 */
function withoutGitLocation(env) {
  return Object.fromEntries(Object.entries(env)
    .filter(([key]) => !GIT_LOCATION_VARIABLES.includes(key.toUpperCase())));
}

/**
 * The paths of `git ls-files -z` output, each with the mode null.
 * @param {string} stdout
 * @returns {Map<string, null>}
 */
function parseFileList(stdout) {
  return new Map(stdout.split('\0').filter((p) => p.length > 0).map((p) => [p, null]));
}

/**
 * The paths and index modes of `git diff --cached --raw -z --no-renames` output: for each path
 * a header `:<old mode> <new mode> <old id> <new id> <status>` and the path, each ended by a
 * zero byte.
 * @param {string} stdout
 * @returns {Map<string, string>}
 */
function parseStagedList(stdout) {
  const fields = stdout.split('\0');
  const entries = [];
  for (let i = 0; i + 1 < fields.length; i += 2) {
    entries.push([fields[i + 1], fields[i].split(' ')[1]]);
  }
  return new Map(entries);
}

/**
 * Reads one path of the work tree. A symbolic link is never followed: git stores its text (the
 * path that it points to), so that text is checked.
 * Returns null when the path is gone; { text } to check; { skipped: reason } for a folder (a
 * submodule or a nested repository), a binary file or a file over 2 MB; { unchecked: reason }
 * when it could not be read. A reason never holds a path.
 * @param {string} fullPath
 * @param {(file: string) => Buffer} readFile
 * @returns {{text?: string, skipped?: string, unchecked?: string} | null}
 */
function readWorkTreeContent(fullPath, readFile) {
  try {
    const info = fs.lstatSync(fullPath, { throwIfNoEntry: false });
    if (info === undefined) {
      return null;
    }
    if (info.isSymbolicLink()) {
      return { text: fs.readlinkSync(fullPath) };
    }
    if (info.isDirectory()) {
      return { skipped: 'submodule or nested repository' };
    }
    if (!info.isFile()) {
      return { skipped: 'not a regular file' };
    }
    if (info.size > MAX_FILE_BYTES) {
      return { skipped: 'larger than 2 MB' };
    }
    return decodeFileBytes(readFile(fullPath));
  } catch (err) {
    const code = errorCode(err);
    if (code === 'ENOENT' || code === 'ENOTDIR') {
      return null;
    }
    return { unchecked: 'could not be read (' + code + ')' };
  }
}

/**
 * The text of a file for the check: UTF-16 with a byte order mark is decoded; other content
 * with a zero byte in its first BINARY_CHECK_BYTES bytes is binary; the rest is UTF-8.
 * @param {Buffer} bytes
 * @returns {{text?: string, skipped?: string}}
 */
function decodeFileBytes(bytes) {
  if (bytes.length > MAX_FILE_BYTES) {
    return { skipped: 'larger than 2 MB' };
  }
  if (bytes.length >= 2 && bytes[0] === 0xff && bytes[1] === 0xfe) {
    return { text: bytes.subarray(2).toString('utf16le') };
  }
  if (bytes.length >= 2 && bytes[0] === 0xfe && bytes[1] === 0xff) {
    // A copy of the bytes after the mark (an even count), each pair swapped: big-endian to
    // little-endian.
    const body = Buffer.from(bytes.subarray(2, bytes.length - (bytes.length % 2)));
    return { text: body.swap16().toString('utf16le') };
  }
  if (bytes.subarray(0, BINARY_CHECK_BYTES).includes(0)) {
    return { skipped: 'binary' };
  }
  return { text: bytes.toString('utf8') };
}

/**
 * Reads the staged content of one path. `mode` is its mode in the index; `gitRun(args)` runs
 * git in the repository, with an output limit of MAX_FILE_BYTES.
 * Returns { text } to check; { skipped: reason } for a submodule, a binary file or a file over
 * 2 MB; { unchecked: reason } when the content could not be read or is UTF-16 text (git output
 * comes here as UTF-8 text, so UTF-16 cannot be decoded).
 * @param {(args: string[]) => Promise<{exitCode: number | null, stdout?: string,
 *   stdoutTruncated?: boolean}>} gitRun
 * @param {string} filePath
 * @param {string | null | undefined} mode
 * @returns {Promise<{text?: string, skipped?: string, unchecked?: string}>}
 */
async function readStagedContent(gitRun, filePath, mode) {
  if (mode === '160000') {
    return { skipped: 'submodule' };
  }
  // ':0:' names stage 0, so that a path such as '1:x' is not read as a stage number.
  const res = await gitRun(['cat-file', 'blob', ':0:' + filePath]);
  if (res.exitCode !== 0) {
    return { unchecked: 'staged content could not be read' };
  }
  if (res.stdoutTruncated) {
    return { skipped: 'larger than 2 MB' };
  }
  if (UTF16_TEXT_START.test(res.stdout)) {
    return { unchecked: 'UTF-16 text' };
  }
  if (res.stdout.substring(0, BINARY_CHECK_BYTES).includes('\u0000')) {
    return { skipped: 'binary' };
  }
  return { text: res.stdout };
}

/**
 * The code of an error for an output line: a short word such as EBUSY, else 'error'. Never the
 * message or the stack, which can hold paths and file names.
 * @param {unknown} err
 * @returns {string}
 */
function errorCode(err) {
  const code = err !== null && typeof err === 'object' ? err.code : undefined;
  return typeof code === 'string' && /^[A-Za-z0-9_]{1,40}$/.test(code) ? code : 'error';
}

/**
 * True when this file is the script that Node.js started (not imported by a test).
 * @returns {boolean}
 */
function isMainModule() {
  try {
    return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
}

if (isMainModule()) {
  let result;
  try {
    result = await main(process.argv.slice(2), process.env);
  } catch (err) {
    // Only the code: the message and the stack of an error can hold paths and file names.
    result = { exitCode: 2, output: 'usage: unexpected error (' + errorCode(err) + ')' };
  }
  if (result.output.length > 0) {
    process.stdout.write(result.output + '\n');
  }
  process.exitCode = result.exitCode;
}
