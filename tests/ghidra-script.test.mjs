import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const JAVA_FILE = fileURLToPath(
  new URL('../skills/rea/scripts/ghidra/RefactorQuery.java', import.meta.url));

const NO_WRITE_METHODS = [
  /\bstartTransaction\s*\(/,
  /\bendTransaction\s*\(/,
  /\.set[A-Z]\w*\s*\(/,
  /\bcreate[A-Z]\w*\s*\(/,
  /\b(?:remove|delete|clear)[A-Z]\w*\s*\(/,
  /\bsave\w*\s*\(/,
  /\bdisassemble\w*\s*\(/,
  /\banalyze\w*\s*\(/
];

const NO_FILES_METHODS = [
  /\bFiles\.writeString\s*\(/,
  /\bFiles\.(?:newOutputStream|newBufferedWriter|delete\w*|move|copy|createDirector\w*)\s*\(/,
  /\b(?:FileOutputStream|FileWriter|PrintWriter|RandomAccessFile)\b/,
  /\b(?:TRUNCATE_EXISTING|APPEND)\b/
];

const FILES_WRITE_REGEX = /\bFiles\.write\s*\(/g;

const NO_PROCESS_METHODS = [
  /\bProcessBuilder\b/,
  /\bRuntime\s*\.\s*getRuntime\b/,
  /\.exec\s*\(/,
  /\bProcessHandle\b/
];

const NO_NETWORK_CLASSES = [
  /\bjava\.net\b/,
  /\bjavax\.net\b/,
  new RegExp(
    '\\b(?:Socket|ServerSocket|DatagramSocket|URL|URI|URLConnection|' +
    'HttpURLConnection|HttpClient|InetAddress)\\b'
  )
];

const GSON_BUILDER_REGEX = /new GsonBuilder\(\)/;
const GSON_BUILDER_CREATE_REGEX = /new GsonBuilder\(\)([^;]*?)\.create\(\)/g;
const GSON_TO_JSON_REGEX = /new Gson\(\)\s*\.\s*toJson/;

const ERROR_CODES = [
  'bad_query',
  'function_not_found',
  'bad_address',
  'decompile_failed',
  'script_error'
];

const RESULT_KEYS = [
  'ok',
  'op',
  'program',
  'name',
  'language',
  'compiler',
  'ghidra_version',
  'result',
  'error',
  'code',
  'message',
  'items',
  'total',
  'next_cursor',
  'address',
  'size',
  'external',
  'thunk',
  'text',
  'truncated',
  'function',
  'omitted_chars',
  'candidates',
  'candidates_total',
  'name_truncated'
];

const QUERY_FIELDS = [
  'out',
  'op',
  'limit',
  'cursor',
  'filter',
  'name',
  'address',
  'max_chars'
];

const NO_EXCEPTION_TEXT_METHODS = [
  /\bgetErrorMessage\s*\(/,
  /\bprintStackTrace\s*\(/,
  /\bgetLocalizedMessage\s*\(/,
  /println\([^;]*getMessage\(\)/
];

/**
 * Returns the Java text without its comments: removes every block comment (from slash-star to
 * star-slash, also over several lines) and every line whose first non-space characters are two
 * slashes.
 * @param {string} text the Java source text
 * @returns {string} the text without comments
 */
function codeOnly(text) {
  return text
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^\s*\/\/.*$/gm, '');
}

const CODE = codeOnly(readFileSync(JAVA_FILE, 'utf8'));

test('the script calls no method that writes to the program or the project', () => {
  for (const re of NO_WRITE_METHODS) {
    assert.doesNotMatch(CODE, re);
  }
});

test('the script writes only one file, as a new file', () => {
  for (const re of NO_FILES_METHODS) {
    assert.doesNotMatch(CODE, re);
  }
  const matches = CODE.match(FILES_WRITE_REGEX);
  assert.strictEqual(matches ? matches.length : 0, 1);
  assert.ok(CODE.includes('StandardOpenOption.CREATE_NEW'));
});

test('the script starts no process', () => {
  for (const re of NO_PROCESS_METHODS) {
    assert.doesNotMatch(CODE, re);
  }
});

test('the script uses no network class', () => {
  for (const re of NO_NETWORK_CLASSES) {
    assert.doesNotMatch(CODE, re);
  }
});

test('every Gson writer writes null members', () => {
  assert.ok(GSON_BUILDER_REGEX.test(CODE));
  const builderMatches = CODE.match(new RegExp(GSON_BUILDER_REGEX.source, 'g')) || [];
  const createMatches = [...CODE.matchAll(GSON_BUILDER_CREATE_REGEX)];
  for (const match of createMatches) {
    assert.ok(match[1].includes('.serializeNulls()'));
  }
  assert.strictEqual(createMatches.length, builderMatches.length);
  assert.doesNotMatch(CODE, GSON_TO_JSON_REGEX);
});

test('each error code is a text literal', () => {
  for (const code of ERROR_CODES) {
    assert.ok(CODE.includes('"' + code + '"'), code);
  }
});

test('each result key is a text literal', () => {
  for (const key of RESULT_KEYS) {
    assert.ok(CODE.includes('"' + key + '"'), key);
  }
});

test('each query field is a text literal', () => {
  for (const field of QUERY_FIELDS) {
    assert.ok(CODE.includes('"' + field + '"'), field);
  }
});

test('no decompiler or exception text reaches the result or the console', () => {
  for (const re of NO_EXCEPTION_TEXT_METHODS) {
    assert.doesNotMatch(CODE, re);
  }
});
