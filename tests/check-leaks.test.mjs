import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkLine, readPrivateTerms, main } from '../tools/check-leaks.mjs';
import { runProcess } from '../skills/rea/scripts/lib/run.mjs';

// Every sample below is built from parts, so that no line of this file is a finding itself.
const AT = '@';
const BS = '\\';
const email = (local, domain) => local + AT + domain;
const TERM = 'zebra' + 'corp';
const ROOT = fileURLToPath(new URL('..', import.meta.url));
const TOOL_PATH = path.join(ROOT, 'tools', 'check-leaks.mjs');

// The environment of each child process of these tests: no git variable of the caller (a git
// hook sets GIT_DIR and GIT_INDEX_FILE, and GIT_AUTHOR_* changes a commit) and no private-terms
// file of the caller.
const CLEAN_ENV = Object.fromEntries(Object.entries(process.env).filter(([key]) => {
  const name = key.toUpperCase();
  return !name.startsWith('GIT_') && name !== 'LEAK_CHECK_PRIVATE_TERMS';
}));

const tempDirs = [];

/**
 * Makes a new temporary folder that is removed when the tests end.
 * @returns {string}
 */
function makeTemp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  tempDirs.push(dir);
  return dir;
}

after(() => {
  for (const dir of tempDirs) {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

const NO_HOOKS = makeTemp();

/**
 * Runs git in `dir` with no hooks, no signing and CLEAN_ENV; fails the test when git fails.
 * @param {string} dir
 * @param {...string} args
 * @returns {Promise<string>}
 */
async function git(dir, ...args) {
  const res = await runProcess('git', ['-C', dir, '-c', 'core.hooksPath=' + NO_HOOKS,
    '-c', 'commit.gpgsign=false', ...args], { timeoutMs: 60_000, env: CLEAN_ENV });
  assert.equal(res.exitCode, 0, 'git ' + args[0] + ' failed');
  return res.stdout;
}

/**
 * Makes a new git repository in a temporary folder and writes `files` into it (not staged).
 * @param {Record<string, string | Buffer>} files
 * @returns {Promise<string>}
 */
async function makeRepo(files) {
  const dir = makeTemp();
  await git(dir, 'init', '-q');
  for (const [name, content] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

/**
 * The rule ids of the findings for one line with no private terms.
 * @param {string} line
 * @returns {string[]}
 */
function rules(line) {
  return checkLine(line, []).map((f) => f.rule);
}

/**
 * Writes a private-terms file that holds TERM and returns its path.
 * @returns {string}
 */
function termsFile() {
  const file = path.join(makeTemp(), 'terms.txt');
  fs.writeFileSync(file, TERM + '\n');
  return file;
}

/**
 * Commits the staged files of `dir` with an invented author and committer.
 * @param {string} dir
 * @param {string} message
 * @param {string} [name]
 * @param {string} [address]
 * @returns {Promise<string>}
 */
function commit(dir, message, name = 'Test', address = email('test', 'example.com')) {
  return git(dir, '-c', 'user.name=' + name, '-c', 'user.email=' + address,
    'commit', '-q', '-m', message);
}

test('email: an address is found; the example domains are allowed', () => {
  assert.deepEqual(checkLine('mail ' + email('someone', 'corp.test') + ' now', []),
    [{ rule: 'email', message: 'email address' }]);
  for (const domain of ['example.com', 'example.org', 'example.net', 'EXAMPLE.COM']) {
    assert.deepEqual(rules('mail ' + email('someone', domain) + ' now'), [], domain);
  }
  assert.deepEqual(rules(email('a', 'example.com') + ' ' + email('b', 'corp.test')), ['email']);
});

test('user-path: a home folder with a user name is found; the example names are allowed', () => {
  assert.deepEqual(checkLine('C:' + BS + 'Users' + BS + 'alice' + BS + 'file', []),
    [{ rule: 'user-path', message: 'home-folder path with a user name' }]);
  assert.deepEqual(rules('D:/Users/' + 'alice/file'), ['user-path']);
  assert.deepEqual(rules('/home/' + 'alice/x'), ['user-path']);
  assert.deepEqual(rules('/Users/' + 'alice/x'), ['user-path']);
  for (const name of ['you', '<you>', 'USERNAME', 'user', 'example', 'Public', 'runner']) {
    assert.deepEqual(rules('C:' + BS + 'Users' + BS + name + BS + 'x'), [], name);
    assert.deepEqual(rules('/home/' + name + '/x'), [], name);
    assert.deepEqual(rules('/Users/' + name + '/x'), [], name);
  }
});

test('private-ip: the private ranges are found; other addresses are allowed', () => {
  assert.deepEqual(checkLine('host ' + '192.168.' + '1.20' + ' here', []),
    [{ rule: 'private-ip', message: 'private network address' }]);
  for (const ip of ['10.' + '1.2.3', '172.' + '16.0.1', '172.' + '31.255.255',
    '169.' + '254.1.1', '192.' + '168.0.1']) {
    assert.deepEqual(rules('at ' + ip), ['private-ip'], ip);
  }
  for (const ip of ['127.' + '0.0.1', '0.' + '0.0.0', '203.' + '0.113.5', '172.' + '32.0.1',
    '172.' + '15.0.1', '192.' + '169.0.1', '1.' + '2.3.4', '10.' + '1.2.300']) {
    assert.deepEqual(rules('at ' + ip), [], ip);
  }
});

test('mac-address: six pairs of hex digits are found', () => {
  assert.deepEqual(checkLine(['aa', 'bb', 'cc', 'dd', 'ee', 'ff'].join(':'), []),
    [{ rule: 'mac-address', message: 'hardware address' }]);
  assert.deepEqual(rules(['AA', 'BB', 'CC', 'DD', 'EE', '0F'].join('-')), ['mac-address']);
  assert.deepEqual(rules(['aa', 'bb', 'cc'].join(':')), []);
  assert.deepEqual(rules(['aa', 'bb', 'cc', 'dd', 'ee'].join(':')), []);
  assert.deepEqual(rules(['aa', 'bb', 'cc', 'dd', 'ee', 'ff'].join(':-')), []);
});

test('local-hostname: a .local name is found; the example names are allowed', () => {
  assert.deepEqual(checkLine('ping ' + 'desk-box' + '.local now', []),
    [{ rule: 'local-hostname', message: 'local host name' }]);
  assert.deepEqual(rules('ping my-pc.local now'), []);
  assert.deepEqual(rules('ping example.local now'), []);
  assert.deepEqual(rules('ping localhost now'), []);
  assert.deepEqual(rules('read settings' + '.local.json'), []);
});

test('secret: keys, assigned values and token prefixes are found', () => {
  const samples = [
    '-----BEGIN RSA ' + 'PRIVATE KEY-----',
    '-----BEGIN ' + 'PRIVATE KEY-----',
    'password = ' + '"hunter2hunter2"',
    'token: ' + '\'abcdefgh12345678\'',
    'API_KEY=' + '"abcdefgh12345678"',
    'ghp_' + 'a'.repeat(36),
    'github_pat_' + 'a'.repeat(22),
    'AKIA' + 'A'.repeat(16),
    'sk-' + 'a'.repeat(20),
    'xoxb-' + '1'.repeat(10),
    'npm_' + 'a'.repeat(36),
  ];
  for (const sample of samples) {
    assert.deepEqual(checkLine(sample, []), [{ rule: 'secret', message: 'possible secret' }],
      'sample ' + samples.indexOf(sample));
  }
  assert.deepEqual(rules('const token = readToken();'), []);
  assert.deepEqual(rules('password = ' + '"short"'), []);
  assert.deepEqual(rules('ghp_' + 'a'.repeat(10)), []);
});

test('user-path: more forms of a home folder are found', () => {
  const name = 'alice';
  const found = [
    'cd /home/' + name,
    'cd /home/' + name + ' now',
    '"cwd": "/home/' + name + '"',
    'HOME=/home/' + name,
    'it is in /home/' + name + '.',
    'cd /Users/' + name,
    '"cwd": "/Users/' + name + '"',
    'cd /c/Users/' + name,
    'cd /mnt/c/Users/' + name,
    'cd /c/users/' + name + '/x',
  ];
  for (const sample of found) {
    assert.deepEqual(rules(sample), ['user-path'], sample);
  }
  const clean = [
    'cd /home/' + 'user.',
    'cd /home/' + 'you',
    'see /Users/' + '...',
    'C:' + BS + 'Users' + BS + '...' + BS + 'x',
  ];
  for (const sample of clean) {
    assert.deepEqual(rules(sample), [], sample);
  }
});

test('local-hostname: a .local name before a full stop or after an underscore is found', () => {
  assert.deepEqual(rules('The server is desk-box' + '.local.'), ['local-hostname']);
  assert.deepEqual(rules('found desk-box' + '.local. Then more'), ['local-hostname']);
  assert.deepEqual(rules('the host desk_box' + '.local'), ['local-hostname']);
  assert.deepEqual(rules('read settings' + '.local.json'), []);
  assert.deepEqual(rules('copy .env' + '.local'), []);
});

test('secret: a PGP key, names with a prefix and the environment-file form are found', () => {
  const value = '"' + 'abcdefgh12345678' + '"';
  const found = [
    '-----BEGIN PGP ' + 'PRIVATE KEY BLOCK-----',
    'DB_PASSWORD = ' + value,
    'GITHUB_TOKEN=' + value,
    'AWS_SECRET_ACCESS_KEY=' + value,
    'dbPassword: ' + value,
    'secret_key = ' + value,
    'private_key = ' + value,
    'PASSWORD=' + 'hunter2hunter2',
    'export API_KEY=' + 'abcdefgh12345678',
    '  DB_PASSWD=' + 'abcdefgh',
  ];
  for (const sample of found) {
    assert.deepEqual(rules(sample), ['secret'], sample);
  }
  const clean = [
    'PASSWORD=' + 'short',
    'PASSWORD=' + '$OTHER_VALUE',
    'password=' + 'abcdefgh12',
    'x = 1; PASSWORD=' + 'abcdefgh12',
    'TOKEN=' + 'abcd efgh ijkl',
    'const token = readToken();',
  ];
  for (const sample of clean) {
    assert.deepEqual(rules(sample), [], sample);
  }
});

test('checkLine: a line of 2 MiB is checked in a few seconds, for each shape', async () => {
  // In a child process: when a pattern is slow again, the time limit stops the child, and the
  // test fails in place of blocking the test run.
  const code = 'const { checkLine } = await import(process.argv[1]);\n'
    + 'for (const unit of ["a", "7f", "a-", "a.", "1."]) {\n'
    + '  const line = unit.repeat(2 * 1024 * 1024 / unit.length);\n'
    + '  const start = Date.now();\n'
    + '  checkLine(line, []);\n'
    + '  console.log(unit + " " + (Date.now() - start));\n'
    + '}\n';
  const toolUrl = new URL('../tools/check-leaks.mjs', import.meta.url).href;
  const res = await runProcess(process.execPath, ['--input-type=module', '-e', code, toolUrl],
    { timeoutMs: 120_000, env: CLEAN_ENV });
  assert.equal(res.timedOut, false, 'checkLine did not end in 120 seconds');
  assert.equal(res.exitCode, 0, res.stderr);
  const times = res.stdout.trim().split(/\r?\n/);
  assert.equal(times.length, 5, res.stdout);
  for (const line of times) {
    assert.ok(Number(line.split(' ')[1]) < 5000, 'more than 5 seconds: ' + line);
  }
});

test('private-term: the first matching term is found, case ignored, never printed', () => {
  assert.deepEqual(checkLine('made at ' + TERM.toUpperCase() + ' today', [TERM]),
    [{ rule: 'private-term', message: 'private term #1' }]);
  assert.deepEqual(checkLine('the widget co laptop', [TERM, 'widget co']),
    [{ rule: 'private-term', message: 'private term #2' }]);
  assert.deepEqual(checkLine(TERM + ' widget co', [TERM, 'widget co']),
    [{ rule: 'private-term', message: 'private term #1' }]);
  assert.deepEqual(checkLine('nothing here', [TERM]), []);
  const terms = Object.freeze([TERM]);
  const found = checkLine(TERM, terms);
  assert.equal(JSON.stringify(found).includes(TERM), false);
  assert.deepEqual(terms, [TERM]);
});

test('Several rules on one line give one finding each, in rule order', () => {
  const line = TERM + ' ' + '10.' + '0.0.1' + ' ' + email('a', 'corp.test') + ' '
    + email('b', 'corp.test');
  assert.deepEqual(checkLine(line, [TERM]).map((f) => f.rule),
    ['email', 'private-ip', 'private-term']);
});

test('A line with the marker leak-check: allow gives no finding', () => {
  const marker = 'leak-check' + ': allow';
  assert.deepEqual(checkLine(email('someone', 'corp.test') + ' // ' + marker, []), []);
  assert.deepEqual(checkLine(TERM + ' ' + marker, [TERM]), []);
});

test('readPrivateTerms trims, skips empty and comment lines, and lowers the case', () => {
  const dir = makeTemp();
  const file = path.join(dir, 'terms.txt');
  fs.writeFileSync(file, '# comment\n\nAcme\n  Widget Co  \r\n\r\n');
  assert.deepEqual(readPrivateTerms(file), ['acme', 'widget co']);
  assert.throws(() => readPrivateTerms(path.join(dir, 'missing.txt')), { code: 'usage' });
});

test('main: a clean repository gives exit code 0', async () => {
  const dir = await makeRepo({ 'a.txt': 'hello\n' });
  const res = await main(['--root', dir], {});
  assert.equal(res.exitCode, 0);
  assert.ok(res.output.endsWith('checked 1 files, 0 findings'), res.output);
});

test('main: a finding gives exit code 1 and names the rule, file and line', async () => {
  const dir = await makeRepo({ 'a.txt': 'line one\nmail ' + email('someone', 'corp.test') + '\n' });
  const res = await main(['--root', dir], {});
  assert.equal(res.exitCode, 1);
  assert.ok(res.output.includes('email a.txt:2: email address'), res.output);
  assert.ok(res.output.endsWith('checked 1 files, 1 findings'), res.output);
  assert.equal(res.output.includes('corp.test'), false);
});

test('main: files in a sub-folder are named with / and ignored files are not read', async () => {
  const dir = await makeRepo({ '.gitignore': 'ignored.txt\n' });
  fs.writeFileSync(path.join(dir, 'ignored.txt'), email('someone', 'corp.test') + '\n');
  fs.mkdirSync(path.join(dir, 'sub'));
  fs.writeFileSync(path.join(dir, 'sub', 'b.txt'), 'x\n' + email('someone', 'corp.test') + '\n');
  const res = await main(['--root', dir], {});
  assert.equal(res.exitCode, 1);
  assert.ok(res.output.includes('email sub/b.txt:2: email address'), res.output);
  assert.equal(res.output.includes('ignored.txt'), false);
  assert.ok(res.output.endsWith('checked 2 files, 1 findings'), res.output);
});

test('main: a private term is found and its text is never printed', async () => {
  const dir = await makeRepo({ 'notes.md': 'made at ' + TERM + '\n' });
  const termsDir = makeTemp();
  const termsFile = path.join(termsDir, 'terms.txt');
  fs.writeFileSync(termsFile, TERM + '\n');
  const viaOption = await main(['--root', dir, '--private-terms', termsFile], {});
  assert.equal(viaOption.exitCode, 1);
  assert.ok(viaOption.output.includes('private-term notes.md:1: private term #1'),
    viaOption.output);
  assert.equal(viaOption.output.toLowerCase().includes(TERM), false);
  const viaEnv = await main(['--root', dir], { LEAK_CHECK_PRIVATE_TERMS: termsFile });
  assert.equal(viaEnv.exitCode, 1);
  assert.ok(viaEnv.output.includes('private-term notes.md:1: private term #1'), viaEnv.output);
  assert.equal(viaEnv.output.toLowerCase().includes(TERM), false);
  const noTerms = await main(['--root', dir], { LEAK_CHECK_PRIVATE_TERMS: '' });
  assert.equal(noTerms.exitCode, 0);
});

test('main: a private term in a file name hides the name in every line', async () => {
  const name = 'Notes-' + TERM.toUpperCase() + '.md';
  const dir = await makeRepo({ [name]: 'mail ' + email('someone', 'corp.test') + '\n' });
  const termsFile = path.join(makeTemp(), 'terms.txt');
  fs.writeFileSync(termsFile, TERM + '\n');
  const res = await main(['--root', dir, '--private-terms', termsFile], {});
  assert.equal(res.exitCode, 1);
  assert.ok(res.output.includes('private-term file#1:0: private term #1 in the file name'),
    res.output);
  assert.ok(res.output.includes('email file#1:1: email address'), res.output);
  assert.equal(res.output.toLowerCase().includes(TERM), false);
});

test('main: binary files and files over 2 MB are skipped and reported', async () => {
  const dir = await makeRepo({
    'bin.dat': Buffer.concat([Buffer.from(email('someone', 'corp.test')), Buffer.from([0, 1])]),
    'big.txt': 'a\n'.repeat(1024 * 1024 + 1),
    'ok.txt': 'fine\n',
  });
  const res = await main(['--root', dir], {});
  assert.equal(res.exitCode, 0);
  assert.ok(res.output.includes('skipped bin.dat: binary'), res.output);
  assert.ok(res.output.includes('skipped big.txt: larger than 2 MB'), res.output);
  assert.ok(res.output.endsWith('checked 1 files, 0 findings'), res.output);
});

test('main: --json prints one JSON document', async () => {
  const dir = await makeRepo({
    'a.txt': 'line one\nmail ' + email('someone', 'corp.test') + '\n',
    'bin.dat': Buffer.from([0, 1, 2]),
  });
  const res = await main(['--root', dir, '--json'], {});
  assert.equal(res.exitCode, 1);
  assert.deepEqual(JSON.parse(res.output), {
    findings: [{ rule: 'email', file: 'a.txt', line: 2, message: 'email address' }],
    skipped: [{ file: 'bin.dat', reason: 'binary' }],
    unchecked: [],
    files_checked: 1,
  });
});

test('main: --staged reads only staged files, and their staged content', async () => {
  const dir = await makeRepo({
    'a.txt': 'mail ' + email('someone', 'corp.test') + '\n',
    'b.txt': 'clean\n',
  });
  await git(dir, 'add', 'b.txt');
  const onlyB = await main(['--root', dir, '--staged'], {});
  assert.equal(onlyB.exitCode, 0, onlyB.output);
  assert.ok(onlyB.output.endsWith('checked 1 files, 0 findings'), onlyB.output);
  await git(dir, 'add', 'a.txt');
  fs.writeFileSync(path.join(dir, 'a.txt'), 'clean now\n');
  const staged = await main(['--root', dir, '--staged'], {});
  assert.equal(staged.exitCode, 1);
  assert.ok(staged.output.includes('email a.txt:1: email address'), staged.output);
});

test('main: --history checks the names, emails and messages of every commit', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  await git(dir, 'add', 'a.txt');
  await git(dir, '-c', 'user.name=Test', '-c', 'user.email=' + email('tester', 'corp.test'),
    'commit', '-q', '-m', 'first line\n\nmade at ' + TERM);
  const termsFile = path.join(makeTemp(), 'terms.txt');
  fs.writeFileSync(termsFile, TERM + '\n');
  const plain = await main(['--root', dir, '--private-terms', termsFile], {});
  assert.equal(plain.exitCode, 0, plain.output);
  const res = await main(['--root', dir, '--history', '--private-terms', termsFile], {});
  assert.equal(res.exitCode, 1);
  assert.match(res.output, /^email commit-[0-9a-f]{12}:author-email: email address$/m);
  assert.match(res.output, /^email commit-[0-9a-f]{12}:committer-email: email address$/m);
  assert.match(res.output, /^private-term commit-[0-9a-f]{12}:message-3: private term #1$/m);
  assert.equal(res.output.toLowerCase().includes(TERM), false);
  assert.equal(res.output.includes('corp.test'), false);
});

test('main: --history in a repository with no commit gives no history finding', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  const res = await main(['--root', dir, '--history'], {});
  assert.equal(res.exitCode, 0, res.output);
});

test('main: --history also checks the files, in default mode and in staged mode', async () => {
  const dir = await makeRepo({ 'clean.txt': 'clean\n' });
  await git(dir, 'add', 'clean.txt');
  await commit(dir, 'clean');
  fs.writeFileSync(path.join(dir, 'leak.txt'), 'mail ' + email('someone', 'corp.test') + '\n');
  const all = await main(['--root', dir, '--history'], {});
  assert.equal(all.exitCode, 1, all.output);
  assert.ok(all.output.includes('email leak.txt:1: email address'), all.output);
  await git(dir, 'add', 'leak.txt');
  const staged = await main(['--root', dir, '--staged', '--history'], {});
  assert.equal(staged.exitCode, 1, staged.output);
  assert.ok(staged.output.includes('email leak.txt:1: email address'), staged.output);
});

test('readPrivateTerms refuses a file that is not UTF-8 text or that holds no term', () => {
  const dir = makeTemp();
  const write = (name, content) => {
    const file = path.join(dir, name);
    fs.writeFileSync(file, content);
    return file;
  };
  const wide = Buffer.from(TERM + '\r\n', 'utf16le');
  const refused = [
    write('le.txt', Buffer.concat([Buffer.from([0xff, 0xfe]), wide])),
    write('be.txt', Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(wide).swap16()])),
    write('zero.txt', Buffer.from(TERM + '\x00\n')),
    write('latin1.txt', Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a])),
    write('empty.txt', ''),
    write('comments.txt', '# a comment only\n\n'),
  ];
  for (const file of refused) {
    assert.throws(() => readPrivateTerms(file), { code: 'usage' }, path.basename(file));
  }
  const bom = String.fromCharCode(0xfeff);
  assert.deepEqual(readPrivateTerms(write('bom.txt', bom + TERM + '\n')), [TERM]);
  assert.deepEqual(readPrivateTerms(write('cr.txt', TERM + '\rWidget Co\r')),
    [TERM, 'widget co']);
});

test('main: a private-terms file that cannot be used gives exit code 2', async () => {
  const dir = await makeRepo({ 'notes.md': 'made at ' + TERM + '\n' });
  const termsDir = makeTemp();
  const wide = path.join(termsDir, 'wide.txt');
  fs.writeFileSync(wide, Buffer.concat([Buffer.from([0xff, 0xfe]),
    Buffer.from(TERM + '\r\n', 'utf16le')]));
  const empty = path.join(termsDir, 'empty.txt');
  fs.writeFileSync(empty, '');
  for (const file of [wide, empty]) {
    const viaOption = await main(['--root', dir, '--private-terms', file], {});
    assert.equal(viaOption.exitCode, 2, viaOption.output);
    assert.ok(viaOption.output.startsWith('usage: the private-terms file '), viaOption.output);
    const viaEnv = await main(['--root', dir], { LEAK_CHECK_PRIVATE_TERMS: file });
    assert.equal(viaEnv.exitCode, 2, viaEnv.output);
  }
});

test('main: --staged checks a path whose type changed from a link to a file', async () => {
  const dir = await makeRepo({});
  const outside = makeTemp();
  fs.writeFileSync(path.join(outside, 'link.txt'), 'target.txt');
  fs.writeFileSync(path.join(outside, 'file.txt'), 'mail ' + email('someone', 'corp.test') + '\n');
  const linkId = (await git(dir, 'hash-object', '-w', path.join(outside, 'link.txt'))).trim();
  const fileId = (await git(dir, 'hash-object', '-w', path.join(outside, 'file.txt'))).trim();
  await git(dir, 'update-index', '--add', '--cacheinfo', '120000,' + linkId + ',swap');
  await commit(dir, 'a link');
  await git(dir, 'update-index', '--cacheinfo', '100644,' + fileId + ',swap');
  const res = await main(['--root', dir, '--staged'], {});
  assert.equal(res.exitCode, 1, res.output);
  assert.ok(res.output.includes('email swap:1: email address'), res.output);
});

test('main: usage errors give exit code 2', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  const notGit = makeTemp();
  const cases = [
    ['--nope'],
    ['--root'],
    ['--root', dir, '--root', dir],
    ['--root', notGit],
    ['--root', dir, '--private-terms', path.join(notGit, 'missing.txt')],
    ['--root', dir, '--private-terms'],
  ];
  for (const argv of cases) {
    const res = await main(argv, {});
    assert.equal(res.exitCode, 2, argv.join(' '));
    assert.ok(res.output.startsWith('usage: '), res.output);
    assert.equal(res.output.includes(notGit), false);
  }
});

test('main: --staged reports staged content that cannot be read, with exit code 1', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  await git(dir, 'add', 'a.txt');
  // An index entry whose object does not exist: git cannot give its content.
  await git(dir, 'update-index', '--add', '--cacheinfo',
    '100644,' + '2'.repeat(40) + ',gone.txt');
  const res = await main(['--root', dir, '--staged'], {});
  assert.equal(res.exitCode, 1, res.output);
  assert.ok(res.output.includes('unchecked gone.txt: staged content could not be read'),
    res.output);
  assert.ok(res.output.endsWith('checked 1 files, 0 findings'), res.output);
  const asJson = JSON.parse((await main(['--root', dir, '--staged', '--json'], {})).output);
  assert.deepEqual(asJson.unchecked,
    [{ file: 'gone.txt', reason: 'staged content could not be read' }]);
});

test('main: a submodule entry and a nested repository are skipped with exit code 0',
  async () => {
    const dir = await makeRepo({ 'a.txt': 'clean\n' });
    await git(dir, 'add', 'a.txt');
    await git(dir, 'update-index', '--add', '--cacheinfo', '160000,' + '1'.repeat(40) + ',sub');
    const staged = await main(['--root', dir, '--staged'], {});
    assert.equal(staged.exitCode, 0, staged.output);
    assert.ok(staged.output.includes('skipped sub: submodule'), staged.output);
    fs.mkdirSync(path.join(dir, 'nested'));
    await git(path.join(dir, 'nested'), 'init', '-q');
    fs.writeFileSync(path.join(dir, 'nested', 'x.txt'), 'x\n');
    const plain = await main(['--root', dir], {});
    assert.equal(plain.exitCode, 0, plain.output);
    assert.ok(plain.output.includes('skipped nested/: submodule or nested repository'),
      plain.output);
  });

test('main: a symbolic link is checked by its text and never followed', async (t) => {
  const outside = makeTemp();
  const target = path.join(outside, 'target.txt');
  fs.writeFileSync(target, 'mail ' + email('someone', 'corp.test') + '\n');
  const homeText = process.platform === 'win32'
    ? 'C:' + BS + 'Users' + BS + 'alice' + BS + 'notes'
    : '/home/' + 'alice/notes/';
  const dir = await makeRepo({});
  try {
    fs.symlinkSync(homeText, path.join(dir, 'home-link'));
    fs.symlinkSync(target, path.join(dir, 'outside-link'));
  } catch (err) {
    if (err.code === 'EPERM') {
      t.skip('this system needs more rights to make a symbolic link');
      return;
    }
    throw err;
  }
  const res = await main(['--root', dir], {});
  assert.ok(res.output.includes('user-path home-link:1: home-folder path with a user name'),
    res.output);
  assert.equal(res.output.includes('email outside-link'), false, res.output);
});

test('main: UTF-16 text is checked in default mode and reported in staged mode', async () => {
  const wide = Buffer.from('mail ' + email('someone', 'corp.test') + '\r\n', 'utf16le');
  const dir = await makeRepo({
    'le.txt': Buffer.concat([Buffer.from([0xff, 0xfe]), wide]),
    'be.txt': Buffer.concat([Buffer.from([0xfe, 0xff]), Buffer.from(wide).swap16()]),
    'photo.jpg': Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10, 0x4a, 0x46, 0x49, 0x46, 0x00]),
  });
  const plain = await main(['--root', dir], {});
  assert.equal(plain.exitCode, 1, plain.output);
  assert.ok(plain.output.includes('email le.txt:1: email address'), plain.output);
  assert.ok(plain.output.includes('email be.txt:1: email address'), plain.output);
  assert.ok(plain.output.includes('skipped photo.jpg: binary'), plain.output);
  await git(dir, 'add', 'le.txt', 'be.txt', 'photo.jpg');
  const staged = await main(['--root', dir, '--staged'], {});
  assert.equal(staged.exitCode, 1, staged.output);
  assert.ok(staged.output.includes('unchecked le.txt: UTF-16 text'), staged.output);
  assert.ok(staged.output.includes('unchecked be.txt: UTF-16 text'), staged.output);
  assert.ok(staged.output.includes('skipped photo.jpg: binary'), staged.output);
});

test('main: --help prints the use line and exit code 0', async () => {
  const res = await main(['--help'], {});
  assert.equal(res.exitCode, 0);
  assert.ok(res.output.startsWith('Use: node tools/check-leaks.mjs'), res.output);
});

test('main: --root wins over the git variables of the caller, and so does the git helper here',
  async () => {
    const other = await makeRepo({ 'o.txt': 'other\n' });
    await git(other, 'add', 'o.txt');
    await commit(other, 'other');
    const dir = await makeRepo({ 'a.txt': 'mail ' + email('someone', 'corp.test') + '\n' });
    const names = ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_AUTHOR_EMAIL'];
    const before = names.map((name) => process.env[name]);
    let res;
    try {
      process.env.GIT_DIR = path.join(other, '.git');
      process.env.GIT_WORK_TREE = other;
      process.env.GIT_INDEX_FILE = path.join(other, '.git', 'index');
      process.env.GIT_AUTHOR_EMAIL = email('ghost', 'example.com');
      await git(dir, 'add', 'a.txt');
      await commit(dir, 'first', 'Test', email('tester', 'corp.test'));
      res = await main(['--root', dir, '--history'], {});
    } finally {
      names.forEach((name, i) => {
        if (before[i] === undefined) {
          delete process.env[name];
        } else {
          process.env[name] = before[i];
        }
      });
    }
    assert.equal(res.exitCode, 1, res.output);
    assert.ok(res.output.includes('email a.txt:1: email address'), res.output);
    assert.match(res.output, /^email commit-[0-9a-f]{12}:author-email: email address$/m);
    assert.equal((await git(other, 'rev-list', '--count', 'HEAD')).trim(), '1');
    assert.equal((await git(other, 'ls-files')).trim(), 'o.txt');
  });

test('main: a file that cannot be read is reported, and the other files are checked',
  async () => {
    const dir = await makeRepo({
      'a.txt': 'mail ' + email('someone', 'corp.test') + '\n',
      'busy.txt': 'clean\n',
      ['Locked-' + TERM + '.txt']: 'clean\n',
    });
    const readFile = (file) => {
      if (path.basename(file) !== 'a.txt') {
        throw Object.assign(new Error('x'), { code: 'EBUSY' });
      }
      return fs.readFileSync(file);
    };
    const res = await main(['--root', dir, '--private-terms', termsFile()], {}, { readFile });
    assert.equal(res.exitCode, 1, res.output);
    assert.ok(res.output.includes('email a.txt:1: email address'), res.output);
    assert.ok(res.output.includes('unchecked busy.txt: could not be read (EBUSY)'), res.output);
    assert.match(res.output, /^unchecked file#\d+: could not be read \(EBUSY\)$/m);
    assert.equal(res.output.includes(dir), false, res.output);
    assert.equal(res.output.toLowerCase().includes(TERM), false, res.output);
    const asJson = JSON.parse((await main(['--root', dir, '--json'], {}, { readFile })).output);
    assert.deepEqual(asJson.unchecked.map((u) => u.reason),
      ['could not be read (EBUSY)', 'could not be read (EBUSY)']);
  });

test('the tool started as a program gives exit codes 0, 1 and 2 and prints the result',
  async () => {
    const clean = await makeRepo({ 'a.txt': 'clean\n' });
    const leak = await makeRepo({ 'a.txt': 'mail ' + email('someone', 'corp.test') + '\n' });
    const run = (args) => runProcess(process.execPath, [TOOL_PATH, ...args],
      { timeoutMs: 60_000, env: CLEAN_ENV });
    const ok = await run(['--root', clean]);
    assert.equal(ok.exitCode, 0, ok.stdout);
    assert.equal(ok.stdout, 'checked 1 files, 0 findings\n');
    const found = await run(['--root', leak]);
    assert.equal(found.exitCode, 1, found.stdout);
    assert.equal(found.stdout, 'email a.txt:1: email address\nchecked 1 files, 1 findings\n');
    const wrong = await run(['--nope']);
    assert.equal(wrong.exitCode, 2, wrong.stdout);
    assert.equal(wrong.stdout, 'usage: unknown argument\n');
  });

test('the tool started with no git on the search path gives usage and exit code 2',
  async () => {
    const dir = await makeRepo({ 'a.txt': 'clean\n' });
    const env = Object.fromEntries(Object.entries(CLEAN_ENV)
      .filter(([key]) => key.toUpperCase() !== 'PATH'));
    const res = await runProcess(process.execPath, [TOOL_PATH, '--root', dir],
      { timeoutMs: 60_000, env: { ...env, PATH: makeTemp() } });
    assert.equal(res.exitCode, 2, res.stdout);
    assert.equal(res.stdout, 'usage: git was not found\n');
  });

test('main: a file that git tracks is checked', async () => {
  const dir = await makeRepo({ 'a.txt': 'mail ' + email('someone', 'corp.test') + '\n' });
  await git(dir, 'add', 'a.txt');
  await commit(dir, 'add a');
  const res = await main(['--root', dir], {});
  assert.equal(res.exitCode, 1, res.output);
  assert.ok(res.output.includes('email a.txt:1: email address'), res.output);
});

test('main: --history checks the author and committer names, on every branch', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  await git(dir, 'add', 'a.txt');
  await commit(dir, 'first', 'Made by ' + TERM);
  await git(dir, 'checkout', '-q', '-b', 'side');
  fs.writeFileSync(path.join(dir, 'b.txt'), 'clean\n');
  await git(dir, 'add', 'b.txt');
  await commit(dir, 'side ' + TERM.toUpperCase());
  await git(dir, 'checkout', '-q', '-');
  const res = await main(['--root', dir, '--history', '--private-terms', termsFile()], {});
  assert.equal(res.exitCode, 1, res.output);
  assert.match(res.output, /^private-term commit-[0-9a-f]{12}:author-name: private term #1$/m);
  assert.match(res.output,
    /^private-term commit-[0-9a-f]{12}:committer-name: private term #1$/m);
  assert.match(res.output, /^private-term commit-[0-9a-f]{12}:message-1: private term #1$/m);
  assert.equal(res.output.toLowerCase().includes(TERM), false, res.output);
});

test('main: --staged skips a binary file and a file over 2 MB', async () => {
  const dir = await makeRepo({
    'bin.dat': Buffer.concat([Buffer.from(email('someone', 'corp.test')), Buffer.from([0, 1])]),
    'big.txt': 'a\n'.repeat(1024 * 1024 + 1),
    'ok.txt': 'fine\n',
  });
  await git(dir, 'add', '.');
  const res = await main(['--root', dir, '--staged'], {});
  assert.equal(res.exitCode, 0, res.output);
  assert.ok(res.output.includes('skipped bin.dat: binary'), res.output);
  assert.ok(res.output.includes('skipped big.txt: larger than 2 MB'), res.output);
  assert.ok(res.output.endsWith('checked 1 files, 0 findings'), res.output);
});

test('main: a skipped file whose name holds a private term is named file#N', async () => {
  const dir = await makeRepo({ ['data-' + TERM + '.bin']: Buffer.from([0, 1, 2]) });
  const res = await main(['--root', dir, '--private-terms', termsFile()], {});
  assert.ok(res.output.includes('skipped file#1: binary'), res.output);
  assert.equal(res.output.toLowerCase().includes(TERM), false, res.output);
});

test('main: CR, U+2028 and U+2029 end a line, so a marker hides only its own line',
  async () => {
    const marker = 'leak-check' + ': allow';
    const leak = 'mail ' + email('someone', 'corp.test');
    const [lineSep, paraSep] = [String.fromCharCode(0x2028), String.fromCharCode(0x2029)];
    const dir = await makeRepo({
      'cr.txt': marker + '\r' + leak + '\r',
      'ls.txt': marker + lineSep + leak + paraSep + 'end\n',
    });
    const res = await main(['--root', dir], {});
    assert.equal(res.exitCode, 1, res.output);
    assert.ok(res.output.includes('email cr.txt:2: email address'), res.output);
    assert.ok(res.output.includes('email ls.txt:2: email address'), res.output);
  });

test('main: --history checks the text after a 0x1E character in a commit message', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  await git(dir, 'add', 'a.txt');
  await commit(dir, 'subject\x1e' + TERM);
  const res = await main(['--root', dir, '--history', '--private-terms', termsFile()], {});
  assert.equal(res.exitCode, 1, res.output);
  assert.match(res.output, /^private-term commit-[0-9a-f]{12}:message-1: private term #1$/m);
});

test('the tool in a hook never reads an older index than the one of the commit', async () => {
  const dir = await makeRepo({ 'a.txt': 'clean\n' });
  await git(dir, 'add', 'a.txt');
  await commit(dir, 'first');
  fs.writeFileSync(path.join(dir, 'a.txt'), 'mail ' + email('someone', 'corp.test') + '\n');
  // What git does for 'git commit -a': the new content goes into a second index file, and
  // the hook gets the path of that file in GIT_INDEX_FILE.
  const second = path.join(dir, '.git', 'next-index');
  fs.copyFileSync(path.join(dir, '.git', 'index'), second);
  const env = { ...CLEAN_ENV, GIT_INDEX_FILE: second };
  const added = await runProcess('git', ['-C', dir, 'add', 'a.txt'], { timeoutMs: 60_000, env });
  assert.equal(added.exitCode, 0, added.stderr);
  const res = await runProcess(process.execPath, [TOOL_PATH, '--root', dir, '--staged'],
    { timeoutMs: 60_000, env });
  assert.notEqual(res.exitCode, 0, res.stdout);
  assert.equal(res.stdout.includes('0 findings'), false, res.stdout);
});

test('the tool in a folder that is not a repository says that --root is needed', async () => {
  const copy = makeTemp();
  fs.cpSync(path.join(ROOT, 'tools'), path.join(copy, 'tools'), { recursive: true });
  fs.cpSync(path.join(ROOT, 'skills', 'rea', 'scripts', 'lib'),
    path.join(copy, 'skills', 'rea', 'scripts', 'lib'), { recursive: true });
  const repo = await makeRepo({ 'a.txt': 'clean\n' });
  const res = await runProcess(process.execPath, [path.join(copy, 'tools', 'check-leaks.mjs')],
    { timeoutMs: 60_000, env: CLEAN_ENV, cwd: repo });
  assert.equal(res.exitCode, 2, res.stdout);
  assert.ok(res.stdout.startsWith('usage: not a git repository: pass --root'), res.stdout);
});

// A source archive has no .git folder or file: then there is no repository to check.
const IN_GIT_REPOSITORY = fs.existsSync(path.join(ROOT, '.git'));

test('main: the repository that holds this tool has no finding',
  { skip: IN_GIT_REPOSITORY ? false : 'not a git repository' }, async () => {
    const res = await main([], {});
    assert.equal(res.exitCode, 0, res.output);
  });
