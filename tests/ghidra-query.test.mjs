import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  buildEngineArgs, cacheRoot, chooseMode, findJava, launcherName, parseQueryOptions,
  readGhidraVersion, scrubTail, shortHome,
} from '../skills/rea/scripts/ghidra-query.mjs';

const input = {
  projectDir: 'P',
  targetPath: 'T/a.bin',
  targetName: 'a.bin',
  scriptDir: 'S',
  queryFile: 'Q',
  timeoutSec: 5,
};

test('cacheRoot uses REFACTOR_CACHE_DIR when it is not empty', () => {
  assert.equal(cacheRoot({ REFACTOR_CACHE_DIR: 'X' }, 'linux', '/home/you'), 'X');
  assert.equal(
    cacheRoot({ REFACTOR_CACHE_DIR: '' }, 'linux', '/home/you'),
    '/home/you/.cache/refactor'
  );
});

test('cacheRoot for each system', () => {
  assert.equal(cacheRoot({}, 'linux', '/home/you'), '/home/you/.cache/refactor');
  assert.equal(
    cacheRoot({ XDG_CACHE_HOME: '/c' }, 'linux', '/home/you'),
    '/c/refactor'
  );
  assert.equal(
    cacheRoot({}, 'darwin', '/Users/you'),
    '/Users/you/Library/Caches/refactor'
  );
  assert.equal(
    cacheRoot({ LOCALAPPDATA: 'D:\\Local' }, 'win32', 'C:\\Users\\you'),
    'D:\\Local\\refactor\\cache'
  );
  assert.equal(
    cacheRoot({}, 'win32', 'C:\\Users\\you'),
    'C:\\Users\\you\\AppData\\Local\\refactor\\cache'
  );
});

test('launcherName', () => {
  assert.equal(launcherName('win32'), 'analyzeHeadless.bat');
  assert.equal(launcherName('linux'), 'analyzeHeadless');
  assert.equal(launcherName('darwin'), 'analyzeHeadless');
});

test('buildEngineArgs in import mode', () => {
  assert.deepEqual(
    buildEngineArgs({ ...input, mode: 'import' }),
    [
      'P',
      'p',
      '-import',
      'T/a.bin',
      '-scriptPath',
      'S',
      '-postScript',
      'RefactorQuery.java',
      'Q',
      '-analysisTimeoutPerFile',
      '5',
    ]
  );
});

test('buildEngineArgs in process mode', () => {
  assert.deepEqual(
    buildEngineArgs({ ...input, mode: 'process' }),
    [
      'P',
      'p',
      '-process',
      'a.bin',
      '-noanalysis',
      '-readOnly',
      '-scriptPath',
      'S',
      '-postScript',
      'RefactorQuery.java',
      'Q',
      '-analysisTimeoutPerFile',
      '5',
    ]
  );
});

test('buildEngineArgs refuses a file name that starts with a dash', () => {
  for (const mode of ['import', 'process']) {
    assert.throws(
      () => buildEngineArgs({ ...input, targetName: '-x.bin', mode }),
      (err) => err.code === 'unsafe_path' && !err.message.includes('-x.bin')
    );
  }
  assert.throws(() => buildEngineArgs({ ...input, scriptDir: 'S;T', mode: 'import' }),
    { code: 'unsafe_path' });
});

test('scrubTail replaces the home folder in each form, case ignored', () => {
  assert.equal(scrubTail('a /home/you/x b', { home: '/home/you' }), 'a ~/x b');
  assert.equal(scrubTail('\\home\\you\\x', { home: '/home/you' }), '~\\x');
  assert.equal(
    scrubTail('at C:\\Users\\you\\p and C:/Users/you/q', { home: 'C:\\Users\\you' }),
    'at ~\\p and ~/q'
  );
  assert.equal(scrubTail('C:\\USERS\\YOU\\p', { home: 'C:\\Users\\you' }), '~\\p');
});

test('scrubTail replaces user and host names only as whole words', () => {
  assert.equal(
    scrubTail('user sam, samuel, sam1, xsam, sam', { user: 'sam' }),
    'user <user>, samuel, sam1, xsam, <user>'
  );
  assert.equal(
    scrubTail('on build-pc.corp.example and build-pc', { host: 'build-pc.corp.example' }),
    'on <host> and <host>'
  );
  assert.equal(
    scrubTail('/home/user/x user', { home: '/home/user', user: 'user' }),
    '~/x <user>'
  );
});

test('scrubTail escapes special characters and skips short or missing values', () => {
  assert.equal(
    scrubTail('C:\\Users\\example\\a.b+c (1)\\f', { home: 'C:\\Users\\example\\a.b+c (1)' }),
    '~\\f'
  );
  assert.equal(
    scrubTail('C:\\Users\\example\\aXb+c (1)\\f',
      { home: 'C:\\Users\\example\\a.b+c (1)' }),
    'C:\\Users\\example\\aXb+c (1)\\f'
  );
  assert.equal(scrubTail('a b', { user: 'a' }), 'a b');
  assert.equal(scrubTail('x $1 y', { home: undefined, user: 42, host: 'y' }), 'x $1 y');
});

test('shortHome finds the short spelling of the home folder', () => {
  const home = 'D:\\homes\\long-folder-name';
  const real = home + '\\AppData\\Temp';
  const short = 'D:\\homes\\LONG-F~1';
  assert.equal(shortHome(home, short + '\\AppData\\Temp', real), short);
  assert.equal(shortHome(home, real, real), home);
  assert.equal(shortHome(home, 'E:\\tmp', 'E:\\tmp'), '');
  assert.equal(shortHome('', real, real), '');
  assert.equal(
    scrubTail('at ' + short + '\\AppData\\q and D:/homes/LONG-F~1/x', { home, homeShort: short }),
    'at ~\\AppData\\q and ~/x'
  );
});

test('scrubTail keeps the end of the text', () => {
  assert.equal(scrubTail('x'.repeat(3000), {}).length, 2000);
  assert.equal(scrubTail('abcdef', {}, 3), 'def');
  assert.equal(scrubTail('ab', {}, 5), 'ab');
});

test('readGhidraVersion', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    fs.mkdirSync(path.join(dir, 'Ghidra'));
    const file = path.join(dir, 'Ghidra', 'application.properties');
    assert.equal(readGhidraVersion(null), null);
    assert.equal(readGhidraVersion(dir), null);
    fs.writeFileSync(
      file,
      'application.name=Ghidra\r\napplication.version = 11.1.2 \r\napplication.version=9\r\n'
    );
    assert.equal(readGhidraVersion(dir), '11.1.2');
    fs.writeFileSync(file, 'application.version=\n');
    assert.equal(readGhidraVersion(dir), null);
    fs.writeFileSync(file, 'application.name=Ghidra\n');
    assert.equal(readGhidraVersion(dir), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('findJava uses JAVA_HOME first', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const jhBin = path.join(dir, 'jh', 'bin');
    fs.mkdirSync(jhBin, { recursive: true });
    fs.writeFileSync(path.join(jhBin, 'java'), '');
    fs.writeFileSync(path.join(jhBin, 'java.exe'), '');
    const p1 = path.join(dir, 'p1');
    fs.mkdirSync(p1, { recursive: true });
    fs.writeFileSync(path.join(p1, 'java'), '');

    assert.deepEqual(
      findJava({ JAVA_HOME: path.join(dir, 'jh'), PATH: path.join(dir, 'p1') }, 'linux'),
      { found: true, source: 'JAVA_HOME', path: path.join(dir, 'jh', 'bin', 'java') }
    );
    assert.deepEqual(
      findJava({ JAVA_HOME: path.join(dir, 'jh') }, 'win32'),
      { found: true, source: 'JAVA_HOME', path: path.join(dir, 'jh', 'bin', 'java.exe') }
    );
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('findJava searches PATH, then Path', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const a = path.join(dir, 'a');
    const b = path.join(dir, 'b');
    fs.mkdirSync(a, { recursive: true });
    fs.mkdirSync(b, { recursive: true });
    fs.writeFileSync(path.join(b, 'java'), '');
    const list = ['', a, b].join(path.delimiter);
    const expected = { found: true, source: 'PATH', path: path.join(b, 'java') };
    assert.deepEqual(findJava({ JAVA_HOME: path.join(dir, 'none'), PATH: list }, 'linux'),
      expected);
    assert.deepEqual(findJava({ Path: list }, 'linux'), expected);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('findJava reports not found', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'refactor-test-'));
  try {
    const c = path.join(dir, 'c', 'java');
    fs.mkdirSync(c, { recursive: true });
    const expected = { found: false, source: null, path: null };
    assert.deepEqual(findJava({ PATH: path.join(dir, 'c') }, 'linux'), expected);
    assert.deepEqual(findJava({}, 'linux'), expected);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('parseQueryOptions gives the defaults and the values', () => {
  assert.deepEqual(
    parseQueryOptions('functions', {}),
    {
      limit: 100,
      cursor: '0',
      filter: null,
      name: null,
      address: null,
      maxChars: 20000,
      timeoutSec: 600,
    }
  );
  assert.deepEqual(
    parseQueryOptions('strings', Object.freeze({
      limit: '5',
      cursor: '10',
      filter: 'abc',
      'max-chars': '1',
      'timeout-sec': '86400',
    })),
    {
      limit: 5,
      cursor: '10',
      filter: 'abc',
      name: null,
      address: null,
      maxChars: 1,
      timeoutSec: 86400,
    }
  );
});

test('parseQueryOptions for decompile', () => {
  assert.deepEqual(
    parseQueryOptions('decompile', { name: 'main' }),
    {
      limit: 100,
      cursor: '0',
      filter: null,
      name: 'main',
      address: null,
      maxChars: 20000,
      timeoutSec: 600,
    }
  );
  assert.deepEqual(
    parseQueryOptions('decompile', { address: '0x401000', 'max-chars': '200000' }),
    {
      limit: 100,
      cursor: '0',
      filter: null,
      name: null,
      address: '0x401000',
      maxChars: 200000,
      timeoutSec: 600,
    }
  );
});

test('parseQueryOptions refuses bad values', () => {
  const cases = [
    ['functions', { limit: '0' }, 'limit must be a whole number from 1 to 1000'],
    ['functions', { cursor: '-1' }, 'cursor must be a text of digits'],
    ['functions', { 'max-chars': '0' }, 'max-chars must be a whole number from 1 to 200000'],
    ['functions', { 'max-chars': '200001' }, 'max-chars must be a whole number from 1 to 200000'],
    ['functions', { 'max-chars': 'abc' }, 'max-chars must be a whole number from 1 to 200000'],
    ['strings', { 'timeout-sec': '0' }, 'timeout-sec must be a whole number from 1 to 86400'],
    ['strings', { 'timeout-sec': '86401' }, 'timeout-sec must be a whole number from 1 to 86400'],
    ['strings', { 'timeout-sec': '1.5' }, 'timeout-sec must be a whole number from 1 to 86400'],
    ['decompile', {}, 'decompile needs exactly one of --name and --address'],
    ['decompile', { name: '' }, 'decompile needs exactly one of --name and --address'],
    ['decompile', { name: 'a', address: '0x1' },
      'decompile needs exactly one of --name and --address'],
    ['decompile', { address: 'xyz' }, 'address must be hex digits, for example 0x401000'],
    ['decompile', { address: '0x' + '1'.repeat(17) },
      'address must be hex digits, for example 0x401000'],
    ['functions', { name: 'main' }, '--name and --address are only for decompile'],
    ['strings', { address: '0x1' }, '--name and --address are only for decompile'],
  ];
  for (const [command, options, message] of cases) {
    assert.throws(() => parseQueryOptions(command, options), { code: 'usage', message });
  }
});

test('chooseMode', () => {
  const sha = 'a'.repeat(64);
  const marker = {
    sha256: sha,
    program_name: 'a.bin',
    ghidra_version: '11.0',
  };
  assert.equal(chooseMode(null, sha, null), 'import');
  assert.equal(chooseMode(marker, sha, null), 'process');
  assert.equal(chooseMode(marker, sha, '11.0'), 'process');
  assert.equal(chooseMode(marker, sha, '11.1'), 'import');
  assert.equal(chooseMode({ ...marker, sha256: 'b'.repeat(64) }, sha, null), 'import');
  assert.equal(chooseMode({ ...marker, program_name: '' }, sha, null), 'import');
  assert.equal(chooseMode({ sha256: sha }, sha, null), 'import');
  assert.equal(chooseMode([], sha, null), 'import');
  assert.equal(chooseMode('text', sha, null), 'import');
});
