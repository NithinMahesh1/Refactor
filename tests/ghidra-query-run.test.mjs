import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { runProcess } from '../skills/rea/scripts/lib/run.mjs';
import {
  argAfter, FAKE, holdsPath, JAVA_NAME, makeBatGhidraFolder, makeGhidraFolder,
  readLog, run, setup
} from './support/ghidra-harness.mjs';

const DIGEST = createHash('sha256').update(Buffer.alloc(64, 0x41)).digest('hex');

test('check with a made-up Ghidra folder reports found and the version', async () => {
  const s = await setup();
  try {
    const g = makeGhidraFolder(s.tmp);
    const r = await run(['check', '--ghidra', g], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.schema, 'refactor.check/1');
    assert.deepEqual(r.json.ghidra, { found: true, version: '11.0.3' });
    assert.equal(holdsPath(r.stdout, s.tmp), false);
    assert.deepEqual(readLog(s.log), []);
  } finally {
    await s.cleanup();
  }
});

test('check --show-path adds the folder', async () => {
  const s = await setup();
  try {
    const g = makeGhidraFolder(s.tmp);
    const r = await run(['check', '--show-path', '--ghidra', g], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.schema, 'refactor.check/1');
    assert.deepEqual(r.json.ghidra, { found: true, version: '11.0.3', path: g });
    assert.deepEqual(Object.keys(r.json.ghidra), ['found', 'version', 'path']);
  } finally {
    await s.cleanup();
  }
});

test('check with no Ghidra reports not found and exit code 0', async () => {
  const s = await setup();
  try {
    const r = await run(['check'], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.ghidra, { found: false, version: null });
    assert.equal(r.json.ready, false);
  } finally {
    await s.cleanup();
  }
});

test('check finds java through JAVA_HOME', async () => {
  const s = await setup();
  try {
    const jh = path.join(s.tmp, 'jh');
    const bin = path.join(jh, 'bin');
    fs.mkdirSync(bin, { recursive: true });
    fs.writeFileSync(path.join(bin, JAVA_NAME), '');
    const env = { ...s.env, JAVA_HOME: jh };
    const r = await run(['check'], env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.java, { found: true, source: 'JAVA_HOME' });
    assert.equal(holdsPath(r.stdout, s.tmp), false);
    const r2 = await run(['check', '--show-path'], env);
    assert.deepEqual(r2.json.java.path, path.join(bin, JAVA_NAME));
  } finally {
    await s.cleanup();
  }
});

test('functions through the stand-in returns an Evidence record', async () => {
  const s = await setup();
  try {
    const r = await run(['functions', s.target], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.schema, 'refactor.evidence/1');
    assert.match(r.json.id, /^ev_[0-9a-f]{32}$/);
    assert.deepEqual(r.json.tool, {
      name: 'ghidra-query', version: '0.1.0', engine: { name: 'ghidra', version: '11.0-test' },
    });
    assert.equal(r.json.operation, 'functions');
    assert.equal(r.json.confidence, 'observed');
    assert.deepEqual(r.json.subject, { name: 'sample.bin', sha256: DIGEST, size_bytes: 64 });
    assert.deepEqual(r.json.parameters, { limit: 100, cursor: '0', filter: null });
    assert.equal(r.json.result.items[0].name, 'main');
    assert.deepEqual(r.json.result.program,
      { name: 'sample.bin', language: 'x86:LE:64:default', compiler: 'gcc' });
    assert.deepEqual(r.json.coverage, {
      examined: 'functions that Ghidra found in its analysis, in address order',
      not_examined: [], truncated: false, next_cursor: null,
    });
    assert.equal(holdsPath(r.stdout, s.tmp), false);
    const log = readLog(s.log);
    assert.equal(log.length, 1);
    assert.equal(log[0].cwd_is_query_dir, true);
  } finally {
    await s.cleanup();
  }
});

test('the second call for the same target uses -process and -noanalysis', async () => {
  const s = await setup();
  try {
    const r1 = await run(['functions', s.target], s.env);
    assert.equal(r1.status, 0);
    const r2 = await run(['functions', s.target], s.env);
    assert.equal(r2.status, 0);
    const log = readLog(s.log);
    assert.equal(log.length, 2);
    assert.ok(log[0].args.includes('-import'));
    assert.ok(!log[0].args.includes('-process'));
    assert.equal(argAfter(log[0].args, '-import'), s.target);
    assert.ok(log[1].args.includes('-process'));
    assert.ok(log[1].args.includes('-noanalysis'));
    assert.ok(log[1].args.includes('-readOnly'));
    assert.ok(!log[0].args.includes('-readOnly'));
    assert.ok(!log[1].args.includes('-import'));
    assert.equal(argAfter(log[1].args, '-process'), 'sample.bin');
    assert.equal(log[1].args[0], log[0].args[0]);
    assert.equal(path.basename(log[0].args[0]), DIGEST.slice(0, 16));
    assert.equal(fs.readdirSync(path.join(s.tmp, 'cache', 'ghidra')).length, 1);
    const marker = path.join(log[0].args[0], 'imported.json');
    assert.deepEqual(JSON.parse(fs.readFileSync(marker, 'utf8')),
      { sha256: DIGEST, ghidra_version: '11.0-test', program_name: 'sample.bin' });
  } finally {
    await s.cleanup();
  }
});

test('a failed import is not marked, so the next call imports again', async () => {
  const s = await setup();
  try {
    const r1 = await run(['functions', s.target], { ...s.env, FAKE_GHIDRA_MODE: 'fail' });
    assert.equal(r1.status, 3);
    const r2 = await run(['functions', s.target], s.env);
    assert.equal(r2.status, 0);
    const log = readLog(s.log);
    assert.equal(log.length, 2);
    assert.ok(log[1].args.includes('-import'));
  } finally {
    await s.cleanup();
  }
});

test('--no-cache leaves no folder behind', async () => {
  const s = await setup();
  try {
    const r = await run(['functions', s.target, '--no-cache'], s.env);
    assert.equal(r.status, 0);
    assert.equal(fs.existsSync(path.join(s.tmp, 'cache')), false);
    const log = readLog(s.log);
    assert.ok(log[0].args.includes('-import'));
    assert.equal(fs.existsSync(log[0].args[0]), false);
    assert.equal(fs.existsSync(argAfter(log[0].args, 'RefactorQuery.java')), false);
  } finally {
    await s.cleanup();
  }
});

test('the query file holds the options and the filter is never an argument', async () => {
  const s = await setup();
  try {
    const r = await run(['functions', s.target, '--filter', 'needle-4711', '--limit', '5',
      '--cursor', '10'], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.parameters, { limit: 5, cursor: '10', filter: 'needle-4711' });
    const log = readLog(s.log);
    for (const arg of log[0].args) {
      assert.equal(arg.includes('needle-4711'), false);
    }
    const queryFile = argAfter(log[0].args, 'RefactorQuery.java');
    const { out, ...rest } = log[0].query;
    assert.equal(out, path.join(path.dirname(queryFile), 'result.json'));
    assert.deepEqual(rest, { op: 'functions', limit: 5, cursor: '10', filter: 'needle-4711',
      name: null, address: null, max_chars: 20000 });
  } finally {
    await s.cleanup();
  }
});

test('strings through the stand-in', async () => {
  const s = await setup();
  try {
    const r = await run(['strings', s.target], s.env);
    assert.equal(r.status, 0);
    assert.equal(r.json.operation, 'strings');
    assert.equal(r.json.result.items[0].text, 'hello');
    assert.equal(r.json.coverage.examined, 'strings that Ghidra defined, in address order');
    assert.deepEqual(r.json.limits, ['Only strings that Ghidra defined are listed. '
      + 'A text longer than 200 characters is cut and flagged.']);
    assert.deepEqual(r.json.coverage.not_examined,
      ['strings inside structures and arrays are not listed']);
  } finally {
    await s.cleanup();
  }
});

test('decompile --name main', async () => {
  const s = await setup();
  try {
    const r = await run(['decompile', s.target, '--name', 'main'], s.env);
    assert.equal(r.status, 0);
    assert.equal(r.json.confidence, 'derived');
    assert.ok(r.json.result.code.startsWith('int main'));
    assert.deepEqual(r.json.parameters, { name: 'main', address: null, max_chars: 20000 });
    assert.ok(r.json.limits.includes(
      'Decompiler output is a reconstruction. It is not the original source code.'));
    assert.deepEqual(r.json.coverage, {
      examined: 'one function, decompiled by Ghidra', not_examined: ['all other functions'],
      truncated: false, next_cursor: null,
    });
    assert.equal(r.json.result.omitted_chars, 0);
    const log = readLog(s.log);
    assert.ok(!log[0].args.includes('main'));
  } finally {
    await s.cleanup();
  }
});

test('a stand-in that exits 1 gives engine_failed with the home folder replaced', async () => {
  const s = await setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'fail' };
    const r = await run(['functions', s.target], env);
    assert.equal(r.status, 3);
    assert.deepEqual(r.json.schema, 'refactor.error/1');
    assert.equal(r.json.error.code, 'engine_failed');
    assert.equal(r.json.error.message, 'Ghidra ended with exit code 1');
    assert.equal(r.json.error.details.exit_code, 1);
    assert.ok(r.json.error.details.output.includes(path.join('~', 'project')));
    assert.equal(holdsPath(r.stdout, os.homedir()), false);
  } finally {
    await s.cleanup();
  }
});

test('a stand-in that sleeps gives engine_timeout', { timeout: 60000 }, async () => {
  const s = await setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'sleep' };
    const r = await run(['functions', s.target, '--timeout-sec', '1'], env);
    assert.equal(r.status, 3);
    assert.equal(r.json.error.code, 'engine_timeout');
    assert.equal(r.json.error.message, 'Ghidra did not finish within 1 seconds');
  } finally {
    await s.cleanup();
  }
});

test('a result file that is not JSON gives bad_engine_output', async () => {
  const s = await setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'badjson' };
    const r = await run(['functions', s.target], env);
    assert.equal(r.status, 3);
    assert.equal(r.json.error.code, 'bad_engine_output');
    assert.equal(r.json.error.message, 'Ghidra did not write a valid result file');
  } finally {
    await s.cleanup();
  }
});

test('a missing or too large result file gives bad_engine_output', async () => {
  const s = await setup();
  try {
    for (const mode of ['noresult', 'big']) {
      const env = { ...s.env, FAKE_GHIDRA_MODE: mode };
      const r = await run(['functions', s.target], env);
      assert.equal(r.status, 3);
      assert.equal(r.json.error.code, 'bad_engine_output');
    }
  } finally {
    await s.cleanup();
  }
});

test('an error reported by the Ghidra script gives engine_failed', async () => {
  const s = await setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'scripterror' };
    const r1 = await run(['functions', s.target], env);
    assert.equal(r1.status, 3);
    assert.equal(r1.json.error.code, 'engine_failed');
    assert.equal(r1.json.error.message, 'the Ghidra script reported an error');
    assert.deepEqual(r1.json.error.details.engine_error,
      { code: 'script_error', message: 'IllegalStateException' });
    const r2 = await run(['functions', s.target], s.env);
    assert.equal(r2.status, 0);
    const log = readLog(s.log);
    assert.ok(log[1].args.includes('-process'));
  } finally {
    await s.cleanup();
  }
});

test('no engine at all gives engine_not_found', async () => {
  const s = setup({ REFACTOR_ENGINE_COMMAND: undefined });
  try {
    const r = await run(['functions', s.target], s.env);
    assert.equal(r.status, 3);
    assert.equal(r.json.error.code, 'engine_not_found');
    assert.deepEqual(readLog(s.log), []);
  } finally {
    s.cleanup();
  }
});

test('a Ghidra folder without the launcher gives engine_not_found', async () => {
  const s = setup({ REFACTOR_ENGINE_COMMAND: undefined });
  try {
    const g = path.join(s.tmp, 'g');
    const r = await run(['functions', s.target, '--ghidra', g], s.env);
    assert.equal(r.status, 3);
    assert.equal(r.json.error.code, 'engine_not_found');
  } finally {
    s.cleanup();
  }
});

test('a bad REFACTOR_ENGINE_COMMAND is a usage error', async () => {
  const s = await setup();
  try {
    for (const value of ['not json', '[]', '[1]', JSON.stringify(['relative-node'])]) {
      const env = { ...s.env, REFACTOR_ENGINE_COMMAND: value };
      const r = await run(['functions', s.target], env);
      assert.equal(r.status, 2);
      assert.equal(r.json.error.code, 'usage');
    }
  } finally {
    await s.cleanup();
  }
});

test('usage errors give exit code 2 and name the problem', async () => {
  const s = await setup();
  try {
    const rows = [
      [[], 'give one of: check, functions, strings, decompile'],
      [['nope'], 'give one of: check, functions, strings, decompile'],
      [['functions'], 'give the path of the program file'],
      [['functions', s.target, 'extra'], 'give only one program file'],
      [['check', 'a', 'b'], 'too many arguments for check'],
      [['decompile', s.target], 'decompile needs exactly one of --name and --address'],
      [['decompile', s.target, '--address', 'xyz'],
        'address must be hex digits, for example 0x401000'],
      [['functions', s.target, '--limit', '0'], 'limit must be a whole number from 1 to 1000'],
      [['functions', '--bogus'], 'unknown option --bogus'],
    ];
    for (const [args, message] of rows) {
      const r = await run(args, s.env);
      assert.equal(r.status, 2);
      assert.equal(r.json.error.code, 'usage');
      assert.equal(r.json.error.message, message);
    }
    assert.deepEqual(readLog(s.log), []);
  } finally {
    await s.cleanup();
  }
});

test('not_found and is_directory give exit code 2 without the path', async () => {
  const s = await setup();
  try {
    const r1 = await run(['functions', path.join(s.tmp, 'missing.bin')], s.env);
    assert.equal(r1.status, 2);
    assert.equal(r1.json.error.code, 'not_found');
    assert.equal(holdsPath(r1.stdout, s.tmp), false);
    const r2 = await run(['functions', s.tmp], s.env);
    assert.equal(r2.status, 2);
    assert.equal(r2.json.error.code, 'is_directory');
  } finally {
    await s.cleanup();
  }
});

test('a file name that starts with a dash gives unsafe_path', async () => {
  const s = await setup();
  try {
    const file = path.join(s.tmp, '-x.bin');
    fs.writeFileSync(file, Buffer.alloc(64, 0x41));
    const r = await run(['functions', file], s.env);
    assert.equal(r.status, 2);
    assert.equal(r.json.error.code, 'unsafe_path');
    assert.deepEqual(readLog(s.log), []);
  } finally {
    await s.cleanup();
  }
});

test('--pretty, --show-path and --help', async () => {
  const s = await setup();
  try {
    const r1 = await run(['functions', s.target, '--pretty', '--show-path'], s.env);
    assert.equal(r1.status, 0);
    assert.ok(r1.stdout.trim().split('\n').length > 1);
    assert.equal(r1.json.subject.path, s.target);
    const r2 = await run(['--help'], s.env);
    assert.equal(r2.status, 0);
    assert.ok(r2.stdout.startsWith('Use: node ghidra-query.mjs'));
  } finally {
    await s.cleanup();
  }
});

const notWindows = process.platform !== 'win32';

test('the Windows launcher runs through cmd.exe', { skip: notWindows }, async () => {
  const s = setup({ REFACTOR_ENGINE_COMMAND: undefined });
  try {
    const g = makeBatGhidraFolder(s.tmp);
    const r = await run(['functions', s.target, '--ghidra', g], s.env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.tool.engine.version, '11.0-test');
    const log = readLog(s.log);
    assert.ok(log[0].args.includes('-import'));
    assert.equal(log[0].cwd_is_query_dir, true);
  } finally {
    s.cleanup();
  }
});

test('a page that is not the last one sets next_cursor', async () => {
  const s = await setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'page' };
    const r = await run(['functions', s.target, '--limit', '1'], env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.coverage, {
      examined: 'functions that Ghidra found in its analysis, in address order',
      not_examined: ['items after this page'], truncated: true, next_cursor: '1',
    });
    assert.equal(r.json.result.total, 2);
  } finally {
    await s.cleanup();
  }
});

test('a query that the Ghidra script refuses is a usage error', async () => {
  const s = setup();
  try {
    const r = await run(['functions', s.target], { ...s.env, FAKE_GHIDRA_MODE: 'badquery' });
    assert.equal(r.status, 2);
    assert.equal(r.json.error.code, 'usage');
    assert.equal(r.json.error.details.engine_error.code, 'bad_query');
  } finally {
    s.cleanup();
  }
});

test('a function that is not found gives exit code 2', async () => {
  const s = setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'nofunction' };
    const r = await run(['decompile', s.target, '--name', 'nothing'], env);
    assert.equal(r.status, 2);
    assert.equal(r.json.error.code, 'function_not_found');
  } finally {
    s.cleanup();
  }
});

test('several functions with the name give the candidates and no code', async () => {
  const s = setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'candidates' };
    const r = await run(['decompile', s.target, '--name', 'run'], env);
    assert.equal(r.status, 0);
    assert.equal(r.json.result.code, null);
    assert.equal(r.json.result.candidates_total, 2);
    assert.equal(r.json.result.candidates.length, 2);
    assert.deepEqual(r.json.coverage, {
      examined: 'function names only: several functions have the given name',
      not_examined: ['the code of every candidate: no function was decompiled'],
      truncated: false, next_cursor: null,
    });
  } finally {
    s.cleanup();
  }
});

test('an analysis that timed out is named in coverage', async () => {
  const s = setup();
  try {
    const env = { ...s.env, FAKE_GHIDRA_MODE: 'analysistimeout' };
    const r = await run(['functions', s.target], env);
    assert.equal(r.status, 0);
    assert.deepEqual(r.json.coverage.not_examined,
      ['the analysis timed out, so the program is only partly analysed']);
  } finally {
    s.cleanup();
  }
});

test('a missing result file names a compile error or an exception', async () => {
  const s = setup();
  try {
    const rows = [
      ['compileerror', 'Ghidra did not write a result file: the Ghidra script did not compile'],
      ['exception',
        'Ghidra did not write a result file: the Ghidra script stopped with an exception'],
    ];
    for (const [mode, message] of rows) {
      const r = await run(['functions', s.target], { ...s.env, FAKE_GHIDRA_MODE: mode });
      assert.equal(r.status, 3);
      assert.equal(r.json.error.code, 'bad_engine_output');
      assert.equal(r.json.error.message, message);
      assert.equal(holdsPath(r.stdout, os.homedir()), false);
    }
  } finally {
    s.cleanup();
  }
});

test('words of a normal Ghidra log are not read as a script error', async () => {
  const s = setup();
  try {
    const r = await run(['functions', s.target], { ...s.env, FAKE_GHIDRA_MODE: 'noresultlog' });
    assert.equal(r.status, 3);
    assert.equal(r.json.error.code, 'bad_engine_output');
    assert.equal(r.json.error.message, 'Ghidra did not write a valid result file');
  } finally {
    s.cleanup();
  }
});

test('engine_failed hides every spelling of the home folder', async () => {
  const s = setup();
  try {
    const r = await run(['functions', s.target], { ...s.env, FAKE_GHIDRA_MODE: 'failcwd' });
    assert.equal(r.json.error.code, 'engine_failed');
    assert.ok(r.json.error.details.output.includes('query.json'));
    const given = path.resolve(os.tmpdir());
    const real = fs.realpathSync.native(given);
    const home = os.homedir();
    if (real.toLowerCase().startsWith(home.toLowerCase()) && given !== real) {
      const short = given.slice(0, given.length - (real.length - home.length));
      assert.equal(holdsPath(r.stdout, short), false);
    }
    assert.equal(holdsPath(r.stdout, home), false);
  } finally {
    s.cleanup();
  }
});

test('long option values are refused before the engine starts', async () => {

  const s = setup();
  try {
    const long = 'a'.repeat(501);
    const rows = [
      ['functions', s.target, '--filter', long],
      ['decompile', s.target, '--name', long],
    ];
    for (const args of rows) {
      const r = await run(args, s.env);
      assert.equal(r.status, 2);
      assert.equal(r.json.error.code, 'usage');
      assert.equal(r.json.error.message,
        '--filter, --name and --address hold at most 500 characters');
    }
    assert.deepEqual(readLog(s.log), []);
    const okRun = await run(['functions', s.target, '--filter', 'a'.repeat(500)], s.env);
    assert.equal(okRun.status, 0);
  } finally {
    s.cleanup();
  }
});

test('the stand-in writes only keys and error codes that the Ghidra script writes', async () => {
  const javaFile = fileURLToPath(
    new URL('../skills/rea/scripts/ghidra/RefactorQuery.java', import.meta.url));
  const java = fs.readFileSync(javaFile, 'utf8');
  const s = setup();
  try {
    const keys = new Set();
    const codes = new Set();
    const collect = (value) => {
      if (Array.isArray(value)) {
        for (const item of value) {
          collect(item);
        }
      } else if (value !== null && typeof value === 'object') {
        for (const [key, item] of Object.entries(value)) {
          keys.add(key);
          collect(item);
        }
      }
    };
    const runs = [['ok', 'functions'], ['ok', 'strings'], ['ok', 'decompile'],
      ['page', 'functions'], ['candidates', 'decompile'], ['scripterror', 'functions'],
      ['badquery', 'functions'], ['nofunction', 'decompile']];
    for (const [mode, op] of runs) {
      const dir = fs.mkdtempSync(path.join(s.tmp, 'q-'));
      const queryFile = path.join(dir, 'query.json');
      const out = path.join(dir, 'result.json');
      fs.writeFileSync(queryFile, JSON.stringify({ op, out, limit: 100, cursor: '0',
        filter: null, name: null, address: null, max_chars: 20000 }));
      const args = [FAKE, path.join(dir, 'project'), 'p', '-import', s.target,
        '-scriptPath', dir, '-postScript', 'RefactorQuery.java', queryFile,
        '-analysisTimeoutPerFile', '5'];
      const env = { ...s.env, FAKE_GHIDRA_MODE: mode };
      const r = await runProcess(process.execPath, args, { cwd: dir, env });
      assert.equal(r.exitCode, 0);
      const file = JSON.parse(fs.readFileSync(out, 'utf8'));
      collect(file);
      if (file.ok === false) {
        codes.add(file.error.code);
      }
    }
    assert.equal(codes.size, 3);
    for (const key of [...keys, ...codes]) {
      assert.ok(java.includes('"' + key + '"'), 'not a text literal in the Java file: ' + key);
    }
  } finally {
    s.cleanup();
  }
});
