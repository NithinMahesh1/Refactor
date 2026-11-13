// A stand-in for Ghidra's analyzeHeadless launcher, for the tests only. It reads the same
// arguments, finds the query file, writes a fixed result file, and never reads the target.
// FAKE_GHIDRA_MODE chooses what it does; FAKE_GHIDRA_ARGS_LOG names a file for its log.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const args = process.argv.slice(2);
const i = args.indexOf('-postScript');
const queryFile = i === -1 ? undefined : args[i + 2];

let query = null;
if (queryFile !== undefined) {
  query = JSON.parse(fs.readFileSync(queryFile, 'utf8'));
}

const cwdIsQueryDir = queryFile !== undefined &&
  fs.realpathSync.native(process.cwd()) ===
  fs.realpathSync.native(path.dirname(queryFile));

if (process.env.FAKE_GHIDRA_ARGS_LOG) {
  fs.appendFileSync(
    process.env.FAKE_GHIDRA_ARGS_LOG,
    JSON.stringify({ args, cwd_is_query_dir: cwdIsQueryDir, query }) + '\n',
  );
}

if (
  query === null ||
  args[1] !== 'p' ||
  (!args.includes('-import') && !args.includes('-process')) ||
  !args.includes('-scriptPath') ||
  !args.includes('-analysisTimeoutPerFile')
) {
  process.stderr.write('bad argument list\n');
  process.exit(2);
}

let programName;
const importIdx = args.indexOf('-import');
if (importIdx !== -1) {
  programName = path.basename(args[importIdx + 1]);
} else {
  const processIdx = args.indexOf('-process');
  programName = args[processIdx + 1];
}

const items = {
  functions: [{
    name: 'main', name_truncated: false, address: '00101000', size: 42,
    external: false, thunk: false,
  }],
  strings: [{ address: '00102000', text: 'hello', truncated: false }],
};

let R;
const op = query.op;
if (op === 'functions' || op === 'strings') {
  R = { items: items[op], total: 1, next_cursor: null };
} else if (op === 'decompile') {
  R = {
    function: { name: 'main', address: '00101000' },
    code: 'int main(void) { return 0; }',
    truncated: false,
    omitted_chars: 0,
  };
} else {
  process.stderr.write('unknown op\n');
  process.exit(2);
}

const okResult = {
  ok: true,
  op: query.op,
  program: { name: programName, language: 'x86:LE:64:default', compiler: 'gcc' },
  ghidra_version: '11.0-test',
  result: R,
};

const failResult = (code, message) => ({
  ok: false,
  error: { code, message },
});

const mode = process.env.FAKE_GHIDRA_MODE ?? 'ok';

if (mode === 'ok') {
  fs.writeFileSync(query.out, JSON.stringify(okResult));
  process.exit(0);
} else if (mode === 'fail') {
  process.stderr.write(
    'analysis failed near ' + path.join(os.homedir(), 'project') + '\n',
  );
  process.exit(1);
} else if (mode === 'sleep') {
  setTimeout(() => {}, 60000);
} else if (mode === 'badjson') {
  fs.writeFileSync(query.out, 'not json');
  process.exit(0);
} else if (mode === 'noresult') {
  process.exit(0);
} else if (mode === 'big') {
  fs.writeFileSync(query.out, JSON.stringify(okResult) + ' '.repeat(5 * 1024 * 1024));
  process.exit(0);
} else if (mode === 'page') {
  const res = { ...okResult, result: { ...R, total: 2, next_cursor: '1' } };
  fs.writeFileSync(query.out, JSON.stringify(res));
  process.exit(0);
} else if (mode === 'scripterror') {
  const res = JSON.stringify(failResult('script_error', 'IllegalStateException'));
  fs.writeFileSync(query.out, res);
  process.exit(0);
} else if (mode === 'badquery') {
  const res = JSON.stringify(failResult('bad_query', 'the query is not valid'));
  fs.writeFileSync(query.out, res);
  process.exit(0);
} else if (mode === 'nofunction') {
  const res = JSON.stringify(
    failResult('function_not_found', 'no function matches the name or the address'),
  );
  fs.writeFileSync(query.out, res);
  process.exit(0);
} else if (mode === 'candidates') {
  const res = JSON.stringify({
    ...okResult,
    result: {
      candidates: [
        { name: 'one::run', address: '00101000', thunk: false },
        { name: 'two::run', address: '00102000', thunk: false },
      ],
      candidates_total: 2,
      code: null,
      truncated: false,
    },
  });
  fs.writeFileSync(query.out, res);
  process.exit(0);
} else if (mode === 'analysistimeout') {
  process.stdout.write('Analysis timed out at 600 seconds\n');
  fs.writeFileSync(query.out, JSON.stringify(okResult));
  process.exit(0);
} else if (mode === 'compileerror') {
  process.stderr.write('RefactorQuery.java:12: error: cannot find symbol\n');
  process.exit(0);
} else if (mode === 'exception') {
  process.stderr.write(
    'java.lang.IllegalStateException near ' + path.join(os.homedir(), 'q.json') + '\n'
      + '\tat RefactorQuery.run(RefactorQuery.java:104)\n',
  );
  process.exit(0);
} else if (mode === 'noresultlog') {
  process.stdout.write('INFO  Using Language/Compiler: x86:LE:64:default:gcc (AutoImporter)\n'
    + '    Decompiler Switch Analysis                 0.201 secs\n'
    + '    GCC Exception Handlers                     0.022 secs\n');
  process.exit(0);
} else if (mode === 'failcwd') {
  process.stderr.write('could not read ' + path.join(process.cwd(), 'query.json') + '\n');
  process.exit(1);
} else {
  process.stderr.write('unknown mode\n');
  process.exit(2);
}
