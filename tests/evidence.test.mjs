import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  makeEvidence, canonicalJson, makeError, sha256Hex, TOOL_VERSION,
} from '../skills/rea/scripts/lib/evidence.mjs';

function validInput() {
  return {
    subject: { name: 'sample.bin', sha256: 'a'.repeat(64), size_bytes: 10 },
    tool: { name: 'file-identity', version: '0.1.0', engine: null },
    operation: 'identify',
    parameters: { x: 1 },
    confidence: 'observed',
    result: { type: 'text' },
    coverage: { examined: 'all', not_examined: [], truncated: false, next_cursor: null },
    limits: ['one limit'],
  };
}

const withSubject = (patch) => ({
  ...validInput(),
  subject: { ...validInput().subject, ...patch },
});

const withTool = (patch) => ({
  ...validInput(),
  tool: { ...validInput().tool, ...patch },
});

const withCoverage = (patch) => ({
  ...validInput(),
  coverage: { ...validInput().coverage, ...patch },
});

test('canonicalJson sorts keys at two levels', () => {
  assert.strictEqual(canonicalJson({ b: 1, a: { d: 2, c: 3 } }), '{"a":{"c":3,"d":2},"b":1}');
});

test('canonicalJson keeps array order', () => {
  assert.strictEqual(canonicalJson([3, 1, 2]), '[3,1,2]');
  assert.strictEqual(canonicalJson({ a: [{ z: 1, y: 2 }] }), '{"a":[{"y":2,"z":1}]}');
});

test('canonicalJson throws TypeError for invalid values', () => {
  assert.throws(() => canonicalJson(undefined), { name: 'TypeError' });
  assert.throws(() => canonicalJson(() => 1), { name: 'TypeError' });
  assert.throws(() => canonicalJson(NaN), { name: 'TypeError' });
  assert.throws(() => canonicalJson(Infinity), { name: 'TypeError' });
  assert.throws(() => canonicalJson({ a: undefined }), { name: 'TypeError' });
  assert.throws(() => canonicalJson([1, undefined]), { name: 'TypeError' });
  const withHole = [1, 2, 3];
  delete withHole[1];
  assert.throws(() => canonicalJson(withHole), { name: 'TypeError' });
  assert.throws(() => canonicalJson({ a: withHole }), { name: 'TypeError' });
});

test('makeEvidence id consistency and format', () => {
  const id1 = makeEvidence(validInput()).id;
  const id2 = makeEvidence(validInput()).id;
  assert.strictEqual(id1, id2);
  assert.match(id1, /^ev_[0-9a-f]{32}$/);
});

test('makeEvidence id changes when fields change', () => {
  const baseId = makeEvidence(validInput()).id;

  assert.notStrictEqual(makeEvidence(withSubject({ name: 'other.bin' })).id, baseId);
  assert.notStrictEqual(makeEvidence(withSubject({ sha256: 'b'.repeat(64) })).id, baseId);
  assert.notStrictEqual(makeEvidence(withSubject({ size_bytes: 11 })).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), operation: 'other' }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), parameters: { x: 2 } }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), confidence: 'derived' }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), result: { type: 'elf' } }).id, baseId);
  assert.notStrictEqual(
    makeEvidence({ ...validInput(), coverage: { ...validInput().coverage, examined: 'part' } }).id,
    baseId
  );
  assert.notStrictEqual(makeEvidence({ ...validInput(), limits: [] }).id, baseId);
  assert.notStrictEqual(makeEvidence(withSubject({ path: 'x/sample.bin' })).id, baseId);
  assert.notStrictEqual(makeEvidence(withTool({ name: 'ghidra-query' })).id, baseId);
  assert.notStrictEqual(makeEvidence(withTool({ version: '0.2.0' })).id, baseId);
  const engineId = makeEvidence(withTool({ engine: { name: 'ghidra', version: '11.0' } })).id;
  assert.notStrictEqual(engineId, baseId);
  assert.notStrictEqual(
    makeEvidence(withTool({ engine: { name: 'ghidra', version: '11.1' } })).id, engineId);
  assert.notStrictEqual(
    makeEvidence(withTool({ engine: { name: 'other', version: '11.0' } })).id, engineId);
  assert.notStrictEqual(makeEvidence(withCoverage({ not_examined: ['x'] })).id, baseId);
  assert.notStrictEqual(makeEvidence(withCoverage({ truncated: true })).id, baseId);
  assert.notStrictEqual(makeEvidence(withCoverage({ next_cursor: '100' })).id, baseId);
});

test('makeEvidence gives a fixed id for a fixed input', () => {
  // Computed once by hand from the rule: 'ev_' + the first 32 hex characters of the SHA-256
  // of the canonical JSON. A change in canonicalJson or in the id rule changes it.
  assert.strictEqual(makeEvidence(validInput()).id, 'ev_7ecdb8b087fcb1bacf273d50d7a23a28');
});

test('makeEvidence id formula', () => {
  const record = makeEvidence(validInput());
  const { id, ...rest } = record;

  assert.strictEqual(id, 'ev_' + sha256Hex(canonicalJson(rest)).slice(0, 32));
});

test('makeEvidence record shape', () => {
  const record = makeEvidence(validInput());
  assert.strictEqual(record.schema, 'refactor.evidence/1');
  assert.deepStrictEqual(Object.keys(record), [
    'schema', 'id', 'subject', 'tool', 'operation', 'parameters',
    'confidence', 'result', 'coverage', 'limits',
  ]);
  assert.strictEqual('path' in record.subject, false);

  // A missing tool.engine becomes null
  const toolNoEngine = { ...validInput().tool, engine: undefined };
  const recordNoEngine = makeEvidence({ ...validInput(), tool: toolNoEngine });
  assert.strictEqual(recordNoEngine.tool.engine, null);

  // when subject.path: 'x/sample.bin' is given it is kept
  const subjectWithPath = { ...validInput().subject, path: 'x/sample.bin' };
  const recordWithPath = makeEvidence({ ...validInput(), subject: subjectWithPath });
  assert.strictEqual(recordWithPath.subject.path, 'x/sample.bin');
});

test('makeEvidence bad fields throw TypeError', () => {
  const assertThrowsField = (fn, field) => {
    assert.throws(fn, (e) => e instanceof TypeError && e.message.startsWith(field));
  };

  assertThrowsField(() => makeEvidence(withSubject({ name: '' })), 'subject.name');
  assertThrowsField(() => makeEvidence(withSubject({ sha256: 'A'.repeat(64) })), 'subject.sha256');
  assertThrowsField(() => makeEvidence(withSubject({ sha256: 'a'.repeat(63) })), 'subject.sha256');
  assertThrowsField(() => makeEvidence(withSubject({ size_bytes: -1 })), 'subject.size_bytes');
  assertThrowsField(() => makeEvidence(withSubject({ size_bytes: 1.5 })), 'subject.size_bytes');
  assertThrowsField(() => makeEvidence({
    ...validInput(),
    tool: { ...validInput().tool, name: '' },
  }), 'tool.name');
  assertThrowsField(() => makeEvidence({
    ...validInput(),
    tool: { ...validInput().tool, engine: { name: '', version: '1' } },
  }), 'tool.engine.name');
  assertThrowsField(() => makeEvidence({ ...validInput(), operation: '' }), 'operation');
  assertThrowsField(() => makeEvidence({ ...validInput(), confidence: 'guess' }), 'confidence');
  assertThrowsField(() => makeEvidence({ ...validInput(), result: [] }), 'result');
  assertThrowsField(() => makeEvidence({
    ...validInput(),
    coverage: { ...validInput().coverage, not_examined: 'text' },
  }), 'coverage.not_examined');
  assertThrowsField(() => makeEvidence({ ...validInput(), limits: [1] }), 'limits');
  assertThrowsField(() => makeEvidence({ ...validInput(), subject: null }), 'subject');
});

test('makeEvidence record is frozen', () => {
  const input = validInput();
  const record = makeEvidence(input);
  assert.strictEqual(Object.isFrozen(record), true);
  assert.strictEqual(Object.isFrozen(record.subject), true);
  assert.strictEqual(Object.isFrozen(record.coverage.not_examined), true);
  assert.strictEqual(Object.isFrozen(record.limits), true);
  assert.strictEqual(Object.isFrozen(input.result), false);
});

test('makeError without details', () => {
  const result = makeError('usage', 'bad');
  assert.deepStrictEqual(result, {
    schema: 'refactor.error/1',
    error: { code: 'usage', message: 'bad' },
  });
  assert.strictEqual('details' in result.error, false);
});

test('makeError with details', () => {
  const result = makeError('not_found', 'gone', { name: 'a' });
  assert.deepStrictEqual(result, {
    schema: 'refactor.error/1',
    error: { code: 'not_found', message: 'gone', details: { name: 'a' } },
  });
});

test('subject keeps only its known fields', () => {
  const input = validInput();
  input.subject.extra = 'x';
  const record = makeEvidence(input);
  assert.deepEqual(Object.keys(record.subject), ['name', 'sha256', 'size_bytes']);
});

test('canonicalJson refuses objects that are not plain', () => {
  assert.throws(() => canonicalJson(new Date(0)), TypeError);
  assert.throws(() => canonicalJson(Buffer.from('a')), TypeError);
  assert.throws(() => canonicalJson({ a: new Map() }), TypeError);
  assert.equal(canonicalJson(Object.assign(Object.create(null), { b: 1, a: 2 })), '{"a":2,"b":1}');
});

test('makeEvidence refuses values that are not plain data', () => {
  assert.throws(() => makeEvidence({ ...validInput(), result: new Date(0) }),
    (e) => e instanceof TypeError && e.message.startsWith('result'));
  const coverageArray = Object.assign([], validInput().coverage);
  assert.throws(() => makeEvidence({ ...validInput(), coverage: coverageArray }),
    { name: 'TypeError', message: 'coverage: must be a plain object' });
});

test('makeEvidence checks every field and names it', () => {
  const cases = [
    [withSubject({ path: 42 }), 'subject.path: must be a string'],
    [{ ...validInput(), tool: null }, 'tool: must be a plain object'],
    [withTool({ version: '' }), 'tool.version: must be a non-empty string'],
    [withTool({ engine: 'ghidra' }), 'tool.engine: must be a plain object or null'],
    [withTool({ engine: { name: 'ghidra', version: 11 } }),
      'tool.engine.version: must be a string'],
    [{ ...validInput(), parameters: [] }, 'parameters: must be a plain object'],
    [withCoverage({ examined: '' }), 'coverage.examined: must be a non-empty string'],
    [withCoverage({ truncated: 'no' }), 'coverage.truncated: must be a boolean'],
    [withCoverage({ next_cursor: 5 }), 'coverage.next_cursor: must be a string or null'],
  ];
  for (const [input, message] of cases) {
    assert.throws(() => makeEvidence(input), { name: 'TypeError', message });
  }
});

test('makeEvidence names the place of a value that is not JSON data', () => {
  const withHole = [1, 2, 3];
  delete withHole[1];
  const loop = { a: 1 };
  loop.self = loop;
  const cases = [
    [{ ...validInput(), result: { type: 'text', details: { bits: undefined } } },
      'result.details.bits: undefined is not allowed'],
    [{ ...validInput(), parameters: { limit: NaN } },
      'parameters.limit: number is not finite'],
    [{ ...validInput(), result: { run: () => 1 } },
      'result.run: function is not allowed'],
    [{ ...validInput(), parameters: { big: 1n } },
      'parameters.big: bigint is not allowed'],
    [{ ...validInput(), result: { names: new Map() } },
      'result.names: only plain objects are allowed'],
    [{ ...validInput(), result: { bytes: new Uint8Array(2) } },
      'result.bytes: only plain objects are allowed'],
    [{ ...validInput(), result: { list: [1, { at: new Date(0) }] } },
      'result.list[1].at: only plain objects are allowed'],
    [{ ...validInput(), result: { list: withHole } },
      'result.list[1]: an array must not have holes'],
    [{ ...validInput(), result: { loop } },
      'result.loop.self: a value must not hold itself'],
  ];
  for (const [input, message] of cases) {
    assert.throws(() => makeEvidence(input), { name: 'TypeError', message });
  }
});

test('makeEvidence refuses holes in limits and in coverage.not_examined', () => {
  const withHole = ['a', 'b'];
  delete withHole[0];
  assert.throws(() => makeEvidence({ ...validInput(), limits: withHole }),
    { name: 'TypeError', message: 'limits: must be an array of strings' });
  assert.throws(() => makeEvidence(withCoverage({ not_examined: withHole })),
    { name: 'TypeError', message: 'coverage.not_examined: must be an array of strings' });
});

test('the record shares no object with the input and keeps a key named __proto__', () => {
  const shared = { a: 1 };
  const input = { ...validInput(), result: { x: shared, y: shared, list: [shared] } };
  const record = makeEvidence(input);
  assert.deepStrictEqual(record.result, { x: { a: 1 }, y: { a: 1 }, list: [{ a: 1 }] });
  assert.notStrictEqual(record.result.x, shared);
  assert.notStrictEqual(record.result.list, input.result.list);
  assert.strictEqual(Object.isFrozen(shared), false);

  const parsed = JSON.parse('{"__proto__":{"x":1},"type":"text"}');
  const withKey = makeEvidence({ ...validInput(), result: parsed });
  assert.deepStrictEqual(Object.keys(withKey.result), ['__proto__', 'type']);
  assert.strictEqual(Object.getPrototypeOf(withKey.result), Object.prototype);
  assert.strictEqual(JSON.stringify(withKey.result), '{"__proto__":{"x":1},"type":"text"}');
  const { id, ...rest } = withKey;
  assert.strictEqual(id, 'ev_' + sha256Hex(canonicalJson(rest)).slice(0, 32));
});

test('TOOL_VERSION is the version in package.json', () => {
  const pkg = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  assert.strictEqual(TOOL_VERSION, pkg.version);
});

test('tool.engine keeps only name and version', () => {
  const engine = { name: 'ghidra', version: '11.0', install_dir: 'X:\\apps\\ghidra' };
  const record = makeEvidence({ ...validInput(), tool: { ...validInput().tool, engine } });
  assert.deepEqual(Object.keys(record.tool.engine), ['name', 'version']);
  assert.strictEqual(record.tool.engine.install_dir, undefined);
});
