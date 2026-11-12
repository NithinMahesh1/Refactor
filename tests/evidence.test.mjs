import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  makeEvidence, canonicalJson, makeError, sha256Hex,
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
});

test('makeEvidence id consistency and format', () => {
  const id1 = makeEvidence(validInput()).id;
  const id2 = makeEvidence(validInput()).id;
  assert.strictEqual(id1, id2);
  assert.match(id1, /^ev_[0-9a-f]{32}$/);
});

test('makeEvidence id changes when fields change', () => {
  const baseId = makeEvidence(validInput()).id;

  assert.notStrictEqual(withSubject({ name: 'other.bin' }).id, baseId);
  assert.notStrictEqual(withSubject({ sha256: 'b'.repeat(64) }).id, baseId);
  assert.notStrictEqual(withSubject({ size_bytes: 11 }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), operation: 'other' }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), parameters: { x: 2 } }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), confidence: 'derived' }).id, baseId);
  assert.notStrictEqual(makeEvidence({ ...validInput(), result: { type: 'elf' } }).id, baseId);
  assert.notStrictEqual(
    makeEvidence({ ...validInput(), coverage: { ...validInput().coverage, examined: 'part' } }).id,
    baseId
  );
  assert.notStrictEqual(makeEvidence({ ...validInput(), limits: [] }).id, baseId);
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
