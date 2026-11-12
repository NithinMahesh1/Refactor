import { test } from 'node:test';
import assert from 'node:assert/strict';
import { page, capText } from '../skills/rea/scripts/lib/limits.mjs';

test('Default limit', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  const res = page(items);
  assert.deepEqual(res.items, Array.from({ length: 100 }, (_, i) => i));
  assert.strictEqual(res.total, 250);
  assert.strictEqual(res.truncated, true);
  assert.strictEqual(res.next_cursor, '100');
});

test('Limit 1', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  const res = page(items, { limit: 1 });
  assert.deepEqual(res.items, [0]);
  assert.strictEqual(res.next_cursor, '1');
});

test('Limit 1000', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  const res1 = page(items, { limit: 1000 });
  assert.deepEqual(res1.items, items);
  assert.strictEqual(res1.truncated, false);
  assert.strictEqual(res1.next_cursor, null);

  const res2 = page(items, { limit: '1000' });
  assert.deepEqual(res2.items, items);
  assert.strictEqual(res2.truncated, false);
  assert.strictEqual(res2.next_cursor, null);
});

test('Limit 0 fails', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  assert.throws(() => page(items, { limit: 0 }), { code: 'bad_limit' });
  assert.throws(() => page(items, { limit: 1001 }), { code: 'bad_limit' });
  assert.throws(() => page(items, { limit: 'abc' }), { code: 'bad_limit' });
  assert.throws(() => page(items, { limit: 1.5 }), { code: 'bad_limit' });
  assert.throws(() => page(items, { limit: '-1' }), { code: 'bad_limit' });
});

test('Cursor in the middle', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  const res = page(items, { limit: 100, cursor: '200' });
  assert.strictEqual(res.items.length, 50);
  assert.strictEqual(res.items[0], 200);
  assert.strictEqual(res.truncated, false);
  assert.strictEqual(res.next_cursor, null);
});

test('Cursor at the end', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  const res1 = page(items, { cursor: '250' });
  assert.deepEqual(res1.items, []);
  assert.strictEqual(res1.total, 250);
  assert.strictEqual(res1.next_cursor, null);

  const res2 = page(items, { cursor: '999' });
  assert.deepEqual(res2.items, []);
  assert.strictEqual(res2.next_cursor, null);
});

test('Bad cursor fails', () => {
  const items = Array.from({ length: 250 }, (_, i) => i);
  assert.throws(() => page(items, { cursor: '-1' }), { code: 'bad_cursor' });
  assert.throws(() => page(items, { cursor: '1.5' }), { code: 'bad_cursor' });
  assert.throws(() => page(items, { cursor: 'abc' }), { code: 'bad_cursor' });
  assert.throws(() => page(items, { cursor: '' }), { code: 'bad_cursor' });
  assert.throws(() => page(items, { cursor: 5 }), { code: 'bad_cursor' });
});

test('capText under the limit', () => {
  assert.deepEqual(capText('abc', 5), { text: 'abc', truncated: false, omitted_chars: 0 });
});

test('capText at the limit', () => {
  assert.deepEqual(capText('abcde', 5), { text: 'abcde', truncated: false, omitted_chars: 0 });
});

test('capText over the limit', () => {
  assert.deepEqual(capText('abcdefg', 5), { text: 'abcde', truncated: true, omitted_chars: 2 });
});

test('capText bad maxChars', () => {
  assert.throws(() => capText('abc', -1), { code: 'bad_limit' });
  assert.throws(() => capText('abc', 1.5), { code: 'bad_limit' });
});
