// Paging and text limits, so that every answer stays small.

import { codedError } from './evidence.mjs';

export const DEFAULT_LIMIT = 100;
export const MIN_LIMIT = 1;
export const MAX_LIMIT = 1000;

/**
 * Checks a limit value. Accepts a number or a text of digits; undefined gives DEFAULT_LIMIT.
 * Throws codedError('bad_limit', ...) when it is not an integer from MIN_LIMIT to MAX_LIMIT.
 * @param {number | string | undefined} limit
 * @returns {number}
 */
export function parseLimit(limit) {
  let n;
  if (limit === undefined) {
    return DEFAULT_LIMIT;
  }
  if (typeof limit === 'string') {
    if (/^[0-9]+$/.test(limit)) {
      n = Number(limit);
    } else {
      throw codedError('bad_limit', 'limit must be a whole number from 1 to 1000');
    }
  } else if (typeof limit === 'number') {
    n = limit;
  } else {
    throw codedError('bad_limit', 'limit must be a whole number from 1 to 1000');
  }

  if (!Number.isInteger(n) || n < MIN_LIMIT || n > MAX_LIMIT) {
    throw codedError('bad_limit', 'limit must be a whole number from 1 to 1000');
  }
  return n;
}

/**
 * Checks a cursor value. A cursor is a text of digits (/^[0-9]+$/), the offset of the first
 * item. undefined gives 0. Throws codedError('bad_cursor', ...) for anything else
 * (also for a number, a negative text or an empty text).
 * @param {string | undefined} cursor
 * @returns {number}
 */
export function parseCursor(cursor) {
  if (cursor === undefined) {
    return 0;
  }
  if (typeof cursor === 'string' && /^[0-9]+$/.test(cursor)) {
    const n = Number(cursor);
    if (Number.isSafeInteger(n)) {
      return n;
    }
  }
  throw codedError('bad_cursor', 'cursor must be a text of digits');
}

/**
 * Returns one page of `items`.
 * next_cursor is String(offset + items returned) when more items follow, else null.
 * truncated is true when more items follow.
 * Throws TypeError('items must be an array') when items is not an array.
 * @param {unknown[]} items
 * @param {{limit?: number | string, cursor?: string}} [options]
 * @returns {{items: unknown[], total: number, truncated: boolean, next_cursor: string | null}}
 */
export function page(items, { limit, cursor } = {}) {
  if (!Array.isArray(items)) {
    throw new TypeError('items must be an array');
  }
  const n = parseLimit(limit);
  const offset = parseCursor(cursor);
  const slice = items.slice(offset, offset + n);
  const end = offset + slice.length;
  const more = end < items.length;
  return {
    items: slice,
    total: items.length,
    truncated: more,
    next_cursor: more ? String(end) : null,
  };
}

/**
 * Cuts text to at most `maxChars` characters (UTF-16 code units).
 * A cut never splits a surrogate pair: then the kept text ends one unit earlier.
 * Returns { text, truncated, omitted_chars }; omitted_chars is the number of UTF-16 code
 * units left out, 0 when not cut.
 * Throws codedError('bad_limit', ...) when maxChars is not an integer >= 0, and
 * TypeError('text must be a string') when text is not a string.
 * @param {string} text
 * @param {number} maxChars
 * @returns {{text: string, truncated: boolean, omitted_chars: number}}
 */
export function capText(text, maxChars) {
  if (typeof text !== 'string') {
    throw new TypeError('text must be a string');
  }
  if (!Number.isInteger(maxChars) || maxChars < 0) {
    throw codedError('bad_limit', 'maxChars must be a whole number of 0 or more');
  }
  if (text.length <= maxChars) {
    return { text, truncated: false, omitted_chars: 0 };
  }
  let end = maxChars;
  const last = text.charCodeAt(end - 1);
  const next = text.charCodeAt(end);
  if (end > 0 && last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
    end -= 1;
  }
  return {
    text: text.slice(0, end),
    truncated: true,
    omitted_chars: text.length - end,
  };
}
