// Evidence records, error records and canonical JSON.
// See docs/evidence-format.md for the meaning of each field.

import { createHash } from 'node:crypto';

export const EVIDENCE_SCHEMA = 'refactor.evidence/1';
export const ERROR_SCHEMA = 'refactor.error/1';
export const TOOL_VERSION = '0.1.0';
export const CONFIDENCE_LEVELS = Object.freeze(['observed', 'derived', 'inferred']);

/**
 * Makes an Error that carries a machine-readable `code` (and optional `details`).
 * Every module uses this for errors that a script turns into an error record.
 * @param {string} code
 * @param {string} message
 * @param {object} [details]
 * @returns {Error & {code: string, details?: object}}
 */
export function codedError(code, message, details) {
  const error = new Error(message);
  error.code = code;
  if (details !== undefined) {
    error.details = details;
  }
  return error;
}

/**
 * Returns JSON text with object keys sorted by code point at every level, arrays in their
 * order, and no white space.
 * Throws TypeError for `undefined`, functions, symbols, bigints and numbers that are not finite
 * (also when they are inside an object or an array).
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null) {
    return 'null';
  }
  const type = typeof value;
  if (type === 'boolean' || type === 'string') {
    return JSON.stringify(value);
  }
  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('canonicalJson: number is not finite');
    }
    return JSON.stringify(value);
  }
  if (type === 'undefined' || type === 'function' || type === 'symbol' || type === 'bigint') {
    throw new TypeError(`canonicalJson: ${type} is not allowed`);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalJson(v)).join(',') + ']';
  }
  if (type === 'object') {
    const keys = Object.keys(value).sort();
    return '{' + keys.map((k) => {
      const keyStr = JSON.stringify(k);
      return `${keyStr}:${canonicalJson(value[k])}`;
    }).join(',') + '}';
  }
  throw new TypeError('canonicalJson: unsupported type');
}

/**
 * Builds a frozen (deeply frozen) Evidence record and computes its `id`.
 * Validation (each failure throws TypeError whose message starts with the field name,
 * for example "subject.sha256: must be 64 lower-case hex characters"):
 * - subject: object; subject.name non-empty string; subject.sha256 /^[0-9a-f]{64}$/;
 *   subject.size_bytes integer >= 0; subject.path optional string (kept only when present).
 * - tool: object; tool.name non-empty string; tool.version non-empty string;
 *   tool.engine null or {name: non-empty string, version: string}. A missing engine becomes null.
 * - operation: non-empty string.
 * - parameters: plain object (default {}).
 * - confidence: one of CONFIDENCE_LEVELS.
 * - result: plain object.
 * - coverage: object; coverage.examined string; coverage.not_examined array of strings;
 *   coverage.truncated boolean (default false); coverage.next_cursor string or null (default null).
 * - limits: array of strings (default []).
 * Key order of the returned object: schema, id, subject, tool, operation, parameters,
 * confidence, result, coverage, limits.
 * id = 'ev_' + first 32 hex characters of sha256(canonicalJson(record without id)).
 * @param {object} input
 * @returns {Readonly<object>}
 */
export function makeEvidence({
  subject,
  tool,
  operation,
  parameters = {},
  confidence,
  result,
  coverage = {},
  limits = [],
} = {}) {
  const isPlainObject = (obj) => typeof obj === 'object' && obj !== null && !Array.isArray(obj);

  const coverageDefault = {
    examined: undefined,
    not_examined: [],
    truncated: false,
    next_cursor: null,
  };
  const finalCoverage = { ...coverageDefault, ...coverage };
  const finalTool = { ...tool, engine: tool?.engine ?? null };

  // subject validation
  if (!isPlainObject(subject)) {
    throw new TypeError('subject: must be a plain object');
  }
  if (typeof subject.name !== 'string' || subject.name === '') {
    throw new TypeError('subject.name: must be a non-empty string');
  }
  if (typeof subject.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(subject.sha256)) {
    throw new TypeError('subject.sha256: must be 64 lower-case hex characters');
  }
  if (!Number.isInteger(subject.size_bytes) || subject.size_bytes < 0) {
    throw new TypeError('subject.size_bytes: must be an integer >= 0');
  }
  if (subject.path !== undefined && typeof subject.path !== 'string') {
    throw new TypeError('subject.path: must be a string');
  }

  // tool validation
  if (!isPlainObject(tool)) {
    throw new TypeError('tool: must be a plain object');
  }
  if (typeof tool.name !== 'string' || tool.name === '') {
    throw new TypeError('tool.name: must be a non-empty string');
  }
  if (typeof tool.version !== 'string' || tool.version === '') {
    throw new TypeError('tool.version: must be a non-empty string');
  }
  if (finalTool.engine !== null) {
    if (!isPlainObject(finalTool.engine)) {
      throw new TypeError('tool.engine: must be a plain object or null');
    }
    if (typeof finalTool.engine.name !== 'string' || finalTool.engine.name === '') {
      throw new TypeError('tool.engine.name: must be a non-empty string');
    }
    if (typeof finalTool.engine.version !== 'string') {
      throw new TypeError('tool.engine.version: must be a string');
    }
  }

  // operation validation
  if (typeof operation !== 'string' || operation === '') {
    throw new TypeError('operation: must be a non-empty string');
  }

  // parameters validation
  if (!isPlainObject(parameters)) {
    throw new TypeError('parameters: must be a plain object');
  }

  // confidence validation
  if (!CONFIDENCE_LEVELS.includes(confidence)) {
    throw new TypeError('confidence: must be one of observed, derived, inferred');
  }

  // result validation
  if (!isPlainObject(result)) {
    throw new TypeError('result: must be a plain object');
  }

  // coverage validation
  if (!isPlainObject(finalCoverage)) {
    throw new TypeError('coverage: must be a plain object');
  }
  if (typeof finalCoverage.examined !== 'string' || finalCoverage.examined === '') {
    throw new TypeError('coverage.examined: must be a non-empty string');
  }
  if (!Array.isArray(finalCoverage.not_examined) ||
    !finalCoverage.not_examined.every((i) => typeof i === 'string')) {
    throw new TypeError('coverage.not_examined: must be an array of strings');
  }
  if (typeof finalCoverage.truncated !== 'boolean') {
    throw new TypeError('coverage.truncated: must be a boolean');
  }
  if (finalCoverage.next_cursor !== null && typeof finalCoverage.next_cursor !== 'string') {
    throw new TypeError('coverage.next_cursor: must be a string or null');
  }

  // limits validation
  if (!Array.isArray(limits) || !limits.every((i) => typeof i === 'string')) {
    throw new TypeError('limits: must be an array of strings');
  }

  const recordWithoutId = {
    schema: EVIDENCE_SCHEMA,
    subject: {
      name: subject.name,
      sha256: subject.sha256,
      size_bytes: subject.size_bytes,
      ...(subject.path === undefined ? {} : { path: subject.path }),
    },
    tool: {
      name: finalTool.name,
      version: finalTool.version,
      engine: structuredClone(finalTool.engine),
    },
    operation,
    parameters: structuredClone(parameters),
    confidence,
    result: structuredClone(result),
    coverage: {
      examined: finalCoverage.examined,
      not_examined: [...finalCoverage.not_examined],
      truncated: finalCoverage.truncated,
      next_cursor: finalCoverage.next_cursor,
    },
    limits: structuredClone(limits),
  };

  const id = 'ev_' + sha256Hex(canonicalJson(recordWithoutId)).slice(0, 32);

  const record = {
    schema: EVIDENCE_SCHEMA,
    id,
    subject: recordWithoutId.subject,
    tool: recordWithoutId.tool,
    operation: recordWithoutId.operation,
    parameters: recordWithoutId.parameters,
    confidence: recordWithoutId.confidence,
    result: recordWithoutId.result,
    coverage: recordWithoutId.coverage,
    limits: recordWithoutId.limits,
  };

  function deepFreeze(obj) {
    Object.freeze(obj);
    Object.getOwnPropertyNames(obj).forEach((prop) => {
      if (
        Object.prototype.hasOwnProperty.call(obj, prop) &&
        obj[prop] !== null &&
        (typeof obj[prop] === 'object' || typeof obj[prop] === 'function') &&
        !Object.isFrozen(obj[prop])
      ) {
        deepFreeze(obj[prop]);
      }
    });
  }

  deepFreeze(record);

  return record;
}

/**
 * Builds an error record: { schema: 'refactor.error/1', error: { code, message, details } }.
 * `details` is left out when it is undefined.
 * @param {string} code
 * @param {string} message
 * @param {object} [details]
 * @returns {object}
 */
export function makeError(code, message, details) {
  const error = { code, message };
  if (details !== undefined) {
    error.details = details;
  }
  return {
    schema: ERROR_SCHEMA,
    error,
  };
}

/**
 * Hex SHA-256 of a string or buffer. Helper for tests and callers.
 * @param {string | Uint8Array} data
 * @returns {string}
 */
export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}
