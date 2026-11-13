import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

/**
 * Lists every .mjs, .js and .cjs file under `dir`, recursively, as paths relative to ROOT
 * written with '/'.
 * @param {string} dir
 * @returns {string[]}
 */
function listCode(dir) {
  const found = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      found.push(...listCode(full));
    } else if (/\.(?:mjs|js|cjs)$/.test(entry.name)) {
      found.push(path.relative(ROOT, full).split(path.sep).join('/'));
    }
  }
  return found;
}

const FILES = [
  ...listCode(path.join(ROOT, 'skills', 'rea', 'scripts')),
  ...listCode(path.join(ROOT, 'tools')),
];

// The patterns are built from parts, so that this file holds no import of a network module.
const NETWORK_MODULES = ['http', 'https', 'http2', 'net', 'tls', 'dgram'];
const IMPORT_PATTERNS = NETWORK_MODULES.map((name) => ({
  name,
  pattern: new RegExp('(?:\\bfrom|\\bimport|\\brequire)\\s*\\(?\\s*[\'"](?:node:)?'
    + name + '[\'"]'),
}));
const FETCH_PATTERN = /\bfetch\s*\(/;
const WEBSOCKET_PATTERN = /\bWebSocket\b/;

/**
 * Names of the network modules whose import pattern matches `text`.
 * @param {string} text
 * @returns {string[]}
 */
function importedNetworkModules(text) {
  return IMPORT_PATTERNS.filter(({ pattern }) => pattern.test(text)).map(({ name }) => name);
}

test('The scan covers the scripts and the tools', () => {
  assert.ok(FILES.includes('skills/rea/scripts/lib/run.mjs'), 'lib/run.mjs is not in the list');
  assert.ok(FILES.includes('tools/check-leaks.mjs'), 'tools/check-leaks.mjs is not in the list');
});

test('No script or tool imports a network module', () => {
  for (const file of FILES) {
    const text = fs.readFileSync(path.join(ROOT, file), 'utf8');
    assert.deepEqual(importedNetworkModules(text), [], file + ' imports a network module');
  }
});

test('No script or tool calls fetch or uses WebSocket', () => {
  for (const file of FILES) {
    const text = fs.readFileSync(path.join(ROOT, file), 'utf8');
    assert.equal(FETCH_PATTERN.test(text), false, file + ' calls fetch');
    assert.equal(WEBSOCKET_PATTERN.test(text), false, file + ' uses WebSocket');
  }
});

test('The patterns find each form of a network import', () => {
  const q = '\'';
  assert.deepEqual(importedNetworkModules('import x from ' + q + 'node:net' + q + ';'), ['net']);
  assert.deepEqual(importedNetworkModules('import ' + q + 'node:tls' + q + ';'), ['tls']);
  assert.deepEqual(importedNetworkModules('const h = require(' + q + 'https' + q + ');'),
    ['https']);
  assert.deepEqual(importedNetworkModules('await import(' + q + 'node:http2' + q + ')'),
    ['http2']);
  assert.deepEqual(importedNetworkModules('import { createSocket } from "dgram";'), ['dgram']);
  assert.deepEqual(importedNetworkModules('import { spawn } from ' + q + 'node:child_process'
    + q + ';'), []);
  assert.deepEqual(importedNetworkModules('import fs from ' + q + 'node:fs' + q + ';'), []);
  assert.equal(FETCH_PATTERN.test('const r = await fetch(url);'), true);
  assert.equal(FETCH_PATTERN.test('const prefetch = 1;'), false);
  assert.equal(WEBSOCKET_PATTERN.test('new WebSocket(url)'), true);
});
