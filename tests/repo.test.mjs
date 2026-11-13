import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));

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

test('package.json has no dependencies of any kind', () => {
  for (const field of ['dependencies', 'devDependencies', 'optionalDependencies',
    'peerDependencies', 'bundleDependencies', 'bundledDependencies']) {
    assert.equal(pkg[field], undefined, 'package.json must not have ' + field);
  }
});

test('package.json has no install scripts', () => {
  for (const name of ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare',
    'postprepare', 'prepublish', 'prepack', 'postpack']) {
    assert.equal(pkg.scripts?.[name], undefined, 'package.json must not have script ' + name);
  }
});

test('package.json is private, an ES module package, for Node.js 22, version 0.1.0', () => {
  assert.equal(pkg.private, true);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.engines?.node, '>=22');
  assert.equal(pkg.version, '0.1.0');
  assert.equal(pkg.license, 'MIT');
});

test('npm test runs node --test', () => {
  assert.equal(typeof pkg.scripts?.test, 'string');
  assert.ok(pkg.scripts.test.startsWith('node --test'), pkg.scripts.test);
});

test('The tool version equals the package version', async () => {
  const url = pathToFileURL(path.join(ROOT, 'skills', 'rea', 'scripts', 'lib', 'evidence.mjs'));
  const { TOOL_VERSION } = await import(url.href);
  assert.equal(TOOL_VERSION, pkg.version);
});

test('Only lib/run.mjs imports the child process module', () => {
  const files = [
    ...listCode(path.join(ROOT, 'skills', 'rea', 'scripts')),
    ...listCode(path.join(ROOT, 'tools')),
  ];
  assert.ok(files.includes('skills/rea/scripts/lib/run.mjs'));
  for (const file of files) {
    if (file === 'skills/rea/scripts/lib/run.mjs') {
      continue;
    }
    const text = fs.readFileSync(path.join(ROOT, file), 'utf8');
    assert.equal(/['"](?:node:)?child_process['"]/.test(text), false,
      file + ' must start processes through lib/run.mjs');
  }
});
