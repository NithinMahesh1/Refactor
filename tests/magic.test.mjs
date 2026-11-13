import { test } from 'node:test';
import assert from 'node:assert/strict';
import { identifyBytes } from '../skills/rea/scripts/lib/magic.mjs';

test('empty', () => {
  assert.deepEqual(identifyBytes(Buffer.alloc(0), 0), { type: 'empty', details: {} });
});

test('ELF 64-bit little-endian x86-64 executable', () => {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 2;
  buf[5] = 1;
  buf.writeUInt16LE(2, 16);
  buf.writeUInt16LE(62, 18);
  assert.deepEqual(identifyBytes(buf, 64), {
    type: 'elf',
    details: { bits: 64, endian: 'little', kind: 'executable', machine: 'x86-64' }
  });
});

test('ELF 32-bit big-endian', () => {
  const buf = Buffer.alloc(52);
  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 1;
  buf[5] = 2;
  buf.writeUInt16BE(3, 16);
  buf.writeUInt16BE(40, 18);
  assert.deepEqual(identifyBytes(buf, 52), {
    type: 'elf',
    details: { bits: 32, endian: 'big', kind: 'shared-object', machine: 'arm' }
  });
});

test('ELF other machine', () => {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 2;
  buf[5] = 1;
  buf.writeUInt16LE(2, 16);
  buf.writeUInt16LE(999, 18);
  assert.deepEqual(identifyBytes(buf, 64), {
    type: 'elf',
    details: { bits: 64, endian: 'little', kind: 'executable', machine: 'machine-999' }
  });
});

test('A 3-byte ELF start', () => {
  const buf = Buffer.from([0x7f, 0x45, 0x4c]);
  assert.deepEqual(identifyBytes(buf, 3), { type: 'elf', details: { incomplete: true } });
});

test('ELF cut after 10 bytes', () => {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 2;
  buf[5] = 1;
  buf.writeUInt16LE(2, 16);
  buf.writeUInt16LE(62, 18);
  assert.deepEqual(identifyBytes(buf.subarray(0, 10), 64), {
    type: 'elf',
    details: { bits: 64, endian: 'little', incomplete: true }
  });
});

test('PE32+ x86-64 DLL', () => {
  const buf = Buffer.alloc(512);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.set([0x50, 0x45, 0x00, 0x00], 0x80);
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(0x2022, 0x96);
  buf.writeUInt16LE(0x20b, 0x98);
  assert.deepEqual(identifyBytes(buf, 512), {
    type: 'pe',
    details: { machine: 'x86-64', format: 'PE32+', dll: true }
  });
});

test('PE32 x86 program', () => {
  const buf = Buffer.alloc(512);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.set([0x50, 0x45, 0x00, 0x00], 0x80);
  buf.writeUInt16LE(0x14c, 0x84);
  buf.writeUInt16LE(0x0102, 0x96);
  buf.writeUInt16LE(0x10b, 0x98);
  assert.deepEqual(identifyBytes(buf, 512), {
    type: 'pe',
    details: { machine: 'x86', format: 'PE32', dll: false }
  });
});

test('PE header outside the bytes read', () => {
  const buf = Buffer.alloc(128);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x2000, 0x3c);
  assert.deepEqual(identifyBytes(buf, 100000), {
    type: 'mz',
    details: { pe_header: 'outside the bytes read' }
  });
});

test('mz without PE', () => {
  const buf = Buffer.alloc(128);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x40, 0x3c);
  // bytes at 0x40 are zero by default
  assert.deepEqual(identifyBytes(buf, 128), { type: 'mz', details: {} });
});

test('Mach-O 64-bit arm64 dylib', () => {
  const buf = Buffer.alloc(32);
  buf.set([0xcf, 0xfa, 0xed, 0xfe], 0);
  buf.writeUInt32LE(0x0100000c, 4);
  buf.writeUInt32LE(6, 12);
  assert.deepEqual(identifyBytes(buf, 32), {
    type: 'macho',
    details: { bits: 64, endian: 'little', cpu: 'arm64', kind: 'dylib' }
  });
});

test('Mach-O 32-bit big-endian x86 executable', () => {
  const buf = Buffer.alloc(28);
  buf.set([0xfe, 0xed, 0xfa, 0xce], 0);
  buf.writeUInt32BE(7, 4);
  buf.writeUInt32BE(2, 12);
  assert.deepEqual(identifyBytes(buf, 28), {
    type: 'macho',
    details: { bits: 32, endian: 'big', cpu: 'x86', kind: 'executable' }
  });
});

test('Universal with 2 architectures', () => {
  const buf = Buffer.alloc(48);
  buf.set([0xca, 0xfe, 0xba, 0xbe], 0);
  buf.writeUInt32BE(2, 4);
  buf.writeUInt32BE(0x01000007, 8);
  buf.writeUInt32BE(0x0100000c, 28);
  assert.deepEqual(identifyBytes(buf, 48), {
    type: 'macho-universal',
    details: { architectures: ['x86-64', 'arm64'] }
  });
});

test('Universal 64 (ca fe ba bf) with 1 entry', () => {
  const buf = Buffer.alloc(40);
  buf.set([0xca, 0xfe, 0xba, 0xbf], 0);
  buf.writeUInt32BE(1, 4);
  buf.writeUInt32BE(12, 8);
  assert.deepEqual(identifyBytes(buf, 40), {
    type: 'macho-universal',
    details: { architectures: ['arm'] }
  });
});

test('Java class major version 61', () => {
  const buf = Buffer.alloc(16);
  buf.set([0xca, 0xfe, 0xba, 0xbe], 0);
  buf.writeUInt16BE(0, 4);
  buf.writeUInt16BE(61, 6);
  assert.deepEqual(identifyBytes(buf, 16), {
    type: 'java-class',
    details: { major_version: 61 }
  });
});

test('zip', () => {
  assert.deepEqual(
    identifyBytes(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0, 0]), 6),
    { type: 'zip', details: {} }
  );
  assert.deepEqual(
    identifyBytes(Buffer.from([0x50, 0x4b, 0x05, 0x06, 0, 0]), 6),
    { type: 'zip', details: {} }
  );
});

test('gzip', () => {
  assert.deepEqual(
    identifyBytes(Buffer.from([0x1f, 0x8b, 0x08, 0]), 4),
    { type: 'gzip', details: {} }
  );
});

test('pdf', () => {
  assert.deepEqual(
    identifyBytes(Buffer.from('%PDF-1.7\n'), 9),
    { type: 'pdf', details: {} }
  );
});

test('png', () => {
  assert.deepEqual(
    identifyBytes(
      Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0]),
      10
    ),
    { type: 'png', details: {} }
  );
});

test('jpeg', () => {
  assert.deepEqual(identifyBytes(Buffer.from([0xff, 0xd8, 0xff, 0xe0]), 4), {
    type: 'jpeg',
    details: {}
  });
});

test('sqlite', () => {
  const buf = Buffer.concat([
    Buffer.from('SQLite format 3'),
    Buffer.from([0]),
    Buffer.alloc(84)
  ]);
  assert.deepEqual(identifyBytes(buf, buf.length), { type: 'sqlite', details: {} });
});

test('script', () => {
  const buf = Buffer.from('#!/usr/bin/env node  \nconsole.log(1)\n');
  assert.deepEqual(identifyBytes(buf, buf.length), {
    type: 'script',
    details: { interpreter: '/usr/bin/env node' }
  });
});

test('script interpreter is cut at 100 characters', () => {
  const buf = Buffer.from('#!' + 'a'.repeat(150) + '\n');
  assert.deepEqual(identifyBytes(buf, buf.length), {
    type: 'script',
    details: { interpreter: 'a'.repeat(100) }
  });
});

test('text', () => {
  assert.deepEqual(identifyBytes(Buffer.from('hello, world\n'), 13), {
    type: 'text',
    details: {}
  });
});

test('text with a character cut at the end', () => {
  assert.deepEqual(
    identifyBytes(Buffer.from('héllo').subarray(0, 2), 6),
    { type: 'text', details: {} }
  );
});

test('unknown (zero byte)', () => {
  assert.deepEqual(identifyBytes(Buffer.from([0x01, 0x00, 0x02]), 3), {
    type: 'unknown',
    details: {}
  });
});

test('unknown (bad UTF-8)', () => {
  assert.deepEqual(identifyBytes(Buffer.from([0xc3, 0x28]), 2), {
    type: 'unknown',
    details: {}
  });
});

test('2 bytes of an ELF start are not an ELF file', () => {
  for (const fileSize of [2, 64]) {
    assert.deepEqual(identifyBytes(Buffer.from([0x7f, 0x45]), fileSize),
      { type: 'text', details: {} });
  }
});

test('ELF with an unknown byte order has no kind and no machine', () => {
  const buf = Buffer.alloc(64);
  buf.set([0x7f, 0x45, 0x4c, 0x46], 0);
  buf[4] = 2;
  buf[5] = 3;
  buf.writeUInt16LE(2, 16);
  buf.writeUInt16LE(62, 18);
  assert.deepEqual(identifyBytes(buf, 64), { type: 'elf', details: { bits: 64 } });
});

test('script interpreter shows control characters as U+FFFD', () => {
  const R = String.fromCharCode(0xfffd);
  const buf = Buffer.from('#!/usr/bin/env\u0007 node\u001b[0m\u007f\u009b\r\n');
  assert.deepEqual(identifyBytes(buf, buf.length), {
    type: 'script',
    details: { interpreter: '/usr/bin/env' + R + ' node' + R + '[0m' + R + R }
  });
});

test('script interpreter cut never splits a character', () => {
  const buf = Buffer.from('#!' + 'a'.repeat(99) + '\u{1f600}b\n');
  assert.deepEqual(identifyBytes(buf, buf.length), {
    type: 'script',
    details: { interpreter: 'a'.repeat(99) + '\u{1f600}' }
  });
});

test('cut MZ header', () => {
  for (const len of [2, 0x3f]) {
    const buf = Buffer.alloc(len);
    buf.set([0x4d, 0x5a], 0);
    assert.deepEqual(identifyBytes(buf, 1000), { type: 'mz', details: { incomplete: true } });
  }
});

test('cut PE header', () => {
  const buf = Buffer.alloc(512);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.set([0x50, 0x45, 0x00, 0x00], 0x80);
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(0x2022, 0x96);
  buf.writeUInt16LE(0x20b, 0x98);
  assert.deepEqual(identifyBytes(buf.subarray(0, 0x84), 512),
    { type: 'pe', details: { incomplete: true } });
  assert.deepEqual(identifyBytes(buf.subarray(0, 0x86), 512),
    { type: 'pe', details: { machine: 'x86-64', incomplete: true } });
  assert.deepEqual(identifyBytes(buf.subarray(0, 0x98), 512),
    { type: 'pe', details: { machine: 'x86-64', dll: true, incomplete: true } });
  assert.deepEqual(identifyBytes(buf.subarray(0, 0x82), 512),
    { type: 'mz', details: { pe_header: 'outside the bytes read' } });
});

test('cut Mach-O header', () => {
  const buf = Buffer.alloc(32);
  buf.set([0xcf, 0xfa, 0xed, 0xfe], 0);
  buf.writeUInt32LE(0x0100000c, 4);
  buf.writeUInt32LE(6, 12);
  assert.deepEqual(identifyBytes(buf.subarray(0, 4), 32),
    { type: 'macho', details: { bits: 64, endian: 'little', incomplete: true } });
  assert.deepEqual(identifyBytes(buf.subarray(0, 8), 32), {
    type: 'macho',
    details: { bits: 64, endian: 'little', cpu: 'arm64', incomplete: true }
  });
});

test('cut universal header', () => {
  const buf = Buffer.alloc(48);
  buf.set([0xca, 0xfe, 0xba, 0xbe], 0);
  buf.writeUInt32BE(2, 4);
  buf.writeUInt32BE(0x01000007, 8);
  buf.writeUInt32BE(0x0100000c, 28);
  assert.deepEqual(identifyBytes(buf.subarray(0, 28), 48), {
    type: 'macho-universal',
    details: { architectures: ['x86-64'], incomplete: true }
  });
  assert.deepEqual(identifyBytes(buf.subarray(0, 6), 48),
    { type: 'unknown', details: { incomplete: true } });
});

test('Mach-O CPU names are the same in both formats', () => {
  const cpus = [7, 0x01000007, 12, 0x0100000c, 99];
  const names = ['x86', 'x86-64', 'arm', 'arm64', 'cpu-99'];
  const fat = Buffer.alloc(8 + cpus.length * 20);
  fat.set([0xca, 0xfe, 0xba, 0xbe], 0);
  fat.writeUInt32BE(cpus.length, 4);
  cpus.forEach((cpu, i) => {
    fat.writeUInt32BE(cpu, 8 + i * 20);
  });
  assert.deepEqual(identifyBytes(fat, fat.length),
    { type: 'macho-universal', details: { architectures: names } });
  cpus.forEach((cpu, i) => {
    const thin = Buffer.alloc(28);
    thin.set([0xfe, 0xed, 0xfa, 0xce], 0);
    thin.writeUInt32BE(cpu, 4);
    thin.writeUInt32BE(2, 12);
    assert.strictEqual(identifyBytes(thin, 28).details.cpu, names[i]);
  });
});

test('A cut header never throws', () => {
  const buf = Buffer.alloc(512);
  buf.set([0x4d, 0x5a], 0);
  buf.writeUInt32LE(0x80, 0x3c);
  buf.set([0x50, 0x45, 0x00, 0x00], 0x80);
  buf.writeUInt16LE(0x8664, 0x84);
  buf.writeUInt16LE(0x2022, 0x96);
  buf.writeUInt16LE(0x20b, 0x98);

  for (let len = 0; len <= 64; len++) {
    const res = identifyBytes(buf.subarray(0, len), 512);
    assert.strictEqual(typeof res.type, 'string');
    assert.strictEqual(typeof res.details, 'object');
  }
});
