// File type from the first bytes of a file. Pure function; reads no file itself.

export const HEAD_BYTES = 4096;

/**
 * Finds the file type from its first bytes.
 * Rules (first match wins, in this order): empty, elf, pe/mz, macho, macho-universal or
 * java-class (both start with ca fe ba be), zip, gzip, pdf, png, jpeg, sqlite, script, text,
 * unknown. The full table is in docs/evidence-format.md.
 * A header that is cut short never throws: the function returns the type that the available
 * bytes prove, with details.incomplete = true.
 * @param {Uint8Array} head  the first bytes of the file (up to HEAD_BYTES)
 * @param {number} fileSize  the size of the whole file in bytes
 * @returns {{type: string, details: object}}  details is {} when the type has no details
 */
export function identifyBytes(head, fileSize) {
  const b = head;

  function u16(off, little) {
    if (off + 2 > b.length) {
      return undefined;
    }
    const val = little
      ? b[off] | (b[off + 1] << 8)
      : (b[off] << 8) | b[off + 1];
    return val >>> 0;
  }

  function u32(off, little) {
    if (off + 4 > b.length) {
      return undefined;
    }
    const val = little
      ? b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)
      : (b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3];
    return val >>> 0;
  }

  // 1. empty
  if (fileSize === 0) {
    return { type: 'empty', details: {} };
  }

  // 2. elf
  const isElfMagic = b.length >= 4 &&
    b[0] === 0x7f && b[1] === 0x45 && b[2] === 0x4c && b[3] === 0x46;
  const isElfPartial = (b.length === 2 || b.length === 3) &&
    b[0] === 0x7f && b[1] === 0x45 && (b.length === 3 ? b[2] === 0x4c : true);
  if (isElfMagic || isElfPartial) {
    if (!isElfMagic) {
      return { type: 'elf', details: { incomplete: true } };
    }
    const details = {};
    if (b.length > 4) {
      if (b[4] === 1) {
        details.bits = 32;
      } else if (b[4] === 2) {
        details.bits = 64;
      }
    }

    if (b.length > 5) {
      if (b[5] === 1) {
        details.endian = 'little';
      } else if (b[5] === 2) {
        details.endian = 'big';
      }
    }

    const useLittle = details.endian !== 'big';

    const kindVal = u16(16, useLittle);
    if (kindVal !== undefined) {
      if (kindVal === 1) {
        details.kind = 'relocatable';
      } else if (kindVal === 2) {
        details.kind = 'executable';
      } else if (kindVal === 3) {
        details.kind = 'shared-object';
      } else if (kindVal === 4) {
        details.kind = 'core';
      } else {
        details.kind = `type-${kindVal}`;
      }
    }

    const machineVal = u16(18, useLittle);
    if (machineVal !== undefined) {
      if (machineVal === 3) {
        details.machine = 'x86';
      } else if (machineVal === 62) {
        details.machine = 'x86-64';
      } else if (machineVal === 40) {
        details.machine = 'arm';
      } else if (machineVal === 183) {
        details.machine = 'arm64';
      } else if (machineVal === 243) {
        details.machine = 'riscv';
      } else {
        details.machine = `machine-${machineVal}`;
      }
    }

    if (b.length < 20) {
      details.incomplete = true;
    }
    return { type: 'elf', details };
  }

  // 3. pe / mz
  if (b[0] === 0x4d && b[1] === 0x5a) {
    if (b.length < 0x40) {
      return { type: 'mz', details: { incomplete: true } };
    }
    const pe = u32(0x3c, true);
    if (pe === undefined || pe + 4 > b.length) {
      if (pe !== undefined && pe + 4 > fileSize) {
        return { type: 'mz', details: {} };
      } else {
        return { type: 'mz', details: { pe_header: 'outside the bytes read' } };
      }
    }
    if (b[pe] !== 0x50 || b[pe + 1] !== 0x45 || b[pe + 2] !== 0x00 || b[pe + 3] !== 0x00) {
      return { type: 'mz', details: {} };
    }

    const details = {};
    const machineVal = u16(pe + 4, true);
    if (machineVal !== undefined) {
      if (machineVal === 0x14c) {
        details.machine = 'x86';
      } else if (machineVal === 0x8664) {
        details.machine = 'x86-64';
      } else if (machineVal === 0x1c0) {
        details.machine = 'arm';
      } else if (machineVal === 0xaa64) {
        details.machine = 'arm64';
      } else {
        details.machine = `machine-${machineVal.toString(16)}`;
      }
    }

    const formatVal = u16(pe + 24, true);
    if (formatVal !== undefined) {
      if (formatVal === 0x10b) {
        details.format = 'PE32';
      } else if (formatVal === 0x20b) {
        details.format = 'PE32+';
      } else {
        details.format = `magic-${formatVal.toString(16)}`;
      }
    }

    const charVal = u16(pe + 22, true);
    if (charVal !== undefined) {
      details.dll = (charVal & 0x2000) !== 0;
    }

    if (machineVal === undefined || formatVal === undefined || charVal === undefined) {
      details.incomplete = true;
    }

    return { type: 'pe', details };
  }

  // 4. macho
  const isMacho = (
    (b.length >= 4 && b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa && b[3] === 0xce) ||
    (b.length >= 4 && b[0] === 0xce && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) ||
    (b.length >= 4 && b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa && b[3] === 0xcf) ||
    (b.length >= 4 && b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe)
  );

  if (isMacho) {
    const details = {};
    let bits;
    let endian;
    let little;

    if (b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa && b[3] === 0xce) {
      bits = 32;
      endian = 'big';
      little = false;
    } else if (b[0] === 0xce && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) {
      bits = 32;
      endian = 'little';
      little = true;
    } else if (b[0] === 0xfe && b[1] === 0xed && b[2] === 0xfa && b[3] === 0xcf) {
      bits = 64;
      endian = 'big';
      little = false;
    } else if (b[0] === 0xcf && b[1] === 0xfa && b[2] === 0xed && b[3] === 0xfe) {
      bits = 64;
      endian = 'little';
      little = true;
    }

    details.bits = bits;
    details.endian = endian;

    const cpuVal = u32(4, little);
    if (cpuVal !== undefined) {
      if (cpuVal === 7) {
        details.cpu = 'x86';
      } else if (cpuVal === 0x01000007) {
        details.cpu = 'x86-64';
      } else if (cpuVal === 12) {
        details.cpu = 'arm';
      } else if (cpuVal === 0x0100000c) {
        details.cpu = 'arm64';
      } else {
        details.cpu = `cpu-${cpuVal}`;
      }
    }

    const filetypeVal = u32(12, little);
    if (filetypeVal !== undefined) {
      if (filetypeVal === 1) {
        details.kind = 'object';
      } else if (filetypeVal === 2) {
        details.kind = 'executable';
      } else if (filetypeVal === 6) {
        details.kind = 'dylib';
      } else if (filetypeVal === 8) {
        details.kind = 'bundle';
      } else {
        details.kind = `filetype-${filetypeVal}`;
      }
    }

    if (cpuVal === undefined || filetypeVal === undefined) {
      details.incomplete = true;
    }
    return { type: 'macho', details };
  }

  // 5. ca fe ba be / ca fe ba bf
  if (b.length >= 4 && ((b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbe) ||
                        (b[0] === 0xca && b[1] === 0xfe && b[2] === 0xba && b[3] === 0xbf))) {
    if (b.length < 8) {
      return { type: 'unknown', details: { incomplete: true } };
    }
    const n = u32(4, false);
    if (b[3] === 0xbe && n >= 45) {
      const majorVersion = u16(6, false);
      return { type: 'java-class', details: { major_version: majorVersion } };
    }
    if (n >= 1 && n <= 30) {
      const details = { architectures: [] };
      const size = b[3] === 0xbe ? 20 : 32;
      let incomplete = false;
      for (let i = 0; i < n; i++) {
        const offset = 8 + i * size;
        const cpu = u32(offset, false);
        if (cpu === undefined) {
          incomplete = true;
          break;
        }
        if (cpu === 7) {
          details.architectures.push('x86');
        } else if (cpu === 0x01000007) {
          details.architectures.push('x86-64');
        } else if (cpu === 12) {
          details.architectures.push('arm');
        } else if (cpu === 0x0100000c) {
          details.architectures.push('arm64');
        } else {
          details.architectures.push(`cpu-${cpu}`);
        }
      }
      if (incomplete) {
        details.incomplete = true;
      }
      return { type: 'macho-universal', details };
    }
    return { type: 'unknown', details: {} };
  }

  // 6. zip
  if (b.length >= 4 && ((b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x03 && b[3] === 0x04) ||
                        (b[0] === 0x50 && b[1] === 0x4b && b[2] === 0x05 && b[3] === 0x06))) {
    return { type: 'zip', details: {} };
  }

  // 7. gzip
  if (b.length >= 2 && b[0] === 0x1f && b[1] === 0x8b) {
    return { type: 'gzip', details: {} };
  }

  // 8. pdf
  const pdfString = '%PDF-';
  if (b.length >= 5 && b.slice(0, 5).every((val, i) => val === pdfString.charCodeAt(i))) {
    return { type: 'pdf', details: {} };
  }

  // 9. png
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 &&
      b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) {
    return { type: 'png', details: {} };
  }

  // 10. jpeg
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) {
    return { type: 'jpeg', details: {} };
  }

  // 11. sqlite
  const sqlitePrefix = 'SQLite format 3';
  if (b.length >= 16 && b.slice(0, 15).every((val, i) => val === sqlitePrefix.charCodeAt(i)) &&
      b[15] === 0x00) {
    return { type: 'sqlite', details: {} };
  }

  // 12. script
  if (b.length >= 2 && b[0] === 0x23 && b[1] === 0x21) {
    const decoder = new TextDecoder('utf-8');
    let end = b.indexOf(0x0a, 2);
    if (end === -1) {
      end = b.length;
    }
    const interpreter = decoder.decode(b.subarray(2, end)).trim().slice(0, 100);
    return { type: 'script', details: { interpreter } };
  }

  // 13. text
  if (b.length > 0 && !b.includes(0)) {
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      decoder.decode(b, { stream: b.length < fileSize });
      return { type: 'text', details: {} };
    } catch (e) {
      // not text
    }
  }

  return { type: 'unknown', details: {} };
}
