// Command-line parsing for the helper scripts, and the one place where a command line is
// built from text (for Windows .bat launchers).

import { codedError } from './evidence.mjs';

/**
 * Parses argv (without node and script) against a fixed option table.
 * - `spec.flags`: names of options without a value, for example ['show-path', 'pretty'].
 * - `spec.values`: names of options that take the next argument as value, for example ['limit'].
 * - `--name=value` is also accepted for value options.
 * - Anything that does not start with `--` is a positional argument. A lone `--` ends the
 *   options; all later arguments are positional.
 * - An unknown option, a value option without a value, or a repeated option throws
 *   codedError('usage', message). A value option followed by an argument that starts with
 *   `--` has no value (`--limit --pretty` throws); `--name=--text` passes such a value.
 * Option names keep their dashes: result.options['show-path'] === true.
 * @param {string[]} argv
 * @param {{flags?: string[], values?: string[]}} spec
 * @returns {{positionals: string[], options: Record<string, string | boolean>}}
 */
export function parseArgs(argv, spec) {
  const flags = spec.flags ?? [];
  const values = spec.values ?? [];
  const options = {};
  const positionals = [];
  let stopParsingOptions = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];

    if (stopParsingOptions) {
      positionals.push(arg);
      continue;
    }

    if (arg === '--') {
      stopParsingOptions = true;
      continue;
    }

    if (arg.startsWith('--')) {
      const rest = arg.slice(2);
      let name, value;
      let valueProvidedByEqual = false;

      if (rest.includes('=')) {
        const index = rest.indexOf('=');
        name = rest.slice(0, index);
        value = rest.slice(index + 1);
        valueProvidedByEqual = true;
      } else {
        name = rest;
      }

      if (Object.hasOwn(options, name)) {
        throw codedError('usage', `option --${name} given twice`);
      }

      if (flags.includes(name)) {
        if (valueProvidedByEqual) {
          throw codedError('usage', `option --${name} takes no value`);
        }
        options[name] = true;
      } else if (values.includes(name)) {
        if (valueProvidedByEqual) {
          options[name] = value;
        } else {
          i++;
          if (i >= argv.length || argv[i].startsWith('--')) {
            throw codedError('usage', `option --${name} needs a value`);
          }
          options[name] = argv[i];
        }
      } else {
        throw codedError('usage', `unknown option --${name}`);
      }
    } else {
      positionals.push(arg);
    }
  }

  return { positionals, options };
}

// Characters that cmd.exe treats in a special way, plus control characters.
const UNSAFE_BAT_CHARS = /["%^&|<>!\u0000-\u001f\u007f]/;

/**
 * Builds the argument list for `cmd.exe` that runs a .bat file without a shell parse of user
 * text. Node.js refuses to start a .bat file directly when `shell` is false.
 * Refuses (throws codedError('unsafe_path', message)) any of batPath or args that holds
 * `"`, `%`, `^`, `&`, `|`, `<`, `>`, `!` or a control character. The message names the
 * position of the bad argument but does not repeat its text.
 * Returns ['/d', '/s', '/c', '"' + ['"' + batPath + '"', ...args.map(a => '"' + a + '"')]
 * .join(' ') + '"'].
 * Also refuses a value that ends with a backslash: the started program would read `\"` as a
 * quote character and merge the next arguments into it (so a drive root such as `D:\` is
 * refused too).
 * The caller runs cmd.exe by its full path, never by its bare name:
 * runProcess(windowsSystemProgram('cmd.exe'), result, { windowsVerbatimArguments: true })
 * (both from run.mjs).
 * @param {string} batPath
 * @param {string[]} args
 * @returns {string[]}
 */
export function buildWindowsBatCommand(batPath, args) {
  if (isUnsafeBatText(batPath)) {
    throw unsafeBatError(0);
  }

  const formattedArgs = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (isUnsafeBatText(arg)) {
      throw unsafeBatError(i + 1);
    }
    formattedArgs.push(arg);
  }

  const joined = ['"' + batPath + '"', ...formattedArgs.map((a) => '"' + a + '"')].join(' ');
  return ['/d', '/s', '/c', '"' + joined + '"'];
}

/**
 * True when `text` is not a string, holds a character that cmd.exe interprets, or ends with
 * a backslash.
 * @param {unknown} text
 * @returns {boolean}
 */
function isUnsafeBatText(text) {
  return typeof text !== 'string' || UNSAFE_BAT_CHARS.test(text) || text.endsWith('\\');
}

/**
 * The error for an unsafe value at position `index`. It never repeats the value.
 * @param {number} index
 * @returns {Error}
 */
function unsafeBatError(index) {
  return codedError('unsafe_path', `argument ${index} cannot be passed to the Windows launcher: `
    + 'copy the file to a path without the characters " % ^ & | < > ! and without a '
    + 'backslash at the end');
}

export { UNSAFE_BAT_CHARS };
