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
 *   codedError('usage', message).
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

      if (name in options) {
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
          if (i >= argv.length) {
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
 * The caller runs: spawn('cmd.exe', result, { windowsVerbatimArguments: true }).
 * @param {string} batPath
 * @param {string[]} args
 * @returns {string[]}
 */
export function buildWindowsBatCommand(batPath, args) {
  if (typeof batPath !== 'string' || UNSAFE_BAT_CHARS.test(batPath)) {
    throw codedError('unsafe_path', 'argument 0 holds a character that cmd.exe would interpret');
  }

  const formattedArgs = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (typeof arg !== 'string' || UNSAFE_BAT_CHARS.test(arg)) {
      throw codedError('unsafe_path',
        `argument ${i + 1} holds a character that cmd.exe would interpret`);
    }
    formattedArgs.push(arg);
  }

  const joined = ['"' + batPath + '"', ...formattedArgs.map((a) => '"' + a + '"')].join(' ');
  return ['/d', '/s', '/c', '"' + joined + '"'];
}

export { UNSAFE_BAT_CHARS };
