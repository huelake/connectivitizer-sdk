// Putting a secret into the file a project keeps its secrets in, without showing it to whoever
// asked for that. The tools of `connectivitizer mcp` create keys this way: the key goes from the
// platform's answer into the file, and the caller learns where it is, not what it is.

import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, extname, resolve } from 'node:path';
import { ConnectivitizerError, ErrorCodes } from '../core/errors.js';

/** Where a secret lives: a file, and the name it has there. */
export interface SecretPlace {
  /** `.h`: a `#define`. `.json`: a property. `.ps1`: a variable. Anything else: a `NAME=value` line. */
  file: string;
  /** The name of the define, property or variable, e.g. `DEVICE_KEY`. */
  name: string;
}

export interface SecretWritten {
  file: string;
  name: string;
  /** Whether the file is new, the name was new in it, or an earlier value was replaced. */
  action: 'created' | 'added' | 'replaced';
  /** Set when the file is inside a git repository that does not ignore it. */
  warning?: string;
}

type Format = 'header' | 'json' | 'powershell' | 'env';

function formatOf(file: string): Format {
  switch (extname(file).toLowerCase()) {
    case '.h':
    case '.hpp':
      return 'header';
    case '.json':
      return 'json';
    case '.ps1':
      return 'powershell';
    default:
      return 'env';
  }
}

const escapeRegExp = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

function checkPlace(place: SecretPlace): void {
  if (typeof place?.file !== 'string' || place.file.trim() === '') {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A file to put the secret in is required.');
  }
  if (typeof place.name !== 'string' || !/^[A-Za-z_][A-Za-z0-9_]*$/.test(place.name)) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `"${place?.name}" is not a name a secret can have in a file: letters, digits and underscores, not starting with a digit.`);
  }
}

// The lines of a file each format recognizes as "the value of NAME".
function linePattern(format: Exclude<Format, 'json'>, name: string): RegExp {
  const escaped = escapeRegExp(name);
  switch (format) {
    case 'header':
      return new RegExp(`^([ \\t]*#[ \\t]*define[ \\t]+${escaped})(?![A-Za-z0-9_]).*$`, 'm');
    case 'powershell':
      return new RegExp(`^([ \\t]*\\$${escaped})[ \\t]*=.*$`, 'mi');
    case 'env':
      return new RegExp(`^([ \\t]*(?:export[ \\t]+)?${escaped})=.*$`, 'm');
  }
}

function lineFor(format: Exclude<Format, 'json'>, start: string, value: string): string {
  switch (format) {
    case 'header':
      return `${start} "${value}"`;
    case 'powershell':
      return `${start} = '${value}'`;
    case 'env':
      return `${start}=${value}`;
  }
}

function freshLine(format: Exclude<Format, 'json'>, name: string, value: string): string {
  return lineFor(format, format === 'header' ? `#define ${name}` : format === 'powershell' ? `$${name}` : name, value);
}

/** The keys this package handles contain none of the characters that would need escaping in these files. */
function checkValue(value: string): void {
  if (!/^[A-Za-z0-9_\-.:/+=]+$/.test(value)) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'The secret contains characters that cannot be written to a secrets file safely.');
  }
}

function gitWarning(file: string): string | undefined {
  try {
    const directory = dirname(file);
    const inside = spawnSync('git', ['-C', directory, 'rev-parse', '--is-inside-work-tree'], { encoding: 'utf8', windowsHide: true });
    if (inside.status !== 0 || inside.stdout.trim() !== 'true') {
      return undefined;
    }
    const ignored = spawnSync('git', ['-C', directory, 'check-ignore', '-q', file], { windowsHide: true });
    return ignored.status === 1 ? 'This file is inside a git repository and not ignored by it. Add it to .gitignore before committing.' : undefined;
  } catch {
    return undefined;
  }
}

/** Throws when `place` cannot take a secret: a name that does not fit, or a JSON file that is no object. */
export function checkSecretPlace(place: SecretPlace, cwd = process.cwd()): void {
  checkPlace(place);
  const file = resolve(cwd, place.file);
  if (formatOf(file) === 'json' && existsSync(file)) {
    const content = readFileSync(file, 'utf8').replace(/^﻿/, '');
    let parsed: unknown = {};
    try {
      parsed = content.trim() === '' ? {} : JSON.parse(content);
    } catch {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `${file} is not valid JSON.`);
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `${file} is not a JSON object.`);
    }
  }
}

/** Reads the value `name` has in `file`. Throws when the file or the name is not there. */
export function readSecret(place: SecretPlace, cwd = process.cwd()): string {
  checkPlace(place);
  const file = resolve(cwd, place.file);
  if (!existsSync(file)) {
    throw new ConnectivitizerError(ErrorCodes.NotFound, `There is no file ${file}.`);
  }
  const text = readFileSync(file, 'utf8').replace(/^﻿/, '');
  const format = formatOf(file);
  let value: unknown;
  if (format === 'json') {
    value = (JSON.parse(text) as Record<string, unknown>)[place.name];
  } else {
    const line = linePattern(format, place.name).exec(text)?.[0];
    const rest = line === undefined ? undefined : format === 'header' ? line.replace(/^[ \t]*#[ \t]*define[ \t]+\S+/, '') : line.slice(line.indexOf('=') + 1);
    // The value up to a comment, without its quotes.
    value = rest === undefined ? undefined : /^\s*(?:"([^"]*)"|'([^']*)'|([^\s#;/]+))/.exec(rest)?.slice(1).find((part) => part !== undefined);
  }
  if (typeof value !== 'string' || value === '') {
    throw new ConnectivitizerError(ErrorCodes.NotFound, `${file} has no value for ${place.name}.`);
  }
  return value;
}

/**
 * Writes `value` under `name` into `file`, replacing an earlier value of that name and leaving
 * everything else in the file as it is. The file is created when it is missing.
 */
export function writeSecret(place: SecretPlace, value: string, cwd = process.cwd()): SecretWritten {
  checkPlace(place);
  checkValue(value);
  const file = resolve(cwd, place.file);
  const format = formatOf(file);
  const existed = existsSync(file);
  const before = existed ? readFileSync(file, 'utf8') : '';
  let after: string;
  let action: SecretWritten['action'] = existed ? 'added' : 'created';

  if (format === 'json') {
    let content: Record<string, unknown> = {};
    if (before.trim() !== '') {
      const parsed: unknown = JSON.parse(before.replace(/^﻿/, ''));
      if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `${file} is not a JSON object.`);
      }
      content = parsed as Record<string, unknown>;
    }
    if (place.name in content) {
      action = 'replaced';
    }
    content[place.name] = value;
    after = JSON.stringify(content, null, 2) + '\n';
  } else {
    const pattern = linePattern(format, place.name);
    const eol = before.includes('\r\n') ? '\r\n' : '\n';
    if (pattern.test(before)) {
      action = 'replaced';
      after = before.replace(pattern, (_line, start: string) => lineFor(format, start, value));
    } else {
      after = before + (before === '' || before.endsWith('\n') ? '' : eol) + freshLine(format, place.name, value) + eol;
    }
  }

  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, after);
  if (!existed && process.platform !== 'win32') {
    chmodSync(file, 0o600);
  }
  const warning = gitWarning(file);
  return { file, name: place.name, action, ...(warning ? { warning } : {}) };
}

/** Copies a secret from one file to others without it passing through the caller. */
export function copySecret(from: SecretPlace, to: readonly SecretPlace[], cwd = process.cwd()): SecretWritten[] {
  const value = readSecret(from, cwd);
  return to.map((place) => writeSecret(place, value, cwd));
}
