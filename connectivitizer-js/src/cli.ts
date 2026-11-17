#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { ConnectivitizerError } from './core/errors.js';
import { newSharedKey } from './index.js';
import { serveMcp } from './node/mcp.js';
import { writeSecret } from './node/secretFiles.js';
import { WorkspaceTools } from './node/tools.js';

const HELP = `connectivitizer - manage a Connectivitizer workspace from the command line, or let an AI client do it

  connectivitizer login [--api <url>] [--name <name>]    sign in through the browser (an admin of the workspace approves)
  connectivitizer status | logout

  connectivitizer devices                                 the devices, their services and keys
  connectivitizer device <device> [--alias <text>] [--allow <key>,... | --allow-all]
  connectivitizer keys                                    the keys, without their secrets
  connectivitizer key create <name> --device|--app [--sessions] [--reach all|none|<device>[/<service>],...]
                             [--expires-in-days <n>] --save <file>:<NAME> [--save ...]
  connectivitizer key update <key> [--name <name>] [--sessions on|off] [--reach ...]
  connectivitizer sessions [--device <device>] [--failed] [--limit <n>]

  connectivitizer keygen [--save <file>:<NAME>]...        a new shared key (czs_...); printed when no file is named
  connectivitizer secret copy <file>:<NAME> <file>:<NAME>...

  connectivitizer mcp                                     the same as tools for an AI client (Model Context Protocol, stdio)

Keys go into the files named with --save (.h: #define, .json: property, .ps1: variable, else NAME=value)
and are not printed. Answers are JSON. --state <dir> uses another state directory than the default.`;

class Arguments {
  private readonly rest: string[];

  constructor(args: string[]) {
    this.rest = [...args];
  }

  flag(name: string): boolean {
    const at = this.rest.indexOf(name);
    if (at < 0) {
      return false;
    }
    this.rest.splice(at, 1);
    return true;
  }

  option(name: string): string | undefined {
    const at = this.rest.indexOf(name);
    if (at < 0) {
      return undefined;
    }
    const value = this.rest[at + 1];
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`${name} needs a value.`);
    }
    this.rest.splice(at, 2);
    return value;
  }

  options(name: string): string[] {
    const values: string[] = [];
    for (let value = this.option(name); value !== undefined; value = this.option(name)) {
      values.push(value);
    }
    return values;
  }

  next(what: string): string {
    const value = this.rest.shift();
    if (value === undefined || value.startsWith('--')) {
      throw new Error(`Missing: ${what}.`);
    }
    return value;
  }

  done(): void {
    if (this.rest.length > 0) {
      throw new Error(`Not understood: ${this.rest.join(' ')}`);
    }
  }
}

/** `secrets.h:DEVICE_KEY`; the name is what follows the last colon, so Windows paths work. */
function placeOf(text: string): { file: string; name: string } {
  const at = text.lastIndexOf(':');
  if (at <= 1 || at === text.length - 1) {
    throw new Error(`"${text}" must be <file>:<NAME>, for example include/secrets.h:DEVICE_KEY.`);
  }
  return { file: text.slice(0, at), name: text.slice(at + 1) };
}

function reachOf(text: string | undefined): unknown {
  if (text === undefined || text === 'all' || text === 'none') {
    return text;
  }
  return text.split(',').map((entry) => {
    const [device, service] = entry.split('/', 2);
    return service ? { device, service } : { device };
  });
}

function version(): string {
  try {
    return (JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8')) as { version: string }).version;
  } catch {
    return 'dev';
  }
}

const defined = (values: Record<string, unknown>): Record<string, unknown> => Object.fromEntries(Object.entries(values).filter(([, value]) => value !== undefined));

async function main(): Promise<number> {
  const args = new Arguments(process.argv.slice(2));
  const command = process.argv[2];
  if (command === undefined || command === 'help' || command === '--help' || command === '-h') {
    console.log(HELP);
    return 0;
  }
  args.next('command');
  const print = (value: unknown): number => {
    console.log(JSON.stringify(value, null, 2));
    return 0;
  };

  if (command === 'keygen') {
    const saves = args.options('--save').map(placeOf);
    args.done();
    const key = newSharedKey();
    if (saves.length === 0) {
      // The key is made here and printed once. It is never sent anywhere.
      console.log(key);
      return 0;
    }
    return print({ savedTo: saves.map((place) => writeSecret(place, key)) });
  }

  const stateDirectory = args.option('--state');
  const { StateDirectory } = await import('./node/state.js');
  const tools = new WorkspaceTools({ state: stateDirectory === undefined ? undefined : new StateDirectory(stateDirectory) });
  const call = async (name: string, input: Record<string, unknown>): Promise<number> => {
    args.done();
    const tool = tools.list().find((candidate) => candidate.name === name);
    if (!tool) {
      throw new Error(`No tool ${name}.`);
    }
    return print(await tool.run(defined(input)));
  };

  switch (command) {
    case 'mcp':
      args.done();
      await serveMcp(tools, version());
      // The client is gone. A sign-in that still waits for the browser must not keep the process alive.
      process.exit(0);
    case 'login': {
      const started = await tools.signIn({ apiUrl: args.option('--api'), name: args.option('--name'), again: true });
      args.done();
      if (started.waitingForApproval) {
        console.error(`Opening ${String(started.open)}\nApprove there as an admin of the workspace. The page must show the code ${String(started.code)}.`);
      }
      const outcome = await tools.waitForSignIn();
      print(outcome);
      return outcome.signedIn === true && outcome.lastSignIn === undefined ? 0 : 1;
    }
    case 'logout':
      args.done();
      return print(tools.signOut());
    case 'status':
      return call('status', {});
    case 'devices':
      return call('list_devices', {});
    case 'device': {
      const device = args.next('the device');
      const allow = args.option('--allow');
      const all = args.flag('--allow-all');
      const alias = args.option('--alias');
      if (alias === undefined && allow === undefined && !all) {
        args.done();
        return print(await tools.workspace().device(device));
      }
      return call('update_device', { device, alias, allowedKeys: all ? 'all' : allow?.split(',') });
    }
    case 'keys':
      return call('list_keys', {});
    case 'key': {
      const action = args.next('create or update');
      if (action === 'create') {
        const name = args.next('a name for the key');
        const device = args.flag('--device');
        const app = args.flag('--app');
        if (device === app) {
          throw new Error('Say which kind: --device (devices log in with it) or --app (a program that opens sessions).');
        }
        const saveTo = args.options('--save').map(placeOf);
        const reach = reachOf(args.option('--reach'));
        const days = args.option('--expires-in-days');
        return device
          ? call('create_device_key', { name, maySessions: args.flag('--sessions') || undefined, reach, saveTo })
          : call('create_api_key', { name, reach, expiresInDays: days === undefined ? undefined : Number(days), saveTo });
      }
      if (action === 'update') {
        const key = args.next('the key');
        const sessions = args.option('--sessions');
        if (sessions !== undefined && sessions !== 'on' && sessions !== 'off') {
          throw new Error('--sessions is on or off.');
        }
        return call('update_key', { key, name: args.option('--name'), maySessions: sessions === undefined ? undefined : sessions === 'on', reach: reachOf(args.option('--reach')) });
      }
      throw new Error('connectivitizer key create ... or connectivitizer key update ...');
    }
    case 'sessions': {
      const limit = args.option('--limit');
      return call('list_sessions', { device: args.option('--device'), failedOnly: args.flag('--failed') || undefined, limit: limit === undefined ? undefined : Number(limit) });
    }
    case 'secret': {
      if (args.next('copy') !== 'copy') {
        throw new Error('connectivitizer secret copy <file>:<NAME> <file>:<NAME>...');
      }
      const from = placeOf(args.next('where the secret is'));
      const to: { file: string; name: string }[] = [placeOf(args.next('where it goes'))];
      for (;;) {
        try {
          to.push(placeOf(args.next('')));
        } catch {
          break;
        }
      }
      return call('copy_secret', { from, to });
    }
    default:
      console.error(HELP);
      return 64;
  }
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(error instanceof ConnectivitizerError ? `${error.code}: ${error.message}` : error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  },
);
