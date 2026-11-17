// What `connectivitizer mcp` offers an AI client, and what the same commands of the command line
// do. Every tool answers with plain data. None of them returns a key: keys are written to the
// files the caller names.

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { type LinkPrompt, linkWith } from '../core/link.js';
import { ConnectivitizerError, ErrorCodes } from '../core/errors.js';
import { generateSharedKey } from '../core/noise.js';
import type { Platform } from '../core/platform.js';
import { nodePlatform } from './platform.js';
import { type SecretPlace, type SecretWritten, checkSecretPlace, copySecret, writeSecret } from './secretFiles.js';
import { StateDirectory, type WorkspaceLogin } from './state.js';
import { type Reach, Workspace } from './workspace.js';

export const DEFAULT_API_URL = 'https://api.connectivitizer.com/api/connectivitizer';

type Json = Record<string, unknown>;

export interface Tool {
  name: string;
  description: string;
  /** JSON Schema of the arguments. */
  inputSchema: Json;
  run(args: Json): Promise<unknown>;
}

export interface ToolsOptions {
  state?: StateDirectory;
  platform?: Platform;
  /** The API to sign in to when the caller names none. */
  apiUrl?: string;
  /** Relative paths of secrets files are resolved against this directory. */
  cwd?: string;
  /** Opens the sign-in page for the person. The default starts the system's browser. */
  openBrowser?: (url: string) => void;
}

/** A sign-in that waits for the person in the browser. */
interface PendingSignIn {
  prompt: LinkPrompt;
  apiUrl: string;
  startedAt: number;
  outcome: 'waiting' | 'approved' | 'refused' | 'expired' | 'failed';
  detail?: string;
  done: Promise<void>;
  cancel: { aborted: boolean };
}

const place = {
  type: 'object',
  properties: {
    file: { type: 'string', description: 'Path of the file, absolute or relative to the working directory. .h: a #define. .json: a property. .ps1: a variable. Anything else (.env): a NAME=value line.' },
    name: { type: 'string', description: 'The name the secret has in the file, e.g. DEVICE_KEY.' },
  },
  required: ['file', 'name'],
  additionalProperties: false,
};

const saveTo = {
  type: 'array',
  minItems: 1,
  items: place,
  description: 'Where the key is written. It is not returned. An existing value of that name is replaced; the rest of the file stays.',
};

const reach = {
  description: 'What the key may reach: "all", "none", or a list of devices, each with an optional service.',
  oneOf: [
    { type: 'string', enum: ['all', 'none'] },
    {
      type: 'array',
      items: {
        type: 'object',
        properties: { device: { type: 'string', description: 'Name, alias or id of a device.' }, service: { type: 'string', description: 'One service of it. Without: all its services.' } },
        required: ['device'],
        additionalProperties: false,
      },
    },
  ],
};

function text(args: Json, name: string, required: true): string;
function text(args: Json, name: string, required?: false): string | undefined;
function text(args: Json, name: string, required = false): string | undefined {
  const value = args[name];
  if (value === undefined || value === null) {
    if (required) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `"${name}" is required.`);
    }
    return undefined;
  }
  if (typeof value !== 'string' || value.trim() === '') {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `"${name}" must be a text.`);
  }
  return value.trim();
}

function flag(args: Json, name: string): boolean | undefined {
  const value = args[name];
  if (value === undefined || value === null) {
    return undefined;
  }
  if (typeof value !== 'boolean') {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `"${name}" must be true or false.`);
  }
  return value;
}

function places(args: Json, name: string): SecretPlace[] {
  const value = args[name];
  if (!Array.isArray(value) || value.length === 0) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `"${name}" must name at least one file and the name the secret gets in it. Keys are written to files, never returned.`);
  }
  return value.map((entry) => entry as SecretPlace);
}

function reachOf(args: Json): Reach | undefined {
  const value = args.reach;
  if (value === undefined || value === null) {
    return undefined;
  }
  if (value === 'all' || value === 'none') {
    return value;
  }
  if (Array.isArray(value) && value.every((entry) => entry !== null && typeof entry === 'object' && typeof (entry as Json).device === 'string')) {
    return value as { device: string; service?: string }[];
  }
  throw new ConnectivitizerError(ErrorCodes.InvalidRequest, '"reach" must be "all", "none", or a list of { device, service? }.');
}

function startBrowser(url: string): void {
  // For machines without a screen: the address and the code are in the answer either way.
  if (process.env.CONNECTIVITIZER_NO_BROWSER) {
    return;
  }
  try {
    const [command, args] =
      process.platform === 'win32' ? ['rundll32', ['url.dll,FileProtocolHandler', url]] : process.platform === 'darwin' ? ['open', [url]] : ['xdg-open', [url]];
    const child = spawn(command as string, args as string[], { detached: true, stdio: 'ignore', windowsHide: true });
    child.on('error', () => undefined);
    child.unref();
  } catch {
    // The caller shows the address as well; a machine without a browser is not an error.
  }
}

/** The tools, bound to one state directory. */
export class WorkspaceTools {
  readonly state: StateDirectory;
  private readonly platform: Platform;
  private readonly cwd: string;
  private readonly apiUrl: string;
  private readonly openBrowser: (url: string) => void;
  private pending: PendingSignIn | null = null;

  constructor(options: ToolsOptions = {}) {
    this.state = options.state ?? new StateDirectory();
    this.platform = options.platform ?? nodePlatform();
    this.cwd = options.cwd ?? process.cwd();
    this.apiUrl = options.apiUrl ?? process.env.CONNECTIVITIZER_API_URL?.trim() ?? DEFAULT_API_URL;
    this.openBrowser = options.openBrowser ?? startBrowser;
  }

  /**
   * Starts a sign-in: the person approves this program in the web app, as an admin of the
   * workspace. Answers at once with the page and the code; `status` says when it is done.
   */
  async signIn(options: { apiUrl?: string; name?: string; again?: boolean } = {}): Promise<Json> {
    const login = this.state.loadWorkspaceLogin();
    if (login && !options.again && !expired(login)) {
      return { ...this.describe(login), note: 'Already signed in. Pass again: true to sign in to another workspace.' };
    }
    if (this.pending?.outcome === 'waiting') {
      this.pending.cancel.aborted = true;
    }
    const apiUrl = options.apiUrl ?? login?.apiUrl ?? this.apiUrl;
    const cancel = { aborted: false };
    let announce: (prompt: LinkPrompt) => void = () => undefined;
    let refuse: (error: unknown) => void = () => undefined;
    const prompted = new Promise<LinkPrompt>((resolve, reject) => {
      announce = resolve;
      refuse = reject;
    });
    const pending: PendingSignIn = { prompt: { url: '', page: '', code: '', expiresIn: 0 }, apiUrl, startedAt: Date.now(), outcome: 'waiting', done: Promise.resolve(), cancel };
    pending.done = linkWith(this.platform, {
      apiUrl,
      client: options.name ?? 'Connectivitizer tools',
      platformName: `connectivitizer on ${process.platform}`,
      manage: true,
      signal: cancel,
      onPrompt: announce,
    }).then(
      (linked) => {
        this.state.saveWorkspaceLogin({
          apiUrl,
          apiKey: linked.apiKey,
          workspaceId: linked.workspaceId,
          workspaceName: linked.workspaceName,
          client: linked.client,
          credentialId: linked.credentialId,
          expiresAt: linked.expiresAt,
        });
        pending.outcome = linked.manage ? 'approved' : 'failed';
        pending.detail = linked.manage ? undefined : 'The platform linked this program without the right to manage. It is older than this tool; update the platform.';
      },
      (error: unknown) => {
        const code = error instanceof ConnectivitizerError ? error.code : '';
        pending.outcome = cancel.aborted ? 'expired' : code === ErrorCodes.LinkDenied ? 'refused' : code === ErrorCodes.LinkExpired ? 'expired' : 'failed';
        pending.detail = error instanceof Error ? error.message : String(error);
        refuse(error);
      },
    );
    pending.prompt = await prompted;
    this.pending = pending;
    this.openBrowser(pending.prompt.url);
    return {
      signedIn: false,
      waitingForApproval: true,
      open: pending.prompt.url,
      code: pending.prompt.code,
      expiresInSeconds: pending.prompt.expiresIn,
      note: 'The page was opened in the browser. The person signs in there, checks that the page shows this code, and approves; that takes an admin of the workspace. Call status to see when it is done.',
    };
  }

  /** Resolves when the sign-in that is waiting has been decided. */
  async waitForSignIn(): Promise<Json> {
    await this.pending?.done;
    return this.status();
  }

  status(): Json {
    const login = this.state.loadWorkspaceLogin();
    const pending = this.pending;
    if (pending?.outcome === 'waiting') {
      return {
        signedIn: false,
        waitingForApproval: true,
        open: pending.prompt.url,
        code: pending.prompt.code,
        expiresInSeconds: Math.max(0, pending.prompt.expiresIn - Math.round((Date.now() - pending.startedAt) / 1000)),
      };
    }
    if (pending && pending.outcome !== 'approved') {
      this.pending = null;
      return { signedIn: login !== null && !expired(login), lastSignIn: pending.outcome, detail: pending.detail, ...(login ? this.describe(login) : {}) };
    }
    if (login === null) {
      return { signedIn: false, note: 'Not signed in. Call sign_in; the person approves in the browser.' };
    }
    return this.describe(login);
  }

  signOut(): Json {
    const login = this.state.loadWorkspaceLogin();
    if (this.pending?.outcome === 'waiting') {
      this.pending.cancel.aborted = true;
    }
    this.pending = null;
    this.state.removeWorkspaceLogin();
    return login
      ? { signedIn: false, note: `The key was removed from this machine. In the workspace it is still valid until it expires; revoke "${login.client}" under Credentials in the web app to end it now.` }
      : { signedIn: false };
  }

  workspace(): Workspace {
    const login = this.state.loadWorkspaceLogin();
    if (login === null) {
      throw new ConnectivitizerError(ErrorCodes.Unauthenticated, 'Not signed in. Call sign_in first (command line: connectivitizer login); the person approves in the browser.');
    }
    if (expired(login)) {
      throw new ConnectivitizerError(ErrorCodes.CredentialRevoked, 'The sign-in has expired. Call sign_in again (command line: connectivitizer login).');
    }
    return new Workspace(login, this.platform);
  }

  private describe(login: WorkspaceLogin): Json {
    return { signedIn: !expired(login), workspace: login.workspaceName, as: login.client, api: login.apiUrl, expiresAt: login.expiresAt };
  }

  private save(args: Json, secret: string): SecretWritten[] {
    return places(args, 'saveTo').map((entry) => writeSecret(entry, secret, this.cwd));
  }

  private async createKey(kind: 'device' | 'app', args: Json): Promise<Json> {
    const targets = places(args, 'saveTo');
    // Before the key exists: a place that cannot take it would leave a key nobody holds.
    for (const target of targets) {
      checkSecretPlace(target, this.cwd);
    }
    const days = args.expiresInDays;
    if (days !== undefined && (typeof days !== 'number' || days <= 0)) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, '"expiresInDays" must be a positive number.');
    }
    const created = await this.workspace().createKey({
      name: text(args, 'name', true),
      kind,
      maySessions: kind === 'device' ? flag(args, 'maySessions') : undefined,
      reach: reachOf(args),
      expiresInDays: days as number | undefined,
    });
    return { key: created.key, savedTo: targets.map((target) => writeSecret(target, created.secret, this.cwd)), note: 'The key itself is in the file(s) only. It cannot be shown again; make a new one if it is lost.' };
  }

  list(): Tool[] {
    return [
      {
        name: 'sign_in',
        description:
          'Signs this machine in to a Connectivitizer workspace. Opens the web app in the browser; the person signs in there and approves (they must be an admin of the workspace). Answers at once with the page and a code to compare; call status afterwards. The sign-in is kept on this machine and lasts 30 days.',
        inputSchema: {
          type: 'object',
          properties: {
            apiUrl: { type: 'string', description: `The API of the installation. Default: ${DEFAULT_API_URL}` },
            name: { type: 'string', description: 'The name this program gets in the workspace, e.g. "Assistant on my laptop".' },
            again: { type: 'boolean', description: 'Sign in anew although a sign-in exists, e.g. for another workspace.' },
          },
          additionalProperties: false,
        },
        run: (args) => this.signIn({ apiUrl: text(args, 'apiUrl'), name: text(args, 'name'), again: flag(args, 'again') }),
      },
      {
        name: 'status',
        description: 'Whether this machine is signed in, to which workspace, and whether a sign-in is still waiting for the person in the browser.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        run: async () => this.status(),
      },
      {
        name: 'sign_out',
        description: 'Removes the sign-in from this machine.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        run: async () => this.signOut(),
      },
      {
        name: 'list_devices',
        description: 'The devices of the workspace: name, whether each is online, its services, the device key it logs in with, and which keys may connect to it.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        run: async () => this.workspace().devices(),
      },
      {
        name: 'update_device',
        description:
          'Gives a device an alias, or sets which keys may connect to it. allowedKeys replaces the list; "all" lifts the restriction so that every key whose rules cover the device may connect. Sessions of keys that are no longer allowed end.',
        inputSchema: {
          type: 'object',
          properties: {
            device: { type: 'string', description: 'Name, alias or id of the device.' },
            alias: { type: 'string', description: 'A name for people. Empty text removes it.' },
            allowedKeys: { description: 'Names or prefixes (czd_…, czk_…) of keys, or "all".', oneOf: [{ type: 'string', enum: ['all'] }, { type: 'array', items: { type: 'string' } }] },
          },
          required: ['device'],
          additionalProperties: false,
        },
        run: async (args) => {
          const allowed = args.allowedKeys;
          if (allowed !== undefined && allowed !== 'all' && !(Array.isArray(allowed) && allowed.every((entry) => typeof entry === 'string'))) {
            throw new ConnectivitizerError(ErrorCodes.InvalidRequest, '"allowedKeys" must be "all" or a list of key names or prefixes.');
          }
          const alias = args.alias;
          if (alias !== undefined && typeof alias !== 'string') {
            throw new ConnectivitizerError(ErrorCodes.InvalidRequest, '"alias" must be a text.');
          }
          return this.workspace().updateDevice(text(args, 'device', true), { alias, allowedKeys: allowed as 'all' | string[] | undefined });
        },
      },
      {
        name: 'list_keys',
        description: 'The keys of the workspace, without their secrets: device keys and API keys, with prefix, what each may reach, and how many devices use a device key.',
        inputSchema: { type: 'object', properties: {}, additionalProperties: false },
        run: async () => this.workspace().keys(),
      },
      {
        name: 'create_device_key',
        description:
          'Creates a device key (czd_…): what a device logs in with. The key is written to the file(s) in saveTo and not returned. With maySessions the devices of this key may also open sessions to other devices (ESP32: link; other SDKs: connect on the agent), within reach.',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'A name for the key, e.g. "Lamps".' },
            maySessions: { type: 'boolean', description: 'Its devices may open sessions to other devices. Default: false.' },
            reach: { ...reach, description: reach.description + ' Only with maySessions. Default then: "all".' },
            saveTo,
          },
          required: ['name', 'saveTo'],
          additionalProperties: false,
        },
        run: (args) => this.createKey('device', args),
      },
      {
        name: 'create_api_key',
        description:
          'Creates an API key (czk_…): what a program that opens sessions to devices authenticates with. The key is written to the file(s) in saveTo and not returned. It cannot manage the workspace.',
        inputSchema: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'A name for the key, e.g. "Dashboard".' },
            reach: { ...reach, description: reach.description + ' Default: "all".' },
            expiresInDays: { type: 'number', description: 'The key stops working after this many days. Default: it does not expire.' },
            saveTo,
          },
          required: ['name', 'saveTo'],
          additionalProperties: false,
        },
        run: (args) => this.createKey('app', args),
      },
      {
        name: 'update_key',
        description:
          'Renames a key, switches whether the devices of a device key may open sessions to other devices, or changes what a key may reach. Takes effect at once, without restarting devices. Sessions the new rules do not cover end.',
        inputSchema: {
          type: 'object',
          properties: {
            key: { type: 'string', description: 'Name or prefix (czd_…, czk_…) of the key.' },
            name: { type: 'string' },
            maySessions: { type: 'boolean', description: 'Device keys only. Switched on without reach, the key may reach all devices.' },
            reach,
          },
          required: ['key'],
          additionalProperties: false,
        },
        run: async (args) => this.workspace().updateKey(text(args, 'key', true), { name: text(args, 'name'), maySessions: flag(args, 'maySessions'), reach: reachOf(args) }),
      },
      {
        name: 'create_shared_key',
        description:
          'Makes a shared key (czs_…): the end-to-end secret both ends of a session hold. It is made on this machine, written to the file(s) in saveTo and never sent to Connectivitizer. Name every place that needs it, e.g. the device\'s secrets file and the app\'s.',
        inputSchema: { type: 'object', properties: { saveTo }, required: ['saveTo'], additionalProperties: false },
        run: async (args) => {
          const key = generateSharedKey((length) => new Uint8Array(randomBytes(length)));
          return { savedTo: this.save(args, key), note: 'The workspace does not know this key. Both ends of a session need the same one.' };
        },
      },
      {
        name: 'copy_secret',
        description: 'Copies a key from one secrets file to others without showing it, e.g. the shared key of a device into the secrets file of the app that calls it.',
        inputSchema: { type: 'object', properties: { from: place, to: { type: 'array', minItems: 1, items: place } }, required: ['from', 'to'], additionalProperties: false },
        run: async (args) => ({ savedTo: copySecret(args.from as SecretPlace, places(args, 'to'), this.cwd) }),
      },
      {
        name: 'list_sessions',
        description:
          'Recent sessions, newest first: which device, who opened it, direct or relayed, whether it failed and why (endReason, directFailureReason). The place to look when a connection does not work.',
        inputSchema: {
          type: 'object',
          properties: {
            device: { type: 'string', description: 'Only sessions to this device.' },
            failedOnly: { type: 'boolean' },
            limit: { type: 'number', description: 'How many, 1 to 100. Default: 20.' },
          },
          additionalProperties: false,
        },
        run: async (args) => {
          const limit = args.limit;
          if (limit !== undefined && typeof limit !== 'number') {
            throw new ConnectivitizerError(ErrorCodes.InvalidRequest, '"limit" must be a number.');
          }
          return this.workspace().sessions({ device: text(args, 'device'), failedOnly: flag(args, 'failedOnly'), limit });
        },
      },
    ];
  }
}

function expired(login: WorkspaceLogin): boolean {
  return login.expiresAt !== undefined && Date.parse(login.expiresAt) < Date.now();
}
