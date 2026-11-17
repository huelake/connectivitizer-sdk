import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { ConnectivitizerError, ErrorCodes } from '../src/core/errors.js';
import type { Platform } from '../src/core/platform.js';
import { serveMcp } from '../src/node/mcp.js';
import { copySecret, readSecret, writeSecret } from '../src/node/secretFiles.js';
import { StateDirectory } from '../src/node/state.js';
import { WorkspaceTools } from '../src/node/tools.js';

const API = 'https://api.example.test/api/connectivitizer';
const WORKSPACE = '11111111-1111-1111-1111-111111111111';
const LAMP = '22222222-2222-2222-2222-222222222222';
const CABIN = '33333333-3333-3333-3333-333333333333';

interface FakeKey {
  id: string;
  name: string;
  keyPrefix: string;
  canConnect: boolean;
  canManage: boolean;
  accessRules: { deviceId?: string | null; serviceName?: string | null }[];
  kind: string;
  deviceCount: number;
  revokedAt?: string | null;
  expiresAt?: string | null;
}

/** As much of the control plane as the tools talk to, in memory. */
class FakePlatform {
  approved = false;
  refuseManage = false;
  readonly secrets: string[] = [];
  readonly keys: FakeKey[] = [];
  readonly devices = [
    { id: LAMP, name: 'lamp', slug: 'lamp', status: 'active', online: true, alias: 'Lamp in the hall', keyId: null as string | null, allowedClientIds: [] as string[], capabilities: ['path.udp-kcp'], services: [{ name: 'api', declared: true, enabled: true }] },
    { id: CABIN, name: 'cabin', slug: 'cabin', status: 'active', online: false, alias: null, keyId: null as string | null, allowedClientIds: [] as string[], capabilities: [], services: [{ name: 'api', declared: true, enabled: true }, { name: 'old', declared: false, enabled: true }] },
  ];
  linkRequest: Record<string, unknown> | null = null;
  private counter = 0;

  readonly platform = {
    fetch: async (url: string, init: { method: string; headers: Record<string, string>; body?: string }) => {
      const [status, body] = this.route(init.method, url.slice(API.length + 1), init.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined, init.headers);
      return { status, text: async () => (body === undefined ? '' : JSON.stringify(body)) };
    },
  } as unknown as Platform;

  private secret(kind: string): { prefix: string; value: string } {
    const prefix = (++this.counter).toString(16).padStart(10, '0');
    const value = `${kind}_${prefix}_SECRET${this.counter}SECRET`;
    this.secrets.push(value);
    return { prefix, value };
  }

  private route(method: string, path: string, body: Record<string, unknown> | undefined, headers: Record<string, string>): [number, unknown?] {
    if (path === 'v1/auth/link') {
      this.linkRequest = body ?? null;
      return [200, { userCode: 'KQTR-7MPL', deviceCode: 'device-code', verificationUrl: 'https://app.example.test/link', verificationUrlComplete: 'https://app.example.test/link?code=KQTR-7MPL', expiresIn: 600, interval: 0.01 }];
    }
    if (path === 'v1/auth/link/token') {
      if (!this.approved) {
        return [200, { status: 'pending' }];
      }
      const made = this.secret('czk');
      this.keys.push({ id: 'aaaaaaaa-0000-0000-0000-000000000001', name: 'Assistant', keyPrefix: made.prefix, canConnect: true, canManage: true, accessRules: [{}], kind: 'linked-app', deviceCount: 0 });
      return [200, { status: 'approved', apiKey: made.value, workspaceId: WORKSPACE, workspaceName: 'Acme', credentialId: 'aaaaaaaa-0000-0000-0000-000000000001', client: 'Assistant', manage: !this.refuseManage, expiresAt: new Date(Date.now() + 30 * 86_400_000).toISOString() }];
    }
    if (path === 'v1/auth/credential/token') {
      return this.secrets.includes(String(body?.apiKey)) ? [200, { accessToken: 'token', expiresIn: 600, endpointType: 'credential', endpointId: 'x', workspaceId: WORKSPACE }] : [401, { error: 'CREDENTIAL_REVOKED' }];
    }
    const prefix = `v1/workspaces/${WORKSPACE}/`;
    if (!path.startsWith(prefix) || headers.Authorization !== 'Bearer token') {
      return [404, { error: 'NOT_FOUND' }];
    }
    const [resource, id] = path.slice(prefix.length).split('?')[0].split('/');
    if (resource === 'devices' && method === 'GET') {
      return [200, this.devices];
    }
    if (resource === 'devices' && method === 'PATCH') {
      const device = this.devices.find((candidate) => candidate.id === id)!;
      if (typeof body?.alias === 'string') {
        device.alias = body.alias === '' ? null : body.alias;
      }
      if (Array.isArray(body?.allowedClientIds)) {
        device.allowedClientIds = body.allowedClientIds as string[];
      }
      return [200, device];
    }
    if (resource === 'credentials' && method === 'GET') {
      return [200, this.keys];
    }
    if (resource === 'credentials' && method === 'POST') {
      const made = this.secret(body?.kind === 'device' ? 'czd' : 'czk');
      const key: FakeKey = {
        id: `bbbbbbbb-0000-0000-0000-00000000000${this.counter}`,
        name: String(body?.name),
        keyPrefix: made.prefix,
        canConnect: body?.canConnect === true,
        canManage: false,
        accessRules: (body?.accessRules as FakeKey['accessRules']) ?? [],
        kind: String(body?.kind),
        deviceCount: 0,
        expiresAt: (body?.expiresAt as string | undefined) ?? null,
      };
      this.keys.push(key);
      return [201, { details: key, apiKey: made.value }];
    }
    if (resource === 'credentials' && method === 'PATCH') {
      const key = this.keys.find((candidate) => candidate.id === id)!;
      if (typeof body?.name === 'string') {
        key.name = body.name;
      }
      if (typeof body?.canConnect === 'boolean') {
        key.canConnect = body.canConnect;
      }
      if (Array.isArray(body?.accessRules)) {
        key.accessRules = body.accessRules as FakeKey['accessRules'];
      }
      return [200, key];
    }
    if (resource === 'sessions') {
      return [200, [{ id: 's1', deviceName: 'lamp', initiatorType: 'device', initiatorName: 'cabin', services: ['api'], state: 'failed', mode: null, endReason: 'FORBIDDEN', requestedAt: '2026-11-17T10:00:00Z' }]];
    }
    return [404, { error: 'NOT_FOUND' }];
  }
}

function setup(): { tools: WorkspaceTools; platform: FakePlatform; directory: string; opened: string[]; call: (name: string, args?: Record<string, unknown>) => Promise<any>; remove: () => void } {
  const directory = mkdtempSync(join(tmpdir(), 'cz-tools-'));
  const platform = new FakePlatform();
  const opened: string[] = [];
  const tools = new WorkspaceTools({ state: new StateDirectory(join(directory, 'state')), platform: platform.platform, apiUrl: API, cwd: directory, openBrowser: (url) => opened.push(url) });
  const call = (name: string, args: Record<string, unknown> = {}) => tools.list().find((tool) => tool.name === name)!.run(args);
  return { tools, platform, directory, opened, call, remove: () => rmSync(directory, { recursive: true, force: true }) };
}

async function signedIn(): Promise<ReturnType<typeof setup>> {
  const context = setup();
  context.platform.approved = true;
  await context.call('sign_in', { name: 'Assistant' });
  await context.tools.waitForSignIn();
  return context;
}

/** No answer of a tool may contain a key the platform handed out or a shared key. */
function assertNoSecret(platform: FakePlatform, answer: unknown): void {
  const text = JSON.stringify(answer);
  for (const secret of platform.secrets) {
    assert.ok(!text.includes(secret), 'a tool answered with a key');
  }
  assert.doesNotMatch(text, /czs_[A-Za-z0-9_-]{20,}/);
}

test('a secret is written into a header, a JSON file, a PowerShell script and an env file, replacing an earlier value only', () => {
  const directory = mkdtempSync(join(tmpdir(), 'cz-secrets-'));
  try {
    const header = join(directory, 'secrets.h');
    writeFileSync(header, '#define WIFI_SSID "home"\r\n#define DEVICE_KEY "czd_old" // from the web app\r\n#define DEVICE_KEY_NAME "x"\r\n');
    assert.equal(writeSecret({ file: header, name: 'DEVICE_KEY' }, 'czd_new_1').action, 'replaced');
    assert.equal(writeSecret({ file: header, name: 'SHARED_KEY' }, 'czs_new').action, 'added');
    assert.equal(readFileSync(header, 'utf8'), '#define WIFI_SSID "home"\r\n#define DEVICE_KEY "czd_new_1"\r\n#define DEVICE_KEY_NAME "x"\r\n#define SHARED_KEY "czs_new"\r\n');
    assert.equal(readSecret({ file: header, name: 'DEVICE_KEY' }), 'czd_new_1');

    const json = join(directory, 'nested', 'secrets.json');
    assert.equal(writeSecret({ file: json, name: 'deviceKey' }, 'czd_a').action, 'created');
    writeSecret({ file: json, name: 'sharedKey' }, 'czs_b');
    assert.deepEqual(JSON.parse(readFileSync(json, 'utf8')), { deviceKey: 'czd_a', sharedKey: 'czs_b' });

    const script = join(directory, 'setup.ps1');
    writeFileSync(script, "$ApiUrl = 'https://x'\n$DeviceKey = ''\n");
    writeSecret({ file: script, name: 'DeviceKey' }, 'czd_c');
    assert.equal(readFileSync(script, 'utf8'), "$ApiUrl = 'https://x'\n$DeviceKey = 'czd_c'\n");
    assert.equal(readSecret({ file: script, name: 'DeviceKey' }), 'czd_c');

    const env = join(directory, '.env');
    writeFileSync(env, 'PORT=8080\nexport CZ_API_KEY=old');
    writeSecret({ file: env, name: 'CZ_API_KEY' }, 'czk_d');
    writeSecret({ file: env, name: 'CZ_SHARED_KEY' }, 'czs_e');
    assert.equal(readFileSync(env, 'utf8'), 'PORT=8080\nexport CZ_API_KEY=czk_d\nCZ_SHARED_KEY=czs_e\n');

    copySecret({ file: env, name: 'CZ_SHARED_KEY' }, [{ file: header, name: 'SHARED_KEY' }]);
    assert.equal(readSecret({ file: header, name: 'SHARED_KEY' }), 'czs_e');

    assert.throws(() => writeSecret({ file: env, name: 'not a name' }, 'x'), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.InvalidRequest);
    assert.throws(() => writeSecret({ file: env, name: 'X' }, 'two\nlines'), ConnectivitizerError);
    assert.throws(() => readSecret({ file: env, name: 'MISSING' }), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.NotFound);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('signing in asks to manage, opens the browser, and keeps the key in the state directory only', async () => {
  const { tools, platform, opened, call, remove } = setup();
  try {
    await assert.rejects(call('list_devices'), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.Unauthenticated);

    const started = await call('sign_in', { name: 'Assistant' });
    assert.equal(started.waitingForApproval, true);
    assert.equal(started.code, 'KQTR-7MPL');
    assert.deepEqual(opened, ['https://app.example.test/link?code=KQTR-7MPL']);
    assert.equal(platform.linkRequest?.manage, true);
    assert.equal((await call('status')).waitingForApproval, true);

    platform.approved = true;
    const done = await tools.waitForSignIn();
    assert.equal(done.signedIn, true);
    assert.equal(done.workspace, 'Acme');
    assertNoSecret(platform, done);
    assertNoSecret(platform, await call('status'));
    assert.equal(tools.state.loadWorkspaceLogin()?.apiKey, platform.secrets[0]);

    assert.match(String((await call('sign_in')).note), /Already signed in/);
    assert.equal((await call('sign_out')).signedIn, false);
    assert.equal(tools.state.loadWorkspaceLogin(), null);
  } finally {
    remove();
  }
});

test('a device key is created into the files named, with its right and reach, and is never in an answer', async () => {
  const { platform, directory, call, remove } = await signedIn();
  try {
    writeFileSync(join(directory, 'secrets.h'), '#define DEVICE_KEY "czd_..."\n');
    const created = await call('create_device_key', { name: 'Lamps', maySessions: true, reach: [{ device: 'Lamp in the hall', service: 'api' }], saveTo: [{ file: 'secrets.h', name: 'DEVICE_KEY' }, { file: 'pi/secrets.json', name: 'deviceKey' }] });
    assertNoSecret(platform, created);
    assert.equal(created.key.prefix, `czd_${platform.keys[1].keyPrefix}`);
    assert.deepEqual(created.key.reach, ['lamp/api']);
    assert.equal(created.key.maySessions, true);
    assert.deepEqual(platform.keys[1].accessRules, [{ deviceId: LAMP, serviceName: 'api' }]);
    const secret = platform.secrets[1];
    assert.equal(readFileSync(join(directory, 'secrets.h'), 'utf8'), `#define DEVICE_KEY "${secret}"\n`);
    assert.equal(JSON.parse(readFileSync(join(directory, 'pi', 'secrets.json'), 'utf8')).deviceKey, secret);

    // Without the right, a device key reaches nothing, whatever was asked.
    const plain = await call('create_device_key', { name: 'Sensors', saveTo: [{ file: '.env', name: 'CZ_DEVICE_KEY' }] });
    assert.equal(plain.key.maySessions, false);
    assert.equal(plain.key.reach, 'none');

    const api = await call('create_api_key', { name: 'Dashboard', saveTo: [{ file: '.env', name: 'CZ_API_KEY' }] });
    assert.equal(api.key.reach, 'all');
    assert.equal(api.key.managesWorkspace, false);
    assertNoSecret(platform, api);

    // A place that cannot take the key is refused before a key exists.
    const before = platform.keys.length;
    await assert.rejects(call('create_device_key', { name: 'Bad', saveTo: [{ file: 'x.h', name: '1BAD' }] }), ConnectivitizerError);
    await assert.rejects(call('create_device_key', { name: 'Bad' }), ConnectivitizerError);
    assert.equal(platform.keys.length, before);

    const listed = await call('list_keys');
    assertNoSecret(platform, listed);
    assert.deepEqual(listed.map((key: { name: string }) => key.name), ['Assistant', 'Lamps', 'Sensors', 'Dashboard']);
  } finally {
    remove();
  }
});

test('a key is found by name or prefix and its right is switched; a device by name or alias', async () => {
  const { platform, call, remove } = await signedIn();
  try {
    await call('create_device_key', { name: 'Sensors', saveTo: [{ file: '.env', name: 'A' }] });
    const prefix = `czd_${platform.keys[1].keyPrefix}`;

    // Switched on without saying for what: all devices, or the key would be refused everywhere.
    const on = await call('update_key', { key: prefix, maySessions: true });
    assert.equal(on.maySessions, true);
    assert.equal(on.reach, 'all');
    const narrowed = await call('update_key', { key: 'sensors', reach: [{ device: 'cabin' }] });
    assert.deepEqual(narrowed.reach, ['cabin']);
    const off = await call('update_key', { key: `${prefix}_and_the_rest_of_a_pasted_key`, maySessions: false });
    assert.equal(off.reach, 'none');

    await assert.rejects(call('update_key', { key: 'Assistant', maySessions: true }), /Only a device key/);
    await assert.rejects(call('update_key', { key: 'nobody', name: 'x' }), /Its keys: Assistant/);

    const device = await call('update_device', { device: 'Lamp in the hall', allowedKeys: ['Sensors'] });
    assert.equal(device.name, 'lamp');
    assert.deepEqual(device.allowedKeys, [`Sensors (${prefix})`]);
    assert.deepEqual(platform.devices[0].allowedClientIds, [platform.keys[1].id]);
    assert.equal((await call('update_device', { device: 'lamp', allowedKeys: 'all' })).allowedKeys, undefined);

    const devices = await call('list_devices');
    assert.deepEqual(devices[1].services, ['api']);
    await assert.rejects(call('update_device', { device: 'garage', alias: 'x' }), /Its devices: lamp, cabin/);

    const sessions = await call('list_sessions', { device: 'lamp', failedOnly: true });
    assert.equal(sessions[0].from, 'device cabin');
    assert.equal(sessions[0].endReason, 'FORBIDDEN');
  } finally {
    remove();
  }
});

test('a shared key is made here, written to every place named, and never sent or returned', async () => {
  const { platform, directory, call, remove } = setup();
  try {
    const made = await call('create_shared_key', { saveTo: [{ file: 'device/secrets.h', name: 'SHARED_KEY' }, { file: 'app/.env', name: 'CZ_SHARED_KEY' }] });
    assertNoSecret(platform, made);
    const key = readSecret({ file: join(directory, 'device', 'secrets.h'), name: 'SHARED_KEY' });
    assert.match(key, /^czs_/);
    assert.equal(readSecret({ file: join(directory, 'app', '.env'), name: 'CZ_SHARED_KEY' }), key);
    assert.equal(platform.linkRequest, null);

    const copied = await call('copy_secret', { from: { file: 'app/.env', name: 'CZ_SHARED_KEY' }, to: [{ file: 'pi/secrets.json', name: 'sharedKey' }] });
    assertNoSecret(platform, copied);
    assert.equal(JSON.parse(readFileSync(join(directory, 'pi', 'secrets.json'), 'utf8')).sharedKey, key);
  } finally {
    remove();
  }
});

test('the MCP server answers initialize, lists the tools, runs them, and reports a refusal as a tool error', async () => {
  const { tools, platform, remove } = await signedIn();
  const input = new PassThrough();
  const output = new PassThrough();
  const lines: any[] = [];
  let waiting: ((message: any) => void) | null = null;
  let buffered = '';
  output.on('data', (chunk: Buffer) => {
    buffered += chunk.toString('utf8');
    for (let at = buffered.indexOf('\n'); at >= 0; at = buffered.indexOf('\n')) {
      const message = JSON.parse(buffered.slice(0, at));
      buffered = buffered.slice(at + 1);
      if (waiting) {
        const resolve = waiting;
        waiting = null;
        resolve(message);
      } else {
        lines.push(message);
      }
    }
  });
  const ask = (message: unknown): Promise<any> => {
    input.write(JSON.stringify(message) + '\n');
    return new Promise((resolve) => {
      waiting = resolve;
    });
  };
  const served = serveMcp(tools, '1.2.3', input, output);
  try {
    const hello = await ask({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'test', version: '0' } } });
    assert.equal(hello.result.protocolVersion, '2025-03-26');
    assert.equal(hello.result.serverInfo.name, 'connectivitizer');
    assert.deepEqual(hello.result.capabilities, { tools: {} });
    input.write(JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }) + '\n');

    const listed = await ask({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const names = listed.result.tools.map((tool: { name: string }) => tool.name);
    assert.deepEqual(names, ['sign_in', 'status', 'sign_out', 'list_devices', 'update_device', 'list_keys', 'create_device_key', 'create_api_key', 'update_key', 'create_shared_key', 'copy_secret', 'list_sessions']);
    assert.ok(listed.result.tools.every((tool: { inputSchema: { type: string } }) => tool.inputSchema.type === 'object'));
    assert.ok(!names.some((name: string) => /revoke|delete/.test(name)));

    const devices = await ask({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'list_devices', arguments: {} } });
    assert.equal(JSON.parse(devices.result.content[0].text)[0].name, 'lamp');
    assertNoSecret(platform, devices);

    const refused = await ask({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'update_device', arguments: { device: 'garage', alias: 'x' } } });
    assert.equal(refused.result.isError, true);
    assert.match(refused.result.content[0].text, /^DEVICE_NOT_FOUND: /);

    assert.equal((await ask({ jsonrpc: '2.0', id: 5, method: 'tools/call', params: { name: 'nothing' } })).error.code, -32602);
    assert.equal((await ask({ jsonrpc: '2.0', id: 6, method: 'resources/list' })).error.code, -32601);
    assert.deepEqual((await ask({ jsonrpc: '2.0', id: 7, method: 'ping' })).result, {});
    assert.deepEqual(lines, [], 'a notification gets no answer');
  } finally {
    input.end();
    await served;
    remove();
  }
});
