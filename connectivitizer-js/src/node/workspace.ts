// Managing a workspace from a program: its devices, its keys, and who may reach what. This is the
// management part of the REST API (the part the web app uses), for a key that may manage: the one
// `connectivitizer login` obtains, or an API key created with that right in the web app.

import { PlatformApi } from '../core/api.js';
import { ConnectivitizerError, ErrorCodes } from '../core/errors.js';
import type { Platform } from '../core/platform.js';
import { nodePlatform } from './platform.js';

/**
 * What a key may reach: every device and service, nothing, or a list. An entry without a service
 * covers every service of that device.
 */
export type Reach = 'all' | 'none' | readonly { device: string; service?: string }[];

export interface DeviceView {
  /** The name sessions are opened to. */
  name: string;
  id: string;
  /** A name people gave the device in the web app. */
  alias?: string;
  online: boolean;
  status: string;
  lastSeenAt?: string;
  services: string[];
  /** The device key the device logs in with, e.g. `Lamps (czd_1c25660e1a)`. Absent for an enrolled device. */
  key?: string;
  /** The keys that may connect to this device. Absent: every key whose rules cover it. */
  allowedKeys?: string[];
  platform?: string;
  agentVersion?: string;
  /** `path.udp-kcp` among them: the device offers peer-to-peer. */
  capabilities: string[];
}

export interface KeyView {
  name: string;
  id: string;
  /** `device`: devices log in with it. `app`: an API key. `linked-app`: an app or tool that was linked through the browser. */
  kind: string;
  /** The public beginning of the key, e.g. `czd_1c25660e1a`. The secret part is never returned. */
  prefix: string;
  status: 'active' | 'revoked' | 'expired';
  /** For a device key: its devices may open sessions to other devices. For the others: it may open sessions. */
  maySessions: boolean;
  managesWorkspace: boolean;
  /** `all`, `none`, or entries like `cabin` and `cabin/api`. */
  reach: string | string[];
  /** For a device key: how many devices last logged in with it. */
  devices?: number;
  expiresAt?: string;
  lastUsedAt?: string;
}

export interface SessionView {
  id: string;
  device: string;
  /** Who opened it, e.g. `device connect-esp32` or `credential Lamp app`. */
  from: string;
  services: string[];
  state: string;
  /** `direct` (peer to peer), `e2e-relay`, or `compatibility`. */
  mode?: string;
  endToEndEncrypted?: boolean;
  /** Why a relayed session did not become direct. */
  directFailureReason?: string;
  endReason?: string;
  requestedAt: string;
  establishedAt?: string;
  endedAt?: string;
}

interface ApiService {
  name: string;
  declared: boolean;
  enabled: boolean;
}

interface ApiDevice {
  id: string;
  name: string;
  slug: string;
  status: string;
  online: boolean;
  lastSeenAt?: string | null;
  platform?: string | null;
  agentVersion?: string | null;
  capabilities?: string[];
  services?: ApiService[];
  alias?: string | null;
  allowedClientIds?: string[];
  keyId?: string | null;
}

interface ApiRule {
  deviceId?: string | null;
  serviceName?: string | null;
}

interface ApiKey {
  id: string;
  name: string;
  keyPrefix: string;
  canConnect: boolean;
  canManage: boolean;
  expiresAt?: string | null;
  lastUsedAt?: string | null;
  revokedAt?: string | null;
  accessRules: ApiRule[];
  kind: string;
  deviceCount?: number;
}

interface ApiSession {
  id: string;
  deviceName: string;
  initiatorType: string;
  initiatorName: string;
  services: string[];
  state: string;
  mode?: string | null;
  endToEndEncrypted?: boolean | null;
  directFailureReason?: string | null;
  endReason?: string | null;
  requestedAt: string;
  establishedAt?: string | null;
  endedAt?: string | null;
}

const prefixes: Record<string, string> = { device: 'czd', app: 'czk', 'linked-app': 'czk' };

const same = (a: string | null | undefined, b: string): boolean => a !== null && a !== undefined && a.toLowerCase() === b.toLowerCase();

const optional = <T>(value: T | null | undefined): T | undefined => (value === null || value === undefined ? undefined : value);

export class Workspace {
  private readonly api: PlatformApi;
  private readonly platform: Platform;
  private readonly base: string;
  private token: { value: string; until: number } | null = null;

  constructor(
    private readonly login: { apiUrl: string; apiKey: string; workspaceId: string },
    platform?: Platform,
  ) {
    this.platform = platform ?? nodePlatform();
    this.api = new PlatformApi(login.apiUrl, this.platform);
    this.base = `${this.api.baseUrl}v1/workspaces/${login.workspaceId}/`;
  }

  async devices(): Promise<DeviceView[]> {
    const [devices, keys] = await Promise.all([this.get<ApiDevice[]>('devices'), this.get<ApiKey[]>('credentials')]);
    return devices.map((device) => this.deviceView(device, keys));
  }

  async device(nameOrId: string): Promise<DeviceView> {
    const [devices, keys] = await Promise.all([this.get<ApiDevice[]>('devices'), this.get<ApiKey[]>('credentials')]);
    return this.deviceView(pickDevice(devices, nameOrId), keys);
  }

  /**
   * Changes a device's alias, or which keys may connect to it. `allowedKeys` replaces the list;
   * `all` lifts the restriction, so that every key whose rules cover the device may connect.
   */
  async updateDevice(nameOrId: string, change: { alias?: string; allowedKeys?: 'all' | readonly string[] }): Promise<DeviceView> {
    const [devices, keys] = await Promise.all([this.get<ApiDevice[]>('devices'), this.get<ApiKey[]>('credentials')]);
    const device = pickDevice(devices, nameOrId);
    const body: { alias?: string; allowedClientIds?: string[] } = {};
    if (change.alias !== undefined) {
      body.alias = change.alias;
    }
    if (change.allowedKeys !== undefined) {
      body.allowedClientIds = change.allowedKeys === 'all' ? [] : change.allowedKeys.map((key) => pickKey(keys, key).id);
    }
    const updated = await this.send<ApiDevice>('PATCH', `devices/${device.id}`, body);
    return this.deviceView(updated, keys);
  }

  async keys(): Promise<KeyView[]> {
    const [keys, devices] = await Promise.all([this.get<ApiKey[]>('credentials'), this.get<ApiDevice[]>('devices')]);
    return keys.map((key) => keyView(key, devices));
  }

  /**
   * Creates a key and returns its secret together with what the workspace knows about it. The
   * secret exists in this answer only; the platform keeps a hash.
   */
  async createKey(options: { name: string; kind: 'device' | 'app'; maySessions?: boolean; reach?: Reach; expiresInDays?: number }): Promise<{ key: KeyView; secret: string }> {
    const devices = await this.get<ApiDevice[]>('devices');
    const maySessions = options.maySessions ?? options.kind === 'app';
    const reach: Reach = options.reach ?? (options.kind === 'app' ? 'all' : maySessions ? 'all' : 'none');
    const created = await this.send<{ details: ApiKey; apiKey: string }>('POST', 'credentials', {
      name: options.name,
      kind: options.kind,
      canConnect: maySessions,
      accessRules: maySessions ? rulesOf(reach, devices) : [],
      expiresAt: options.expiresInDays === undefined ? undefined : new Date(Date.now() + options.expiresInDays * 86_400_000).toISOString(),
    });
    return { key: keyView(created.details, devices), secret: created.apiKey };
  }

  /** Renames a key, switches its right to open sessions, or changes what it may reach. Running sessions the new rules do not cover end. */
  async updateKey(nameOrPrefix: string, change: { name?: string; maySessions?: boolean; reach?: Reach }): Promise<KeyView> {
    const [keys, devices] = await Promise.all([this.get<ApiKey[]>('credentials'), this.get<ApiDevice[]>('devices')]);
    const key = pickKey(keys, nameOrPrefix);
    const body: { name?: string; canConnect?: boolean; accessRules?: ApiRule[] } = {};
    if (change.name !== undefined) {
      body.name = change.name;
    }
    if (change.maySessions !== undefined) {
      if (key.kind !== 'device') {
        throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'Only a device key has a switch for opening sessions; an API key always may.');
      }
      body.canConnect = change.maySessions;
    }
    const willConnect = body.canConnect ?? key.canConnect;
    if (change.reach !== undefined) {
      body.accessRules = rulesOf(change.reach, devices);
    } else if (change.maySessions === true && key.accessRules.length === 0) {
      // Switched on without saying for what: a key that may reach nothing would be refused everywhere.
      body.accessRules = rulesOf('all', devices);
    }
    if (body.accessRules !== undefined && body.accessRules.length > 0 && !willConnect) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'This device key does not let its devices open sessions, so it reaches nothing. Set maySessions as well.');
    }
    const updated = await this.send<ApiKey>('PATCH', `credentials/${key.id}`, body);
    return keyView(updated, devices);
  }

  /** The most recent sessions, newest first. */
  async sessions(options: { device?: string; limit?: number; failedOnly?: boolean } = {}): Promise<SessionView[]> {
    const query = new URLSearchParams({ take: String(Math.min(Math.max(options.limit ?? 20, 1), 100)) });
    if (options.device !== undefined) {
      query.set('deviceId', pickDevice(await this.get<ApiDevice[]>('devices'), options.device).id);
    }
    if (options.failedOnly) {
      query.set('state', 'failed');
    }
    const answer = await this.get<ApiSession[] | { items: ApiSession[] }>(`sessions?${query}`);
    return (Array.isArray(answer) ? answer : answer.items).map((session) => ({
      id: session.id,
      device: session.deviceName,
      from: `${session.initiatorType} ${session.initiatorName}`,
      services: session.services,
      state: session.state,
      mode: optional(session.mode),
      endToEndEncrypted: optional(session.endToEndEncrypted),
      directFailureReason: optional(session.directFailureReason),
      endReason: optional(session.endReason),
      requestedAt: session.requestedAt,
      establishedAt: optional(session.establishedAt),
      endedAt: optional(session.endedAt),
    }));
  }

  private deviceView(device: ApiDevice, keys: readonly ApiKey[]): DeviceView {
    const label = (id: string): string => {
      const key = keys.find((candidate) => candidate.id === id);
      return key ? `${key.name} (${prefixOf(key)})` : id;
    };
    const allowed = device.allowedClientIds ?? [];
    return {
      name: device.slug,
      id: device.id,
      alias: optional(device.alias),
      online: device.online,
      status: device.status,
      lastSeenAt: optional(device.lastSeenAt),
      services: (device.services ?? []).filter((service) => service.declared && service.enabled).map((service) => service.name),
      key: device.keyId ? label(device.keyId) : undefined,
      allowedKeys: allowed.length > 0 ? allowed.map(label) : undefined,
      platform: optional(device.platform),
      agentVersion: optional(device.agentVersion),
      capabilities: device.capabilities ?? [],
    };
  }

  private get<T>(path: string): Promise<T> {
    return this.send<T>('GET', path);
  }

  private async send<T>(method: string, path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = { Accept: 'application/json', Authorization: `Bearer ${await this.accessToken()}` };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    let status: number;
    let text: string;
    try {
      const response = await this.platform.fetch(this.base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      status = response.status;
      text = await response.text();
    } catch (error) {
      throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, `The Connectivitizer API at ${this.api.baseUrl} could not be reached.`, { cause: error });
    }
    let parsed: unknown = null;
    try {
      parsed = text.length > 0 ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    if (status >= 200 && status < 300) {
      return parsed as T;
    }
    const failure = parsed as { error?: unknown; message?: unknown } | null;
    const code = typeof failure?.error === 'string' ? failure.error : status === 401 ? ErrorCodes.Unauthenticated : ErrorCodes.SignalingUnavailable;
    // The API answers "not found" for a workspace a key may not manage.
    const hint = status === 404 && path.split('?')[0].split('/').length === 1 ? ' The key this program is signed in with may not manage the workspace.' : '';
    throw new ConnectivitizerError(code, (typeof failure?.message === 'string' ? failure.message : `The API refused the request (${status} ${code}).`) + hint);
  }

  private async accessToken(): Promise<string> {
    if (this.token === null || Date.now() > this.token.until) {
      const answer = await this.api.credentialToken(this.login.apiKey);
      this.token = { value: answer.accessToken, until: Date.now() + Math.max(answer.expiresIn - 60, 10) * 1000 };
    }
    return this.token.value;
  }
}

function prefixOf(key: ApiKey): string {
  return `${prefixes[key.kind] ?? 'czk'}_${key.keyPrefix}`;
}

function keyView(key: ApiKey, devices: readonly ApiDevice[]): KeyView {
  const expired = key.expiresAt !== null && key.expiresAt !== undefined && Date.parse(key.expiresAt) < Date.now();
  const everything = key.accessRules.some((rule) => !rule.deviceId && !rule.serviceName);
  const entries = key.accessRules.map((rule) => {
    const device = rule.deviceId ? (devices.find((candidate) => candidate.id === rule.deviceId)?.slug ?? rule.deviceId) : '*';
    return rule.serviceName ? `${device}/${rule.serviceName}` : device;
  });
  return {
    name: key.name,
    id: key.id,
    kind: key.kind,
    prefix: prefixOf(key),
    status: key.revokedAt ? 'revoked' : expired ? 'expired' : 'active',
    maySessions: key.canConnect,
    managesWorkspace: key.canManage,
    reach: !key.canConnect || entries.length === 0 ? 'none' : everything ? 'all' : entries,
    devices: key.kind === 'device' ? (key.deviceCount ?? 0) : undefined,
    expiresAt: optional(key.expiresAt),
    lastUsedAt: optional(key.lastUsedAt),
  };
}

function rulesOf(reach: Reach, devices: readonly ApiDevice[]): ApiRule[] {
  if (reach === 'all') {
    return [{}];
  }
  if (reach === 'none') {
    return [];
  }
  return reach.map((entry) => ({ deviceId: entry.device === '*' ? undefined : pickDevice(devices, entry.device).id, serviceName: entry.service || undefined }));
}

function pickDevice(devices: readonly ApiDevice[], wanted: string): ApiDevice {
  const matches = devices.filter((device) => device.id === wanted || same(device.slug, wanted) || same(device.name, wanted));
  const found = matches.length > 0 ? matches : devices.filter((device) => same(device.alias, wanted));
  if (found.length === 1) {
    return found[0];
  }
  const names = devices.map((device) => device.slug).join(', ') || 'none';
  throw new ConnectivitizerError(
    ErrorCodes.DeviceNotFound,
    found.length === 0 ? `The workspace has no device "${wanted}". Its devices: ${names}.` : `"${wanted}" fits several devices. Use the name or the id of one: ${found.map((d) => `${d.slug} (${d.id})`).join(', ')}.`,
  );
}

function pickKey(keys: readonly ApiKey[], wanted: string): ApiKey {
  // A prefix as the web app shows it, with or without "czd_", or the beginning of a whole key somebody pasted.
  const prefix = /^cz[dk]_([0-9a-f]{10})/.exec(wanted)?.[1] ?? wanted;
  const byId = keys.filter((key) => key.id === wanted || key.keyPrefix === prefix);
  const live = keys.filter((key) => !key.revokedAt && same(key.name, wanted));
  const found = byId.length > 0 ? byId : live.length > 0 ? live : keys.filter((key) => same(key.name, wanted));
  if (found.length === 1) {
    return found[0];
  }
  const names = keys.filter((key) => !key.revokedAt).map((key) => `${key.name} (${prefixOf(key)})`).join(', ') || 'none';
  throw new ConnectivitizerError(
    ErrorCodes.NotFound,
    found.length === 0 ? `The workspace has no key "${wanted}". Its keys: ${names}.` : `"${wanted}" fits several keys. Use the prefix of one: ${found.map((key) => `${key.name} (${prefixOf(key)})`).join(', ')}.`,
  );
}
