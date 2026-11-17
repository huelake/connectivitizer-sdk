// The state directory of an endpoint and pairing, in the files and formats `cz` and the .NET
// library use. A Node.js application and `cz` can share one directory, and the two strings of a
// pairing can travel between a Node.js endpoint and a `cz` endpoint in either direction.

import { createHash, createHmac, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes, sign, timingSafeEqual } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import type { ServiceOptions } from '../core/agent.js';
import { PlatformApi, type TokenResponse } from '../core/api.js';
import { type SharedKey, parseSharedKey } from '../core/noise.js';
import type { Platform } from '../core/platform.js';
import { EndpointIdentity, type TrustedIdentity, TrustStore, normalizeFingerprint } from './certificates.js';
import { nodePlatform } from './platform.js';

const IDENTITY_CERTIFICATE_FILE = 'identity.cert.pem';
const IDENTITY_KEY_FILE = 'identity.key.pem';
const TRUST_FILE = 'trust.json';
const PAIRINGS_FILE = 'pairings.json';
const SHARED_KEYS_FILE = 'sharedkeys.json';
const DEVICE_FILE = 'device.json';
const AUTH_KEY_FILE = 'auth.key.pem';
const SERVICES_FILE = 'services.json';
const WORKSPACE_FILE = 'workspace.json';

/** What `cz device login` or `cz device enroll` recorded about this machine as a device. */
export interface DeviceRegistration {
  apiUrl: string;
  deviceId: string;
  workspaceId: string;
  name: string;
  slug?: string;
  /** Present for a device that logs in with a device key. */
  deviceKey?: string;
}

/** A sign-in of this installation to a workspace, with a key that may manage it (`connectivitizer login`). */
export interface WorkspaceLogin {
  apiUrl: string;
  apiKey: string;
  workspaceId: string;
  workspaceName: string;
  /** The name the key has in the workspace. */
  client: string;
  credentialId: string;
  /** When the key stops working (ISO 8601). */
  expiresAt?: string;
}

interface PendingPairing {
  secret: string;
  createdAt: string;
}

const base64Url = (bytes: Uint8Array): string => Buffer.from(bytes).toString('base64url');

/**
 * Keys, trust and settings of one installation, as files in a directory that only its owner can
 * read. The default is the directory `cz` uses: `CONNECTIVITIZER_HOME`, else `connectivitizer`
 * in the user's application-data folder.
 */
export class StateDirectory {
  readonly path: string;

  constructor(path?: string) {
    this.path = resolve(path ?? StateDirectory.defaultPath());
    mkdirSync(this.path, { recursive: true });
    restrictToOwner(this.path, true);
  }

  static defaultPath(): string {
    const configured = process.env.CONNECTIVITIZER_HOME?.trim();
    if (configured) {
      return configured;
    }
    const applicationData =
      process.platform === 'win32'
        ? (process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'))
        : process.platform === 'darwin'
          ? join(homedir(), 'Library', 'Application Support')
          : (process.env.XDG_CONFIG_HOME?.trim() || join(homedir(), '.config'));
    return join(applicationData, 'connectivitizer');
  }

  get hasIdentity(): boolean {
    return existsSync(this.file(IDENTITY_CERTIFICATE_FILE)) && existsSync(this.file(IDENTITY_KEY_FILE));
  }

  loadIdentity(): EndpointIdentity {
    return EndpointIdentity.fromPem(readFileSync(this.file(IDENTITY_CERTIFICATE_FILE), 'utf8'), readFileSync(this.file(IDENTITY_KEY_FILE), 'utf8'));
  }

  /** The identity of this installation; created, with its key, on first use. */
  loadOrCreateIdentity(name: string): EndpointIdentity {
    if (this.hasIdentity) {
      return this.loadIdentity();
    }
    const identity = EndpointIdentity.create(name);
    this.saveIdentity(identity);
    return identity;
  }

  saveIdentity(identity: EndpointIdentity): void {
    this.writePrivate(IDENTITY_KEY_FILE, identity.exportPrivateKeyPem());
    writeFileSync(this.file(IDENTITY_CERTIFICATE_FILE), identity.certificatePem);
  }

  /** The trust store of this installation. Every change is written to `trust.json` at once. */
  openTrustStore(): TrustStore {
    const initial = this.readJson<{ identities?: TrustedIdentity[] }>(TRUST_FILE)?.identities ?? [];
    return new TrustStore(initial, (identities) => writeFileSync(this.file(TRUST_FILE), JSON.stringify({ identities }, null, 2)));
  }

  loadSharedKeys(): SharedKey[] {
    const keys = this.readJson<{ keys?: { name: string; key: string }[] }>(SHARED_KEYS_FILE)?.keys ?? [];
    return keys.map((entry) => parseSharedKey(entry.key, entry.name));
  }

  /** Stores shared keys in their text form (`czs_…`), under the names this endpoint calls them. */
  saveSharedKeys(keys: readonly { name: string; key: string }[]): void {
    for (const entry of keys) {
      parseSharedKey(entry.key, entry.name);
    }
    this.writePrivate(SHARED_KEYS_FILE, JSON.stringify({ keys: keys.map(({ name, key }) => ({ name, key: key.trim() })) }, null, 2));
  }

  loadDevice(): DeviceRegistration | null {
    return this.readJson<DeviceRegistration>(DEVICE_FILE);
  }

  saveDevice(registration: DeviceRegistration): void {
    this.writePrivate(DEVICE_FILE, JSON.stringify(registration, null, 2));
  }

  get hasAuthKey(): boolean {
    return existsSync(this.file(AUTH_KEY_FILE));
  }

  /** The key an enrolled device logs in with (ECDSA P-256). Created on first use; it never leaves the device. */
  loadOrCreateAuthKey(): KeyObject {
    if (this.hasAuthKey) {
      return createPrivateKey(readFileSync(this.file(AUTH_KEY_FILE), 'utf8'));
    }
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    this.writePrivate(AUTH_KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }) as string);
    return privateKey;
  }

  /** The services `cz service add` declared, with their allow-lists. */
  loadServices(): Record<string, ServiceOptions> {
    const services = this.readJson<{ services?: { name: string; target: string; protocol?: string; allow?: string[] }[] }>(SERVICES_FILE)?.services ?? [];
    return Object.fromEntries(services.map((service) => [service.name, { target: service.target, protocol: service.protocol ?? 'tcp', allow: service.allow ?? undefined }]));
  }

  /** The workspace this installation is signed in to, if any. */
  loadWorkspaceLogin(): WorkspaceLogin | null {
    return this.readJson<WorkspaceLogin>(WORKSPACE_FILE);
  }

  saveWorkspaceLogin(login: WorkspaceLogin): void {
    this.writePrivate(WORKSPACE_FILE, JSON.stringify(login, null, 2));
  }

  removeWorkspaceLogin(): void {
    rmSync(this.file(WORKSPACE_FILE), { force: true });
  }

  /** @internal */
  loadPendingPairings(): PendingPairing[] {
    return this.readJson<{ pending?: PendingPairing[] }>(PAIRINGS_FILE)?.pending ?? [];
  }

  /** @internal */
  savePendingPairings(pending: readonly PendingPairing[]): void {
    this.writePrivate(PAIRINGS_FILE, JSON.stringify({ pending }, null, 2));
  }

  private file(name: string): string {
    return join(this.path, name);
  }

  private readJson<T>(name: string): T | null {
    const path = this.file(name);
    // .NET writes these files without a byte-order mark, but an editor may have added one.
    return existsSync(path) ? (JSON.parse(readFileSync(path, 'utf8').replace(/^﻿/, '')) as T) : null;
  }

  private writePrivate(name: string, content: string): void {
    const path = this.file(name);
    writeFileSync(path, content);
    restrictToOwner(path, false);
  }
}

function restrictToOwner(path: string, isDirectory: boolean): void {
  // On Windows the per-user profile folder already limits access to the user.
  if (process.platform !== 'win32') {
    chmodSync(path, isDirectory ? 0o700 : 0o600);
  }
}

// ---------------------------------------------------------------- enrolled devices

const signP1363 = (key: KeyObject, data: Uint8Array): string => sign('sha256', data, { key, dsaEncoding: 'ieee-p1363' }).toString('base64');

const sha256Hex = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');

/**
 * Enrolls this installation as a device with a one-time token (`cze_…`), as `cz device enroll`
 * does: the login key and the identity are made here, and only their public halves and proofs
 * of possession are sent. Records the result in the state directory.
 */
export async function enrollDevice(
  state: StateDirectory,
  apiUrl: string,
  enrollmentToken: string,
  name: string,
  options: { platform?: Platform; agentVersion?: string } = {},
): Promise<DeviceRegistration> {
  const platform = options.platform ?? nodePlatform();
  const authKey = state.loadOrCreateAuthKey();
  const identity = state.loadOrCreateIdentity(name);
  const authPublicKey = createPublicKey(authKey);
  const authPublicKeyPem = authPublicKey.export({ type: 'spki', format: 'pem' }) as string;
  const timestamp = Math.floor(Date.now() / 1000);
  const proof = Buffer.from(
    `cz-enroll-v1|${sha256Hex(enrollmentToken)}|${timestamp}|${sha256Hex(authPublicKey.export({ type: 'spki', format: 'der' }))}|${identity.fingerprint}`,
    'ascii',
  );
  const enrolled = await new PlatformApi(apiUrl, platform).enroll({
    token: enrollmentToken,
    name,
    platform: platform.description,
    agentVersion: options.agentVersion,
    authPublicKeyPem,
    identityCertificatePem: identity.certificatePem,
    timestamp,
    authSignature: signP1363(authKey, proof),
    identitySignature: Buffer.from(identity.sign(proof)).toString('base64'),
  });
  const registration: DeviceRegistration = { apiUrl, deviceId: enrolled.deviceId, workspaceId: enrolled.workspaceId, name: enrolled.name, slug: enrolled.slug };
  state.saveDevice(registration);
  return registration;
}

/**
 * What a state directory contributes to `createAgent`: how the device logs in (as `cz device
 * enroll` or `cz device login` left it), its identity and trust store, its shared keys and the
 * services declared with `cz service add`. Spread it into the options and override what the
 * application decides itself:
 *
 * ```ts
 * createAgent({ ...agentOptionsFrom(state), services: { api: '127.0.0.1:8080' } })
 * ```
 */
export function agentOptionsFrom(state: StateDirectory): {
  apiUrl: string;
  deviceKey?: string;
  name?: string;
  login?: (api: PlatformApi) => Promise<TokenResponse>;
  identity?: EndpointIdentity;
  trust?: TrustStore;
  sharedKey?: SharedKey[];
  services: Record<string, ServiceOptions>;
} {
  const device = state.loadDevice();
  if (!device) {
    throw new Error(`${state.path} holds no device: enroll it (enrollDevice, cz device enroll) or log it in with a device key first.`);
  }
  const sharedKeys = state.loadSharedKeys();
  const certificates = state.hasIdentity ? { identity: state.loadIdentity(), trust: state.openTrustStore() } : {};
  const common = { apiUrl: device.apiUrl, ...certificates, sharedKey: sharedKeys.length > 0 ? sharedKeys : undefined, services: state.loadServices() };
  if (device.deviceKey) {
    return { ...common, deviceKey: device.deviceKey, name: device.name };
  }
  if (!state.hasAuthKey) {
    throw new Error(`${state.path} holds an enrolled device but not its login key (auth.key.pem).`);
  }
  const authKey = state.loadOrCreateAuthKey();
  return {
    ...common,
    login: async (api) => {
      const { challenge } = await api.deviceChallenge(device.deviceId);
      return api.deviceToken(device.deviceId, challenge, signP1363(authKey, Buffer.from(`cz-device-auth-v1|${challenge}`, 'ascii')));
    },
  };
}

// ---------------------------------------------------------------- pairing

const INVITATION_PREFIX = 'czp1.';
const RESPONSE_PREFIX = 'czr1.';
const INVITATION_LIFETIME_MS = 30 * 60_000;

const isOpen = (pending: PendingPairing): boolean => Date.parse(pending.createdAt) + INVITATION_LIFETIME_MS > Date.now();

/** Binds the response to both identities and the responder's name, keyed with the invitation's secret. */
const pairingMac = (secret: Uint8Array, inviterFingerprint: string, responderFingerprint: string, responderName: string): Buffer =>
  createHmac('sha256', secret).update(`cz-pair-v1|${inviterFingerprint}|${responderFingerprint}|${responderName}`, 'utf8').digest();

function decode<T>(text: string, prefix: string): T | null {
  const trimmed = text.trim();
  if (!trimmed.startsWith(prefix)) {
    return null;
  }
  try {
    return JSON.parse(Buffer.from(trimmed.slice(prefix.length), 'base64url').toString('utf8')) as T;
  } catch {
    return null;
  }
}

/**
 * Step 1, on the endpoint that invites (usually the device): an invitation with this endpoint's
 * name, its fingerprint and a fresh secret. The secret stays in the state directory.
 *
 * The invitation should travel over a channel the user trusts. Whoever observes it gains only
 * the ability to be pinned by this endpoint; reaching a service also needs a credential and an
 * access rule of the platform.
 */
export function createInvitation(state: StateDirectory, identity: EndpointIdentity, ownName: string): string {
  if (!ownName.trim()) {
    throw new Error('Pairing needs the name of this endpoint.');
  }
  const secret = base64Url(randomBytes(32));
  state.savePendingPairings([...state.loadPendingPairings().filter(isOpen), { secret, createdAt: new Date().toISOString() }]);
  return INVITATION_PREFIX + base64Url(Buffer.from(JSON.stringify({ peer: ownName.trim(), fp: identity.fingerprint, k: secret }), 'utf8'));
}

/**
 * Step 2, on the other endpoint: pins the inviting endpoint and returns the response to hand
 * back to it.
 *
 * @param pinAs Name to pin the inviting endpoint under; the name in the invitation otherwise.
 */
export function acceptInvitation(invitation: string, identity: EndpointIdentity, ownName: string, trust: TrustStore, pinAs?: string): { response: string; pinned: TrustedIdentity } {
  if (!ownName.trim()) {
    throw new Error('Pairing needs the name of this endpoint.');
  }
  const parsed = decode<{ peer?: string; fp?: string; k?: string }>(invitation, INVITATION_PREFIX);
  if (!parsed) {
    throw new Error('This is not a pairing invitation.');
  }
  const peerFingerprint = normalizeFingerprint(parsed.fp);
  if (!peerFingerprint || !parsed.peer?.trim() || typeof parsed.k !== 'string' || !/^[A-Za-z0-9_-]+$/.test(parsed.k)) {
    throw new Error('The pairing invitation is damaged.');
  }
  const pinned = trust.pin(peerFingerprint, pinAs ?? parsed.peer, 'pairing');
  const mac = pairingMac(Buffer.from(parsed.k, 'base64url'), peerFingerprint, identity.fingerprint, ownName.trim());
  const response = RESPONSE_PREFIX + base64Url(Buffer.from(JSON.stringify({ peer: ownName.trim(), fp: identity.fingerprint, mac: base64Url(mac) }), 'utf8'));
  return { response, pinned };
}

/**
 * Step 3, on the inviting endpoint: the response is accepted only if it was made with the
 * secret of one of this endpoint's open invitations, which is then used up.
 */
export function completePairing(response: string, state: StateDirectory, identity: EndpointIdentity, trust: TrustStore): TrustedIdentity {
  const parsed = decode<{ peer?: string; fp?: string; mac?: string }>(response, RESPONSE_PREFIX);
  if (!parsed) {
    throw new Error('This is not a pairing response.');
  }
  const peerFingerprint = normalizeFingerprint(parsed.fp);
  if (!peerFingerprint || !parsed.peer?.trim() || typeof parsed.mac !== 'string' || !/^[A-Za-z0-9_-]+$/.test(parsed.mac)) {
    throw new Error('The pairing response is damaged.');
  }
  const presented = Buffer.from(parsed.mac, 'base64url');
  const pending = state.loadPendingPairings();
  const match = pending.find((candidate) => {
    const expected = pairingMac(Buffer.from(candidate.secret, 'base64url'), identity.fingerprint, peerFingerprint, parsed.peer!);
    return isOpen(candidate) && expected.length === presented.length && timingSafeEqual(expected, presented);
  });
  if (!match) {
    throw new Error('The response does not belong to an open invitation of this endpoint (it may have expired or already been used).');
  }
  state.savePendingPairings(pending.filter((candidate) => candidate !== match));
  return trust.pin(peerFingerprint, parsed.peer, 'pairing');
}
