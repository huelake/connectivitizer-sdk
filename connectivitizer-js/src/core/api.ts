import { ConnectivitizerError, ErrorCodes } from './errors.js';
import { type GrantKeys, type GrantValidation, parseJwks, readKeyId, validateGrant } from './grants.js';
import type { Platform } from './platform.js';

// The machine-facing REST calls of the control plane (protocol section 11).

export interface TokenResponse {
  accessToken: string;
  expiresIn: number;
  endpointType: string;
  endpointId: string;
  workspaceId: string;
  /** The control plane's clock, Unix seconds. */
  serverTime?: number;
  /** Device logins: the name the device is addressed by. */
  slug?: string;
}

/** A certificate and the proof that its key belongs to the caller (protocol section 11.3). */
export interface IdentityRegistration {
  identityCertificatePem: string;
  timestamp: number;
  identitySignature: string;
}

export interface EnrollRequest {
  token: string;
  name: string;
  platform?: string;
  agentVersion?: string;
  authPublicKeyPem: string;
  identityCertificatePem: string;
  timestamp: number;
  /** Both signatures are over the same proof string, base64 of the 64-byte r||s form. */
  authSignature: string;
  identitySignature: string;
}

export interface EnrollResponse {
  deviceId: string;
  workspaceId: string;
  name: string;
  slug: string;
}

export interface LinkStartResponse {
  userCode: string;
  deviceCode: string;
  verificationUrl: string;
  verificationUrlComplete: string;
  expiresIn: number;
  interval: number;
}

export interface LinkTokenResponse {
  status: 'pending' | 'approved' | string;
  apiKey?: string;
  workspaceId?: string;
  workspaceName?: string;
  credentialId?: string;
  client?: string;
}

/** A device an application may open sessions to. */
export interface ReachableDevice {
  id: string;
  /** What the device calls itself. */
  name: string;
  /** The name sessions are opened to. */
  slug: string;
  /** A name people gave the device in the web app. */
  alias?: string | null;
  online: boolean;
  /** What the device's software announced; empty while it is offline. `path.udp-kcp` means it offers peer-to-peer. */
  capabilities: string[];
  /** The services of the device this application may use. */
  services: string[];
}

export class PlatformApi {
  readonly baseUrl: string;

  constructor(
    apiUrl: string,
    private readonly platform: Platform,
  ) {
    this.baseUrl = apiUrl.replace(/\/+$/, '') + '/';
  }

  /** The signaling endpoint that belongs to this API. */
  get signalUrl(): string {
    return this.baseUrl.replace(/^http/, 'ws') + 'v1/signal';
  }

  /** Exchanges an application's API key for an access token, registering its certificate if it has one. */
  credentialToken(apiKey: string, identity?: IdentityRegistration): Promise<TokenResponse> {
    return this.post<TokenResponse>('v1/auth/credential/token', { apiKey, ...identity });
  }

  /** Logs a device in with a device key and its name. The first login under a name creates the device. */
  deviceKeyToken(key: string, name: string, platformName?: string, agentVersion?: string, identity?: IdentityRegistration): Promise<TokenResponse> {
    return this.post<TokenResponse>('v1/auth/device-key/token', { key, name, platform: platformName, agentVersion, ...identity });
  }

  /**
   * For an application whose user is signed in: exchanges the user's access token for a token to
   * connect with, as the client `client` of the workspace.
   */
  appToken(userAccessToken: string, workspaceId: string, client: string): Promise<TokenResponse> {
    return this.post<TokenResponse>('v1/auth/app/token', { workspaceId, client }, userAccessToken);
  }

  /**
   * Enrolls a device with a one-time token (protocol section 11.2). The caller made both keys
   * itself; only their public halves and proofs of possession are sent.
   */
  enroll(request: EnrollRequest): Promise<EnrollResponse> {
    return this.post<EnrollResponse>('v1/devices/enroll', request);
  }

  /** The challenge an enrolled device signs with its login key. */
  deviceChallenge(deviceId: string): Promise<{ challenge: string; expiresIn: number }> {
    return this.post('v1/auth/device/challenge', { deviceId });
  }

  /** Logs an enrolled device in with the signature over its challenge. */
  deviceToken(deviceId: string, challenge: string, signature: string): Promise<TokenResponse> {
    return this.post<TokenResponse>('v1/auth/device/token', { deviceId, challenge, signature });
  }

  /** An app asks to be linked to somebody's account. Nothing is granted until that person approves in the web app. */
  startLink(client: string, platformName?: string): Promise<LinkStartResponse> {
    return this.post<LinkStartResponse>('v1/auth/link', { client, platform: platformName });
  }

  /** Whether a link was approved: "pending", or "approved" with the API key - once. Refused and expired links reject. */
  pollLink(deviceCode: string): Promise<LinkTokenResponse> {
    return this.post<LinkTokenResponse>('v1/auth/link/token', { deviceCode });
  }

  /** The devices the application behind `accessToken` may open sessions to. */
  reachableDevices(accessToken: string): Promise<ReachableDevice[]> {
    return this.request('GET', 'v1/devices', undefined, accessToken) as Promise<ReachableDevice[]>;
  }

  /** The public keys session grants are signed with. */
  async grantKeys(): Promise<GrantKeys> {
    return parseJwks(await this.request('GET', '.well-known/jwks.json'));
  }

  private post<T>(path: string, body: unknown, bearer?: string): Promise<T> {
    return this.request('POST', path, body, bearer) as Promise<T>;
  }

  private async request(method: string, path: string, body?: unknown, bearer?: string): Promise<unknown> {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (bearer) {
      headers.Authorization = `Bearer ${bearer}`;
    }

    let status: number;
    let text: string;
    try {
      const response = await this.platform.fetch(this.baseUrl + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
      status = response.status;
      text = await response.text();
    } catch (error) {
      throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, `The Connectivitizer API at ${this.baseUrl} could not be reached.`, { cause: error });
    }

    let parsed: unknown = null;
    try {
      parsed = text.length > 0 ? JSON.parse(text) : null;
    } catch {
      parsed = null;
    }
    // Only the API names its refusals. An answer without a code comes from something in between (a proxy while
    // the API restarts, a captive portal) and is a passing failure: devices keep retrying instead of giving up.
    if (status >= 200 && status < 300) {
      if (parsed === null) {
        throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, 'The API returned an empty response.');
      }
      return parsed;
    }
    const failure = parsed as { error?: unknown; message?: unknown } | null;
    const code = typeof failure?.error === 'string' ? failure.error : status === 401 ? ErrorCodes.Unauthenticated : ErrorCodes.SignalingUnavailable;
    throw new ConnectivitizerError(code, typeof failure?.message === 'string' ? failure.message : `The API refused the request (${status} ${code}).`);
  }
}

/** Verifies grants offline with the control plane's published keys, fetching them when a new key id appears. */
export class GrantVerifier {
  private static readonly minRefreshMs = 30_000;
  private keys: GrantKeys = new Map();
  private lastRefresh = Number.NEGATIVE_INFINITY;
  private refreshing: Promise<void> | null = null;

  constructor(
    private readonly api: PlatformApi,
    private readonly nowSeconds: () => number,
  ) {}

  async validate(token: string, forSessionStart: boolean): Promise<GrantValidation> {
    const keyId = readKeyId(token);
    if (keyId === null) {
      return { error: ErrorCodes.GrantInvalid };
    }
    if (!this.keys.has(keyId)) {
      await this.refresh();
    }
    return this.validateKnown(token, forSessionStart);
  }

  /** Validates with the keys already known (for in-session lease renewals, which must not wait on the network). */
  validateKnown(token: string, forSessionStart: boolean): GrantValidation {
    return validateGrant(token, this.keys, this.nowSeconds(), forSessionStart);
  }

  private refresh(): Promise<void> {
    if (this.refreshing) {
      return this.refreshing;
    }
    if (Date.now() - this.lastRefresh < GrantVerifier.minRefreshMs) {
      return Promise.resolve();
    }
    this.lastRefresh = Date.now();
    this.refreshing = this.api
      .grantKeys()
      .then((keys) => {
        this.keys = keys;
      })
      // Without keys the grant simply does not validate; the caller reports GRANT_INVALID.
      .catch(() => undefined)
      .finally(() => {
        this.refreshing = null;
      });
    return this.refreshing;
  }
}
