import { GrantVerifier, PlatformApi, type ReachableDevice, type TokenResponse } from './api.js';
import { base64Decode, base64Encode } from './bytes.js';
import { DirectAttempt, DirectFailureReasons, peerReflexiveFor } from './direct/attempt.js';
import { ConnectivitizerError, ErrorCodes, codeOf } from './errors.js';
import { Capabilities, ConnectionModes, E2eMethods, Roles, type SessionGrant, e2eMethodOf } from './grants.js';
import { type SharedKey, parseSharedKey } from './noise.js';
import type { Platform } from './platform.js';
import { RelayPath } from './relayPath.js';
import { type SecureLayer, TunnelSession } from './session.js';
import { type SignalConnectGrant, type SignalEnvelope, SignalingClient } from './signaling.js';
import { Deferred, delay, settledWithin, withTimeout } from './streams.js';

export interface ClientOptions {
  /** Base URL of the Connectivitizer API, e.g. `https://api.connectivitizer.com/api/connectivitizer`. */
  apiUrl: string;

  /**
   * How the application authenticates:
   *  - `apiKey`: with its API key (`czk_…`);
   *  - `signIn`: as an application whose user signed in with a Connectivitizer account. The
   *    workspace is the one the user chose; `client` is the name the application appears under
   *    in that workspace;
   *  - `getToken`: with a function that returns a fresh token, for anything else.
   */
  auth: { apiKey: string } | { signIn: SignInOptions } | { getToken: () => Promise<TokenResponse> };

  /**
   * The key (or keys) this application shares with devices, as `czs_…` text or parsed. With
   * several, the one named like the device is used, else the one named `default`. The platform
   * never sees them.
   */
  sharedKey?: string | SharedKey | readonly SharedKey[];

  /** When true, never attempt a peer-to-peer connection and always use the relay. */
  disableDirect?: boolean;

  /** STUN servers (`host:port`) to learn the public address from, instead of the ones the platform announces. */
  stunServers?: readonly string[];

  /** Certificate layer of the runtime, where there is one (Node.js). Set by the platform adapter. */
  certificates?: CertificateSupport;

  platform: Platform;
}

export interface SignInOptions {
  workspaceId: string;

  /** The name of this application, e.g. `example-app`. Devices can be restricted to named clients. */
  client: string;

  /** The signed-in user's access token, refreshed by the application as needed. */
  getAccessToken: () => Promise<string>;
}

/** What a runtime that can do the certificate layer contributes to a client or an agent. */
export interface CertificateSupport {
  /** Fingerprint of this endpoint's identity, announced to the platform. */
  fingerprint: string;
  /** PEM of the certificate plus the proof that registers it (protocol section 11.3). */
  registration(secret: string, timestamp: number): { identityCertificatePem: string; timestamp: number; identitySignature: string };
  /** True when a certificate of the device is pinned locally (then certificates are preferred over a shared key). */
  hasPinFor(device: string): boolean;
  /** The layer for one session, given what the platform said about the peer. */
  layerFor(device: string, peer: { id: string; name?: string }, grant: SessionGrant): SecureLayer;
}

const ANSWER_TIMEOUT_MS = 15_000;
/** How long a direct path is looked for before the relay is used instead. */
const DIRECT_BUDGET_MS = 3_000;

function toKeys(value: ClientOptions['sharedKey']): SharedKey[] {
  if (value === undefined) {
    return [];
  }
  if (typeof value === 'string') {
    return [parseSharedKey(value)];
  }
  return Array.isArray(value) ? [...(value as readonly SharedKey[])] : [value as SharedKey];
}

/**
 * The calling side: an application that connects to services on devices.
 *
 * ```ts
 * const client = createClient({ apiUrl, auth: { apiKey }, sharedKey });
 * const session = await client.connect('living-room-lamp', ['api']);
 * const response = await session.fetch('api', '/state');
 * console.log(session.info.mode); // direct or e2e-relay - as verified by this endpoint
 * ```
 */
export class ConnectivitizerClient {
  private readonly api: PlatformApi;
  private readonly grants: GrantVerifier;
  private readonly keys: SharedKey[];
  private readonly answers = new Map<string, Deferred<{ accept: boolean; error?: string }>>();
  private readonly candidates = new Map<string, Deferred<Uint8Array>>();
  private readonly sessions = new Map<string, TunnelSession>();
  private signaling: SignalingClient | null = null;
  private connecting: Promise<SignalingClient> | null = null;
  private clockOffset = 0;
  private closed = false;

  constructor(private readonly options: ClientOptions) {
    this.keys = toKeys(options.sharedKey);
    if (this.keys.length === 0 && !options.certificates) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'An application needs a shared key (or, in Node.js, a certificate identity): without either there is nothing to encrypt end to end with.');
    }
    this.api = new PlatformApi(options.apiUrl, options.platform);
    this.grants = new GrantVerifier(this.api, () => this.nowSeconds());
  }

  /** The current time by the control plane's clock, which is what grants are judged against. */
  private nowSeconds(): number {
    return Math.floor(Date.now() / 1000) + this.clockOffset;
  }

  /**
   * Opens a session to `device` (its name or id) for the named services. Rejects with a
   * {@link ConnectivitizerError}; there is no silent fallback to a weaker mode.
   */
  async connect(device: string, services: string[]): Promise<TunnelSession> {
    if (this.closed) {
      throw new ConnectivitizerError(ErrorCodes.SessionClosed, 'The client is closed.');
    }
    const sharedKey = this.selectSharedKey(device);
    const signaling = await this.ensureSignaling();

    const reply = await signaling.request('connect.request', { device, services, e2e: this.acceptableE2e(device, sharedKey) }, ANSWER_TIMEOUT_MS);
    const granted = reply.d as unknown as SignalConnectGrant;
    if (reply.t !== 'connect.grant' || !granted?.sid || !granted.grant || !granted.peer) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'The control plane sent an unexpected answer.');
    }
    const sessionId = granted.sid;

    let attempt: DirectAttempt | null = null;
    try {
      let answer: { accept: boolean; error?: string };
      try {
        answer = await withTimeout(this.waiter(this.answers, sessionId).promise, ANSWER_TIMEOUT_MS,
          () => new ConnectivitizerError(ErrorCodes.SignalingTimeout, 'The device did not answer the connection request in time.'));
      } finally {
        this.answers.delete(sessionId);
      }
      if (!answer.accept) {
        const code = answer.error ?? ErrorCodes.DeviceRejected;
        throw new ConnectivitizerError(code, `The device refused the connection (${code}).`);
      }

      const validation = await this.grants.validate(granted.grant, true);
      const grant = validation.grant;
      if (!grant || grant.jti !== sessionId) {
        throw new ConnectivitizerError(validation.error ?? ErrorCodes.GrantInvalid, 'The session grant could not be verified.');
      }
      if (grant.modes.includes(ConnectionModes.Compatibility)) {
        throw new ConnectivitizerError(ErrorCodes.NoPermittedMode, 'The session grant offers a mode this endpoint does not take part in.');
      }

      // The grant names the end-to-end layer; this endpoint must be able to run exactly that one.
      const method = e2eMethodOf(grant);
      const bySharedKey = method === E2eMethods.SharedKey;
      if (bySharedKey ? !sharedKey : method !== E2eMethods.Tls13 || !this.options.certificates) {
        throw new ConnectivitizerError(ErrorCodes.E2eNoCommonMethod, `The session was granted with the end-to-end layer '${method}', which this application is not set up for.`);
      }
      const certificateLayer = bySharedKey ? undefined : this.options.certificates!.layerFor(device, granted.peer, grant);
      const peerLabel = granted.peer.name ?? device;
      const common = {
        platform: this.options.platform,
        role: Roles.Initiator,
        grantToken: granted.grant,
        grant,
        sharedKeys: bySharedKey ? [sharedKey!] : undefined,
        certificateLayer,
        peerLabel,
        nowSeconds: () => this.nowSeconds(),
      };

      const peerCaps = granted.peer.caps ?? [];
      const relayPermitted = grant.modes.includes(ConnectionModes.E2eRelay) && !!grant.relay;
      const canDirect = !this.options.disableDirect && !!this.options.platform.udp;
      const peerSupportsDirect = peerCaps.includes(Capabilities.PathUdpKcp);
      const directPermitted = grant.modes.includes(ConnectionModes.Direct) && canDirect && peerSupportsDirect;
      let directFailure: string | undefined = directPermitted ? undefined
        : !canDirect || !peerSupportsDirect ? DirectFailureReasons.PeerNoDirectSupport
        : DirectFailureReasons.PolicyRelayOnly;

      let session: TunnelSession | null = null;
      if (directPermitted) {
        attempt = new DirectAttempt(this.options.platform, Roles.Initiator, sessionId, granted.grant, this.options.stunServers ?? signaling.welcome.stunServers ?? [], {
          peerReflexive: peerReflexiveFor(e2eMethodOf(grant)),
        });
        const current = attempt;
        void this.waiter(this.candidates, sessionId).promise.then((blob) => current.setRemoteCandidates(blob), () => undefined);
        const blob = await attempt.gather();
        signaling.send('path.candidates', { sid: sessionId, blob: base64Encode(blob) });

        const path = await attempt.open(DIRECT_BUDGET_MS);
        if (path === null) {
          directFailure = attempt.failureReason();
          if (relayPermitted) {
            signaling.send('path.fallback', { sid: sessionId, reason: directFailure });
          }
        } else {
          // A path exists. From here on a failure is a failure of the session - falling back to
          // the relay would not make the peer more trustworthy.
          session = await TunnelSession.establish({
            ...common,
            path: path.stream,
            mode: ConnectionModes.Direct,
            transport: 'udp-kcp',
            peerAddress: path.peerAddress,
            localCandidatesHash: attempt.localCandidatesHash,
            remoteCandidatesHash: attempt.remoteCandidatesHash,
          });
        }
      }

      if (session === null) {
        if (!relayPermitted) {
          // Nothing else is allowed for this session: say so instead of using a path that was not asked for.
          throw new ConnectivitizerError(ErrorCodes.DirectUnavailable, `A direct connection could not be established (${directFailure}) and relaying is not permitted for this session.`);
        }
        const relay = await RelayPath.connect(this.options.platform, grant.relay!, granted.grant, Roles.Initiator);
        session = await TunnelSession.establish({ ...common, path: relay.stream, relay, mode: ConnectionModes.E2eRelay, transport: 'relay-ws', directFailureReason: directFailure });
      }

      this.sessions.set(sessionId, session);
      this.report({ sid: sessionId, state: 'established', mode: session.info.mode, trust: session.info.trust, directFailureReason: session.info.directFailureReason, transport: session.info.transport });
      void this.watch(session);
      void this.renewLeases(session);
      return session;
    } catch (error) {
      this.report({ sid: sessionId, state: 'failed', error: codeOf(error) });
      throw error;
    } finally {
      this.candidates.delete(sessionId);
      attempt?.close();
    }
  }

  /**
   * The devices this application may open sessions to, with their names, whether they are
   * online and the services it may use: what an app shows its user to choose from.
   */
  async listDevices(): Promise<ReachableDevice[]> {
    const auth = this.options.auth;
    const token =
      'apiKey' in auth
        ? await this.api.credentialToken(auth.apiKey)
        : 'signIn' in auth
          ? await this.api.appToken(await auth.signIn.getAccessToken(), auth.signIn.workspaceId, auth.signIn.client)
          : await auth.getToken();
    return this.api.reachableDevices(token.accessToken);
  }

  /** Ends every session and the connection to the platform. */
  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    await Promise.all([...this.sessions.values()].map((session) => session.close()));
    // Give the end-of-session reports a moment to leave before the channel closes.
    await delay(50);
    this.signaling?.close();
  }

  /** The shared key for a device: the one named like it, else the only one, else the one named "default". */
  private selectSharedKey(device: string): SharedKey | null {
    const lower = device.toLowerCase();
    return this.keys.find((key) => key.name.toLowerCase() === lower)
      ?? (this.keys.length === 1 ? this.keys[0] : this.keys.find((key) => key.name.toLowerCase() === 'default') ?? null);
  }

  /**
   * The end-to-end layers to ask for, best first. A pinned certificate of the device is the
   * strongest statement about who it is; without one, a key shared with it comes first.
   */
  private acceptableE2e(device: string, sharedKey: SharedKey | null): string[] {
    const certificates = this.options.certificates;
    if (!sharedKey) {
      return [E2eMethods.Tls13];
    }
    if (!certificates) {
      return [E2eMethods.SharedKey];
    }
    return certificates.hasPinFor(device) ? [E2eMethods.Tls13, E2eMethods.SharedKey] : [E2eMethods.SharedKey, E2eMethods.Tls13];
  }

  private waiter<T>(map: Map<string, Deferred<T>>, sessionId: string): Deferred<T> {
    let waiter = map.get(sessionId);
    if (!waiter) {
      waiter = new Deferred<T>();
      map.set(sessionId, waiter);
    }
    return waiter;
  }

  private ensureSignaling(): Promise<SignalingClient> {
    if (this.signaling?.isOpen) {
      return Promise.resolve(this.signaling);
    }
    this.connecting ??= this.openSignaling().finally(() => {
      this.connecting = null;
    });
    return this.connecting;
  }

  private async openSignaling(): Promise<SignalingClient> {
    const { auth, certificates, platform } = this.options;
    let token: TokenResponse;
    let announceCertificate = false;
    if ('apiKey' in auth) {
      // A certificate is registered together with the token exchange, so only this way of signing in announces one.
      token = certificates
        ? await this.api.credentialToken(auth.apiKey, certificates.registration(auth.apiKey, Math.floor(Date.now() / 1000) + this.clockOffset))
        : await this.api.credentialToken(auth.apiKey);
      announceCertificate = !!certificates;
    } else if ('signIn' in auth) {
      token = await this.api.appToken(await auth.signIn.getAccessToken(), auth.signIn.workspaceId, auth.signIn.client);
    } else {
      token = await auth.getToken();
    }
    if (typeof token.serverTime === 'number') {
      this.clockOffset = token.serverTime - Math.floor(Date.now() / 1000);
    }

    const caps: string[] = [Capabilities.MuxYamux, Capabilities.PathRelayWs];
    if (announceCertificate) {
      caps.unshift(Capabilities.E2eTls13);
    }
    if (this.keys.length > 0) {
      caps.push(Capabilities.E2eSharedKey);
    }
    if (!this.options.disableDirect && platform.udp) {
      caps.push(Capabilities.PathUdpKcp);
    }
    const signaling = await SignalingClient.connect(platform, this.api.signalUrl, token.accessToken, {
      caps,
      fp: announceCertificate ? certificates!.fingerprint : undefined,
      platform: platform.description,
    });
    if (typeof signaling.welcome.serverTime === 'number') {
      this.clockOffset = signaling.welcome.serverTime - Math.floor(Date.now() / 1000);
    }
    signaling.onMessage = (message) => this.onSignal(message);
    this.signaling = signaling;
    return signaling;
  }

  private onSignal(message: SignalEnvelope): void {
    const data = message.d ?? {};
    const sessionId = typeof data.sid === 'string' ? data.sid : null;
    switch (message.t) {
      case 'connect.answer':
        if (sessionId) {
          this.waiter(this.answers, sessionId).resolve({ accept: data.accept === true, error: typeof data.error === 'string' ? data.error : undefined });
        }
        break;
      case 'path.candidates':
        if (sessionId && typeof data.blob === 'string') {
          try {
            this.waiter(this.candidates, sessionId).resolve(base64Decode(data.blob));
          } catch {
            // Not base64: as good as no candidates.
          }
        }
        break;
      case 'revoke': {
        const sids = Array.isArray(data.sids) ? (data.sids as string[]) : null;
        const reason = typeof data.reason === 'string' ? data.reason : ErrorCodes.SessionRevoked;
        for (const session of [...this.sessions.values()]) {
          if (sids === null || sids.includes(session.info.sessionId)) {
            void session.end(reason);
          }
        }
        break;
      }
      default:
        break;
    }
  }

  /** Tells the control plane when and why the session ended, with this endpoint's own traffic count. */
  private async watch(session: TunnelSession): Promise<void> {
    const reason = await session.completion;
    this.sessions.delete(session.info.sessionId);
    this.report({ sid: session.info.sessionId, state: 'ended', error: reason, bytesSent: session.bytesSent, bytesReceived: session.bytesReceived });
  }

  /** Keeps a running session authorised by fetching a new grant well before the lease ends. */
  private async renewLeases(session: TunnelSession): Promise<void> {
    while (!session.isEnded && !this.closed) {
      const remaining = session.leaseExpires - this.nowSeconds();
      const ended = await settledWithin(session.completion, Math.max(remaining / 2, 1) * 1000);
      if (ended || this.closed) {
        return;
      }
      try {
        const signaling = await this.ensureSignaling();
        const reply = await signaling.request('lease.request', { sid: session.info.sessionId }, ANSWER_TIMEOUT_MS);
        const token = reply.d?.grant;
        if (reply.t === 'lease.grant' && typeof token === 'string') {
          const renewed = this.grants.validateKnown(token, false).grant ?? (await this.grants.validate(token, false)).grant;
          if (renewed) {
            await session.renewLease(token, renewed);
          }
        }
      } catch (error) {
        const code = codeOf(error, '');
        const gone: string[] = [ErrorCodes.CredentialRevoked, ErrorCodes.DeviceRevoked, ErrorCodes.Forbidden, ErrorCodes.ServiceDisabled, ErrorCodes.ServiceNotExposed, ErrorCodes.SessionClosed, ErrorCodes.NotFound];
        if (gone.includes(code)) {
          // Authorisation is gone: end the session now instead of letting it run to the end of its lease.
          await session.end(code === ErrorCodes.NotFound || code === ErrorCodes.SessionClosed ? ErrorCodes.SessionRevoked : code);
          return;
        }
        // Control plane unreachable: keep trying until the lease runs out by itself.
      }
    }
  }

  private report(update: Record<string, unknown>): void {
    try {
      if (this.signaling?.isOpen) {
        this.signaling.send('session.update', update);
      }
    } catch {
      // Reporting is best effort; the session itself is unaffected.
    }
  }
}
