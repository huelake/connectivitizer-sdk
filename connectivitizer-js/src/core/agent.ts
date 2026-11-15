import { GrantVerifier, PlatformApi, type TokenResponse } from './api.js';
import { base64Decode, base64Encode } from './bytes.js';
import type { CertificateSupport } from './client.js';
import { DirectAttempt, peerReflexiveFor } from './direct/attempt.js';
import { ConnectivitizerError, ErrorCodes, codeOf } from './errors.js';
import { Capabilities, ConnectionModes, E2eMethods, Roles, type SessionGrant, e2eMethodOf } from './grants.js';
import { type SharedKey, parseSharedKey } from './noise.js';
import type { Platform } from './platform.js';
import { RelayPath } from './relayPath.js';
import { type ConnectionInfo, type PeerInfo, type ServiceResolution, type SessionParameters, TunnelSession } from './session.js';
import { type SignalConnectGrant, type SignalEnvelope, type SignalPeer, SignalingClient } from './signaling.js';
import { Deferred, delay, settledWithin, withTimeout } from './streams.js';

/** A local service a device exposes. The target never leaves the device. */
export interface ServiceOptions {
  /** `host:port` of the local application. */
  target: string;
  /** `http`, `ws` or `tcp`. Informational; every service is carried as a byte stream. */
  protocol?: string;
  /** Who may use the service: `key:<name>` for holders of that shared key, or certificate fingerprints. Absent: every peer the device trusts. */
  allow?: string[];
}

export interface AgentOptions {
  apiUrl: string;

  /** A device key of the workspace (`czd_…`). The first login under `name` creates the device. */
  deviceKey?: string;

  /** The device's name. It is how the device is addressed, so it does not change. */
  name?: string;

  /**
   * Instead of `deviceKey` and `name`: the login of a device that enrolled with a key of its own
   * making. The runtime that holds that key supplies it (Node.js: `agentOptionsFrom`).
   */
  login?: (api: PlatformApi) => Promise<TokenResponse>;

  /** The key (or keys) this device shares with the applications that connect, as `czs_…` text or parsed. */
  sharedKey?: string | SharedKey | readonly SharedKey[];

  /** The services this device exposes, by name. Nothing else is reachable. */
  services: Record<string, string | ServiceOptions>;

  /** When true, never attempt a peer-to-peer connection and always use the relay. */
  disableDirect?: boolean;

  stunServers?: readonly string[];

  agentVersion?: string;

  /** Receives one line per noteworthy event (connected, session accepted, refused, …). */
  log?: (message: string) => void;

  /** Certificate layer of the runtime, where there is one (Node.js). Set by the platform adapter. */
  certificates?: CertificateSupport & { trusts(fingerprint: string): boolean };

  platform: Platform;
}

const PATH_TIMEOUT_MS = 12_000;

function toKeys(value: AgentOptions['sharedKey']): SharedKey[] {
  if (value === undefined) {
    return [];
  }
  if (typeof value === 'string') {
    return [parseSharedKey(value)];
  }
  return Array.isArray(value) ? [...(value as readonly SharedKey[])] : [value as SharedKey];
}

function parseTarget(target: string): { host: string; port: number } {
  const colon = target.lastIndexOf(':');
  const port = Number.parseInt(target.substring(colon + 1), 10);
  if (colon <= 0 || Number.isNaN(port) || port < 1 || port > 65535) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, `'${target}' is not a valid target; expected host:port.`);
  }
  return { host: target.substring(0, colon).replace(/^\[|\]$/g, ''), port };
}

/**
 * The device side: keeps an outbound connection to the platform, and when an authorised
 * application that holds the shared key asks, opens a session and forwards its streams to local
 * services. Nothing is reachable that the device did not declare itself, and no port listens.
 */
export class ConnectivitizerAgent {
  private readonly api: PlatformApi;
  private readonly grants: GrantVerifier;
  private readonly keys: SharedKey[];
  private readonly services = new Map<string, { host: string; port: number; protocol: string; allow?: string[] }>();
  private readonly sessions = new Map<string, TunnelSession>();
  private readonly candidates = new Map<string, Deferred<Uint8Array>>();
  private readonly fallbacks = new Map<string, Deferred<string>>();
  private signaling: SignalingClient | null = null;
  private deviceId: string | null = null;
  private clockOffset = 0;
  private stopped = false;
  private readonly stopSignal = new Deferred<void>();
  private connected = new Deferred<void>();

  constructor(private readonly options: AgentOptions) {
    this.keys = toKeys(options.sharedKey);
    if (this.keys.length === 0 && !options.certificates) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A device needs a shared key (or, in Node.js, a certificate identity): without either nobody can reach it end to end.');
    }
    if (!options.login && !(options.deviceKey && options.name)) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A device logs in with a device key and its name, or with the login of an enrolled device.');
    }
    if (!options.platform.connectTcp) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'This runtime cannot open connections to local services, so it cannot be a device.');
    }
    for (const [name, value] of Object.entries(options.services)) {
      const service = typeof value === 'string' ? { target: value } : value;
      this.services.set(name, { ...parseTarget(service.target), protocol: service.protocol ?? 'tcp', allow: service.allow });
    }
    this.api = new PlatformApi(options.apiUrl, options.platform);
    this.grants = new GrantVerifier(this.api, () => this.nowSeconds());
  }

  /** True while the device is connected to the platform and can be reached. */
  get isConnected(): boolean {
    return this.signaling?.isOpen ?? false;
  }

  /** The sessions currently open to this device. */
  get openSessions(): ConnectionInfo[] {
    return [...this.sessions.values()].map((session) => session.info);
  }

  /** Resolves when the agent is connected to the platform. */
  waitUntilConnected(): Promise<void> {
    return this.connected.promise;
  }

  /**
   * Runs until {@link stop} is called, reconnecting with back-off whenever the connection to the
   * platform is lost. Rejects when the platform no longer accepts this device (its key was
   * revoked), because retrying cannot help then.
   */
  async run(): Promise<void> {
    let backoff = 1000;
    while (!this.stopped) {
      try {
        const certificates = this.options.certificates;
        const now = Math.floor(Date.now() / 1000) + this.clockOffset;
        // An enrolled device registered its certificate when it enrolled; a key device does it with every login.
        const token: TokenResponse = this.options.login
          ? await this.options.login(this.api)
          : await this.api.deviceKeyToken(this.options.deviceKey!, this.options.name!, this.options.platform.description, this.options.agentVersion,
              certificates?.registration(this.options.deviceKey!, now));
        this.deviceId = token.endpointId;
        if (typeof token.serverTime === 'number') {
          this.clockOffset = token.serverTime - Math.floor(Date.now() / 1000);
        }

        const caps: string[] = [Capabilities.MuxYamux, Capabilities.PathRelayWs];
        if (certificates) {
          caps.unshift(Capabilities.E2eTls13);
        }
        if (this.keys.length > 0) {
          caps.push(Capabilities.E2eSharedKey);
        }
        if (!this.options.disableDirect && this.options.platform.udp) {
          caps.push(Capabilities.PathUdpKcp);
        }
        const signaling = await SignalingClient.connect(this.options.platform, this.api.signalUrl, token.accessToken, {
          caps,
          fp: certificates?.fingerprint,
          agentVersion: this.options.agentVersion,
          platform: this.options.platform.description,
          services: [...this.services.entries()].map(([name, service]) => ({ name, protocol: service.protocol, compat: false })),
        });
        if (typeof signaling.welcome.serverTime === 'number') {
          this.clockOffset = signaling.welcome.serverTime - Math.floor(Date.now() / 1000);
        }
        signaling.onMessage = (message) => this.onSignal(signaling, message);
        this.signaling = signaling;
        backoff = 1000;
        this.connected.resolve();
        this.log(`connected to ${this.api.baseUrl} as device ${token.slug ?? this.options.name ?? token.endpointId}; services: ${[...this.services.keys()].join(', ') || '(none)'}`);

        const reason = await Promise.race([signaling.closed, this.stopSignal.promise.then(() => ErrorCodes.SessionClosed)]);
        this.connected = new Deferred<void>();
        if (this.stopped) {
          break;
        }
        this.log(`disconnected from the platform (${reason})`);
        if (reason === ErrorCodes.DeviceRevoked || reason === ErrorCodes.CredentialRevoked) {
          await this.endAllSessions(reason);
          throw new ConnectivitizerError(reason, reason === ErrorCodes.DeviceRevoked ? 'This device was revoked.' : 'The device key this device logs in with was revoked.');
        }
      } catch (error) {
        const code = codeOf(error, ErrorCodes.SignalingUnavailable);
        const final: string[] = [ErrorCodes.DeviceRevoked, ErrorCodes.CredentialRevoked, ErrorCodes.IdentityNotRegistered, ErrorCodes.Unauthenticated, ErrorCodes.InvalidRequest, ErrorCodes.Conflict];
        if (final.includes(code)) {
          this.log(`the platform does not accept this device (${code})`);
          throw error;
        }
        this.log(`platform unavailable (${code}); retrying in ${Math.round(backoff / 1000)} s`);
      }
      if (this.stopped) {
        break;
      }
      // Jitter keeps a fleet of devices from reconnecting in the same instant after an outage.
      await settledWithin(this.stopSignal.promise, backoff + Math.floor(Math.random() * 500));
      backoff = Math.min(backoff * 2, 30_000);
    }
  }

  /** Ends all sessions and disconnects from the platform. */
  async stop(): Promise<void> {
    if (this.stopped) {
      return;
    }
    this.stopped = true;
    await Promise.all([...this.sessions.values()].map((session) => session.close()));
    await delay(50);
    this.signaling?.close();
    this.stopSignal.resolve();
  }

  private nowSeconds(): number {
    return Math.floor(Date.now() / 1000) + this.clockOffset;
  }

  private log(message: string): void {
    this.options.log?.(message);
  }

  private waiter<T>(map: Map<string, Deferred<T>>, sessionId: string): Deferred<T> {
    let waiter = map.get(sessionId);
    if (!waiter) {
      waiter = new Deferred<T>();
      map.set(sessionId, waiter);
    }
    return waiter;
  }

  private onSignal(signaling: SignalingClient, message: SignalEnvelope): void {
    const data = message.d ?? {};
    const sessionId = typeof data.sid === 'string' ? data.sid : null;
    switch (message.t) {
      case 'connect.offer':
        if (sessionId && typeof data.grant === 'string' && data.peer) {
          void this.handleOffer(signaling, data as unknown as SignalConnectGrant);
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
      case 'path.fallback':
        if (sessionId) {
          this.waiter(this.fallbacks, sessionId).resolve(typeof data.reason === 'string' ? data.reason : 'unknown');
        }
        break;
      case 'revoke': {
        const sids = Array.isArray(data.sids) ? (data.sids as string[]) : null;
        const reason = typeof data.reason === 'string' ? data.reason : ErrorCodes.SessionRevoked;
        for (const session of [...this.sessions.values()]) {
          if (sids === null || sids.includes(session.info.sessionId)) {
            this.log(`session ${session.info.sessionId} revoked by the platform (${reason})`);
            void session.end(reason);
          }
        }
        break;
      }
      default:
        break;
    }
  }

  /**
   * The platform says an application wants to connect. The device checks the grant's signature
   * and that the grant is really about this device. Whether the application is trusted is not
   * the platform's to say: with a shared key the handshake proves it, with certificates the
   * device's own pins do.
   */
  private async handleOffer(signaling: SignalingClient, offer: SignalConnectGrant): Promise<void> {
    const validation = await this.grants.validate(offer.grant, true);
    const grant = validation.grant;
    const peerName = offer.peer.name ?? offer.peer.id;
    const refusal = !grant ? validation.error ?? ErrorCodes.GrantInvalid : this.checkOffer(grant, offer);

    try {
      signaling.send('connect.answer', { sid: offer.sid, accept: refusal === null, error: refusal ?? undefined });
    } catch {
      return;
    }
    if (refusal !== null || !grant) {
      this.log(`refused connection from ${peerName} (${refusal})`);
      return;
    }

    try {
      const session = await this.openPathAndEstablish(signaling, offer, grant);
      this.sessions.set(grant.jti, session);
      this.log(`session ${grant.jti} established with ${session.peer.name} (${session.info.mode}, ${session.info.trust}${session.info.peerAddress ? `, peer at ${session.info.peerAddress}` : ''})`);
      this.report({ sid: grant.jti, state: 'established', mode: session.info.mode, trust: session.info.trust, transport: session.info.transport });
      void this.watch(session);
    } catch (error) {
      const code = codeOf(error);
      this.log(`session ${grant.jti} with ${peerName} failed (${code})`);
      this.report({ sid: grant.jti, state: 'failed', error: code });
    } finally {
      this.candidates.delete(grant.jti);
      this.fallbacks.delete(grant.jti);
    }
  }

  /** Null when the offer can be accepted, otherwise the refusal code. */
  private checkOffer(grant: SessionGrant, offer: SignalConnectGrant): string | null {
    if (grant.jti !== offer.sid || grant.dev.id !== this.deviceId) {
      return ErrorCodes.GrantInvalid;
    }
    if (grant.modes.includes(ConnectionModes.Compatibility)) {
      // The gateway can read what it forwards; a device run by this SDK never opts in to that.
      return ErrorCodes.CompatibilityNotEnabled;
    }
    const method = e2eMethodOf(grant);
    if (method === E2eMethods.SharedKey) {
      if (this.keys.length === 0) {
        return ErrorCodes.E2eNoCommonMethod;
      }
    } else if (method === E2eMethods.Tls13 && this.options.certificates) {
      const certificates = this.options.certificates;
      if (grant.dev.fp && grant.dev.fp !== certificates.fingerprint) {
        return ErrorCodes.E2eSessionBindMismatch;
      }
      if (!grant.ini.fp) {
        return ErrorCodes.E2eTrustMissing;
      }
      if (!certificates.trusts(grant.ini.fp)) {
        return ErrorCodes.E2ePeerUntrusted;
      }
    } else {
      return ErrorCodes.E2eNoCommonMethod;
    }
    return this.canServe(grant, offer.peer) ? null : ErrorCodes.NoPermittedMode;
  }

  private directPossible(grant: SessionGrant, peer: SignalPeer): boolean {
    return grant.modes.includes(ConnectionModes.Direct) && !this.options.disableDirect && !!this.options.platform.udp
      && (peer.caps ?? []).includes(Capabilities.PathUdpKcp);
  }

  private canServe(grant: SessionGrant, peer: SignalPeer): boolean {
    return (grant.modes.includes(ConnectionModes.E2eRelay) && !!grant.relay) || this.directPossible(grant, peer);
  }

  /**
   * Follows the initiator's lead: a direct path if the initiator finds one, the relay if it says
   * so. The device never decides on its own to use a path the initiator did not choose.
   */
  private async openPathAndEstablish(signaling: SignalingClient, offer: SignalConnectGrant, grant: SessionGrant): Promise<TunnelSession> {
    const sessionId = grant.jti;
    const bySharedKey = e2eMethodOf(grant) === E2eMethods.SharedKey;
    const common: Omit<SessionParameters, 'path' | 'mode' | 'transport'> = {
      platform: this.options.platform,
      role: Roles.Device,
      grantToken: offer.grant,
      grant,
      sharedKeys: bySharedKey ? this.keys : undefined,
      certificateLayer: bySharedKey ? undefined : this.options.certificates?.layerFor(offer.peer.name ?? offer.peer.id, offer.peer, grant),
      peerLabel: offer.peer.name ?? offer.peer.id,
      validateRenewedGrant: (token) => this.grants.validateKnown(token, false),
      resolveService: (service, peer) => this.resolveService(service, peer),
      nowSeconds: () => this.nowSeconds(),
    };

    if (this.directPossible(grant, offer.peer)) {
      const attempt = new DirectAttempt(this.options.platform, Roles.Device, sessionId, offer.grant, this.options.stunServers ?? signaling.welcome.stunServers ?? [], {
        peerReflexive: peerReflexiveFor(e2eMethodOf(grant)),
      });
      try {
        void this.waiter(this.candidates, sessionId).promise.then((blob) => attempt.setRemoteCandidates(blob), () => undefined);
        const fallback = this.waiter(this.fallbacks, sessionId).promise;
        const expired = () => new ConnectivitizerError(ErrorCodes.SignalingTimeout, 'The initiator did not complete the path negotiation in time.');

        const blob = await withTimeout(attempt.gather(), PATH_TIMEOUT_MS, expired);
        signaling.send('path.candidates', { sid: sessionId, blob: base64Encode(blob) });

        const selection = attempt.waitForSelection();
        selection.catch(() => undefined);
        const first = await withTimeout(Promise.race([selection.then((path) => ({ path })), fallback.then((reason) => ({ reason }))]), PATH_TIMEOUT_MS, expired);
        if ('path' in first) {
          const direct = TunnelSession.establish({
            ...common,
            path: first.path.stream,
            mode: ConnectionModes.Direct,
            transport: 'udp-kcp',
            peerAddress: first.path.peerAddress,
            localCandidatesHash: attempt.localCandidatesHash,
            remoteCandidatesHash: attempt.remoteCandidatesHash,
          });
          direct.catch(() => undefined);
          // The initiator may have given up on the direct path while this side thought it was selected.
          const outcome = await Promise.race([direct.then((session) => ({ session })), fallback.then((reason) => ({ reason }))]);
          if ('session' in outcome) {
            return outcome.session;
          }
          await first.path.stream.close().catch(() => undefined);
          this.log(`session ${sessionId}: no direct path (${outcome.reason}), using the relay`);
        } else {
          this.log(`session ${sessionId}: no direct path (${first.reason}), using the relay`);
        }
      } finally {
        attempt.close();
      }
    }

    if (!grant.relay || !grant.modes.includes(ConnectionModes.E2eRelay)) {
      throw new ConnectivitizerError(ErrorCodes.DirectUnavailable, 'No direct path was found and relaying is not permitted for this session.');
    }
    const relay = await RelayPath.connect(this.options.platform, grant.relay, offer.grant, Roles.Device);
    return TunnelSession.establish({ ...common, path: relay.stream, relay, mode: ConnectionModes.E2eRelay, transport: 'relay-ws' });
  }

  /** The device's own, local answer to "may this peer use this service, and where does it go?". */
  private resolveService(name: string, peer: PeerInfo): ServiceResolution {
    const service = this.services.get(name);
    if (!service) {
      return { error: ErrorCodes.ServiceNotExposed };
    }
    if (service.allow && !service.allow.includes(peer.fingerprint)) {
      return { error: ErrorCodes.DeniedByLocalPolicy };
    }
    return { host: service.host, port: service.port };
  }

  private async watch(session: TunnelSession): Promise<void> {
    const reason = await session.completion;
    this.sessions.delete(session.info.sessionId);
    this.log(`session ${session.info.sessionId} ended (${reason})`);
    this.report({ sid: session.info.sessionId, state: 'ended', error: reason, bytesSent: session.bytesSent, bytesReceived: session.bytesReceived });
  }

  private report(update: Record<string, unknown>): void {
    try {
      if (this.signaling?.isOpen) {
        this.signaling.send('session.update', update);
      }
    } catch {
      // Reporting is best effort.
    }
  }

  private async endAllSessions(reason: string): Promise<void> {
    await Promise.all([...this.sessions.values()].map((session) => session.end(reason)));
  }
}
