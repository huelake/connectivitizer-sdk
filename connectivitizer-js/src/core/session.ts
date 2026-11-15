import { readUint16, readUint32, utf8Decode, utf8Encode, writeUint16, writeUint32 } from './bytes.js';
import { ConnectivitizerError, ErrorCodes, codeOf } from './errors.js';
import { ConnectionModes, E2eMethods, type GrantValidation, Roles, type Role, type SessionGrant, e2eMethodOf, hashGrant } from './grants.js';
import { type TunnelRequestInit, type TunnelResponse, httpRequest } from './http.js';
import { MuxSession, type MuxStream } from './mux.js';
import { type SharedKey, acceptSharedKey, connectSharedKey, prologue } from './noise.js';
import type { Platform } from './platform.js';
import type { RelayPath } from './relayPath.js';
import { type ByteStream, StreamReader, settledWithin, withTimeout } from './streams.js';
import { StreamWebSocket } from './websocket.js';

// A session: the end-to-end channel over one path, the bind that ties it to its grant, and the
// streams to services inside it (protocol sections 4 and 5).

/** How the peer's identity was established. */
export type TrustLevel = 'none' | 'platform-introduced' | 'shared-key' | 'workspace-ca' | 'local-pinned';

/** The authenticated other end of a session. */
export interface PeerInfo {
  /** A certificate fingerprint, or `key:<name>` for a peer that proved to hold that shared key. */
  fingerprint: string;
  /** From the certificate, or - with a shared key - the label the platform gave the peer. */
  name: string;
  trust: TrustLevel;
}

/**
 * The routing and security properties of an established session, as this endpoint observed and
 * verified them - not as anybody claimed.
 */
export interface ConnectionInfo {
  sessionId: string;
  /** `direct`, `e2e-relay` or `compatibility`. */
  mode: string;
  /** What carries the bytes: `udp-kcp` or `tcp` for direct sessions, `relay-ws` otherwise. */
  transport: string;
  /** True when the traffic passes through Connectivitizer infrastructure. */
  relayed: boolean;
  /** True when only the two endpoints hold the keys protecting the traffic. */
  endToEndEncrypted: boolean;
  /** True only in compatibility mode. */
  platformCanReadPayload: boolean;
  /** `tls13` (certificates) or `shared-key`. */
  e2eMethod: string;
  trust: TrustLevel;
  peerFingerprint: string;
  peerName: string;
  /** Direct sessions: the network address this endpoint exchanges packets with. */
  peerAddress?: string;
  /** Why a direct connection was not used, when the session is relayed and the reason is known. */
  directFailureReason?: string;
}

/** An end-to-end layer: turns a path into an encrypted stream to an authenticated peer. */
export type SecureLayer = (path: ByteStream, role: Role) => Promise<{ stream: ByteStream; peer: PeerInfo }>;

/** Where a device forwards the streams of one service, or the reason it does not. */
export type ServiceResolution = { host: string; port: number; error?: undefined } | { error: string };

export interface SessionParameters {
  platform: Platform;
  /** The byte stream to the peer. Owned by the session from here on. */
  path: ByteStream;
  role: Role;
  /** The connection mode this endpoint observed for `path`. */
  mode: string;
  transport: string;
  grantToken: string;
  grant: SessionGrant;
  /** For a `shared-key` grant. The initiator uses the first; the device accepts whichever the initiator proves to hold. */
  sharedKeys?: readonly SharedKey[];
  /** For a `tls13` grant, where the runtime can do it. */
  certificateLayer?: SecureLayer;
  /** What the platform calls the peer. A label; it authenticates nothing. */
  peerLabel: string;
  directFailureReason?: string;
  peerAddress?: string;
  /** Direct sessions: SHA-256 (hex) of the candidate list this endpoint announced, and of the one it received. */
  localCandidatesHash?: string;
  remoteCandidatesHash?: string;
  /** Relayed sessions: so that lease renewals also reach the relay. */
  relay?: RelayPath;
  /** Device side: verifies a renewed grant with the keys already known. */
  validateRenewedGrant?: (token: string) => GrantValidation;
  /** Device side: the local service configuration. */
  resolveService?: (service: string, peer: PeerInfo) => ServiceResolution;
  nowSeconds: () => number;
}

const HANDSHAKE_TIMEOUT_MS = 15_000;
const SERVICE_OPEN_TIMEOUT_MS = 15_000;
const LOCAL_CONNECT_TIMEOUT_MS = 5_000;
const LEASE_GRACE_SECONDS = 30;
const MAX_CONTROL_MESSAGE = 64 * 1024;

interface ControlMessage {
  bind?: { sid: string; grant: string; role: string; mode: string; cands?: string; dial?: string };
  lease?: { grant: string };
  error?: string;
}

function framed(message: unknown, lengthBytes: 2 | 4): Uint8Array {
  const json = utf8Encode(JSON.stringify(message));
  const bytes = new Uint8Array(lengthBytes + json.length);
  if (lengthBytes === 2) {
    writeUint16(bytes, 0, json.length);
  } else {
    writeUint32(bytes, 0, json.length);
  }
  bytes.set(json, lengthBytes);
  return bytes;
}

/** Reads one length-prefixed JSON message; null at a clean end of the stream. */
async function readFramed<T>(reader: StreamReader, lengthBytes: 2 | 4): Promise<T | null> {
  const prefix = await reader.readExact(lengthBytes);
  if (prefix === null) {
    return null;
  }
  const length = lengthBytes === 2 ? readUint16(prefix, 0) : readUint32(prefix, 0);
  if (length === 0 || length > MAX_CONTROL_MESSAGE) {
    throw new ConnectivitizerError(ErrorCodes.MuxProtocolError, 'Malformed tunnel message.');
  }
  const json = await reader.readExact(length);
  if (json === null) {
    return null;
  }
  return JSON.parse(utf8Decode(json)) as T;
}

/**
 * An authenticated, end-to-end encrypted session between an initiator and a device, carrying any
 * number of streams to the device's services.
 */
export class TunnelSession {
  /** The verified properties of this session. */
  readonly info: ConnectionInfo;

  /** The authenticated remote endpoint. */
  readonly peer: PeerInfo;

  /** Resolves with an error code once the session has ended. */
  readonly completion: Promise<string>;

  /** Application bytes this endpoint sent to and received from the peer on service streams. */
  bytesSent = 0;
  bytesReceived = 0;

  private leaseExpiresAt: number;
  private endReason: string | null = null;
  private resolveCompletion!: (reason: string) => void;
  private controlWriting: Promise<void> = Promise.resolve();
  private watchdog: ReturnType<typeof setInterval> | null = null;

  private constructor(
    private readonly parameters: SessionParameters,
    private readonly mux: MuxSession,
    private readonly control: MuxStream,
    private readonly controlReader: StreamReader,
    peer: PeerInfo,
  ) {
    this.peer = peer;
    this.leaseExpiresAt = parameters.grant.iat + parameters.grant.lease;
    const mode = parameters.mode;
    this.info = {
      sessionId: parameters.grant.jti,
      mode,
      transport: parameters.transport,
      relayed: mode !== ConnectionModes.Direct,
      endToEndEncrypted: mode !== ConnectionModes.Compatibility,
      platformCanReadPayload: mode === ConnectionModes.Compatibility,
      e2eMethod: e2eMethodOf(parameters.grant),
      trust: peer.trust,
      peerFingerprint: peer.fingerprint,
      peerName: peer.name,
      peerAddress: parameters.peerAddress,
      directFailureReason: parameters.directFailureReason,
    };
    this.completion = new Promise((resolve) => {
      this.resolveCompletion = resolve;
    });
    const controlDone = this.controlLoop();
    // A peer that ends the session says why on the control stream and closes the mux right after.
    // Both arrive together, so the control loop reads the reason before the mux's own, less
    // specific one is taken.
    void mux.completion.then(async (reason) => {
      await settledWithin(controlDone, 2_000);
      this.finish(reason);
    });
    if (parameters.role === Roles.Device) {
      void this.acceptLoop();
      this.watchdog = setInterval(() => this.checkLease(), 5_000);
    }
  }

  /** Unix time until which the session is authorised without a renewed grant. */
  get leaseExpires(): number {
    return this.leaseExpiresAt;
  }

  get isEnded(): boolean {
    return this.endReason !== null;
  }

  /**
   * Runs the end-to-end handshake over an established path - the layer the grant names - and then
   * the session bind that ties the encrypted channel to the grant and to the observed route.
   * Never returns a session that is not fully verified.
   */
  static establish(parameters: SessionParameters): Promise<TunnelSession> {
    return withTimeout(TunnelSession.establishCore(parameters), HANDSHAKE_TIMEOUT_MS, () => {
      void parameters.path.close().catch(() => undefined);
      return new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The end-to-end handshake timed out.');
    });
  }

  private static async establishCore(parameters: SessionParameters): Promise<TunnelSession> {
    const { grant, role } = parameters;
    const isInitiator = role === Roles.Initiator;
    const method = e2eMethodOf(grant);
    const grantHash = hashGrant(parameters.grantToken);

    // The grant says which end-to-end layer the session uses; an endpoint never picks another one.
    let secure: { stream: ByteStream; peer: PeerInfo };
    if (method === E2eMethods.SharedKey) {
      const keys = parameters.sharedKeys ?? [];
      if (keys.length === 0) {
        await parameters.path.close().catch(() => undefined);
        throw new ConnectivitizerError(ErrorCodes.E2eSharedKeyMismatch, 'This endpoint has no shared key for the session.');
      }
      const bound = prologue(grant.jti, grantHash);
      const channel = isInitiator
        ? await connectSharedKey(parameters.path, keys[0], bound, parameters.platform.randomBytes)
        : await acceptSharedKey(parameters.path, keys, bound, parameters.platform.randomBytes);
      // The key proves the peer is a holder; which holder, it cannot tell. The name is the platform's label.
      secure = { stream: channel.stream, peer: { fingerprint: `key:${channel.keyName}`, name: parameters.peerLabel, trust: 'shared-key' } };
    } else if (method === E2eMethods.Tls13 && parameters.certificateLayer) {
      secure = await parameters.certificateLayer(parameters.path, role);
      // The platform said which identity to expect; the handshake showed which one is really there.
      const expected = isInitiator ? grant.dev.fp : grant.ini.fp;
      if (expected && expected !== secure.peer.fingerprint) {
        await secure.stream.close().catch(() => undefined);
        throw new ConnectivitizerError(ErrorCodes.E2eSessionBindMismatch, "The peer's identity is not the one named in the session grant.");
      }
    } else {
      await parameters.path.close().catch(() => undefined);
      throw new ConnectivitizerError(ErrorCodes.E2eNoCommonMethod, `This endpoint cannot take part in a session with the end-to-end layer '${method}'.`);
    }

    const mux = new MuxSession(secure.stream, isInitiator);
    mux.start();
    try {
      const control = isInitiator ? mux.open() : await mux.accept();
      if (control === null) {
        throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer ended the session during the handshake.');
      }
      const reader = new StreamReader(control);
      const direct = parameters.mode === ConnectionModes.Direct;
      const ownBind = { sid: grant.jti, grant: grantHash, role, mode: parameters.mode, cands: direct ? parameters.localCandidatesHash : undefined };
      await control.write(framed({ bind: ownBind }, 4));

      let received: ControlMessage | null;
      try {
        received = await readFramed<ControlMessage>(reader, 4);
      } catch (error) {
        throw new ConnectivitizerError(codeOf(error, ErrorCodes.E2eHandshakeFailed) === ErrorCodes.PathClosed ? ErrorCodes.E2eHandshakeFailed : codeOf(error, ErrorCodes.E2eHandshakeFailed),
          'The peer ended the session during the handshake.', { cause: error });
      }
      if (received === null) {
        throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer ended the session during the handshake; it may not trust this endpoint.');
      }
      if (typeof received.error === 'string') {
        throw new ConnectivitizerError(received.error, `The peer refused the session (${received.error}).`);
      }
      const peerBind = received.bind;
      if (!peerBind || peerBind.sid !== ownBind.sid || peerBind.grant !== ownBind.grant || peerBind.mode !== ownBind.mode
        || peerBind.role !== (isInitiator ? Roles.Device : Roles.Initiator)
        // The addresses probed came through the control plane; here the authenticated peer confirms them.
        || (direct && (!peerBind.cands || peerBind.cands !== parameters.remoteCandidatesHash))) {
        await control.write(framed({ error: ErrorCodes.E2eSessionBindMismatch }, 4)).catch(() => undefined);
        throw new ConnectivitizerError(ErrorCodes.E2eSessionBindMismatch, 'The two endpoints do not agree on the session they are part of.');
      }
      return new TunnelSession(parameters, mux, control, reader, secure.peer);
    } catch (error) {
      await mux.close();
      throw error;
    }
  }

  /** Opens a stream to one of the device's services. Initiator side. */
  async openStream(service: string): Promise<ByteStream> {
    if (this.parameters.role !== Roles.Initiator) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'Only the initiating endpoint opens service streams.');
    }
    if (this.endReason !== null) {
      throw new ConnectivitizerError(this.endReason, `The session is over (${this.endReason}).`);
    }
    const stream = this.mux.open();
    try {
      const reader = new StreamReader(stream);
      const answer = await withTimeout(
        (async () => {
          await stream.write(framed({ svc: service }, 2));
          return await readFramed<{ ok?: boolean; error?: string }>(reader, 2);
        })(),
        SERVICE_OPEN_TIMEOUT_MS,
        () => new ConnectivitizerError(ErrorCodes.SessionClosed, `Opening service '${service}' timed out.`),
      );
      if (!answer?.ok) {
        const code = answer?.error ?? ErrorCodes.SessionClosed;
        throw new ConnectivitizerError(code, `The device did not open service '${service}' (${code}).`);
      }
      return {
        read: async () => {
          const chunk = await reader.readSome();
          if (chunk) {
            this.bytesReceived += chunk.length;
          }
          return chunk;
        },
        write: async (data) => {
          await stream.write(data);
          this.bytesSent += data.length;
        },
        end: () => stream.end(),
        close: () => stream.close(),
      };
    } catch (error) {
      await stream.close();
      throw error instanceof ConnectivitizerError ? error : new ConnectivitizerError(ErrorCodes.SessionClosed, 'The session ended while opening the service.', { cause: error });
    }
  }

  /**
   * An HTTP request to a service of the device. The device's local application receives it as an
   * ordinary request on its own port, with `service` as the host name.
   */
  fetch(service: string, path: string, init?: TunnelRequestInit): Promise<TunnelResponse> {
    return httpRequest(() => this.openStream(service), service, path, init);
  }

  /** A WebSocket to a service of the device. */
  async webSocket(service: string, path: string, options: { protocols?: string[]; headers?: Record<string, string> } = {}): Promise<StreamWebSocket> {
    const stream = await this.openStream(service);
    return StreamWebSocket.connect(stream, { host: service, path, protocols: options.protocols, headers: options.headers, randomBytes: this.parameters.platform.randomBytes });
  }

  /** Extends the session with a freshly issued grant. Initiator side. */
  async renewLease(grantToken: string, grant: SessionGrant): Promise<void> {
    if (grant.jti !== this.parameters.grant.jti) {
      throw new ConnectivitizerError(ErrorCodes.GrantInvalid, 'The grant belongs to another session.');
    }
    await this.writeControl({ lease: { grant: grantToken } });
    this.parameters.relay?.renewLease(grantToken);
    this.leaseExpiresAt = Math.max(this.leaseExpiresAt, grant.iat + grant.lease);
  }

  /** Ends the session for `reason` (an error code), telling the peer why. */
  async end(reason: string = ErrorCodes.SessionClosed): Promise<void> {
    if (this.endReason !== null) {
      return;
    }
    this.finish(reason);
    await withTimeout(this.writeControl({ error: reason }), 2_000, () => new Error('timeout')).catch(() => undefined);
    await this.mux.close();
  }

  /** Closes the session in an orderly way. */
  close(): Promise<void> {
    return this.end(ErrorCodes.SessionClosed);
  }

  private finish(reason: string): void {
    if (this.endReason !== null) {
      return;
    }
    this.endReason = reason;
    if (this.watchdog) {
      clearInterval(this.watchdog);
      this.watchdog = null;
    }
    this.resolveCompletion(reason);
  }

  private writeControl(message: ControlMessage): Promise<void> {
    const result = this.controlWriting.then(() => this.control.write(framed(message, 4)));
    this.controlWriting = result.catch(() => undefined);
    return result;
  }

  private async controlLoop(): Promise<void> {
    try {
      while (this.endReason === null) {
        const message = await readFramed<ControlMessage>(this.controlReader, 4);
        if (message === null) {
          return;
        }
        if (typeof message.error === 'string') {
          this.finish(message.error);
          await this.mux.close();
          return;
        }
        if (message.lease && this.parameters.role === Roles.Device) {
          this.handleLeaseRenewal(message.lease.grant);
        }
      }
    } catch {
      // The mux reports why the session ended.
    }
  }

  private handleLeaseRenewal(token: string): void {
    const renewed = this.parameters.validateRenewedGrant?.(token).grant;
    const original = this.parameters.grant;
    // A renewal may only prolong this very session for the same two endpoints; it cannot widen anything.
    if (renewed && renewed.jti === original.jti && renewed.ws === original.ws && renewed.ini.id === original.ini.id
      && (renewed.ini.fp ?? null) === (original.ini.fp ?? null) && renewed.dev.id === original.dev.id && e2eMethodOf(renewed) === e2eMethodOf(original)) {
      this.leaseExpiresAt = Math.max(this.leaseExpiresAt, renewed.iat + renewed.lease);
    }
  }

  /** Device side: a session whose authorisation ran out is ended, whatever the platform or the peer say. */
  private checkLease(): void {
    if (this.parameters.nowSeconds() >= this.leaseExpiresAt + LEASE_GRACE_SECONDS) {
      void this.end(ErrorCodes.LeaseExpired);
    }
  }

  private async acceptLoop(): Promise<void> {
    while (this.endReason === null) {
      const stream = await this.mux.accept();
      if (stream === null) {
        return;
      }
      void this.serveStream(stream);
    }
  }

  /** Device side: authorise one service stream, connect it to the local application and copy bytes. */
  private async serveStream(stream: MuxStream): Promise<void> {
    let local: ByteStream | null = null;
    try {
      const reader = new StreamReader(stream);
      const request = await withTimeout(readFramed<{ svc?: string }>(reader, 2), SERVICE_OPEN_TIMEOUT_MS, () => new Error('timeout'));
      if (!request || typeof request.svc !== 'string' || request.svc.length === 0) {
        return;
      }

      // Platform authorisation (the grant) and the device's own configuration both have to agree.
      let refusal: string | null = null;
      let target: { host: string; port: number } | null = null;
      if (!this.parameters.grant.svc.includes(request.svc)) {
        refusal = ErrorCodes.DeniedByGrant;
      } else {
        const resolved = this.parameters.resolveService?.(request.svc, this.peer) ?? { error: ErrorCodes.ServiceNotExposed };
        if (resolved.error !== undefined) {
          refusal = resolved.error;
        } else {
          target = resolved;
        }
      }
      if (target && this.parameters.platform.connectTcp) {
        try {
          local = await withTimeout(this.parameters.platform.connectTcp(target.host, target.port), LOCAL_CONNECT_TIMEOUT_MS, () => new Error('timeout'));
        } catch {
          refusal = ErrorCodes.TargetUnreachable;
        }
      } else if (target) {
        refusal = ErrorCodes.TargetUnreachable;
      }

      await stream.write(framed(refusal === null ? { ok: true } : { ok: false, error: refusal }, 2));
      if (refusal !== null || local === null) {
        await stream.end();
        return;
      }

      const service = local;
      const toLocal = (async () => {
        while (true) {
          const chunk = await reader.readSome();
          if (chunk === null) {
            break;
          }
          await service.write(chunk);
          this.bytesReceived += chunk.length;
        }
        await service.end();
      })();
      const toPeer = (async () => {
        while (true) {
          const chunk = await service.read();
          if (chunk === null) {
            break;
          }
          await stream.write(chunk);
          this.bytesSent += chunk.length;
        }
        await stream.end();
      })();
      await Promise.all([toLocal, toPeer]);
    } catch {
      // One stream failing (the local application closed, the peer reset it) does not concern the session.
    } finally {
      await local?.close().catch(() => undefined);
      await stream.close().catch(() => undefined);
    }
  }
}
