import { utf8Decode } from './bytes.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import type { Platform, WebSocketConnection } from './platform.js';
import { Deferred, withTimeout } from './streams.js';

// The signaling channel (protocol section 8): one WebSocket to the control plane that says who
// wants to talk to whom and how to reach them. It never carries application data.

export interface SignalEnvelope {
  t: string;
  id?: string;
  re?: string;
  d?: Record<string, unknown>;
}

export interface ServiceDeclaration {
  name: string;
  protocol?: string;
  compat?: boolean;
}

export interface SignalHello {
  caps: string[];
  fp?: string;
  agentVersion?: string;
  platform?: string;
  services?: ServiceDeclaration[];
}

export interface SignalWelcome {
  endpointType: string;
  endpointId: string;
  workspaceId: string;
  heartbeatSeconds?: number;
  stunServers?: string[];
  serverTime?: number;
}

export interface SignalPeer {
  type: string;
  id: string;
  name?: string;
  fp?: string;
  caps?: string[];
}

export interface SignalConnectGrant {
  sid: string;
  grant: string;
  peer: SignalPeer;
}

const HELLO_TIMEOUT_MS = 15_000;
const PING_INTERVAL_MS = 25_000;
/** A connection on which nothing arrived for this long is treated as dead. */
const SILENCE_LIMIT_MS = 70_000;

export class SignalingClient {
  /** What the control plane answered to `hello`. */
  welcome!: SignalWelcome;

  /** Called for every message that is not the reply to a request. */
  onMessage: ((message: SignalEnvelope) => void) | null = null;

  private readonly pending = new Map<string, Deferred<SignalEnvelope>>();
  private readonly closedSignal = new Deferred<string>();
  private nextId = 1;
  private lastReceived = Date.now();
  private timer: ReturnType<typeof setInterval> | null = null;

  private constructor(private readonly socket: WebSocketConnection) {}

  /** Resolves with the reason once the connection is over. */
  get closed(): Promise<string> {
    return this.closedSignal.promise;
  }

  get isOpen(): boolean {
    return !this.closedSignal.settled;
  }

  static async connect(platform: Platform, url: string, accessToken: string, hello: SignalHello, extraHeaders: Record<string, string> = {}): Promise<SignalingClient> {
    let socket: WebSocketConnection;
    try {
      socket = await platform.connectWebSocket(url, { Authorization: `Bearer ${accessToken}`, ...extraHeaders });
    } catch (error) {
      // A refusal the adapter could read (the token is not accepted) is passed on as it is.
      if (error instanceof ConnectivitizerError && (error.code === ErrorCodes.Unauthenticated || error.code === ErrorCodes.Forbidden)) {
        throw error;
      }
      throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, 'The signaling channel could not be opened.', { cause: error });
    }

    const client = new SignalingClient(socket);
    socket.onMessage = (data) => client.receive(data);
    socket.onClose = (_code, reason) => client.finish(reason || ErrorCodes.SignalingUnavailable);
    try {
      const reply = await client.request('hello', hello as unknown as Record<string, unknown>, HELLO_TIMEOUT_MS);
      if (reply.t !== 'welcome' || !reply.d) {
        throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, 'The control plane did not welcome this endpoint.');
      }
      client.welcome = reply.d as unknown as SignalWelcome;
    } catch (error) {
      client.close();
      throw error;
    }
    // Some runtimes hide WebSocket pings from the application, so liveness is checked with messages.
    client.timer = setInterval(() => client.keepAlive(), PING_INTERVAL_MS);
    return client;
  }

  /** Sends a message that expects no reply. */
  send(type: string, data: Record<string, unknown>): void {
    this.write({ t: type, d: data });
  }

  /** Sends a request and waits for its reply. An `error` reply rejects with the platform's code. */
  async request(type: string, data: Record<string, unknown>, timeoutMs: number): Promise<SignalEnvelope> {
    const id = String(this.nextId++);
    const reply = new Deferred<SignalEnvelope>();
    this.pending.set(id, reply);
    try {
      this.write({ t: type, id, d: data });
      const envelope = await withTimeout(reply.promise, timeoutMs, () => new ConnectivitizerError(ErrorCodes.SignalingTimeout, `The control plane did not answer '${type}' in time.`));
      if (envelope.t === 'error') {
        const code = typeof envelope.d?.code === 'string' ? envelope.d.code : ErrorCodes.InvalidRequest;
        throw new ConnectivitizerError(code, typeof envelope.d?.message === 'string' ? envelope.d.message : `The control plane refused '${type}' (${code}).`);
      }
      return envelope;
    } finally {
      this.pending.delete(id);
    }
  }

  close(): void {
    this.finish(ErrorCodes.SessionClosed);
    try {
      this.socket.close(1000, '');
    } catch {
      // Already gone.
    }
  }

  private write(envelope: SignalEnvelope): void {
    if (!this.isOpen) {
      throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, 'The signaling channel is closed.');
    }
    try {
      this.socket.send(JSON.stringify(envelope));
    } catch (error) {
      throw new ConnectivitizerError(ErrorCodes.SignalingUnavailable, 'The signaling channel is closed.', { cause: error });
    }
  }

  private receive(data: Uint8Array | string): void {
    this.lastReceived = Date.now();
    let envelope: SignalEnvelope;
    try {
      envelope = JSON.parse(typeof data === 'string' ? data : utf8Decode(data)) as SignalEnvelope;
    } catch {
      return;
    }
    if (!envelope || typeof envelope.t !== 'string') {
      return;
    }
    if (envelope.re !== undefined && this.pending.has(envelope.re)) {
      this.pending.get(envelope.re)!.resolve(envelope);
      return;
    }
    if (envelope.t === 'pong') {
      return;
    }
    try {
      this.onMessage?.(envelope);
    } catch {
      // A handler that throws must not take the channel down with it.
    }
  }

  private keepAlive(): void {
    if (Date.now() - this.lastReceived > SILENCE_LIMIT_MS) {
      this.finish(ErrorCodes.SignalingUnavailable);
      try {
        this.socket.close(1001, '');
      } catch {
        // Already gone.
      }
      return;
    }
    try {
      this.write({ t: 'ping', id: 'k' + this.nextId++ });
    } catch {
      // The close handler takes care of the rest.
    }
  }

  private finish(reason: string): void {
    if (this.closedSignal.settled) {
      return;
    }
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.closedSignal.resolve(reason);
    const error = new ConnectivitizerError(reason === ErrorCodes.SessionClosed ? ErrorCodes.SignalingUnavailable : reason, `The signaling channel closed (${reason}).`);
    for (const waiter of this.pending.values()) {
      waiter.reject(error);
    }
    this.pending.clear();
  }
}
