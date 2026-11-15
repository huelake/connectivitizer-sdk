import type { ByteStream } from './streams.js';

/** One open WebSocket to the platform, as the core uses it. */
export interface WebSocketConnection {
  send(data: Uint8Array | string): void;
  close(code?: number, reason?: string): void;
  onMessage: ((data: Uint8Array | string) => void) | null;
  /** Called once, when the connection is over for whatever reason. */
  onClose: ((code: number, reason: string) => void) | null;
}

/**
 * One UDP socket, used for a direct path. Hosts are plain IP addresses: IPv4 dotted, IPv6 in its
 * canonical form (RFC 5952), and an IPv4 peer as IPv4 even on a dual-stack socket (never
 * `::ffff:a.b.c.d`); `normalizeHost` turns other spellings into that form.
 */
export interface UdpSocket {
  /** The local port the socket is bound to. */
  readonly port: number;
  /** The socket can also send to and receive from IPv6 addresses. */
  readonly ipv6: boolean;
  send(data: Uint8Array, host: string, port: number): void;
  onMessage: ((data: Uint8Array, host: string, port: number) => void) | null;
  close(): void;
}

export interface HttpResponse {
  status: number;
  text(): Promise<string>;
}

/**
 * What the SDK needs from the environment it runs in. The core contains no Node.js and no React
 * Native code; an adapter supplies these few functions.
 */
export interface Platform {
  /** Cryptographically secure random bytes. Session keys are made from them. */
  randomBytes(length: number): Uint8Array;

  /** An HTTP request to the Connectivitizer API. */
  fetch(url: string, init: { method: string; headers: Record<string, string>; body?: string }): Promise<HttpResponse>;

  /**
   * Opens a WebSocket with the given request headers. Rejects with a {@link ConnectivitizerError}
   * whose code is the server's refusal when the adapter can see it.
   */
  connectWebSocket(url: string, headers: Record<string, string>): Promise<WebSocketConnection>;

  /** UDP, for peer-to-peer connections. Without it every session goes through the relay. */
  udp?: {
    bind(): Promise<UdpSocket>;
    /**
     * This machine's own addresses on its networks, offered to the peer as places to reach it:
     * IPv4, and IPv6 (of which only global addresses are used).
     */
    localAddresses(): Promise<string[]>;
    /** The IPv4 address of a host name (for STUN servers given by name). */
    resolve(host: string): Promise<string>;
  };

  /** Device side: opens a TCP connection to a local service. */
  connectTcp?(host: string, port: number): Promise<ByteStream>;

  /** A short description of the runtime, shown in the web app next to a device. */
  description?: string;
}
