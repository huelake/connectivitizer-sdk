import { utf8Decode } from './bytes.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import type { Role } from './grants.js';
import type { Platform, WebSocketConnection } from './platform.js';
import { type ByteStream, ChunkQueue, Deferred, withTimeout } from './streams.js';

// The relay path (protocol section 3): each endpoint opens a WebSocket to the relay, the relay
// pairs the two and forwards bytes it has no key for.

const CONNECT_TIMEOUT_MS = 10_000;
/** The relay waits 15 s for the peer; a little longer here so its own answer arrives first. */
const PAIR_TIMEOUT_MS = 20_000;
const MAX_MESSAGE_BYTES = 32 * 1024;

export class RelayPath {
  readonly stream: ByteStream;
  private readonly incoming = new ChunkQueue();
  private closed = false;

  private constructor(private readonly socket: WebSocketConnection) {
    this.stream = {
      read: () => this.incoming.read(),
      write: async (data) => {
        if (this.closed) {
          throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The relay path is closed.');
        }
        for (let offset = 0; offset < data.length; offset += MAX_MESSAGE_BYTES) {
          this.socket.send(data.subarray(offset, Math.min(offset + MAX_MESSAGE_BYTES, data.length)));
        }
      },
      end: () => this.close(),
      close: () => this.close(),
    };
  }

  /** Connects to the relay with the session's grant and waits until the peer is there too. */
  static async connect(platform: Platform, relayUrl: string, grantToken: string, role: Role): Promise<RelayPath> {
    let socket: WebSocketConnection;
    try {
      socket = await withTimeout(platform.connectWebSocket(relayUrl, { Authorization: `Bearer ${grantToken}`, 'Cz-Role': role }), CONNECT_TIMEOUT_MS,
        () => new ConnectivitizerError(ErrorCodes.RelayUnreachable, 'The relay did not answer in time.'));
    } catch (error) {
      // An adapter that could see the relay's refusal passes its code on; otherwise the relay is simply out of reach.
      throw error instanceof ConnectivitizerError && error.code !== ErrorCodes.PathClosed
        ? error
        : new ConnectivitizerError(ErrorCodes.RelayUnreachable, 'The relay could not be reached.', { cause: error });
    }

    const path = new RelayPath(socket);
    const paired = new Deferred<void>();
    let isPaired = false;
    socket.onMessage = (data) => {
      if (typeof data !== 'string') {
        if (isPaired) {
          path.incoming.push(data);
        }
        return;
      }
      // Text frames come from the relay itself. Only the first one matters to an endpoint.
      if (!isPaired) {
        try {
          if ((JSON.parse(data) as { t?: unknown }).t === 'paired') {
            isPaired = true;
            paired.resolve();
          }
        } catch {
          // Not for us.
        }
      }
    };
    socket.onClose = (code, reason) => {
      path.closed = true;
      // The relay names why it ended a session; "the peer left" is the ordinary end of a stream.
      const named = code >= 4000 && reason && reason !== ErrorCodes.PathClosed;
      const error = named ? new ConnectivitizerError(reason, `The relay ended the session (${reason}).`) : null;
      if (!isPaired) {
        paired.reject(error ?? new ConnectivitizerError(ErrorCodes.RelayUnreachable, 'The relay closed the connection before the peer arrived.'));
      }
      path.incoming.end(error ?? undefined);
    };

    try {
      await withTimeout(paired.promise, PAIR_TIMEOUT_MS, () => new ConnectivitizerError(ErrorCodes.RelayPeerTimeout, 'The peer did not connect to the relay in time.'));
    } catch (error) {
      await path.close();
      throw error;
    }
    return path;
  }

  /** Presents a renewed grant to the relay so that it keeps the session open. */
  renewLease(grantToken: string): void {
    if (!this.closed) {
      this.socket.send(JSON.stringify({ t: 'lease', grant: grantToken }));
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    this.incoming.end();
    try {
      this.socket.close(1000, '');
    } catch {
      // Already gone.
    }
  }
}

/** For adapters: turns a text or binary WebSocket payload into text. */
export const payloadText = (data: Uint8Array | string): string => (typeof data === 'string' ? data : utf8Decode(data));
