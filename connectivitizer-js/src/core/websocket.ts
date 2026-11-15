import { sha1 } from '@noble/hashes/legacy.js';
import { base64Encode, concat, utf8Decode, utf8Encode } from './bytes.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import { type ByteStream, StreamReader } from './streams.js';

// A WebSocket client (RFC 6455) that runs over any byte stream. It serves two purposes: WebSockets
// to a device service through a session, and - in runtimes whose own WebSocket cannot send request
// headers - the connections to the platform.

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const OP_CONTINUATION = 0;
const OP_TEXT = 1;
const OP_BINARY = 2;
const OP_CLOSE = 8;
const OP_PING = 9;
const OP_PONG = 10;
const MAX_HEAD = 16 * 1024;

export interface WebSocketHandshakeOptions {
  /** Host header, e.g. `api.example.com` or `api.example.com:8443`. */
  host: string;
  /** Path and query, e.g. `/ws?room=1`. */
  path: string;
  headers?: Record<string, string>;
  protocols?: string[];
  randomBytes: (length: number) => Uint8Array;
  /** Largest message accepted from the server. */
  maxMessageBytes?: number;
}

/** Thrown when the server answers the WebSocket request with an ordinary HTTP response. */
export class WebSocketRefusedError extends ConnectivitizerError {
  constructor(
    readonly status: number,
    readonly headers: Map<string, string>,
    readonly body: string,
  ) {
    super(ErrorCodes.RelayRejected, `The server refused the WebSocket connection (HTTP ${status}).`);
    this.name = 'WebSocketRefusedError';
  }
}

export function parseHead(head: Uint8Array): { statusLine: string; headers: Map<string, string> } {
  const lines = utf8Decode(head).split('\r\n');
  const headers = new Map<string, string>();
  for (const line of lines.slice(1)) {
    const colon = line.indexOf(':');
    if (colon > 0) {
      const name = line.substring(0, colon).trim().toLowerCase();
      const value = line.substring(colon + 1).trim();
      headers.set(name, headers.has(name) ? `${headers.get(name)}, ${value}` : value);
    }
  }
  return { statusLine: lines[0] ?? '', headers };
}

/**
 * A WebSocket connection. Handlers are plain properties, set before or after messages arrive:
 * anything received in between is kept until `onMessage` is assigned.
 */
export class StreamWebSocket {
  /** The subprotocol the server selected, or an empty string. */
  protocol = '';

  private messageHandler: ((data: Uint8Array | string) => void) | null = null;
  private closeHandler: ((code: number, reason: string) => void) | null = null;
  private readonly backlog: (Uint8Array | string)[] = [];
  private closed: { code: number; reason: string } | null = null;
  private closeReported = false;
  private closeSent = false;
  private closeTimer: ReturnType<typeof setTimeout> | null = null;
  private writing: Promise<void> = Promise.resolve();

  private constructor(
    private readonly stream: ByteStream,
    private readonly reader: StreamReader,
    private readonly randomBytes: (length: number) => Uint8Array,
    private readonly maxMessageBytes: number,
  ) {}

  /** Performs the opening handshake over `stream` and returns the open connection. */
  static async connect(stream: ByteStream, options: WebSocketHandshakeOptions): Promise<StreamWebSocket> {
    const key = base64Encode(options.randomBytes(16));
    const lines = [
      `GET ${options.path} HTTP/1.1`,
      `Host: ${options.host}`,
      'Upgrade: websocket',
      'Connection: Upgrade',
      `Sec-WebSocket-Key: ${key}`,
      'Sec-WebSocket-Version: 13',
    ];
    if (options.protocols?.length) {
      lines.push(`Sec-WebSocket-Protocol: ${options.protocols.join(', ')}`);
    }
    for (const [name, value] of Object.entries(options.headers ?? {})) {
      if (/[\r\n]/.test(name) || /[\r\n]/.test(value)) {
        throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A header contains a line break.');
      }
      lines.push(`${name}: ${value}`);
    }
    await stream.write(utf8Encode(lines.join('\r\n') + '\r\n\r\n'));

    const reader = new StreamReader(stream);
    const head = await reader.readHead(MAX_HEAD);
    if (head === null) {
      throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The connection closed before the WebSocket was established.');
    }
    const { statusLine, headers } = parseHead(head);
    const status = Number.parseInt(statusLine.split(' ')[1] ?? '', 10);
    if (status !== 101) {
      let body = '';
      const length = Number.parseInt(headers.get('content-length') ?? '0', 10);
      if (length > 0 && length <= 4096) {
        body = utf8Decode((await reader.readExact(length).catch(() => null)) ?? new Uint8Array(0));
      }
      await stream.close().catch(() => undefined);
      throw new WebSocketRefusedError(Number.isNaN(status) ? 0 : status, headers, body);
    }
    const expected = base64Encode(sha1(utf8Encode(key + GUID)));
    if (headers.get('sec-websocket-accept') !== expected || (headers.get('upgrade') ?? '').toLowerCase() !== 'websocket') {
      await stream.close().catch(() => undefined);
      throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The server did not complete the WebSocket handshake correctly.');
    }

    const socket = new StreamWebSocket(stream, reader, options.randomBytes, options.maxMessageBytes ?? 16 * 1024 * 1024);
    socket.protocol = headers.get('sec-websocket-protocol') ?? '';
    void socket.readLoop();
    return socket;
  }

  get onMessage(): ((data: Uint8Array | string) => void) | null {
    return this.messageHandler;
  }

  set onMessage(handler: ((data: Uint8Array | string) => void) | null) {
    this.messageHandler = handler;
    while (handler && this.backlog.length > 0) {
      handler(this.backlog.shift()!);
    }
  }

  get onClose(): ((code: number, reason: string) => void) | null {
    return this.closeHandler;
  }

  set onClose(handler: ((code: number, reason: string) => void) | null) {
    this.closeHandler = handler;
    this.reportClose();
  }

  get isOpen(): boolean {
    return this.closed === null && !this.closeSent;
  }

  /** Sends one message: text for a string, binary for bytes. */
  send(data: Uint8Array | string): void {
    if (!this.isOpen) {
      throw new ConnectivitizerError(ErrorCodes.SessionClosed, 'The WebSocket is closed.');
    }
    const payload = typeof data === 'string' ? utf8Encode(data) : data;
    void this.sendFrame(typeof data === 'string' ? OP_TEXT : OP_BINARY, payload);
  }

  /** Resolves once everything sent so far has been handed to the stream below. */
  flush(): Promise<void> {
    return this.writing;
  }

  close(code = 1000, reason = ''): void {
    if (this.closed !== null || this.closeSent) {
      return;
    }
    this.closeSent = true;
    const text = utf8Encode(reason).subarray(0, 123);
    const payload = new Uint8Array(2 + text.length);
    payload[0] = code >> 8;
    payload[1] = code & 0xff;
    payload.set(text, 2);
    void this.sendFrame(OP_CLOSE, payload).then(() => {
      // A server that never answers the close must not keep the stream open forever.
      this.closeTimer = setTimeout(() => this.finish(code, reason), 2000);
    });
  }

  private sendFrame(opcode: number, payload: Uint8Array): Promise<void> {
    const mask = this.randomBytes(4);
    const lengthBytes = payload.length < 126 ? 0 : payload.length < 65536 ? 2 : 8;
    const frame = new Uint8Array(2 + lengthBytes + 4 + payload.length);
    frame[0] = 0x80 | opcode;
    if (lengthBytes === 0) {
      frame[1] = 0x80 | payload.length;
    } else if (lengthBytes === 2) {
      frame[1] = 0x80 | 126;
      frame[2] = payload.length >> 8;
      frame[3] = payload.length & 0xff;
    } else {
      frame[1] = 0x80 | 127;
      // Lengths beyond 2^32 do not occur; the upper four bytes stay zero.
      frame[6] = (payload.length >>> 24) & 0xff;
      frame[7] = (payload.length >>> 16) & 0xff;
      frame[8] = (payload.length >>> 8) & 0xff;
      frame[9] = payload.length & 0xff;
    }
    const maskOffset = 2 + lengthBytes;
    frame.set(mask, maskOffset);
    for (let i = 0; i < payload.length; i++) {
      frame[maskOffset + 4 + i] = payload[i] ^ mask[i & 3];
    }
    const result = this.writing.then(() => this.stream.write(frame));
    this.writing = result.catch(() => undefined);
    return this.writing;
  }

  private async readLoop(): Promise<void> {
    let fragments: Uint8Array[] = [];
    let fragmentOpcode = 0;
    let fragmentBytes = 0;
    try {
      while (this.closed === null) {
        const header = await this.reader.readExact(2);
        if (header === null) {
          return this.finish(1006, '');
        }
        const final = (header[0] & 0x80) !== 0;
        const opcode = header[0] & 0x0f;
        const masked = (header[1] & 0x80) !== 0;
        let length = header[1] & 0x7f;
        if (length === 126) {
          const extended = await this.reader.readExact(2);
          if (extended === null) {
            return this.finish(1006, '');
          }
          length = (extended[0] << 8) | extended[1];
        } else if (length === 127) {
          const extended = await this.reader.readExact(8);
          if (extended === null) {
            return this.finish(1006, '');
          }
          if (extended[0] | extended[1] | extended[2] | extended[3]) {
            return this.fail(1009, 'message too big');
          }
          length = ((extended[4] << 24) | (extended[5] << 16) | (extended[6] << 8) | extended[7]) >>> 0;
        }
        if (length > this.maxMessageBytes) {
          return this.fail(1009, 'message too big');
        }
        const mask = masked ? await this.reader.readExact(4) : null;
        let payload = length === 0 ? new Uint8Array(0) : await this.reader.readExact(length);
        if (payload === null || (masked && mask === null)) {
          return this.finish(1006, '');
        }
        if (mask) {
          payload = payload.slice();
          for (let i = 0; i < payload.length; i++) {
            payload[i] ^= mask[i & 3];
          }
        }

        if (opcode === OP_PING) {
          void this.sendFrame(OP_PONG, payload);
        } else if (opcode === OP_PONG) {
          // Unsolicited pongs are a keep-alive some servers send; nothing to do.
        } else if (opcode === OP_CLOSE) {
          const code = payload.length >= 2 ? (payload[0] << 8) | payload[1] : 1005;
          const reason = payload.length > 2 ? utf8Decode(payload.subarray(2)) : '';
          if (!this.closeSent) {
            this.closeSent = true;
            await this.sendFrame(OP_CLOSE, payload.subarray(0, Math.min(payload.length, 2))).catch(() => undefined);
          }
          return this.finish(code, reason);
        } else if (opcode === OP_TEXT || opcode === OP_BINARY || opcode === OP_CONTINUATION) {
          if (opcode !== OP_CONTINUATION) {
            fragmentOpcode = opcode;
            fragments = [];
            fragmentBytes = 0;
          }
          fragments.push(payload);
          fragmentBytes += payload.length;
          if (fragmentBytes > this.maxMessageBytes) {
            return this.fail(1009, 'message too big');
          }
          if (final) {
            const whole = fragments.length === 1 ? fragments[0] : concat(...fragments);
            fragments = [];
            this.deliver(fragmentOpcode === OP_TEXT ? utf8Decode(whole) : whole);
          }
        } else {
          return this.fail(1002, 'unknown frame');
        }
      }
    } catch (error) {
      // The reason a path gives for ending (the relay names one) travels as the close reason.
      this.finish(1006, error instanceof ConnectivitizerError ? error.code : '');
    }
  }

  private deliver(message: Uint8Array | string): void {
    if (this.messageHandler) {
      this.messageHandler(message);
    } else {
      this.backlog.push(message);
    }
  }

  private fail(code: number, reason: string): void {
    this.close(code, reason);
    this.finish(code, reason);
  }

  private finish(code: number, reason: string): void {
    if (this.closed !== null) {
      return;
    }
    this.closed = { code, reason };
    if (this.closeTimer !== null) {
      clearTimeout(this.closeTimer);
      this.closeTimer = null;
    }
    void this.stream.close().catch(() => undefined);
    this.reportClose();
  }

  private reportClose(): void {
    if (this.closed !== null && this.closeHandler && !this.closeReported) {
      this.closeReported = true;
      this.closeHandler(this.closed.code, this.closed.reason);
    }
  }
}
