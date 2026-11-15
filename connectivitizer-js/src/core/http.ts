import { concat, utf8Decode, utf8Encode } from './bytes.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import { type ByteStream, StreamReader, withTimeout } from './streams.js';
import { parseHead } from './websocket.js';

// A small HTTP/1.1 client that runs over one stream to a device service. The device's local
// application sees an ordinary HTTP request on its own port.

const MAX_HEAD = 64 * 1024;

export interface TunnelRequestInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string | Uint8Array;
  /** Fails the request when no response head arrived within this time. Default 30 s. */
  timeoutMs?: number;
}

/** The answer of the device's local application. The body is read once, by one of the body methods. */
export class TunnelResponse {
  readonly ok: boolean;
  private consumed = false;

  constructor(
    readonly status: number,
    readonly statusText: string,
    /** Header names in lower case. Repeated headers are joined with ", ". */
    readonly headers: ReadonlyMap<string, string>,
    private readonly source: (() => AsyncGenerator<Uint8Array>) | null,
  ) {
    this.ok = status >= 200 && status < 300;
  }

  /** The body piece by piece, for downloads that should not be held in memory at once. */
  chunks(): AsyncGenerator<Uint8Array> {
    if (this.consumed) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'The body of this response was already read.');
    }
    this.consumed = true;
    return this.source ? this.source() : (async function* () {})();
  }

  async bytes(): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    for await (const chunk of this.chunks()) {
      parts.push(chunk);
    }
    return parts.length === 1 ? parts[0] : concat(...parts);
  }

  async arrayBuffer(): Promise<ArrayBuffer> {
    const bytes = await this.bytes();
    return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
  }

  async text(): Promise<string> {
    return utf8Decode(await this.bytes());
  }

  async json<T = unknown>(): Promise<T> {
    return JSON.parse(await this.text()) as T;
  }
}

/**
 * Sends one request over a freshly opened stream and returns once the response head is there.
 * The stream is closed when the body has been read.
 */
export async function httpRequest(openStream: () => Promise<ByteStream>, host: string, path: string, init: TunnelRequestInit = {}): Promise<TunnelResponse> {
  const method = (init.method ?? 'GET').toUpperCase();
  if (!/^[A-Z]+$/.test(method) || /[\r\n ]/.test(path) || !path.startsWith('/')) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'The request needs a method and a path that starts with "/".');
  }
  const body = init.body === undefined ? null : typeof init.body === 'string' ? utf8Encode(init.body) : init.body;
  const headers = new Map<string, [string, string]>();
  const set = (name: string, value: string) => headers.set(name.toLowerCase(), [name, value]);
  set('Host', host);
  set('Accept-Encoding', 'identity');
  if (typeof init.body === 'string') {
    set('Content-Type', 'text/plain; charset=utf-8');
  }
  for (const [name, value] of Object.entries(init.headers ?? {})) {
    if (/[\r\n:]/.test(name) || /[\r\n]/.test(value)) {
      throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A header contains a character that is not allowed.');
    }
    set(name, value);
  }
  // One request per stream: streams are cheap, and it keeps the framing unambiguous.
  set('Connection', 'close');
  if (body !== null) {
    set('Content-Length', String(body.length));
  } else if (method !== 'GET' && method !== 'HEAD') {
    set('Content-Length', '0');
  }
  const head = utf8Encode(`${method} ${path} HTTP/1.1\r\n` + [...headers.values()].map(([name, value]) => `${name}: ${value}\r\n`).join('') + '\r\n');

  const stream = await openStream();
  try {
    const exchange = (async () => {
      await stream.write(body === null ? head : concat(head, body));
      const reader = new StreamReader(stream);
      while (true) {
        const responseHead = await reader.readHead(MAX_HEAD);
        if (responseHead === null) {
          throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The service closed the connection without answering.');
        }
        const parsed = parseHead(responseHead);
        const match = /^HTTP\/1\.[01] (\d{3})(?: (.*))?$/.exec(parsed.statusLine);
        if (!match) {
          throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The service did not answer with HTTP.');
        }
        const status = Number.parseInt(match[1], 10);
        if (status >= 100 && status < 200 && status !== 101) {
          continue; // an interim response such as 100 Continue; the real one follows
        }
        return { reader, status, statusText: match[2] ?? '', headers: parsed.headers };
      }
    })();
    const answer = await withTimeout(exchange, init.timeoutMs ?? 30_000, () => new ConnectivitizerError(ErrorCodes.PathClosed, 'The service did not answer in time.'));

    const noBody = method === 'HEAD' || answer.status === 204 || answer.status === 304;
    if (noBody) {
      await stream.close().catch(() => undefined);
      return new TunnelResponse(answer.status, answer.statusText, answer.headers, null);
    }
    return new TunnelResponse(answer.status, answer.statusText, answer.headers, () => readBody(stream, answer.reader, answer.headers));
  } catch (error) {
    await stream.close().catch(() => undefined);
    throw error;
  }
}

async function* readBody(stream: ByteStream, reader: StreamReader, headers: ReadonlyMap<string, string>): AsyncGenerator<Uint8Array> {
  try {
    if ((headers.get('transfer-encoding') ?? '').toLowerCase().includes('chunked')) {
      while (true) {
        const size = Number.parseInt((await readLine(reader)).split(';')[0].trim(), 16);
        if (Number.isNaN(size) || size < 0) {
          throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The service sent a malformed chunked body.');
        }
        if (size === 0) {
          // Trailers, if any, end with an empty line; nothing in them is used.
          while ((await readLine(reader)) !== '') {
            /* skip */
          }
          return;
        }
        yield* readExactly(reader, size);
        await readLine(reader);
      }
    }

    const declared = headers.get('content-length');
    if (declared !== undefined) {
      const length = Number.parseInt(declared, 10);
      if (Number.isNaN(length) || length < 0) {
        throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The service sent an invalid Content-Length.');
      }
      yield* readExactly(reader, length);
      return;
    }

    // Neither: the body runs until the service closes the connection.
    while (true) {
      const chunk = await reader.readSome();
      if (chunk === null) {
        return;
      }
      yield chunk;
    }
  } finally {
    await stream.close().catch(() => undefined);
  }
}

async function* readExactly(reader: StreamReader, length: number): AsyncGenerator<Uint8Array> {
  let remaining = length;
  while (remaining > 0) {
    const chunk = await reader.readSome();
    if (chunk === null) {
      throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The connection ended in the middle of the response body.');
    }
    if (chunk.length > remaining) {
      reader.unread(chunk.subarray(remaining));
      yield chunk.subarray(0, remaining);
      return;
    }
    remaining -= chunk.length;
    yield chunk;
  }
}

async function readLine(reader: StreamReader): Promise<string> {
  const bytes: number[] = [];
  while (true) {
    const chunk = await reader.readSome();
    if (chunk === null) {
      throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The connection ended in the middle of the response body.');
    }
    for (let i = 0; i < chunk.length; i++) {
      if (chunk[i] === 10) {
        reader.unread(chunk.subarray(i + 1));
        if (bytes[bytes.length - 1] === 13) {
          bytes.pop();
        }
        return utf8Decode(Uint8Array.from(bytes));
      }
      bytes.push(chunk[i]);
    }
    if (bytes.length > 8192) {
      throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The service sent a malformed chunked body.');
    }
  }
}
