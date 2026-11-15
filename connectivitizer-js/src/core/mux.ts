import { readUint16, readUint32, writeUint16, writeUint32 } from './bytes.js';
import { ConnectivitizerError, ErrorCodes, codeOf } from './errors.js';
import { type ByteStream, ChunkQueue, Deferred, StreamReader } from './streams.js';

// Stream multiplexing with yamux framing (protocol section 5): many independent streams over the
// one encrypted channel of a session, each with its own flow control.

const HEADER_SIZE = 12;
const TYPE_DATA = 0;
const TYPE_WINDOW_UPDATE = 1;
const TYPE_PING = 2;
const TYPE_GO_AWAY = 3;
const FLAG_SYN = 1;
const FLAG_ACK = 2;
const FLAG_FIN = 4;
const FLAG_RST = 8;

/** Bytes a stream may have in flight in one direction before the receiver has to make room. */
export const INITIAL_WINDOW = 262_144;
const MAX_DATA = 16_384;
const MAX_STREAMS = 256;

function frame(type: number, flags: number, streamId: number, length: number, payload?: Uint8Array): Uint8Array {
  const bytes = new Uint8Array(HEADER_SIZE + (payload?.length ?? 0));
  bytes[0] = 0;
  bytes[1] = type;
  writeUint16(bytes, 2, flags);
  writeUint32(bytes, 4, streamId);
  writeUint32(bytes, 8, length);
  if (payload) {
    bytes.set(payload, HEADER_SIZE);
  }
  return bytes;
}

export class MuxSession {
  private readonly streams = new Map<number, MuxStream>();
  private readonly acceptQueue: MuxStream[] = [];
  private acceptWaiter: ((stream: MuxStream | null) => void) | null = null;
  private readonly ended = new Deferred<string>();
  private nextId: number;
  private lastRemoteId = 0;
  private writing: Promise<void> = Promise.resolve();
  private endReason: string | null = null;
  private closing = false;

  constructor(
    private readonly transport: ByteStream,
    private readonly isInitiator: boolean,
  ) {
    this.nextId = isInitiator ? 1 : 2;
  }

  /** Resolves with an error code once the session is over, for whatever reason. */
  get completion(): Promise<string> {
    return this.ended.promise;
  }

  get isEnded(): boolean {
    return this.endReason !== null;
  }

  start(): void {
    void this.readLoop();
  }

  open(): MuxStream {
    this.ensureOpen();
    const stream = new MuxStream(this, this.nextId, true);
    this.nextId += 2;
    this.streams.set(stream.id, stream);
    void this.send(frame(TYPE_WINDOW_UPDATE, FLAG_SYN, stream.id, 0)).catch(() => undefined);
    return stream;
  }

  /** The next stream the peer opened; null once the session is over. */
  accept(): Promise<MuxStream | null> {
    const queued = this.acceptQueue.shift();
    if (queued) {
      return Promise.resolve(queued);
    }
    if (this.endReason !== null) {
      return Promise.resolve(null);
    }
    return new Promise((resolve) => {
      this.acceptWaiter = resolve;
    });
  }

  /** Ends the session in an orderly way. */
  async close(): Promise<void> {
    if (this.endReason === null) {
      // Once this side said goodbye, the path going away is the orderly end and not a failure.
      this.closing = true;
      await this.send(frame(TYPE_GO_AWAY, 0, 0, 0)).catch(() => undefined);
    }
    this.end(ErrorCodes.SessionClosed);
  }

  /** @internal Frames go out whole and in the order they were handed over. */
  send(bytes: Uint8Array): Promise<void> {
    const result = this.writing.then(() => {
      this.ensureOpen();
      return this.transport.write(bytes);
    });
    this.writing = result.catch(() => undefined);
    return result;
  }

  /** @internal */
  sendFrame(type: number, flags: number, streamId: number, length: number, payload?: Uint8Array): Promise<void> {
    return this.send(frame(type, flags, streamId, length, payload));
  }

  /** @internal */
  forget(streamId: number): void {
    this.streams.delete(streamId);
  }

  /** @internal */
  end(reason: string): void {
    if (this.endReason !== null) {
      return;
    }
    this.endReason = reason;
    const error = new ConnectivitizerError(reason, `The session ended (${reason}).`);
    for (const stream of this.streams.values()) {
      stream.sessionEnded(error);
    }
    this.streams.clear();
    if (this.acceptWaiter) {
      this.acceptWaiter(null);
      this.acceptWaiter = null;
    }
    this.ended.resolve(reason);
    void this.transport.close().catch(() => undefined);
  }

  private ensureOpen(): void {
    if (this.endReason !== null) {
      throw new ConnectivitizerError(this.endReason, `The session is over (${this.endReason}).`);
    }
  }

  private async readLoop(): Promise<void> {
    const reader = new StreamReader(this.transport);
    try {
      while (this.endReason === null) {
        const header = await reader.readExact(HEADER_SIZE);
        if (header === null) {
          this.end(this.closing ? ErrorCodes.SessionClosed : ErrorCodes.PathClosed);
          return;
        }
        const type = header[1];
        const flags = readUint16(header, 2);
        const streamId = readUint32(header, 4);
        const length = readUint32(header, 8);
        if (header[0] !== 0) {
          return this.end(ErrorCodes.MuxProtocolError);
        }

        if (type === TYPE_PING) {
          if (flags & FLAG_SYN) {
            void this.send(frame(TYPE_PING, FLAG_ACK, 0, length)).catch(() => undefined);
          }
          continue;
        }
        if (type === TYPE_GO_AWAY) {
          return this.end(length === 0 ? ErrorCodes.SessionClosed : ErrorCodes.MuxProtocolError);
        }
        if ((type !== TYPE_DATA && type !== TYPE_WINDOW_UPDATE) || streamId === 0) {
          return this.end(ErrorCodes.MuxProtocolError);
        }

        let stream = this.streams.get(streamId);
        if (flags & FLAG_SYN) {
          const remoteParity = this.isInitiator ? 0 : 1;
          if (stream || streamId % 2 !== remoteParity || streamId <= this.lastRemoteId) {
            return this.end(ErrorCodes.MuxProtocolError);
          }
          this.lastRemoteId = streamId;
          if (this.streams.size >= MAX_STREAMS) {
            void this.send(frame(TYPE_WINDOW_UPDATE, FLAG_RST, streamId, 0)).catch(() => undefined);
          } else {
            stream = new MuxStream(this, streamId, false);
            this.streams.set(streamId, stream);
            if (this.acceptWaiter) {
              const waiter = this.acceptWaiter;
              this.acceptWaiter = null;
              waiter(stream);
            } else {
              this.acceptQueue.push(stream);
            }
          }
        }

        if (type === TYPE_DATA) {
          if (length > INITIAL_WINDOW) {
            return this.end(ErrorCodes.MuxProtocolError);
          }
          const payload = length === 0 ? new Uint8Array(0) : await reader.readExact(length);
          if (payload === null) {
            return this.end(ErrorCodes.PathClosed);
          }
          // Data for a stream that is gone (it was reset here) is read and dropped.
          if (stream && !stream.receive(payload)) {
            return this.end(ErrorCodes.MuxProtocolError);
          }
        } else if (stream) {
          stream.windowGrew(length);
        }

        if (stream && flags & FLAG_RST) {
          stream.remoteReset();
        } else if (stream && flags & FLAG_FIN) {
          stream.remoteFinished();
        }
      }
    } catch (error) {
      // A path that names its own reason for ending (the relay does) is passed on as such.
      this.end(this.closing ? ErrorCodes.SessionClosed : codeOf(error, ErrorCodes.PathClosed));
    }
  }
}

/** One stream of a session. One reader and one writer at a time. */
export class MuxStream implements ByteStream {
  private readonly incoming = new ChunkQueue();
  private receiveWindow = INITIAL_WINDOW;
  private consumed = 0;
  private sendWindow = INITIAL_WINDOW;
  private windowWaiter: Deferred<void> | null = null;
  private acknowledged: boolean;
  private localFinished = false;
  private remoteDone = false;
  private failure: ConnectivitizerError | null = null;
  private closed = false;

  constructor(
    private readonly session: MuxSession,
    readonly id: number,
    opener: boolean,
  ) {
    this.acknowledged = opener;
  }

  async read(): Promise<Uint8Array | null> {
    const chunk = await this.incoming.read();
    if (chunk !== null) {
      this.consumed += chunk.length;
      // Make room again once half the window was used up, as the reference implementation does.
      if (this.consumed >= INITIAL_WINDOW / 2 && !this.remoteDone && !this.closed) {
        const grant = this.consumed;
        this.consumed = 0;
        this.receiveWindow += grant;
        void this.session.sendFrame(TYPE_WINDOW_UPDATE, this.firstFrameFlags(), this.id, grant).catch(() => undefined);
      }
    }
    return chunk;
  }

  async write(data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
      if (this.failure) {
        throw this.failure;
      }
      if (this.localFinished || this.closed) {
        throw new ConnectivitizerError(ErrorCodes.SessionClosed, 'The stream is closed for sending.');
      }
      if (this.sendWindow === 0) {
        this.windowWaiter = new Deferred<void>();
        await this.windowWaiter.promise;
        continue;
      }
      const size = Math.min(data.length - offset, this.sendWindow, MAX_DATA);
      this.sendWindow -= size;
      await this.session.sendFrame(TYPE_DATA, this.firstFrameFlags(), this.id, size, data.subarray(offset, offset + size));
      offset += size;
    }
  }

  /** Finishes sending; the peer can still send. */
  async end(): Promise<void> {
    if (this.localFinished || this.closed || this.failure) {
      return;
    }
    this.localFinished = true;
    await this.session.sendFrame(TYPE_WINDOW_UPDATE, FLAG_FIN | this.firstFrameFlags(), this.id, 0).catch(() => undefined);
    if (this.remoteDone) {
      this.session.forget(this.id);
    }
  }

  async close(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    const abort = !this.failure && !(this.localFinished && this.remoteDone);
    this.incoming.end();
    this.wakeWriter();
    this.session.forget(this.id);
    if (abort && !this.session.isEnded) {
      await this.session.sendFrame(TYPE_WINDOW_UPDATE, FLAG_RST, this.id, 0).catch(() => undefined);
    }
  }

  /** @internal False when the peer sent more than the window allows. */
  receive(payload: Uint8Array): boolean {
    if (payload.length > this.receiveWindow) {
      return false;
    }
    this.receiveWindow -= payload.length;
    this.incoming.push(payload);
    return true;
  }

  /** @internal */
  windowGrew(by: number): void {
    this.sendWindow += by;
    this.wakeWriter();
  }

  /** @internal */
  remoteFinished(): void {
    this.remoteDone = true;
    this.incoming.end();
    if (this.localFinished) {
      this.session.forget(this.id);
    }
  }

  /** @internal */
  remoteReset(): void {
    this.remoteDone = true;
    this.failure = new ConnectivitizerError(ErrorCodes.SessionClosed, 'The peer reset the stream.');
    // What arrived before the reset can still be read; after that reads fail.
    this.incoming.end(this.failure);
    this.wakeWriter();
    this.session.forget(this.id);
  }

  /** @internal */
  sessionEnded(error: ConnectivitizerError): void {
    this.failure ??= error;
    this.incoming.end(this.remoteDone ? undefined : error);
    this.wakeWriter();
  }

  /** The accepting side marks the first frame it sends for a stream. */
  private firstFrameFlags(): number {
    if (this.acknowledged) {
      return 0;
    }
    this.acknowledged = true;
    return FLAG_ACK;
  }

  private wakeWriter(): void {
    const waiter = this.windowWaiter;
    this.windowWaiter = null;
    waiter?.resolve();
  }
}
