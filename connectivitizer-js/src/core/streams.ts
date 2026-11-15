import { concat } from './bytes.js';

/**
 * A two-way stream of bytes: a relay connection, a direct path, the encrypted channel on top of
 * either, or one stream to a service. Chunk boundaries carry no meaning.
 */
export interface ByteStream {
  /** The next bytes, or null once the other side has finished sending. Rejects when the stream broke. */
  read(): Promise<Uint8Array | null>;

  write(data: Uint8Array): Promise<void>;

  /** Finishes sending while still receiving (a half close). Streams that cannot do that close entirely. */
  end(): Promise<void>;

  /** Closes both directions now. */
  close(): Promise<void>;
}

/**
 * Turns something that delivers chunks whenever it likes (a socket, a WebSocket) into something
 * that is read when the reader is ready.
 */
export class ChunkQueue {
  private readonly chunks: Uint8Array[] = [];
  private waiter: { resolve: (chunk: Uint8Array | null) => void; reject: (error: unknown) => void } | null = null;
  private ended = false;
  private error: unknown = null;
  private queuedBytes = 0;

  /** Bytes pushed and not read yet. */
  get size(): number {
    return this.queuedBytes;
  }

  get isEnded(): boolean {
    return this.ended;
  }

  push(chunk: Uint8Array): void {
    if (this.ended || chunk.length === 0) {
      return;
    }
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      waiter.resolve(chunk);
    } else {
      this.chunks.push(chunk);
      this.queuedBytes += chunk.length;
    }
  }

  /** No more chunks will come. With `error`, readers fail once what was queued has been read. */
  end(error?: unknown): void {
    if (this.ended) {
      return;
    }
    this.ended = true;
    this.error = error ?? null;
    if (this.waiter) {
      const waiter = this.waiter;
      this.waiter = null;
      if (error) {
        waiter.reject(error);
      } else {
        waiter.resolve(null);
      }
    }
  }

  read(): Promise<Uint8Array | null> {
    const next = this.chunks.shift();
    if (next) {
      this.queuedBytes -= next.length;
      return Promise.resolve(next);
    }
    if (this.ended) {
      return this.error ? Promise.reject(this.error) : Promise.resolve(null);
    }
    if (this.waiter) {
      return Promise.reject(new Error('A read is already waiting on this stream.'));
    }
    return new Promise((resolve, reject) => {
      this.waiter = { resolve, reject };
    });
  }
}

/** Reads exact amounts from a {@link ByteStream}, keeping what a chunk had left over for the next read. */
export class StreamReader {
  private pending: Uint8Array = new Uint8Array(0);
  private finished = false;

  constructor(private readonly stream: ByteStream) {}

  /**
   * Exactly `length` bytes. Null when the stream ended before the first of them; rejects when it
   * ended in the middle.
   */
  async readExact(length: number): Promise<Uint8Array | null> {
    while (this.pending.length < length) {
      const chunk = this.finished ? null : await this.stream.read();
      if (chunk === null) {
        this.finished = true;
        if (this.pending.length === 0) {
          return null;
        }
        throw new Error('The stream ended in the middle of a message.');
      }
      this.pending = this.pending.length === 0 ? chunk : concat(this.pending, chunk);
    }
    const result = this.pending.subarray(0, length);
    this.pending = this.pending.subarray(length);
    return result;
  }

  /** Whatever is available next: left-over bytes first, then the stream's next chunk. Null at the end. */
  async readSome(): Promise<Uint8Array | null> {
    if (this.pending.length > 0) {
      const result = this.pending;
      this.pending = new Uint8Array(0);
      return result;
    }
    if (this.finished) {
      return null;
    }
    const chunk = await this.stream.read();
    if (chunk === null) {
      this.finished = true;
    }
    return chunk;
  }

  /** Puts bytes back so that the next read returns them first. */
  unread(bytes: Uint8Array): void {
    this.pending = this.pending.length === 0 ? bytes : concat(bytes, this.pending);
  }

  /** Reads up to and including `\r\n\r\n` (the head of an HTTP message). Null when the stream ended first. */
  async readHead(maxLength: number): Promise<Uint8Array | null> {
    let scanned = 0;
    while (true) {
      for (let i = Math.max(0, scanned - 3); i + 3 < this.pending.length; i++) {
        if (this.pending[i] === 13 && this.pending[i + 1] === 10 && this.pending[i + 2] === 13 && this.pending[i + 3] === 10) {
          const head = this.pending.subarray(0, i + 4);
          this.pending = this.pending.subarray(i + 4);
          return head;
        }
      }
      scanned = this.pending.length;
      if (scanned > maxLength) {
        throw new Error('The header is too long.');
      }
      const chunk = this.finished ? null : await this.stream.read();
      if (chunk === null) {
        this.finished = true;
        return null;
      }
      this.pending = this.pending.length === 0 ? chunk : concat(this.pending, chunk);
    }
  }
}

/** Runs `work`, failing with `onTimeout()` when it takes longer than `milliseconds`. */
export function withTimeout<T>(work: Promise<T>, milliseconds: number, onTimeout: () => Error): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(onTimeout()), milliseconds);
    work.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export const delay = (milliseconds: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, milliseconds));

/**
 * Waits for `event`, but no longer than `milliseconds`. True when the event came first.
 *
 * Unlike a race against {@link delay}, the timer is cleared when the event wins: a wait of minutes
 * (for the next lease renewal, say) must not keep a program alive whose session has already ended.
 */
export function settledWithin(event: Promise<unknown>, milliseconds: number): Promise<boolean> {
  return new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), milliseconds);
    const settled = (): void => {
      clearTimeout(timer);
      resolve(true);
    };
    event.then(settled, settled);
  });
}

/** A promise together with the functions that settle it. */
export class Deferred<T> {
  readonly promise: Promise<T>;
  resolve!: (value: T) => void;
  reject!: (error: unknown) => void;
  settled = false;

  constructor() {
    this.promise = new Promise<T>((resolve, reject) => {
      this.resolve = (value) => {
        this.settled = true;
        resolve(value);
      };
      this.reject = (error) => {
        this.settled = true;
        reject(error);
      };
    });
    // A deferred nobody waits for yet must not count as an unhandled rejection.
    this.promise.catch(() => undefined);
  }
}
