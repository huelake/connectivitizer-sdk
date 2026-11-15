import { ConnectivitizerError, ErrorCodes } from '../errors.js';
import type { UdpSocket } from '../platform.js';
import { type ByteStream, ChunkQueue, Deferred, delay } from '../streams.js';
import { formatAddress } from './addresses.js';
import { Kcp } from './kcp.js';

// A reliable, ordered byte stream to one peer over UDP (protocol section 6.2). It provides
// delivery only: confidentiality and peer authentication come from the end-to-end layer above it.

/** First byte of every datagram exchanged directly between two peers. */
export const DatagramType = { Probe: 0xc1, ProbeAck: 0xc2, Kcp: 0xc3, KeepAlive: 0xc4, Close: 0xc5 } as const;

const MAX_DATAGRAM = 1200;
const UPDATE_INTERVAL_MS = 10;
const KEEP_ALIVE_MS = 15_000;
const IDLE_TIMEOUT_MS = 45_000;
const WINDOW = 256;
/** How much may wait to be sent or read before the writer, or the peer, is made to wait. */
const SEND_BACKLOG_SEGMENTS = 512;
const RECEIVE_BACKLOG_BYTES = 256 * 1024;
const FLUSH_ON_CLOSE_MS = 2_000;
const DRAIN_ON_REMOTE_CLOSE_MS = 3_000;

export class KcpPath {
  readonly stream: ByteStream;
  readonly peerAddress: string;

  /** Receives hole-punch probes that still arrive from the peer after the path was selected. */
  onProbe: ((data: Uint8Array, host: string, port: number) => void) | null = null;

  private readonly kcp: Kcp;
  private readonly incoming = new ChunkQueue();
  private readonly timer: ReturnType<typeof setInterval>;
  private lastReceived = Date.now();
  private lastSent = Date.now();
  private closeReason: string | null = null;
  private writeWaiter: Deferred<void> | null = null;
  private flushScheduled = false;

  constructor(
    private readonly socket: UdpSocket,
    private readonly remoteHost: string,
    private readonly remotePort: number,
    conversation: number,
  ) {
    this.peerAddress = formatAddress({ host: remoteHost, port: remotePort });
    this.kcp = new Kcp(conversation, (packet) => {
      // One byte in front of every KCP packet says what the datagram is.
      const datagram = new Uint8Array(packet.length + 1);
      datagram[0] = DatagramType.Kcp;
      datagram.set(packet, 1);
      this.lastSent = Date.now();
      this.socket.send(datagram, this.remoteHost, this.remotePort);
    });
    this.kcp.stream = true;
    this.kcp.setMtu(MAX_DATAGRAM - 1);
    this.kcp.noDelay(1, UPDATE_INTERVAL_MS, 2, 1);
    this.kcp.wndSize(WINDOW, WINDOW);

    socket.onMessage = (data, host, port) => this.onDatagram(data, host, port);
    this.timer = setInterval(() => this.tick(), UPDATE_INTERVAL_MS);
    this.stream = {
      read: () => this.read(),
      write: (data) => this.write(data),
      end: () => this.close(),
      close: () => this.close(),
    };
  }

  private onDatagram(data: Uint8Array, host: string, port: number): void {
    if (host !== this.remoteHost || port !== this.remotePort || data.length === 0 || this.closeReason !== null) {
      return;
    }
    this.lastReceived = Date.now();
    switch (data[0]) {
      case DatagramType.Kcp:
        this.kcp.input(data.subarray(1));
        this.pump();
        this.scheduleFlush();
        break;
      case DatagramType.Close:
        void this.closeAfterDrain();
        break;
      case DatagramType.Probe:
      case DatagramType.ProbeAck:
        this.onProbe?.(data, host, port);
        break;
      default:
        // Keep-alives only refresh the timestamp.
        break;
    }
  }

  private tick(): void {
    if (this.closeReason !== null) {
      return;
    }
    const now = Date.now();
    if (now - this.lastReceived > IDLE_TIMEOUT_MS || this.kcp.state !== 0) {
      this.closeNow(ErrorCodes.PathIdleTimeout);
      return;
    }
    this.kcp.update(now);
    this.pump();
    if (now - this.lastSent > KEEP_ALIVE_MS) {
      this.lastSent = now;
      this.socket.send(Uint8Array.of(DatagramType.KeepAlive), this.remoteHost, this.remotePort);
    }
    if (this.writeWaiter && this.kcp.waitSnd < SEND_BACKLOG_SEGMENTS) {
      const waiter = this.writeWaiter;
      this.writeWaiter = null;
      waiter.resolve();
    }
  }

  /** Hands received data to the reader, but no more than it keeps up with: KCP then closes its window to the peer. */
  private pump(): void {
    while (this.incoming.size < RECEIVE_BACKLOG_BYTES) {
      const chunk = this.kcp.recv();
      if (chunk === null) {
        break;
      }
      this.incoming.push(chunk);
    }
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) {
      return;
    }
    this.flushScheduled = true;
    setTimeout(() => {
      this.flushScheduled = false;
      if (this.closeReason === null) {
        this.kcp.update(Date.now());
        this.kcp.flush();
      }
    }, 0);
  }

  private async read(): Promise<Uint8Array | null> {
    const chunk = await this.incoming.read();
    if (chunk !== null && this.closeReason === null) {
      // Room was made: fetch what KCP held back meanwhile.
      this.pump();
    }
    return chunk;
  }

  private async write(data: Uint8Array): Promise<void> {
    let offset = 0;
    while (offset < data.length) {
      if (this.closeReason !== null) {
        throw new ConnectivitizerError(this.closeReason, `The direct path is closed (${this.closeReason}).`);
      }
      if (this.kcp.waitSnd >= SEND_BACKLOG_SEGMENTS) {
        this.writeWaiter = new Deferred<void>();
        await this.writeWaiter.promise;
        continue;
      }
      // KCP takes at most 127 segments per call; hand it pieces well below that.
      const size = Math.min(data.length - offset, 64 * 1024);
      const taken = this.kcp.send(data.subarray(offset, offset + size));
      if (taken < 0) {
        throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The direct path did not accept the data.');
      }
      offset += taken;
    }
    this.scheduleFlush();
  }

  /** The peer announced it is done: let the reader take what already arrived, then end the stream. */
  private async closeAfterDrain(): Promise<void> {
    const deadline = Date.now() + DRAIN_ON_REMOTE_CLOSE_MS;
    while (this.closeReason === null && Date.now() < deadline && (this.kcp.peekSize() >= 0 || this.incoming.size > 0)) {
      this.pump();
      await delay(20);
    }
    this.closeNow(ErrorCodes.PathClosed);
  }

  private closeNow(reason: string): void {
    if (this.closeReason !== null) {
      return;
    }
    this.closeReason = reason;
    clearInterval(this.timer);
    // Only an orderly close reads as the end of the stream; anything else is an error to the reader.
    this.incoming.end(reason === ErrorCodes.PathClosed ? undefined : new ConnectivitizerError(reason, `The direct path was lost (${reason}).`));
    this.writeWaiter?.resolve();
    this.writeWaiter = null;
    try {
      this.socket.close();
    } catch {
      // Already closed.
    }
  }

  async close(): Promise<void> {
    if (this.closeReason !== null) {
      return;
    }
    // Give data that was already written a chance to reach the peer, then tell it we are done.
    const deadline = Date.now() + FLUSH_ON_CLOSE_MS;
    while (this.closeReason === null && this.kcp.waitSnd > 0 && Date.now() < deadline) {
      await delay(10);
    }
    if (this.closeReason === null) {
      for (let i = 0; i < 2; i++) {
        this.socket.send(Uint8Array.of(DatagramType.Close), this.remoteHost, this.remotePort);
      }
    }
    this.closeNow(ErrorCodes.PathClosed);
  }
}
