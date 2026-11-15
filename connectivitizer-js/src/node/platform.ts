import { randomBytes } from 'node:crypto';
import dgram from 'node:dgram';
import { lookup } from 'node:dns/promises';
import net from 'node:net';
import os from 'node:os';
import tls from 'node:tls';
import { isIpv6, normalizeHost } from '../core/direct/addresses.js';
import { ConnectivitizerError, ErrorCodes } from '../core/errors.js';
import type { Platform, UdpSocket, WebSocketConnection } from '../core/platform.js';
import { type ByteStream, ChunkQueue } from '../core/streams.js';
import { StreamWebSocket, WebSocketRefusedError } from '../core/websocket.js';

export interface NodePlatformOptions {
  /** Additional certificate authorities for the connections to the platform (PEM), e.g. for a self-hosted or development installation. */
  ca?: string | string[];

  /** Offer loopback addresses for peer-to-peer connections. Only useful when both endpoints run on the same machine. */
  includeLoopback?: boolean;
}

/** How much received data may wait for its reader before the socket is told to pause. */
const READ_BACKLOG_BYTES = 1024 * 1024;

/** Wraps a TCP or TLS socket as the byte stream the core works with. */
export function socketStream(socket: net.Socket): ByteStream {
  const incoming = new ChunkQueue();
  let failure: Error | null = null;
  socket.on('data', (chunk: Buffer) => {
    incoming.push(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
    if (incoming.size > READ_BACKLOG_BYTES) {
      socket.pause();
    }
  });
  socket.on('end', () => incoming.end());
  socket.on('error', (error) => {
    failure = error;
    incoming.end(error);
  });
  socket.on('close', () => incoming.end(failure ?? undefined));

  return {
    read: async () => {
      const chunk = await incoming.read();
      if (socket.isPaused() && incoming.size < READ_BACKLOG_BYTES / 2) {
        socket.resume();
      }
      return chunk;
    },
    write: (data) =>
      new Promise<void>((resolve, reject) => {
        if (socket.destroyed) {
          reject(failure ?? new Error('The connection is closed.'));
          return;
        }
        socket.write(data, (error) => (error ? reject(error) : resolve()));
      }),
    end: () =>
      new Promise<void>((resolve) => {
        if (socket.destroyed || socket.writableEnded) {
          resolve();
        } else {
          socket.end(() => resolve());
        }
      }),
    close: async () => {
      socket.destroy();
    },
  };
}

function connectSocket(url: URL, options: NodePlatformOptions): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const secure = url.protocol === 'wss:' || url.protocol === 'https:';
    const port = url.port ? Number.parseInt(url.port, 10) : secure ? 443 : 80;
    const host = url.hostname.replace(/^\[|\]$/g, '');
    const socket = secure
      ? tls.connect({ host, port, servername: net.isIP(host) ? undefined : host, ca: options.ca, ALPNProtocols: ['http/1.1'] })
      : net.connect({ host, port });
    const onError = (error: Error) => reject(error);
    socket.once('error', onError);
    socket.once(secure ? 'secureConnect' : 'connect', () => {
      socket.off('error', onError);
      socket.setNoDelay(true);
      resolve(socket);
    });
  });
}

async function connectWebSocket(url: string, headers: Record<string, string>, options: NodePlatformOptions): Promise<WebSocketConnection> {
  const target = new URL(url);
  const socket = await connectSocket(target, options);
  let webSocket: StreamWebSocket;
  try {
    webSocket = await StreamWebSocket.connect(socketStream(socket), {
      host: target.host,
      path: (target.pathname || '/') + target.search,
      headers,
      randomBytes: (length) => new Uint8Array(randomBytes(length)),
    });
  } catch (error) {
    if (error instanceof WebSocketRefusedError) {
      // The platform names its reason in a header (the relay) or leaves it to the status (signaling).
      const named = error.headers.get('cz-error');
      const code = named ?? (error.status === 401 ? ErrorCodes.Unauthenticated : error.status === 403 ? ErrorCodes.Forbidden : ErrorCodes.RelayRejected);
      throw new ConnectivitizerError(code, `The server refused the connection (HTTP ${error.status}${named ? `, ${named}` : ''}).`);
    }
    throw error;
  }

  const connection: WebSocketConnection = {
    send: (data) => webSocket.send(data),
    close: (code, reason) => webSocket.close(code, reason),
    onMessage: null,
    onClose: null,
  };
  // Assigned late on purpose: messages that arrived meanwhile are kept until a handler is set.
  let messageHandler: WebSocketConnection['onMessage'] = null;
  let closeHandler: WebSocketConnection['onClose'] = null;
  Object.defineProperty(connection, 'onMessage', {
    get: () => messageHandler,
    set: (handler: WebSocketConnection['onMessage']) => {
      messageHandler = handler;
      webSocket.onMessage = handler;
    },
  });
  Object.defineProperty(connection, 'onClose', {
    get: () => closeHandler,
    set: (handler: WebSocketConnection['onClose']) => {
      closeHandler = handler;
      webSocket.onClose = handler;
    },
  });
  return connection;
}

/** A dual-stack socket where the system has IPv6; otherwise IPv4 only. */
async function bindUdp(): Promise<UdpSocket> {
  try {
    return await bindUdpFamily('udp6');
  } catch {
    return bindUdpFamily('udp4');
  }
}

function bindUdpFamily(type: 'udp4' | 'udp6'): Promise<UdpSocket> {
  const ipv6 = type === 'udp6';
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket({ type, ipv6Only: false });
    socket.once('error', reject);
    socket.bind(0, () => {
      socket.off('error', reject);
      socket.on('error', () => undefined);
      const wrapped: UdpSocket = {
        port: socket.address().port,
        ipv6,
        send: (data, host, port) => {
          if (isIpv6(host) && !ipv6) {
            return; // an IPv6 candidate this socket cannot reach
          }
          // A dual-stack socket reaches an IPv4 peer by its IPv4-mapped address.
          socket.send(data, port, ipv6 && !isIpv6(host) ? `::ffff:${host}` : host, () => undefined);
        },
        onMessage: null,
        close: () => {
          try {
            socket.close();
          } catch {
            // Already closed.
          }
        },
      };
      socket.on('message', (message, remote) => {
        const host = remote.address.startsWith('::ffff:') || remote.address.includes('%') ? (normalizeHost(remote.address.split('%')[0]) ?? remote.address) : remote.address;
        wrapped.onMessage?.(new Uint8Array(message.buffer, message.byteOffset, message.byteLength), host, remote.port);
      });
      resolve(wrapped);
    });
  });
}

/** The Node.js adapter: TCP and TLS sockets, UDP, the system's random source and name resolution. */
export function nodePlatform(options: NodePlatformOptions = {}): Platform {
  return {
    description: `node ${process.version} ${process.platform}`,
    randomBytes: (length) => new Uint8Array(randomBytes(length)),
    fetch: async (url, init) => {
      const response = await fetch(url, init);
      return { status: response.status, text: () => response.text() };
    },
    connectWebSocket: (url, headers) => connectWebSocket(url, headers, options),
    udp: {
      bind: bindUdp,
      localAddresses: async () => {
        const addresses: string[] = [];
        for (const list of Object.values(os.networkInterfaces())) {
          for (const entry of list ?? []) {
            // IPv6: only global addresses are offered (the core filters); they need no zone.
            const family = String(entry.family);
            const usable = family === 'IPv4' ? !entry.internal || options.includeLoopback : (family === 'IPv6' || family === '6') && !entry.internal;
            if (usable && !addresses.includes(entry.address)) {
              addresses.push(entry.address);
            }
          }
        }
        return addresses;
      },
      resolve: async (host) => (await lookup(host, { family: 4 })).address,
    },
    connectTcp: (host, port) =>
      new Promise<ByteStream>((resolve, reject) => {
        const socket = net.connect({ host, port });
        socket.once('error', reject);
        socket.once('connect', () => {
          socket.off('error', reject);
          socket.setNoDelay(true);
          resolve(socketStream(socket));
        });
      }),
  };
}
