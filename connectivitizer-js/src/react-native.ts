// The React Native entry point. It contains nothing that needs Node.js: the app passes in the few
// things a phone runtime does not have built in.

import { type ClientOptions, ConnectivitizerClient } from './core/client.js';
import { type LinkedApp, type LinkOptions, linkWith } from './core/link.js';
import { normalizeHost } from './core/direct/addresses.js';
import type { Platform, UdpSocket, WebSocketConnection } from './core/platform.js';

export * from './core/index.js';

/** The part of the module `react-native-udp` the SDK uses. */
export interface ReactNativeUdpModule {
  createSocket(options: { type: 'udp4' }): {
    bind(port: number, callback?: (error?: unknown) => void): void;
    send(message: Uint8Array, offset: number, length: number, port: number, address: string, callback?: (error?: unknown) => void): void;
    on(event: 'message', listener: (message: Uint8Array, remote: { address: string; port: number }) => void): unknown;
    on(event: 'error', listener: (error: unknown) => void): unknown;
    once(event: 'error', listener: (error: unknown) => void): unknown;
    close(): void;
  };
}

export interface ReactNativePlatformOptions {
  /**
   * A cryptographically secure random source, for example `getRandomBytes` from `expo-crypto`.
   * Session keys are made from it; `Math.random` must never be used here.
   */
  randomBytes: (length: number) => Uint8Array;

  /**
   * The module `react-native-udp`, for peer-to-peer connections. Without it every session goes
   * through the relay (and the app then also runs in Expo Go, which has no UDP).
   */
  udp?: ReactNativeUdpModule;

  /**
   * This phone's own addresses: its IPv4 address on its Wi-Fi, and its global IPv6 addresses
   * (Wi-Fi and mobile data). The IPv4 address lets a device on the same Wi-Fi be reached without
   * leaving it; IPv6 lets a device be reached directly from mobile data, where IPv4 goes through
   * the carrier's NAT. The example app's `modules/local-address` reads them from Android's
   * `ConnectivityManager`; on iOS `getIpAddressAsync` of `expo-network` gives the Wi-Fi address.
   */
  localAddress?: () => Promise<string | readonly string[] | null | undefined>;

  /**
   * Whether the UDP socket reaches IPv6 addresses. Default true: on Android react-native-udp's
   * socket is dual-stack. Set false where it is not, so that no IPv6 candidates are announced.
   */
  udpIpv6?: boolean;
}

interface ReactNativeWebSocket {
  binaryType: string;
  onopen: (() => void) | null;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
  onclose: ((event: { code?: number; reason?: string }) => void) | null;
  send(data: string | ArrayBuffer): void;
  close(code?: number, reason?: string): void;
}

function connectWebSocket(url: string, headers: Record<string, string>): Promise<WebSocketConnection> {
  return new Promise((resolve, reject) => {
    // React Native's WebSocket takes request headers as a third argument, which browsers do not.
    const Constructor = (globalThis as unknown as { WebSocket: new (url: string, protocols?: string[] | null, options?: { headers: Record<string, string> }) => ReactNativeWebSocket }).WebSocket;
    const socket = new Constructor(url, null, { headers });
    socket.binaryType = 'arraybuffer';
    let opened = false;
    let closed = false;
    const backlog: (Uint8Array | string)[] = [];
    let closeEvent: { code: number; reason: string } | null = null;

    const connection: WebSocketConnection = {
      send: (data) => {
        // A copy of exactly these bytes: the view may be a window into a larger buffer.
        socket.send(typeof data === 'string' ? data : (data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer));
      },
      close: (code, reason) => {
        try {
          socket.close(code, reason);
        } catch {
          // Already closed.
        }
      },
      onMessage: null,
      onClose: null,
    };
    // Handlers are assigned after the connection is returned; nothing that arrives before may be lost.
    let messageHandler: WebSocketConnection['onMessage'] = null;
    let closeHandler: WebSocketConnection['onClose'] = null;
    Object.defineProperty(connection, 'onMessage', {
      get: () => messageHandler,
      set: (handler: WebSocketConnection['onMessage']) => {
        messageHandler = handler;
        while (handler && backlog.length > 0) {
          handler(backlog.shift()!);
        }
      },
    });
    Object.defineProperty(connection, 'onClose', {
      get: () => closeHandler,
      set: (handler: WebSocketConnection['onClose']) => {
        closeHandler = handler;
        if (handler && closeEvent) {
          const event = closeEvent;
          closeEvent = null;
          handler(event.code, event.reason);
        }
      },
    });

    socket.onopen = () => {
      opened = true;
      resolve(connection);
    };
    socket.onmessage = (event) => {
      const message = typeof event.data === 'string' ? event.data : new Uint8Array(event.data as ArrayBuffer);
      if (messageHandler) {
        messageHandler(message);
      } else {
        backlog.push(message);
      }
    };
    socket.onerror = (event) => {
      if (!opened) {
        reject(new Error(event?.message ?? 'The WebSocket connection failed.'));
      }
    };
    socket.onclose = (event) => {
      if (closed) {
        return;
      }
      closed = true;
      if (!opened) {
        reject(new Error(`The WebSocket connection was refused (${event?.code ?? 0} ${event?.reason ?? ''}).`));
        return;
      }
      const code = event?.code ?? 1006;
      const reason = event?.reason ?? '';
      if (closeHandler) {
        closeHandler(code, reason);
      } else {
        closeEvent = { code, reason };
      }
    };
  });
}

/**
 * Binds a UDP socket to a port of its own choosing. react-native-udp on Android reports the port
 * that was asked for rather than the one the system picked, so binding to port 0 would leave this
 * side announcing the port 0 for its own address, and a device in the same Wi-Fi could not be
 * reached directly.
 */
async function bindUdp(module: ReactNativeUdpModule, randomBytes: (length: number) => Uint8Array, ipv6: boolean): Promise<UdpSocket> {
  let failure: unknown = new Error('No UDP port could be bound.');
  for (let attempt = 0; attempt < 8; attempt++) {
    const bytes = randomBytes(2);
    const port = 49152 + (((bytes[0] << 8) | bytes[1]) % 16384); // the dynamic range
    try {
      return await bindUdpPort(module, port, ipv6);
    } catch (error) {
      failure = error; // most likely in use: try another one
    }
  }
  throw failure;
}

/** IPv6 hosts in canonical form (Java writes them out in full), IPv4-mapped ones as IPv4. */
const plainHost = (host: string): string => (host.includes(':') ? (normalizeHost(host.split('%')[0]) ?? host) : host);

function bindUdpPort(module: ReactNativeUdpModule, port: number, ipv6: boolean): Promise<UdpSocket> {
  return new Promise((resolve, reject) => {
    const socket = module.createSocket({ type: 'udp4' });
    let settled = false;
    const fail = (error: unknown) => {
      if (settled) {
        return;
      }
      settled = true;
      try {
        socket.close();
      } catch {
        // Never bound.
      }
      reject(error);
    };
    socket.on('error', fail);
    socket.bind(port, (error) => {
      if (error) {
        fail(error);
        return;
      }
      if (settled) {
        return;
      }
      settled = true;
      const wrapped: UdpSocket = {
        port,
        ipv6,
        send: (data, host, toPort) => {
          if (host.includes(':') && !ipv6) {
            return;
          }
          socket.send(data, 0, data.length, toPort, host, () => undefined);
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
      socket.on('message', (message, remote) => wrapped.onMessage?.(new Uint8Array(message), plainHost(remote.address), remote.port));
      resolve(wrapped);
    });
  });
}

/** The React Native adapter: the built-in WebSocket and fetch, plus what the app passes in. */
export function reactNativePlatform(options: ReactNativePlatformOptions): Platform {
  const udp = options.udp;
  return {
    description: 'react-native',
    randomBytes: (length) => {
      const bytes = options.randomBytes(length);
      if (!(bytes instanceof Uint8Array) || bytes.length !== length) {
        throw new Error('The random source did not return the requested number of bytes.');
      }
      return bytes;
    },
    fetch: fetchWithRuntime,
    connectWebSocket,
    udp: udp && {
      bind: () => bindUdp(udp, options.randomBytes, options.udpIpv6 ?? true),
      localAddresses: async () => {
        const found = await options.localAddress?.();
        const list = typeof found === 'string' ? [found] : (found ?? []);
        return list.filter((address) => address && address !== '0.0.0.0');
      },
      // The native socket resolves host names itself when sending.
      resolve: async (host) => host,
    },
  };
}

async function fetchWithRuntime(url: string, init: unknown): Promise<{ status: number; text(): Promise<string> }> {
  const response = await (globalThis as unknown as { fetch: (url: string, init: unknown) => Promise<{ status: number; text(): Promise<string> }> }).fetch(url, init);
  return { status: response.status, text: () => response.text() };
}

/**
 * Links this app to an account without a login inside the app: open `prompt.url` in the browser
 * (for example with `Linking.openURL` or `expo-web-browser`), the person signs in on the website
 * and approves, and the app receives an API key of its own. Keep the key in the keystore
 * (`expo-secure-store`) and pass it as `auth: { apiKey }`.
 *
 * ```ts
 * const linked = await linkApp({ apiUrl, client: 'Lamp app', onPrompt: ({ url }) => WebBrowser.openBrowserAsync(url) });
 * await SecureStore.setItemAsync('cz_api_key', linked.apiKey);
 * ```
 */
export function linkApp(options: LinkOptions): Promise<LinkedApp> {
  return linkWith({ fetch: fetchWithRuntime }, { platformName: 'react-native', ...options });
}

/**
 * An application that connects to devices, running in React Native.
 *
 * ```ts
 * import * as Crypto from 'expo-crypto';
 * import dgram from 'react-native-udp';
 * const client = createClient({ apiUrl, auth: { getToken }, sharedKey, reactNative: { randomBytes: Crypto.getRandomBytes, udp: dgram } });
 * ```
 */
export function createClient(options: Omit<ClientOptions, 'platform'> & { reactNative: ReactNativePlatformOptions }): ConnectivitizerClient {
  const { reactNative, ...rest } = options;
  return new ConnectivitizerClient({ ...rest, platform: reactNativePlatform(reactNative) });
}
