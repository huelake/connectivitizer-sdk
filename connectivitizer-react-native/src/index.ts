// Connectivitizer for React Native apps. The protocol is the TypeScript SDK's (@huelake/connectivitizer);
// this package adds what a phone runtime does not have built in: UDP sockets and the phone's own
// addresses (the native module ConnectivitizerNative, on Android), and a secure random source
// (expo-crypto). The app passes nothing of that: only its address, its key and the shared key.

import { requireOptionalNativeModule } from 'expo';
import { getRandomBytes } from 'expo-crypto';
import {
  type ClientOptions,
  ConnectivitizerClient,
  normalizeHost,
  type Platform,
  reactNativePlatform,
  type UdpSocket,
} from '@huelake/connectivitizer/react-native';

export * from '@huelake/connectivitizer/react-native';

interface UdpMessageEvent {
  id: number;
  /** Uint8Array from the native side; a base64 string where the runtime cannot pass bytes in events. */
  data: Uint8Array | string;
  host: string;
  port: number;
}

interface NativeModule {
  udpBind(): Promise<{ id: number; port: number; ipv6: boolean }>;
  udpSend(id: number, data: Uint8Array, host: string, port: number): void;
  udpClose(id: number): void;
  getLocalAddressesAsync(): Promise<string[]>;
  addListener(event: 'onUdpMessage', listener: (event: UdpMessageEvent) => void): { remove(): void };
}

const native = requireOptionalNativeModule<NativeModule>('ConnectivitizerNative');

/**
 * Whether this build can connect peer to peer. False in Expo Go (which cannot contain the native
 * module) and on iOS: sessions then go through the relay, still end-to-end encrypted.
 */
export const peerToPeerAvailable = (): boolean => native !== null;

function bytesOf(data: Uint8Array | string): Uint8Array {
  if (typeof data !== 'string') {
    return data;
  }
  const text = atob(data);
  const bytes = new Uint8Array(text.length);
  for (let index = 0; index < text.length; index++) {
    bytes[index] = text.charCodeAt(index);
  }
  return bytes;
}

/** The sockets of this app by native id; one listener hands each datagram to its socket. */
const sockets = new Map<number, UdpSocket>();
let listening = false;

function nativeUdp(module: NativeModule): NonNullable<Platform['udp']> {
  if (!listening) {
    listening = true;
    module.addListener('onUdpMessage', (event) => {
      const socket = sockets.get(event.id);
      // IPv6 comes written out in full from the native side; the SDK compares canonical forms.
      socket?.onMessage?.(bytesOf(event.data), normalizeHost(event.host) ?? event.host, event.port);
    });
  }
  return {
    bind: async () => {
      const { id, port, ipv6 } = await module.udpBind();
      const socket: UdpSocket = {
        port,
        ipv6,
        send: (data, host, toPort) => module.udpSend(id, data, host, toPort),
        onMessage: null,
        close: () => {
          sockets.delete(id);
          module.udpClose(id);
        },
      };
      sockets.set(id, socket);
      return socket;
    },
    localAddresses: () => module.getLocalAddressesAsync().catch(() => []),
    // The platform announces its STUN servers as IP addresses; there is nothing to resolve.
    resolve: async (host) => host,
  };
}

let warned = false;

/** The platform of this app: the phone's random source, its WebSocket and fetch, and native UDP where the build has it. */
export function platform(): Platform {
  const base = reactNativePlatform({ randomBytes: (length) => getRandomBytes(length) });
  if (native === null) {
    if (!warned) {
      warned = true;
      console.warn('Connectivitizer: this build has no native module (Expo Go, or iOS). Every session goes through the relay, still end-to-end encrypted.');
    }
    return base;
  }
  return { ...base, udp: nativeUdp(native) };
}

/**
 * An app that connects to devices.
 *
 * ```ts
 * const client = createClient({ apiUrl, auth: { apiKey }, sharedKey });
 * const session = await client.connect('living-room-lamp', ['api']);
 * ```
 */
export function createClient(options: Omit<ClientOptions, 'platform'>): ConnectivitizerClient {
  return new ConnectivitizerClient({ ...options, platform: platform() });
}
