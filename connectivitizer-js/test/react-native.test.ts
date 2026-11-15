import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { type ReactNativeUdpModule, reactNativePlatform } from '../src/react-native.js';

/**
 * Behaves like react-native-udp 4.x on Android: the bind callback gets no error and the socket
 * would report the port that was asked for (0 included), not the one the system picked. Ports in
 * `taken` fail as if another socket held them.
 */
function fakeUdpModule(taken: Set<number>) {
  const bound: number[] = [];
  let closed = 0;
  const module: ReactNativeUdpModule = {
    createSocket: () => {
      const listeners: Record<string, ((...args: never[]) => void)[]> = {};
      return {
        bind: (port: number, callback?: (error?: unknown) => void) => {
          queueMicrotask(() => {
            if (taken.has(port)) {
              callback?.(new Error('EADDRINUSE'));
              for (const listener of listeners.error ?? []) {
                (listener as (error: unknown) => void)(new Error('EADDRINUSE'));
              }
              return;
            }
            bound.push(port);
            callback?.();
          });
        },
        send: () => undefined,
        on: (event: string, listener: (...args: never[]) => void) => {
          (listeners[event] ??= []).push(listener);
          return undefined;
        },
        once: () => undefined,
        close: () => {
          closed++;
        },
      };
    },
  };
  return { module, bound, closed: () => closed };
}

test('the React Native UDP socket announces the port it is really bound to', async () => {
  const fake = fakeUdpModule(new Set());
  const platform = reactNativePlatform({ randomBytes: (n) => new Uint8Array(randomBytes(n)), udp: fake.module });
  const socket = await platform.udp!.bind();
  assert.equal(fake.bound.length, 1);
  assert.equal(socket.port, fake.bound[0]);
  assert.ok(socket.port >= 49152 && socket.port <= 65535, `port ${socket.port} is in the dynamic range`);
});

test('a port that is in use is replaced by another one', async () => {
  // The fixed random source makes the first choice 49152 + 0x0102 % 16384 = 49410.
  const sequence = [new Uint8Array([1, 2]), new Uint8Array([3, 4])];
  const fake = fakeUdpModule(new Set([49410]));
  const platform = reactNativePlatform({ randomBytes: () => sequence.shift() ?? new Uint8Array([5, 6]), udp: fake.module });
  const socket = await platform.udp!.bind();
  assert.equal(socket.port, 49152 + 0x0304);
  assert.deepEqual(fake.bound, [49152 + 0x0304]);
  assert.equal(fake.closed(), 1);
});
