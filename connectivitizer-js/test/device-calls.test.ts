import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { ConnectivitizerAgent } from '../src/core/agent.js';
import type { TokenResponse } from '../src/core/api.js';
import { base64Encode } from '../src/core/bytes.js';
import type { ConnectivitizerClient } from '../src/core/client.js';
import { ConnectivitizerError, ErrorCodes } from '../src/core/errors.js';
import { generateSharedKey } from '../src/core/noise.js';
import type { Platform, WebSocketConnection } from '../src/core/platform.js';
import type { SignalEnvelope } from '../src/core/signaling.js';
import { memoryPair } from './support.js';

const sharedKey = generateSharedKey((length) => new Uint8Array(randomBytes(length)));
const blob = base64Encode(new Uint8Array([1, 2, 3]));
const tick = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

/**
 * The platform as far as a device needs it here: the device-key login, the device list and a
 * signaling connection that welcomes the device. Everything else the device sends is kept for the
 * test, which plays the control plane's part by pushing messages.
 */
function fakePlatform(tokenStatus = 200) {
  const sockets: WebSocketConnection[] = [];
  const received: SignalEnvelope[] = [];
  const listRequests: (string | undefined)[] = [];
  let arrived: (() => void) | null = null;
  const token: TokenResponse = { accessToken: 'device-token', expiresIn: 600, endpointType: 'device', endpointId: 'dev-bell', workspaceId: 'ws-1', slug: 'bell' };

  const platform: Platform = {
    randomBytes: (length) => new Uint8Array(randomBytes(length)),
    fetch: async (url, init) => {
      if (url.endsWith('v1/auth/device-key/token')) {
        return { status: tokenStatus, text: async () => (tokenStatus === 200 ? JSON.stringify(token) : '{"error":"DEVICE_REVOKED"}') };
      }
      if (url.endsWith('v1/devices')) {
        listRequests.push(init.headers.Authorization);
        return { status: 200, text: async () => JSON.stringify([{ id: 'dev-lamp', name: 'lamp', slug: 'lamp', online: true, capabilities: [], services: ['api'] }]) };
      }
      return { status: 404, text: async () => '{"error":"NOT_FOUND"}' };
    },
    connectWebSocket: async () => {
      const socket: WebSocketConnection = {
        onMessage: null,
        onClose: null,
        send: (data) => {
          const envelope = JSON.parse(data as string) as SignalEnvelope;
          if (envelope.t === 'hello') {
            queueMicrotask(() => socket.onMessage?.(JSON.stringify({ t: 'welcome', re: envelope.id, d: { endpointType: 'device', endpointId: 'dev-bell', workspaceId: 'ws-1' } })));
            return;
          }
          received.push(envelope);
          arrived?.();
        },
        close: () => undefined,
      };
      sockets.push(socket);
      return socket;
    },
    connectTcp: async () => memoryPair()[0],
  };

  return {
    platform,
    sockets,
    received,
    listRequests,
    /** Delivers a message to the device, as the control plane does. */
    push: (envelope: SignalEnvelope) => sockets[sockets.length - 1].onMessage?.(JSON.stringify(envelope)),
    /** The next message of that type the device sends, or one it sent already. */
    async next(type: string): Promise<SignalEnvelope> {
      while (true) {
        const index = received.findIndex((envelope) => envelope.t === type);
        if (index >= 0) {
          return received.splice(index, 1)[0];
        }
        await new Promise<void>((resolve) => {
          arrived = resolve;
        });
      }
    },
  };
}

function bell(platform: Platform): ConnectivitizerAgent {
  return new ConnectivitizerAgent({ apiUrl: 'https://api.example/', deviceKey: 'czd_x', name: 'bell', sharedKey, services: { api: '127.0.0.1:8080' }, platform });
}

/** The agent's own candidate map and its calling half with the half's map: where a `path.candidates` message ends up. */
function inside(agent: ConnectivitizerAgent) {
  const fields = agent as unknown as { candidates: Map<string, unknown>; caller: ConnectivitizerClient };
  return { device: fields.candidates, caller: fields.caller, calling: (fields.caller as unknown as { candidates: Map<string, unknown> }).candidates };
}

const rejectsWith = (work: Promise<unknown>, code: string): Promise<void> =>
  assert.rejects(work, (error: unknown) => error instanceof ConnectivitizerError && error.code === code);

test('a device opens a session over its own signaling connection, and candidates reach the half they belong to', async () => {
  const server = fakePlatform();
  const agent = bell(server.platform);
  const { device, caller, calling } = inside(agent);

  // Asked before the device is connected: the request waits for the connection.
  const first = agent.connect('lamp', ['api']);
  first.catch(() => undefined);
  const running = agent.run();
  await agent.waitUntilConnected();

  const request = await server.next('connect.request');
  assert.deepEqual(request.d, { device: 'lamp', services: ['api'], e2e: ['shared-key'] });
  assert.equal(server.sockets.length, 1);

  // While the session id of the request is unknown, candidates are kept on both halves.
  server.push({ t: 'path.candidates', d: { sid: 'in-1', blob } });
  assert.deepEqual([...calling.keys()], ['in-1']);
  assert.deepEqual([...device.keys()], ['in-1']);

  // The grant names the session; what belongs to a session opened to the device is dropped by the calling half.
  server.push({ t: 'connect.grant', re: request.id, d: { sid: 'out-1', grant: 'not.a.grant', peer: { type: 'device', id: 'dev-lamp', name: 'lamp' } } });
  await tick();
  assert.equal(caller.owns('out-1'), true);
  assert.deepEqual([...calling.keys()], []);

  // Candidates of the session the device opened go to the calling half only.
  server.push({ t: 'path.candidates', d: { sid: 'out-1', blob } });
  assert.deepEqual([...calling.keys()], ['out-1']);
  assert.deepEqual([...device.keys()], ['in-1']);

  // The other device's answer arrives on the same connection.
  server.push({ t: 'connect.answer', d: { sid: 'out-1', accept: false, error: ErrorCodes.DeviceRejected } });
  await rejectsWith(first, ErrorCodes.DeviceRejected);
  assert.deepEqual((await server.next('session.update')).d, { sid: 'out-1', state: 'failed', error: ErrorCodes.DeviceRejected });
  assert.equal(caller.owns('out-1'), false);
  assert.deepEqual([...calling.keys()], []);
  assert.deepEqual(agent.outgoingSessions, []);

  // With no request pending, candidates of other sessions stay with the device half.
  server.push({ t: 'path.candidates', d: { sid: 'in-2', blob } });
  assert.deepEqual([...calling.keys()], []);
  assert.deepEqual([...device.keys()], ['in-1', 'in-2']);

  // Candidates that arrive together with the grant are on both halves for a moment; the device half lets go of them.
  const second = agent.connect('lamp', ['api']);
  second.catch(() => undefined);
  const again = await server.next('connect.request');
  server.push({ t: 'path.candidates', d: { sid: 'out-2', blob } });
  server.push({ t: 'connect.grant', re: again.id, d: { sid: 'out-2', grant: 'not.a.grant', peer: { type: 'device', id: 'dev-lamp', name: 'lamp' } } });
  server.push({ t: 'connect.answer', d: { sid: 'out-2', accept: true } });
  assert.equal(device.has('out-2'), true);
  // The device accepted, and the grant does not verify.
  await rejectsWith(second, ErrorCodes.GrantInvalid);
  assert.deepEqual([...device.keys()], ['in-1', 'in-2']);
  assert.deepEqual([...calling.keys()], []);

  // The device list is asked for with the device's own token.
  assert.deepEqual((await agent.listDevices()).map((entry) => entry.slug), ['lamp']);
  assert.deepEqual(server.listRequests, ['Bearer device-token']);

  await agent.stop();
  await running;
  assert.equal(server.sockets.length, 1);
  await rejectsWith(agent.connect('lamp', ['api']), ErrorCodes.SessionClosed);
});

test('a refusal of the platform reaches the device that asked', async () => {
  const server = fakePlatform();
  const agent = bell(server.platform);
  const running = agent.run();
  await agent.waitUntilConnected();

  const connecting = agent.connect('bell', ['api']);
  connecting.catch(() => undefined);
  const request = await server.next('connect.request');
  server.push({ t: 'error', re: request.id, d: { code: ErrorCodes.Forbidden, message: 'The device key may not connect.' } });
  await rejectsWith(connecting, ErrorCodes.Forbidden);
  assert.equal(agent.isConnected, true);

  await agent.stop();
  await running;
});

test('a device the platform does not accept opens no sessions', async () => {
  const server = fakePlatform(403);
  const agent = bell(server.platform);
  const connecting = agent.connect('lamp', ['api']);
  connecting.catch(() => undefined);

  await rejectsWith(agent.run(), ErrorCodes.DeviceRevoked);
  await rejectsWith(connecting, ErrorCodes.DeviceRevoked);
  await rejectsWith(agent.connect('lamp', ['api']), ErrorCodes.DeviceRevoked);
});

test('a device stopped before it connected opens no sessions', async () => {
  const agent = bell(fakePlatform().platform);
  const connecting = agent.connect('lamp', ['api']);
  connecting.catch(() => undefined);
  await agent.stop();
  await rejectsWith(connecting, ErrorCodes.SessionClosed);
});

test('only a device that logs in with a device key lists the devices it may reach', async () => {
  const server = fakePlatform();
  const enrolled = new ConnectivitizerAgent({
    apiUrl: 'https://api.example/',
    login: async () => ({ accessToken: 'enrolled-token', expiresIn: 600, endpointType: 'device', endpointId: 'dev-box', workspaceId: 'ws-1' }),
    sharedKey,
    services: {},
    platform: server.platform,
  });
  await rejectsWith(enrolled.listDevices(), ErrorCodes.Forbidden);
  assert.deepEqual(server.listRequests, []);
});
