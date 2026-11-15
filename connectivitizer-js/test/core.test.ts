import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { PlatformApi } from '../src/core/api.js';
import { base64Decode, base64Encode, base64UrlEncode, concat, utf8Decode, utf8Encode } from '../src/core/bytes.js';
import { Kcp } from '../src/core/direct/kcp.js';
import { ConnectivitizerError, ErrorCodes } from '../src/core/errors.js';
import { httpRequest } from '../src/core/http.js';
import { INITIAL_WINDOW, MuxSession } from '../src/core/mux.js';
import type { Platform } from '../src/core/platform.js';
import { type ByteStream, StreamReader } from '../src/core/streams.js';
import { StreamWebSocket } from '../src/core/websocket.js';
import { memoryPair } from './support.js';

const sha = (bytes: Uint8Array): string => createHash('sha256').update(bytes).digest('hex');

async function readAll(stream: ByteStream): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  while (true) {
    const chunk = await stream.read();
    if (chunk === null) {
      return concat(...parts);
    }
    parts.push(chunk);
  }
}

test('text and base64 helpers agree with the runtime', () => {
  for (const text of ['', 'plain', 'Grüße aus Köln', '日本語', 'emoji 🙂 and a lone \ud800 surrogate']) {
    assert.deepEqual(utf8Encode(text), new Uint8Array(Buffer.from(text, 'utf8')));
    assert.equal(utf8Decode(new Uint8Array(Buffer.from(text, 'utf8'))), Buffer.from(text, 'utf8').toString('utf8'));
  }
  for (let length = 0; length < 70; length++) {
    const bytes = new Uint8Array(randomBytes(length));
    assert.equal(base64Encode(bytes), Buffer.from(bytes).toString('base64'));
    assert.equal(base64UrlEncode(bytes), Buffer.from(bytes).toString('base64url'));
    assert.deepEqual(base64Decode(base64Encode(bytes)), bytes);
    assert.deepEqual(base64Decode(base64UrlEncode(bytes)), bytes);
  }
  assert.throws(() => base64Decode('not base64!'));
});

test('mux: streams are independent, flow-controlled and half-closable', async () => {
  const [a, b] = memoryPair();
  const initiator = new MuxSession(a, true);
  const device = new MuxSession(b, false);
  initiator.start();
  device.start();

  // The device echoes every stream until the opener finishes sending.
  void (async () => {
    while (true) {
      const stream = await device.accept();
      if (stream === null) {
        return;
      }
      void (async () => {
        while (true) {
          const chunk = await stream.read();
          if (chunk === null) {
            break;
          }
          await stream.write(chunk);
        }
        await stream.end();
      })();
    }
  })();

  // Several times the window, on three streams at once: nothing gets lost or mixed up.
  const payloads = [0, 1, 2].map(() => new Uint8Array(randomBytes(3 * INITIAL_WINDOW + 12345)));
  const echoed = await Promise.all(payloads.map(async (payload) => {
    const stream = initiator.open();
    assert.equal(stream.id % 2, 1);
    const reading = readAll(stream);
    await stream.write(payload);
    await stream.end();
    return reading;
  }));
  echoed.forEach((bytes, index) => assert.equal(sha(bytes), sha(payloads[index])));

  await initiator.close();
  assert.equal(await initiator.completion, ErrorCodes.SessionClosed);
  assert.equal(await device.completion, ErrorCodes.SessionClosed);
});

test('mux: a peer that breaks the framing ends the session with a protocol error', async () => {
  const [a, b] = memoryPair();
  const session = new MuxSession(a, true);
  session.start();
  // Version 1 does not exist.
  await b.write(Uint8Array.of(1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0));
  assert.equal(await session.completion, ErrorCodes.MuxProtocolError);
  assert.throws(() => session.open(), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.MuxProtocolError);
});

test('mux: a stream opened with the wrong parity is a protocol error', async () => {
  const [a, b] = memoryPair();
  const session = new MuxSession(a, true);
  session.start();
  // The device side may only open even streams; this SYN claims stream 3.
  await b.write(Uint8Array.of(0, 1, 0, 1, 0, 0, 0, 3, 0, 0, 0, 0));
  assert.equal(await session.completion, ErrorCodes.MuxProtocolError);
});

/** Serves exactly one HTTP exchange on the other end of a memory stream. */
function serveOnce(response: (request: string) => Uint8Array[], closeAfter = true): { open: () => Promise<ByteStream>; request: Promise<string> } {
  const [client, server] = memoryPair();
  const request = (async () => {
    const reader = new StreamReader(server);
    const head = utf8Decode((await reader.readHead(65536))!);
    const length = Number.parseInt(/content-length: (\d+)/i.exec(head)?.[1] ?? '0', 10);
    const body = length > 0 ? utf8Decode((await reader.readExact(length))!) : '';
    for (const part of response(head + body)) {
      await server.write(part);
    }
    if (closeAfter) {
      await server.end();
    }
    return head + body;
  })();
  return { open: async () => client, request };
}

test('http: a body with Content-Length, and what the service receives', async () => {
  const server = serveOnce(() => [utf8Encode('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nX-A: 1\r\nX-A: 2\r\nContent-Length: 5\r\n\r\nhello')]);
  const response = await httpRequest(server.open, 'api', '/things?x=1', { method: 'post', body: 'ping', headers: { 'X-Token': 'abc' } });
  assert.equal(response.status, 200);
  assert.equal(response.ok, true);
  assert.equal(response.headers.get('x-a'), '1, 2');
  assert.equal(await response.text(), 'hello');
  const request = await server.request;
  assert.match(request, /^POST \/things\?x=1 HTTP\/1\.1\r\n/);
  assert.match(request, /\r\nHost: api\r\n/);
  assert.match(request, /\r\nX-Token: abc\r\n/);
  assert.match(request, /\r\nContent-Length: 4\r\n/);
  assert.ok(request.endsWith('\r\n\r\nping'));
});

test('http: chunked bodies, interim responses and bodies that end with the connection', async () => {
  const chunked = serveOnce(() => [
    utf8Encode('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n'),
    utf8Encode('6;ext=1\r\npedia \r\nE\r\nin \r\n\r\nchunks.\r\n0\r\nTrailer: x\r\n\r\n'),
  ]);
  assert.equal(await (await httpRequest(chunked.open, 'api', '/')).text(), 'Wikipedia in \r\n\r\nchunks.');

  const untilClose = serveOnce(() => [utf8Encode('HTTP/1.0 200 OK\r\n\r\npart one, '), utf8Encode('part two')]);
  assert.equal(await (await httpRequest(untilClose.open, 'api', '/')).text(), 'part one, part two');

  const empty = serveOnce(() => [utf8Encode('HTTP/1.1 204 No Content\r\n\r\n')]);
  const none = await httpRequest(empty.open, 'api', '/', { method: 'DELETE' });
  assert.equal(none.status, 204);
  assert.equal((await none.bytes()).length, 0);

  const json = serveOnce(() => [utf8Encode('HTTP/1.1 404 Not Found\r\nContent-Length: 15\r\n\r\n{"error":"gone"}'.replace('15', '16'))]);
  const missing = await httpRequest(json.open, 'api', '/nothing');
  assert.equal(missing.ok, false);
  assert.deepEqual(await missing.json(), { error: 'gone' });
});

test('http: a truncated body and a request that cannot be sent are errors', async () => {
  const cut = serveOnce(() => [utf8Encode('HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nonly this')]);
  await assert.rejects((await httpRequest(cut.open, 'api', '/')).bytes(), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.PathClosed);

  await assert.rejects(httpRequest(async () => memoryPair()[0], 'api', 'no-slash'), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.InvalidRequest);
  await assert.rejects(httpRequest(async () => memoryPair()[0], 'api', '/', { headers: { 'X-Evil': 'a\r\nInjected: 1' } }));
});

test('api: only a refusal the API names is passed on; anything else is a passing failure', async () => {
  const answering = (status: number, body: string) =>
    new PlatformApi('https://api.example', { fetch: async () => ({ status, text: async () => body }) } as unknown as Platform);
  const fails = (status: number, body: string, code: string) =>
    assert.rejects(answering(status, body).deviceKeyToken('czd_x', 'd'), (error: unknown) => error instanceof ConnectivitizerError && error.code === code);

  // What a proxy says while the API restarts must not make a device give up.
  await fails(502, '<html><body>502 Bad Gateway</body></html>', ErrorCodes.SignalingUnavailable);
  await fails(503, '', ErrorCodes.SignalingUnavailable);
  await fails(200, '', ErrorCodes.SignalingUnavailable);
  await fails(401, '', ErrorCodes.Unauthenticated);
  await fails(403, '{"error":"DEVICE_REVOKED"}', ErrorCodes.DeviceRevoked);
});

test('websocket: handshake, text, binary, fragments, ping and close', async () => {
  const [client, server] = memoryPair();
  const serverSide = (async () => {
    const reader = new StreamReader(server);
    const head = utf8Decode((await reader.readHead(65536))!);
    const key = /sec-websocket-key: (.+)\r\n/i.exec(head)![1];
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    await server.write(utf8Encode(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\nSec-WebSocket-Protocol: chat\r\n\r\n`));

    // One masked client frame: echo its payload back as a text frame in two fragments, after a ping.
    const header = (await reader.readExact(2))!;
    assert.equal(header[1] & 0x80, 0x80, 'client frames are masked');
    const length = header[1] & 0x7f;
    const mask = (await reader.readExact(4))!;
    const payload = (await reader.readExact(length))!.slice();
    payload.forEach((byte, index) => (payload[index] = byte ^ mask[index & 3]));
    await server.write(Uint8Array.of(0x89, 2, 1, 2));
    await server.write(concat(Uint8Array.of(0x01, 3), payload.subarray(0, 3)));
    await server.write(concat(Uint8Array.of(0x80, payload.length - 3), payload.subarray(3)));
    // A binary message long enough for the 16-bit length form.
    const binary = new Uint8Array(300).fill(7);
    await server.write(concat(Uint8Array.of(0x82, 126, 300 >> 8, 300 & 255), binary));
    // The client answers the ping with a pong carrying the same payload.
    const pong = (await reader.readExact(2))!;
    assert.equal(pong[0], 0x8a);
    await reader.readExact(4 + (pong[1] & 0x7f));
    await server.write(Uint8Array.of(0x88, 2, 0x0f, 0xa0));
    return head;
  })();

  const socket = await StreamWebSocket.connect(client, { host: 'api', path: '/ws', protocols: ['chat'], randomBytes: (length) => new Uint8Array(randomBytes(length)) });
  assert.equal(socket.protocol, 'chat');
  const messages: (string | Uint8Array)[] = [];
  const closed = new Promise<{ code: number; reason: string }>((resolve) => (socket.onClose = (code, reason) => resolve({ code, reason })));
  socket.onMessage = (message) => messages.push(message);
  socket.send('hello world');

  assert.equal((await closed).code, 4000);
  assert.equal(messages[0], 'hello world');
  assert.deepEqual(messages[1], new Uint8Array(300).fill(7));
  assert.match(await serverSide, /^GET \/ws HTTP\/1\.1\r\nHost: api\r\n/);
  assert.throws(() => socket.send('after close'));
});

test('kcp: a megabyte arrives intact over a link that loses, duplicates and reorders packets', async () => {
  let now = 1_000_000;
  const inFlight: { at: number; to: Kcp; packet: Uint8Array }[] = [];
  let seed = 42;
  const random = () => {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    return seed / 0x7fffffff;
  };
  const link = (to: () => Kcp) => (packet: Uint8Array) => {
    assert.ok(packet.length <= 1199, 'no packet exceeds the datagram size');
    if (random() < 0.1) {
      return; // lost
    }
    const copies = random() < 0.05 ? 2 : 1;
    for (let i = 0; i < copies; i++) {
      inFlight.push({ at: now + 5 + Math.floor(random() * 40), to: to(), packet });
    }
  };
  const configure = (kcp: Kcp) => {
    kcp.stream = true;
    kcp.setMtu(1199);
    kcp.noDelay(1, 10, 2, 1);
    kcp.wndSize(256, 256);
    return kcp;
  };
  const sender: Kcp = configure(new Kcp(0x11223345, link(() => receiver)));
  const receiver: Kcp = configure(new Kcp(0x11223345, link(() => sender)));

  const payload = new Uint8Array(randomBytes(1_000_000));
  const received: Uint8Array[] = [];
  let offset = 0;
  let total = 0;
  for (let steps = 0; total < payload.length && steps < 200_000; steps++) {
    now += 10;
    while (offset < payload.length && sender.waitSnd < 512) {
      offset += sender.send(payload.subarray(offset, Math.min(offset + 16_000, payload.length)));
    }
    for (let i = inFlight.length - 1; i >= 0; i--) {
      if (inFlight[i].at <= now) {
        const [due] = inFlight.splice(i, 1);
        assert.equal(due.to.input(due.packet), 0);
      }
    }
    sender.update(now);
    receiver.update(now);
    for (let chunk = receiver.recv(); chunk !== null; chunk = receiver.recv()) {
      received.push(chunk);
      total += chunk.length;
    }
  }
  assert.equal(total, payload.length);
  assert.equal(sha(concat(...received)), sha(payload));
  assert.equal(sender.state, 0);
});

test('kcp: a packet of another conversation is refused', () => {
  const kcp = new Kcp(7, () => undefined);
  const other = new Kcp(8, (packet) => assert.equal(kcp.input(packet), -1));
  other.send(utf8Encode('hello'));
  other.update(1);
});
