// A calling application driven entirely by its environment, for the interoperability tests: it
// connects to a device, uses its service in every way the SDK offers, and prints one JSON
// document saying what happened. The .NET example client prints the same document.
//
//   CZ_API_URL, CZ_API_KEY, CZ_DEVICE (default home-pc), CZ_SERVICE (default api)
//   CZ_SHARED_KEY         the key shared with the device, and/or
//   CZ_HOME               a state directory (as cz uses it) with this application's identity and trust store
//   CZ_LIST_DEVICES=true  also report the devices this application may reach
//   CZ_DIRECT=none        never attempt a peer-to-peer connection
//   CZ_LOOPBACK=true      offer loopback addresses (both endpoints on one machine)
//   CZ_HELLO_PATH, CZ_ECHO_PATH, CZ_WS_PATH, CZ_BLOB_PATH   paths of the device's application
//   CZ_BLOB_BYTES         additionally download this many bytes
//   CZ_HOLD_SECONDS       keep the session open this long and report how it ended

import { createHash, randomBytes } from 'node:crypto';
import { ConnectivitizerError, StateDirectory, createClient } from '../dist/index.js';

const env = (name, fallback) => {
  const value = process.env[name];
  if (value) {
    return value;
  }
  if (fallback === undefined) {
    throw new Error(`${name} is not set.`);
  }
  return fallback;
};

/** Identity and trust store from the state directory, when one is given. */
const certificates = () => {
  if (!process.env.CZ_HOME) {
    return {};
  }
  const state = new StateDirectory(process.env.CZ_HOME);
  return { identity: state.loadIdentity(), trust: state.openTrustStore(), allowPlatformIntroducedPeers: process.env.CZ_ALLOW_PLATFORM_INTRODUCED === 'true' };
};

const report = {};
let exitCode = 0;
let client;
try {
  const device = env('CZ_DEVICE', 'home-pc');
  const service = env('CZ_SERVICE', 'api');
  client = createClient({
    apiUrl: env('CZ_API_URL'),
    auth: { apiKey: env('CZ_API_KEY') },
    sharedKey: process.env.CZ_SHARED_KEY || undefined,
    ...certificates(),
    disableDirect: process.env.CZ_DIRECT === 'none',
    node: { includeLoopback: process.env.CZ_LOOPBACK === 'true' },
  });

  if (process.env.CZ_LIST_DEVICES === 'true') {
    // What an app shows its user to choose from.
    report.devices = (await client.listDevices()).map(({ name, slug, alias, online, services }) => ({ name, slug, alias: alias ?? null, online, services }));
  }

  const session = await client.connect(device, [service]);
  // What this endpoint verified about the connection - not what anyone claimed.
  const info = session.info;
  report.session = {
    id: info.sessionId,
    mode: info.mode,
    transport: info.transport,
    relayed: info.relayed,
    endToEndEncrypted: info.endToEndEncrypted,
    platformCanReadPayload: info.platformCanReadPayload,
    trust: info.trust,
    e2eMethod: info.e2eMethod,
    peerFingerprint: info.peerFingerprint,
    peerName: info.peerName,
    directFailureReason: info.directFailureReason ?? null,
    peerAddress: info.peerAddress ?? null,
  };

  // 1. REST.
  const hello = await session.fetch(service, env('CZ_HELLO_PATH', '/health'));
  report.helloStatus = hello.status;
  report.hello = await hello.text();

  const canary = process.env.CZ_CANARY || 'canary-' + randomBytes(12).toString('hex');
  const echoed = await session.fetch(service, env('CZ_ECHO_PATH', '/api/echo'), { method: 'POST', body: canary });
  report.echoMatches = (await echoed.text()) === canary;

  const large = randomBytes(300_000);
  const largeEchoed = await session.fetch(service, env('CZ_ECHO_PATH', '/api/echo'), { method: 'POST', body: large, headers: { 'Content-Type': 'application/octet-stream' } });
  report.largeEchoMatches = Buffer.compare(Buffer.from(await largeEchoed.bytes()), large) === 0;

  // 2. A WebSocket.
  const socket = await session.webSocket(service, env('CZ_WS_PATH', '/ws'));
  report.webSocketEchoMatches = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('no WebSocket echo in time')), 10_000);
    socket.onMessage = (data) => {
      clearTimeout(timer);
      resolve(data === 'ping over websocket');
    };
    socket.onClose = () => reject(new Error('the WebSocket closed before the echo'));
    socket.send('ping over websocket');
  });
  socket.onClose = null;
  socket.close();

  // 3. Optionally a larger download, to see the throughput of the path in use.
  const blobBytes = Number.parseInt(process.env.CZ_BLOB_BYTES ?? '0', 10);
  if (blobBytes > 0) {
    const started = Date.now();
    const response = await session.fetch(service, env('CZ_BLOB_PATH', '/api/blob/') + blobBytes, { timeoutMs: 60_000 });
    const hash = createHash('sha256');
    let received = 0;
    for await (const chunk of response.chunks()) {
      hash.update(chunk);
      received += chunk.length;
    }
    const seconds = Math.max((Date.now() - started) / 1000, 0.001);
    report.blob = { bytes: received, sha256: hash.digest('hex'), milliseconds: Date.now() - started, megabytesPerSecond: Math.round((received / 1024 / 1024 / seconds) * 100) / 100 };
  }

  report.bytesSent = session.bytesSent;
  report.bytesReceived = session.bytesReceived;
  report.ok = true;

  // Keep the session open for a while when asked to (lets a test revoke access and watch it end).
  const hold = Number.parseInt(process.env.CZ_HOLD_SECONDS ?? '0', 10);
  if (hold > 0) {
    report.endedWhileHolding = await Promise.race([session.completion, new Promise((resolve) => setTimeout(() => resolve(null), hold * 1000))]);
  }
} catch (error) {
  // Every refusal carries a stable code that says which layer said no.
  report.ok = false;
  report.error = error instanceof ConnectivitizerError ? error.code : (error?.constructor?.name ?? 'Error');
  report.message = String(error?.message ?? error);
  exitCode = 2;
}

await client?.close().catch(() => undefined);
process.stdout.write(JSON.stringify(report, null, 2) + '\n', () => process.exit(exitCode));
