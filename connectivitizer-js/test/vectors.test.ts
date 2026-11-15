// The shared test vectors in docs/protocol/vectors: byte-exact examples every implementation is checked
// against (the Python and JVM SDKs read them in their own tests). This SDK is the reference for the
// files: the test fails when what it computes differs from what is written there, so the files cannot
// drift from the code.
//
//   WRITE_VECTORS=1 npm test      rewrites the files from this SDK (review the diff before committing)

import assert from 'node:assert/strict';
import { createPrivateKey, sign as nodeSign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { x25519 } from '@noble/curves/ed25519.js';
import { p256 } from '@noble/curves/nist.js';
import { base64UrlEncode, fromHex, toHex, utf8Encode } from '../src/core/bytes.js';
import { formatAddress, isGlobalIpv6, normalizeHost, parseAddress } from '../src/core/direct/addresses.js';
import { readStunSuccess } from '../src/core/direct/attempt.js';
import { Kcp } from '../src/core/direct/kcp.js';
import { hashGrant, parseJwks, validateGrant } from '../src/core/grants.js';
import { MuxSession } from '../src/core/mux.js';
import { NoiseHandshake, parseSharedKey, prologue } from '../src/core/noise.js';
import { memoryPair } from './support.js';

// build-test/test -> the repository root
const folder = fileURLToPath(new URL('../../../../docs/protocol/vectors/', import.meta.url));
const writing = process.env.WRITE_VECTORS === '1';

/** Compares with the file, or (re)writes it. */
function check(name: string, computed: unknown): void {
  const file = `${folder}${name}`;
  if (writing) {
    mkdirSync(folder, { recursive: true });
    writeFileSync(file, `${JSON.stringify(computed, null, 2)}\n`);
    return;
  }
  assert.ok(existsSync(file), `${name} is missing: run WRITE_VECTORS=1 npm test`);
  assert.deepEqual(computed, JSON.parse(readFileSync(file, 'utf8')), `${name} differs from what this SDK computes`);
}

const stored = <T>(name: string): T | undefined => (existsSync(`${folder}${name}`) ? (JSON.parse(readFileSync(`${folder}${name}`, 'utf8')) as T) : undefined);

test('vectors: Noise_NNpsk0_25519_ChaChaPoly_SHA256 and the shared-key prologue', () => {
  // The published vector (cacophony), as in noise.test.ts; the handshake hash and the split keys are
  // what an implementation compares first when it does not match.
  const vector = {
    prologue: '4a6f686e2047616c74',
    psk: '54686973206973206d7920417573747269616e20706572737065637469766521',
    initiatorEphemeral: '893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a',
    responderEphemeral: 'bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b',
    payload1: '4c756477696720766f6e204d69736573',
    payload2: '4d757272617920526f746862617264',
  };
  const initiator = NoiseHandshake.startInitiator(fromHex(vector.prologue), fromHex(vector.psk), fromHex(vector.initiatorEphemeral));
  const message1 = initiator.writeFirst(fromHex(vector.payload1));
  const responder = NoiseHandshake.tryStartResponder(fromHex(vector.prologue), fromHex(vector.psk), message1)!;
  const message2 = responder.handshake.writeSecond(fromHex(vector.responderEphemeral), fromHex(vector.payload2));
  initiator.readSecond(message2);
  const keys = initiator.split();

  const sessionId = '0123456789abcdef0123456789abcdef';
  const grantHash = hashGrant('header.payload.signature');
  check('noise-nnpsk0.json', {
    description:
      'Noise_NNpsk0_25519_ChaChaPoly_SHA256 (protocol section 4a). handshake: the published cacophony vector. Transport messages use nonce = 4 zero bytes + 8-byte little-endian counter, counting from 0 per direction. prologue: the bytes an endpoint passes as the Noise prologue for a session.',
    handshake: {
      ...vector,
      message1: toHex(message1),
      message2: toHex(message2),
      handshakeHash: toHex(initiator.handshakeHash),
      initiatorToResponderKey: toHex(keys.initiator),
      responderToInitiatorKey: toHex(keys.responder),
    },
    prologue: { sessionId, grantToken: 'header.payload.signature', grantHash, bytes: toHex(prologue(sessionId, grantHash)) },
  });
});

test('vectors: X25519 (RFC 7748, sections 5.2 and 6.1)', () => {
  const cases = [
    { scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4', u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c', output: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552' },
    { scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d', u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493', output: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957' },
  ];
  for (const entry of cases) {
    assert.equal(toHex(x25519.getSharedSecret(fromHex(entry.scalar), fromHex(entry.u))), entry.output);
  }
  const alice = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
  const bob = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
  check('x25519.json', {
    description: 'X25519 from RFC 7748: scalar multiplication (section 5.2) and the Diffie-Hellman example (section 6.1).',
    multiply: cases,
    diffieHellman: {
      alicePrivate: alice,
      alicePublic: toHex(x25519.getPublicKey(fromHex(alice))),
      bobPrivate: bob,
      bobPublic: toHex(x25519.getPublicKey(fromHex(bob))),
      shared: toHex(x25519.getSharedSecret(fromHex(alice), x25519.getPublicKey(fromHex(bob)))),
    },
  });
});

test('vectors: shared keys in their text form', () => {
  const valid = [new Uint8Array(32), Uint8Array.from({ length: 32 }, (_, index) => 0xff - index * 7)].map((bytes) => `czs_${base64UrlEncode(bytes)}`);
  const invalid = ['czk_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'czs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'czs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', 'czs_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=', ''];
  for (const text of invalid) {
    assert.throws(() => parseSharedKey(text), text);
  }
  check('shared-keys.json', {
    description: 'Shared keys (protocol section 1.2): "czs_" + base64url without padding of 32 bytes. Everything in "invalid" must be refused.',
    valid: valid.map((text) => ({ text, bytes: toHex(parseSharedKey(text).bytes) })),
    invalid,
  });
});

test('vectors: session grants (ES256 JWS)', () => {
  const now = 1_760_000_000;
  const claims = {
    iss: 'https://api.connectivitizer.example',
    aud: ['cz-agent'],
    jti: '6f1c2a9e0b3d4c5e8f7a6b5c4d3e2f10',
    ws: 'ws_01',
    ini: { type: 'credential', id: 'cred_01' },
    dev: { type: 'device', id: 'dev_01' },
    svc: ['api'],
    modes: ['direct', 'e2e-relay'],
    e2e: 'shared-key',
    relay: 'wss://relay.connectivitizer.example/relay/v1',
    iat: now - 10,
    exp: now + 50,
    lease: 600,
  };
  const old = stored<{ jwks: unknown; cases: { name: string; token: string }[] }>('grants.json');

  // Tokens are signed once (ECDSA signatures are randomised) and kept; the test verifies them.
  let jwks = old?.jwks;
  let tokens = new Map(old?.cases.map((entry) => [entry.name, entry.token]));
  if (writing || !old) {
    const d = fromHex('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
    const publicKey = p256.getPublicKey(d, false);
    const jwk = { kty: 'EC', crv: 'P-256', kid: 'grant-2026-01', x: base64UrlEncode(publicKey.subarray(1, 33)), y: base64UrlEncode(publicKey.subarray(33)) };
    jwks = { keys: [jwk] };
    const privateKey = createPrivateKey({ key: { ...jwk, d: base64UrlEncode(d) }, format: 'jwk' });
    const signed = (header: object, payload: object, tamper = false): string => {
      const input = `${base64UrlEncode(utf8Encode(JSON.stringify(header)))}.${base64UrlEncode(utf8Encode(JSON.stringify(payload)))}`;
      const signature = new Uint8Array(nodeSign('sha256', utf8Encode(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }));
      if (tamper) signature[10] ^= 1;
      return `${input}.${base64UrlEncode(signature)}`;
    };
    const header = { alg: 'ES256', kid: 'grant-2026-01', typ: 'JWT' };
    tokens = new Map([
      ['valid', signed(header, claims)],
      ['bad-signature', signed(header, claims, true)],
      ['unknown-key', signed({ ...header, kid: 'grant-1999-01' }, claims)],
      ['alg-none', `${base64UrlEncode(utf8Encode(JSON.stringify({ alg: 'none', kid: 'grant-2026-01' })))}.${base64UrlEncode(utf8Encode(JSON.stringify(claims)))}.`],
      ['wrong-audience', signed(header, { ...claims, aud: ['someone-else'] })],
      ['expired-start-window', signed(header, { ...claims, iat: now - 200, exp: now - 100 })],
    ]);
  }
  const keys = parseJwks(jwks);
  const outcome = (token: string, forSessionStart: boolean) => {
    const result = validateGrant(token, keys, now, forSessionStart);
    return result.error ?? 'valid';
  };
  const cases = [...tokens].map(([name, token]) => ({
    name,
    token,
    atSessionStart: outcome(token, true),
    duringLease: outcome(token, false),
  }));
  check('grants.json', {
    description:
      'Session grants (protocol section 2): compact JWS, ES256 over the ASCII of "header.payload", the signature as 64 bytes r||s. Validate with the keys of jwks at time "now" (seconds) and 30 s of clock skew; atSessionStart checks exp, duringLease checks iat + lease. Expected: "valid" or the error code. hash: SHA-256 hex of the token text, as the session bind and the shared-key prologue use it.',
    now,
    jwks,
    claims,
    cases,
    hash: { token: tokens.get('valid'), sha256: hashGrant(tokens.get('valid')!) },
  });
});

test('vectors: candidate addresses', () => {
  const hosts = ['192.168.2.176', '2003:E1:0:0:0:0:0:1', '2003:00e1::0001', '::ffff:192.168.2.176', '0:0:0:0:0:ffff:c0a8:2b0', 'fe80::1', '::', '2001:db8::1:0:0:1', 'not-an-ip', '256.1.1.1', '1.2.3'];
  const candidates = ['91.57.244.102:54249', '[2003:e1::1]:54249', '[2003:E1:0::1]:443', '[::ffff:10.0.0.1]:1', '10.0.0.1:0', '10.0.0.1:65536', '2003:e1::1:54249', 'example.com:80'];
  check('addresses.json', {
    description:
      'Hosts and UDP candidates (protocol section 6.4). normalize: IPv4 dotted, IPv6 canonical (RFC 5952), IPv4-mapped IPv6 as IPv4, null when not an IP address. candidates: parsed and written back, null when invalid. globalIpv6: within 2000::/3.',
    normalize: hosts.map((text) => ({ text, host: normalizeHost(text) })),
    candidates: candidates.map((text) => {
      const parsed = parseAddress(text);
      return { text, host: parsed?.host ?? null, port: parsed?.port ?? null, formatted: parsed ? formatAddress(parsed) : null };
    }),
    globalIpv6: ['2003:e1::1', '2a01:598::5', 'fe80::1', 'fd00::1', '::1', '192.168.1.1'].map((host) => ({ host, global: isGlobalIpv6(host) })),
  });
});

test('vectors: STUN Binding (RFC 5389)', () => {
  const transactionId = fromHex('b7e7a701bc34d686fa87dfae');
  const request = new Uint8Array(20);
  request.set([0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42]);
  request.set(transactionId, 8);
  // A success response with a SOFTWARE attribute first (padded) and then XOR-MAPPED-ADDRESS 192.0.0.1:48839.
  const software = utf8Encode('test vector');
  const softwareAttribute = new Uint8Array(4 + 12);
  softwareAttribute.set([0x80, 0x22, 0x00, software.length]);
  softwareAttribute.set(software, 4);
  const mapped = fromHex('0020000800019fd5e112a443');
  const body = new Uint8Array(softwareAttribute.length + mapped.length);
  body.set(softwareAttribute);
  body.set(mapped, softwareAttribute.length);
  const response = new Uint8Array(20 + body.length);
  response.set([0x01, 0x01, body.length >> 8, body.length & 255, 0x21, 0x12, 0xa4, 0x42]);
  response.set(transactionId, 8);
  response.set(body, 20);
  const otherTransaction = response.slice();
  otherTransaction[19] ^= 1;
  check('stun.json', {
    description:
      'STUN Binding (RFC 5389) as the endpoints use it (protocol section 6.3): a request is the 20-byte header only. From a success response the endpoint reads XOR-MAPPED-ADDRESS (IPv4); attributes are padded to 4 bytes. A response to another transaction is ignored (mapped: null).',
    transactionId: toHex(transactionId),
    request: toHex(request),
    responses: [
      { response: toHex(response), mapped: readStunSuccess(response, transactionId) },
      { response: toHex(otherTransaction), mapped: readStunSuccess(otherTransaction, transactionId) },
    ],
  });
});

test('vectors: yamux frames', async () => {
  const [a, b] = memoryPair();
  const initiator = new MuxSession(a, true);
  initiator.start();
  const stream = initiator.open();
  await stream.write(utf8Encode('GET / HTTP/1.1\r\n\r\n'));
  await stream.end();
  const frames: string[] = [];
  for (let index = 0; index < 3; index++) {
    frames.push(toHex((await b.read())!));
  }
  await initiator.close();
  check('yamux.json', {
    description:
      'Stream multiplexing (protocol section 5.1, yamux framing): 12-byte header version(0) type flags(2 bytes) stream id(4) length(4), big-endian. Types: 0 data, 1 window update, 2 ping, 3 go away. Flags: 1 SYN, 2 ACK, 4 FIN, 8 RST. These are the frames an initiator sends to open stream 1, send a request on it and finish sending.',
    frames: [
      { meaning: 'open stream 1 (window update with SYN, delta 0)', hex: frames[0] },
      { meaning: 'data on stream 1', hex: frames[1] },
      { meaning: 'finish sending on stream 1 (window update with FIN)', hex: frames[2] },
    ],
  });
});

test('vectors: KCP segments', () => {
  const packets: string[] = [];
  const kcp = new Kcp(0x11223344, (packet) => packets.push(toHex(packet)));
  kcp.update(1000);
  kcp.send(utf8Encode('hello'));
  kcp.update(1100);
  check('kcp.json', {
    description:
      'KCP (protocol section 6.2, reference ikcp.c with default settings): segment header conv(4) cmd(1) frg(1) wnd(2) ts(4) sn(4) una(4) len(4), little-endian, then the data. cmd 81 push, 82 ack, 83 window probe, 84 window size. The packet a new KCP object with conv 0x11223344 sends after update(1000), send("hello"), update(1100).',
    conv: 0x11223344,
    packets,
  });
});
