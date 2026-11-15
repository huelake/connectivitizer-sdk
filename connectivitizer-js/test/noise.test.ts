import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { test } from 'node:test';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { fromHex, toHex, utf8Encode } from '../src/core/bytes.js';
import { ConnectivitizerError, ErrorCodes } from '../src/core/errors.js';
import { acceptSharedKey, connectSharedKey, generateSharedKey, MAX_PLAINTEXT, NoiseHandshake, parseSharedKey, prologue } from '../src/core/noise.js';
import { memoryPair } from './support.js';

const random = (length: number): Uint8Array => new Uint8Array(randomBytes(length));
const sessionPrologue = prologue('0123456789abcdef0123456789abcdef', 'a'.repeat(64));

function transport(key: Uint8Array, counter: number, plaintextHex: string): string {
  const nonce = new Uint8Array(12);
  nonce[4] = counter;
  return toHex(chacha20poly1305(key, nonce).encrypt(fromHex(plaintextHex)));
}

// The published vector for Noise_NNpsk0_25519_ChaChaPoly_SHA256 (cacophony), the same one the .NET
// and the C implementation are checked against.
test('handshake matches the published test vector', () => {
  const vectorPrologue = fromHex('4a6f686e2047616c74');
  const key = fromHex('54686973206973206d7920417573747269616e20706572737065637469766521');

  const initiator = NoiseHandshake.startInitiator(vectorPrologue, key, fromHex('893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a'));
  const first = initiator.writeFirst(fromHex('4c756477696720766f6e204d69736573'));
  assert.equal(toHex(first), 'ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c794479b962b8aff8485742ac32f905ba45369e2465fb59e138a93d67a0d1266b6a54');

  const responder = NoiseHandshake.tryStartResponder(vectorPrologue, key, first);
  assert.ok(responder);
  assert.equal(toHex(responder.payload), '4c756477696720766f6e204d69736573');

  const second = responder.handshake.writeSecond(fromHex('bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b'), fromHex('4d757272617920526f746862617264'));
  assert.equal(toHex(second), '95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843d6062704d5a9c422a8e834423f8c1feada7e8d0d910a1a2cd030fb584221e3');

  const payload = initiator.readSecond(second);
  assert.ok(payload);
  assert.equal(toHex(payload), '4d757272617920526f746862617264');
  assert.equal(toHex(initiator.handshakeHash), 'f4d03dc34495c95729ea6de9e1b59004b59733102488b3e24bc441e0be208eaf');
  assert.deepEqual(initiator.handshakeHash, responder.handshake.handshakeHash);

  const keys = initiator.split();
  assert.deepEqual(keys, responder.handshake.split());
  assert.equal(transport(keys.initiator, 0, '462e20412e20486179656b'), 'e632c3763d7669067383433197a3baddf146e9e70ad4b4e9e59e0f');
  assert.equal(transport(keys.responder, 0, '4361726c204d656e676572'), '64c6bee32ea91c8474bb4c21d7a700109ad45af77b29764ba5eb1e');
  assert.equal(transport(keys.initiator, 1, '4a65616e2d426170746973746520536179'), 'e2fa0bed0603b62d3ccac2ecabbf3fe33f3e86514909b323361626266cb2471cc8');
  assert.equal(transport(keys.responder, 1, '457567656e2042f6686d20766f6e2042617765726b'), '0c01dc9cec1fe4ddd692e8dd32188aa351088dc91183639a53b57aa4692b5ebdef8b8ca111');
});

test('a channel with the same key on both ends carries data both ways', async () => {
  const text = generateSharedKey(random);
  const [appSide, deviceSide] = memoryPair();

  const accepting = acceptSharedKey(deviceSide, [parseSharedKey(generateSharedKey(random), 'other'), parseSharedKey(text, 'example app')], sessionPrologue, random);
  const app = await connectSharedKey(appSide, parseSharedKey(text, 'lamp'), sessionPrologue, random);
  const device = await accepting;

  assert.equal(app.keyName, 'lamp');
  // The device held two keys; it reports the one the application proved to have.
  assert.equal(device.keyName, 'example app');

  // Larger than one message, so it is split and reassembled.
  const request = random(3 * MAX_PLAINTEXT + 17);
  const writing = app.stream.write(request);
  const received: number[] = [];
  while (received.length < request.length) {
    received.push(...(await device.stream.read())!);
  }
  await writing;
  assert.deepEqual(Uint8Array.from(received), request);

  await device.stream.write(utf8Encode('200 OK'));
  assert.deepEqual(await app.stream.read(), utf8Encode('200 OK'));
});

test('different keys give no channel, and both ends say why', async () => {
  const [appSide, deviceSide] = memoryPair();
  const accepting = acceptSharedKey(deviceSide, [parseSharedKey(generateSharedKey(random))], sessionPrologue, random);
  accepting.catch(() => undefined);

  await assert.rejects(connectSharedKey(appSide, parseSharedKey(generateSharedKey(random)), sessionPrologue, random),
    (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.E2eSharedKeyMismatch);
  await assert.rejects(accepting, (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.E2eSharedKeyMismatch);
});

test('ends that disagree about the session get no channel', async () => {
  const key = parseSharedKey(generateSharedKey(random));
  const [appSide, deviceSide] = memoryPair();
  const accepting = acceptSharedKey(deviceSide, [key], prologue('f'.repeat(32), 'a'.repeat(64)), random);
  accepting.catch(() => undefined);

  await assert.rejects(connectSharedKey(appSide, key, sessionPrologue, random));
  await assert.rejects(accepting);
});

test('altered ciphertext is detected', async () => {
  const key = parseSharedKey(generateSharedKey(random));
  const [appSide, deviceSide] = memoryPair();
  let armed = false;
  const tampering = {
    ...deviceSide,
    read: async () => {
      const chunk = await deviceSide.read();
      if (armed && chunk && chunk.length > 2) {
        chunk[chunk.length - 1] ^= 1;
        armed = false;
      }
      return chunk;
    },
    write: (data: Uint8Array) => deviceSide.write(data),
    end: () => deviceSide.end(),
    close: () => deviceSide.close(),
  };

  const accepting = acceptSharedKey(tampering, [key], sessionPrologue, random);
  const app = await connectSharedKey(appSide, key, sessionPrologue, random);
  const device = await accepting;

  armed = true;
  await app.stream.write(utf8Encode('transfer 10 to alice'));
  await assert.rejects(device.stream.read());
});

test('the text form of a key round-trips and other strings are refused', () => {
  const text = generateSharedKey(random);
  assert.match(text, /^czs_[A-Za-z0-9_-]{43}$/);
  // Generated readable (protocol section 1.2): one case, no I, O, 0 or 1.
  for (let i = 0; i < 200; i++) {
    const readable = generateSharedKey(random);
    assert.match(readable, /^czs_[A-HJ-NP-Z2-9]{42}[AQ]$/);
    assert.equal(parseSharedKey(readable).bytes.length, 32);
  }
  assert.equal(parseSharedKey(text).bytes.length, 32);
  assert.throws(() => parseSharedKey('czk_' + text.substring(4)));
  assert.throws(() => parseSharedKey(text.substring(0, text.length - 2)));
  assert.throws(() => parseSharedKey(text + 'AA'));
});
