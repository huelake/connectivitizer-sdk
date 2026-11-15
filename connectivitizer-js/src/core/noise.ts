import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { x25519 } from '@noble/curves/ed25519.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64Decode, concat, readUint16, utf8Encode, writeUint16 } from './bytes.js';
import { ConnectivitizerError, ErrorCodes } from './errors.js';
import { type ByteStream, StreamReader } from './streams.js';

// The end-to-end layer for endpoints that share a key (protocol section 4a): the Noise handshake
// NNpsk0 with X25519, ChaCha20-Poly1305 and SHA-256. Each session agrees on fresh keys, so
// recorded traffic stays unreadable even if the shared key leaks later; the shared key is what
// authenticates the two ends to each other. Nothing between them holds it.

const PROTOCOL_NAME = utf8Encode('Noise_NNpsk0_25519_ChaChaPoly_SHA256');
const KEY_SIZE = 32;
const TAG_SIZE = 16;
const HANDSHAKE_MESSAGE_SIZE = KEY_SIZE + TAG_SIZE;
const EMPTY = new Uint8Array(0);

/** Largest number of plaintext bytes in one message, so an endpoint with little memory needs only small buffers. */
export const MAX_PLAINTEXT = 4096;

export const SHARED_KEY_PREFIX = 'czs_';

/**
 * A key that two endpoints hold and nobody else does, written `czs_` followed by 43 characters.
 * The platform never receives it. Whoever has it can talk to the other holders, so it is kept
 * like a password.
 */
export interface SharedKey {
  /** What this endpoint calls the key, for example the device it is for. Never transmitted. */
  readonly name: string;
  readonly bytes: Uint8Array;
}

export function parseSharedKey(text: string, name = 'default'): SharedKey {
  const trimmed = text.trim();
  let bytes: Uint8Array | null = null;
  if (trimmed.startsWith(SHARED_KEY_PREFIX) && trimmed.length === SHARED_KEY_PREFIX.length + 43) {
    try {
      bytes = base64Decode(trimmed.substring(SHARED_KEY_PREFIX.length));
    } catch {
      bytes = null;
    }
  }
  if (!bytes || bytes.length !== KEY_SIZE) {
    throw new ConnectivitizerError(ErrorCodes.InvalidRequest, 'A shared key looks like czs_ followed by 43 characters.');
  }
  return { name, bytes };
}

/**
 * The characters of a generated key (protocol section 1.2): one case, no I and O, no 0 and 1, so a
 * person or a phone's text recognition can read the key without mixing up characters.
 */
export const READABLE_KEY_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

/**
 * A new shared key in its text form, readable (protocol section 1.2): 42 characters from
 * READABLE_KEY_ALPHABET and a last one of `A` or `Q`, 211 bits of randomness. `randomBytes` must
 * be a cryptographically secure source.
 */
export function generateSharedKey(randomBytes: (length: number) => Uint8Array): string {
  const bytes = randomBytes(43);
  if (bytes.length !== 43) {
    throw new Error('The random source did not return 43 bytes.');
  }
  let text = SHARED_KEY_PREFIX;
  for (let i = 0; i < 42; i++) {
    // 32 characters: the low five bits of a random byte pick one uniformly.
    text += READABLE_KEY_ALPHABET[bytes[i] & 31];
  }
  return text + ((bytes[42] & 1) === 0 ? 'A' : 'Q');
}

/**
 * What both handshakes are bound to: this protocol, this session and this grant. Two ends that
 * disagree about any of them derive different keys and never get a channel.
 */
export const prologue = (sessionId: string, grantHashHex: string): Uint8Array => utf8Encode(`cz-e2e-shared-key/1|${sessionId}|${grantHashHex}`);

function nonce(counter: number): Uint8Array {
  // Four zero bytes, then the counter as 64-bit little-endian. A session never sends 2^53 messages.
  const value = new Uint8Array(12);
  let rest = counter;
  for (let i = 4; i < 12 && rest > 0; i++) {
    value[i] = rest % 256;
    rest = Math.floor(rest / 256);
  }
  return value;
}

/**
 * The handshake `Noise_NNpsk0_25519_ChaChaPoly_SHA256` as the Noise specification (revision 34)
 * defines it. Kept apart from the stream handling so it can be checked against published vectors.
 *
 *     -> psk, e
 *     <- e, ee
 */
export class NoiseHandshake {
  private chainingKey: Uint8Array;
  private hash: Uint8Array;
  private key: Uint8Array | null = null;
  private counter = 0;
  private ephemeral: Uint8Array | null = null;
  private remotePublic: Uint8Array | null = null;

  private constructor(prologueBytes: Uint8Array, sharedKey: Uint8Array) {
    // The protocol name is longer than a hash, so the initial hash is the hash of the name.
    this.hash = sha256(PROTOCOL_NAME);
    this.chainingKey = this.hash;
    this.mixHash(prologueBytes);
    this.mixKeyAndHash(sharedKey);
  }

  /** The initiator's side. `ephemeralPrivate` must be 32 fresh random bytes. */
  static startInitiator(prologueBytes: Uint8Array, sharedKey: Uint8Array, ephemeralPrivate: Uint8Array): NoiseHandshake {
    const handshake = new NoiseHandshake(prologueBytes, sharedKey);
    handshake.ephemeral = ephemeralPrivate;
    return handshake;
  }

  /** The initiator's message: its ephemeral public key and the encrypted payload. */
  writeFirst(payload: Uint8Array = EMPTY): Uint8Array {
    const ephemeralPublic = x25519.getPublicKey(this.ephemeral!);
    this.mixHash(ephemeralPublic);
    this.mixKey(ephemeralPublic);
    return concat(ephemeralPublic, this.encryptAndHash(payload));
  }

  /** Processes the responder's message. Null when it was not made with the same shared key. */
  readSecond(message: Uint8Array): Uint8Array | null {
    if (message.length < HANDSHAKE_MESSAGE_SIZE) {
      return null;
    }
    const remotePublic = message.subarray(0, KEY_SIZE);
    this.mixHash(remotePublic);
    this.mixKey(remotePublic);
    this.mixKey(agree(this.ephemeral!, remotePublic));
    this.ephemeral!.fill(0);
    return this.decryptAndHash(message.subarray(KEY_SIZE));
  }

  /**
   * The responder's side: processes the initiator's message with one candidate key. Null when the
   * message was not made with that key.
   */
  static tryStartResponder(prologueBytes: Uint8Array, sharedKey: Uint8Array, firstMessage: Uint8Array): { handshake: NoiseHandshake; payload: Uint8Array } | null {
    if (firstMessage.length < HANDSHAKE_MESSAGE_SIZE) {
      return null;
    }
    const handshake = new NoiseHandshake(prologueBytes, sharedKey);
    const remotePublic = firstMessage.slice(0, KEY_SIZE);
    handshake.mixHash(remotePublic);
    handshake.mixKey(remotePublic);
    const payload = handshake.decryptAndHash(firstMessage.subarray(KEY_SIZE));
    if (payload === null) {
      return null;
    }
    handshake.remotePublic = remotePublic;
    return { handshake, payload };
  }

  /** The responder's message. `ephemeralPrivate` must be 32 fresh random bytes. */
  writeSecond(ephemeralPrivate: Uint8Array, payload: Uint8Array = EMPTY): Uint8Array {
    const ephemeralPublic = x25519.getPublicKey(ephemeralPrivate);
    this.mixHash(ephemeralPublic);
    this.mixKey(ephemeralPublic);
    this.mixKey(agree(ephemeralPrivate, this.remotePublic!));
    ephemeralPrivate.fill(0);
    return concat(ephemeralPublic, this.encryptAndHash(payload));
  }

  /** The hash over everything both sides sent and mixed in. Equal on both ends exactly when the handshake agreed. */
  get handshakeHash(): Uint8Array {
    return this.hash.slice();
  }

  /** The two transport keys: the first protects what the initiator sends, the second what the responder sends. */
  split(): { initiator: Uint8Array; responder: Uint8Array } {
    const temp = hmac(sha256, this.chainingKey, EMPTY);
    const first = hmac(sha256, temp, Uint8Array.of(1));
    const second = hmac(sha256, temp, concat(first, Uint8Array.of(2)));
    return { initiator: first, responder: second };
  }

  private mixHash(data: Uint8Array): void {
    this.hash = sha256(concat(this.hash, data));
  }

  private mixKey(inputKeyMaterial: Uint8Array): void {
    const temp = hmac(sha256, this.chainingKey, inputKeyMaterial);
    const first = hmac(sha256, temp, Uint8Array.of(1));
    const second = hmac(sha256, temp, concat(first, Uint8Array.of(2)));
    this.chainingKey = first;
    this.key = second;
    this.counter = 0;
  }

  private mixKeyAndHash(inputKeyMaterial: Uint8Array): void {
    const temp = hmac(sha256, this.chainingKey, inputKeyMaterial);
    const first = hmac(sha256, temp, Uint8Array.of(1));
    const second = hmac(sha256, temp, concat(first, Uint8Array.of(2)));
    const third = hmac(sha256, temp, concat(second, Uint8Array.of(3)));
    this.chainingKey = first;
    this.mixHash(second);
    this.key = third;
    this.counter = 0;
  }

  private encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ciphertext = chacha20poly1305(this.key!, nonce(this.counter++), this.hash).encrypt(plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  private decryptAndHash(ciphertext: Uint8Array): Uint8Array | null {
    let plaintext: Uint8Array;
    try {
      plaintext = chacha20poly1305(this.key!, nonce(this.counter++), this.hash).decrypt(ciphertext);
    } catch {
      return null;
    }
    this.mixHash(ciphertext);
    return plaintext;
  }
}

function agree(privateKey: Uint8Array, remotePublic: Uint8Array): Uint8Array {
  let shared: Uint8Array;
  try {
    shared = x25519.getSharedSecret(privateKey, remotePublic);
  } catch (error) {
    throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer sent an invalid key-agreement value.', { cause: error });
  }
  // A peer that sends a point of small order forces a known result; such a handshake is refused.
  if (shared.every((byte) => byte === 0)) {
    throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer sent an invalid key-agreement value.');
  }
  return shared;
}

function frame(message: Uint8Array): Uint8Array {
  const framed = new Uint8Array(2 + message.length);
  writeUint16(framed, 0, message.length);
  framed.set(message, 2);
  return framed;
}

/** Reads one length-prefixed message; null at the end of the stream. */
async function readFrame(reader: StreamReader, maxLength: number): Promise<Uint8Array | null> {
  const header = await reader.readExact(2);
  if (header === null) {
    return null;
  }
  const length = readUint16(header, 0);
  if (length > maxLength) {
    throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer sent a message that is too long for this protocol.');
  }
  if (length === 0) {
    return EMPTY;
  }
  return await reader.readExact(length);
}

/** The outcome of a handshake: the encrypted stream and the name of the key that both ends proved to hold. */
export interface SharedKeyChannel {
  stream: ByteStream;
  keyName: string;
}

/** Runs the handshake as the initiating endpoint. */
export async function connectSharedKey(path: ByteStream, key: SharedKey, prologueBytes: Uint8Array, randomBytes: (length: number) => Uint8Array): Promise<SharedKeyChannel> {
  const reader = new StreamReader(path);
  try {
    const handshake = NoiseHandshake.startInitiator(prologueBytes, key.bytes, randomBytes(KEY_SIZE));
    await path.write(frame(handshake.writeFirst()));

    const second = await readFrame(reader, HANDSHAKE_MESSAGE_SIZE);
    if (second !== null && second.length === 0) {
      // The device answers with an empty message when none of its keys fits.
      throw new ConnectivitizerError(ErrorCodes.E2eSharedKeyMismatch, 'The device does not hold this shared key.');
    }
    if (second === null || second.length !== HANDSHAKE_MESSAGE_SIZE) {
      throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer ended the end-to-end handshake.');
    }
    if (handshake.readSecond(second) === null) {
      throw new ConnectivitizerError(ErrorCodes.E2eSharedKeyMismatch, 'The device answered with a different shared key.');
    }
    const keys = handshake.split();
    return { stream: new NoiseStream(path, reader, keys.initiator, keys.responder), keyName: key.name };
  } catch (error) {
    await path.close().catch(() => undefined);
    throw error instanceof ConnectivitizerError ? error : new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The path ended during the end-to-end handshake.', { cause: error });
  }
}

/**
 * Runs the handshake as the accepting endpoint. It may hold several keys (one per peer it shares
 * one with); the one the initiator used is found by trying them.
 */
export async function acceptSharedKey(path: ByteStream, keys: readonly SharedKey[], prologueBytes: Uint8Array, randomBytes: (length: number) => Uint8Array): Promise<SharedKeyChannel> {
  const reader = new StreamReader(path);
  try {
    const first = await readFrame(reader, HANDSHAKE_MESSAGE_SIZE);
    if (first === null || first.length !== HANDSHAKE_MESSAGE_SIZE) {
      throw new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The peer ended the end-to-end handshake.');
    }

    let handshake: NoiseHandshake | null = null;
    let used: SharedKey | null = null;
    for (const key of keys) {
      const started = NoiseHandshake.tryStartResponder(prologueBytes, key.bytes, first);
      if (started) {
        handshake = started.handshake;
        used = key;
        break;
      }
    }
    if (!handshake || !used) {
      await path.write(frame(EMPTY));
      throw new ConnectivitizerError(ErrorCodes.E2eSharedKeyMismatch, 'The initiator used a shared key this endpoint does not hold.');
    }

    await path.write(frame(handshake.writeSecond(randomBytes(KEY_SIZE))));
    const transport = handshake.split();
    return { stream: new NoiseStream(path, reader, transport.responder, transport.initiator), keyName: used.name };
  } catch (error) {
    await path.close().catch(() => undefined);
    throw error instanceof ConnectivitizerError ? error : new ConnectivitizerError(ErrorCodes.E2eHandshakeFailed, 'The path ended during the end-to-end handshake.', { cause: error });
  }
}

/** The encrypted byte stream after the handshake: length-prefixed messages of at most {@link MAX_PLAINTEXT} bytes. */
class NoiseStream implements ByteStream {
  private sendCounter = 0;
  private receiveCounter = 0;
  private writing: Promise<void> = Promise.resolve();

  constructor(
    private readonly path: ByteStream,
    private readonly reader: StreamReader,
    private readonly sendKey: Uint8Array,
    private readonly receiveKey: Uint8Array,
  ) {}

  async read(): Promise<Uint8Array | null> {
    while (true) {
      const header = await this.reader.readExact(2);
      if (header === null) {
        return null;
      }
      const length = readUint16(header, 0);
      if (length < TAG_SIZE || length > MAX_PLAINTEXT + TAG_SIZE) {
        throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The peer sent a malformed encrypted message.');
      }
      const ciphertext = await this.reader.readExact(length);
      if (ciphertext === null) {
        // Cut off inside a message: the path broke, this is not an orderly end.
        throw new ConnectivitizerError(ErrorCodes.PathClosed, 'The path ended inside an encrypted message.');
      }
      let plaintext: Uint8Array;
      try {
        plaintext = chacha20poly1305(this.receiveKey, nonce(this.receiveCounter++)).decrypt(ciphertext);
      } catch (error) {
        throw new ConnectivitizerError(ErrorCodes.PathClosed, 'An encrypted message was altered on the way.', { cause: error });
      }
      if (plaintext.length > 0) {
        return plaintext;
      }
    }
  }

  write(data: Uint8Array): Promise<void> {
    // One writer at a time: the message counter and the order on the path must agree.
    const result = this.writing.then(async () => {
      for (let offset = 0; offset < data.length; offset += MAX_PLAINTEXT) {
        const chunk = data.subarray(offset, Math.min(offset + MAX_PLAINTEXT, data.length));
        const ciphertext = chacha20poly1305(this.sendKey, nonce(this.sendCounter++)).encrypt(chunk);
        await this.path.write(frame(ciphertext));
      }
    });
    this.writing = result.catch(() => undefined);
    return result;
  }

  end(): Promise<void> {
    return this.close();
  }

  close(): Promise<void> {
    return this.path.close();
  }
}
