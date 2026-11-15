// The certificate layer for Node.js: mutual TLS 1.3 between two endpoints over whatever byte
// stream the path provides, with identities each endpoint creates itself and trust that is
// decided locally (protocol sections 1.1 and 4). It is the layer `cz` and the .NET library use;
// an identity, a trust store and a pairing made here are interchangeable with theirs.
//
// React Native has no TLS for a stream the application owns, so this is Node.js only.

import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes, sign, X509Certificate } from 'node:crypto';
import { Duplex } from 'node:stream';
import * as tls from 'node:tls';
import type { CertificateSupport } from '../core/client.js';
import { ConnectivitizerError, type ErrorCode, ErrorCodes } from '../core/errors.js';
import { Roles, type SessionGrant } from '../core/grants.js';
import type { PeerInfo, SecureLayer, TrustLevel } from '../core/session.js';
import type { ByteStream } from '../core/streams.js';
import { socketStream } from './platform.js';

/** ALPN protocol and server name of the tunnel's TLS (protocol section 4). */
const TUNNEL_ALPN = 'cz-tunnel/1';
const TUNNEL_SERVER_NAME = 'cz-tunnel';
const FINGERPRINT_PREFIX = 'sha256:';
const HANDSHAKE_TIMEOUT_MS = 15_000;

// ---------------------------------------------------------------- DER, as much as a certificate needs

function derLength(length: number): Buffer {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes: number[] = [];
  for (let rest = length; rest > 0; rest >>>= 8) {
    bytes.unshift(rest & 0xff);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag: number, ...content: Uint8Array[]): Buffer {
  const body = Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), derLength(body.length), body]);
}

const sequence = (...content: Uint8Array[]): Buffer => der(0x30, ...content);

function objectIdentifier(dotted: string): Buffer {
  const parts = dotted.split('.').map((part) => Number.parseInt(part, 10));
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const group = [part & 0x7f];
    for (let rest = part >>> 7; rest > 0; rest >>>= 7) {
      group.unshift((rest & 0x7f) | 0x80);
    }
    bytes.push(...group);
  }
  return der(0x06, Buffer.from(bytes));
}

/** A non-negative INTEGER from big-endian bytes. */
function unsignedInteger(bytes: Uint8Array): Buffer {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) {
    start++;
  }
  const trimmed = bytes.subarray(start);
  return der(0x02, trimmed[0] & 0x80 ? Buffer.from([0]) : Buffer.alloc(0), trimmed);
}

function time(date: Date): Buffer {
  const text = date.toISOString().replace(/[-:T]/g, '').slice(0, 14) + 'Z';
  // UTCTime up to 2049, GeneralizedTime from 2050 on (RFC 5280, 4.1.2.5).
  return date.getUTCFullYear() < 2050 ? der(0x17, Buffer.from(text.slice(2), 'ascii')) : der(0x18, Buffer.from(text, 'ascii'));
}

const commonName = (name: string): Buffer => sequence(der(0x31, sequence(objectIdentifier('2.5.4.3'), der(0x0c, Buffer.from(name, 'utf8')))));

const extension = (id: string, critical: boolean, value: Uint8Array): Buffer =>
  sequence(objectIdentifier(id), critical ? der(0x01, Buffer.from([0xff])) : Buffer.alloc(0), der(0x04, value));

const ECDSA_WITH_SHA256 = sequence(objectIdentifier('1.2.840.10045.4.3.2'));

/** A self-signed certificate for an ECDSA P-256 key: an end-entity usable as TLS server and as TLS client. */
function selfSignedCertificate(name: string, publicKey: KeyObject, privateKey: KeyObject, notBefore: Date, notAfter: Date): Buffer {
  const subject = commonName(name);
  const extensions = sequence(
    // Not a certificate authority.
    extension('2.5.29.19', true, sequence()),
    // digitalSignature.
    extension('2.5.29.15', true, der(0x03, Buffer.from([0x07, 0x80]))),
    // serverAuth and clientAuth.
    extension('2.5.29.37', false, sequence(objectIdentifier('1.3.6.1.5.5.7.3.1'), objectIdentifier('1.3.6.1.5.5.7.3.2'))),
  );
  const serial = randomBytes(16);
  serial[0] &= 0x7f;
  const toBeSigned = sequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    unsignedInteger(serial),
    ECDSA_WITH_SHA256,
    subject,
    sequence(time(notBefore), time(notAfter)),
    subject,
    publicKey.export({ type: 'spki', format: 'der' }),
    der(0xa3, extensions),
  );
  const signature = sign('sha256', toBeSigned, privateKey);
  return sequence(toBeSigned, ECDSA_WITH_SHA256, der(0x03, Buffer.from([0]), signature));
}

// ---------------------------------------------------------------- identity

const sha256Hex = (data: string | Uint8Array): string => createHash('sha256').update(data).digest('hex');

/** The fingerprint peers pin: SHA-256 of the certificate's public key (SubjectPublicKeyInfo). */
export function fingerprintOf(certificate: X509Certificate): string {
  return FINGERPRINT_PREFIX + sha256Hex(certificate.publicKey.export({ type: 'spki', format: 'der' }));
}

/** Lower case, trimmed, and of the form `sha256:` plus 64 hex digits; null for anything else. */
export function normalizeFingerprint(value: string | null | undefined): string | null {
  const candidate = (value ?? '').trim().toLowerCase();
  return /^sha256:[0-9a-f]{64}$/.test(candidate) ? candidate : null;
}

function nameOf(certificate: X509Certificate): string {
  const match = /(?:^|\n)CN=([^\n]*)/.exec(certificate.subject);
  return match ? match[1] : '';
}

/**
 * The end-to-end identity of one endpoint: an ECDSA P-256 key pair and its self-signed
 * certificate. The private key is created and kept on the endpoint; only the certificate and
 * its fingerprint are meant to leave it.
 */
export class EndpointIdentity {
  readonly fingerprint: string;
  readonly name: string;
  readonly notAfter: Date;
  readonly certificatePem: string;

  private constructor(
    private readonly certificate: X509Certificate,
    private readonly privateKey: KeyObject,
  ) {
    this.fingerprint = fingerprintOf(certificate);
    this.name = nameOf(certificate);
    this.notAfter = new Date(certificate.validTo);
    this.certificatePem = certificate.toString();
  }

  /** Creates a new identity. The key never leaves this process unless it is exported. */
  static create(name: string, validityDays = 365): EndpointIdentity {
    if (!name.trim()) {
      throw new Error('An identity needs a name.');
    }
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const now = Date.now();
    const certificate = selfSignedCertificate(name.trim(), publicKey, privateKey, new Date(now - 5 * 60_000), new Date(now + validityDays * 86_400_000));
    return new EndpointIdentity(new X509Certificate(certificate), privateKey);
  }

  /** Loads an identity from a PEM certificate and a PEM private key (PKCS#8 or SEC1), as `cz` stores them. */
  static fromPem(certificatePem: string, privateKeyPem: string): EndpointIdentity {
    const certificate = new X509Certificate(certificatePem);
    const privateKey = createPrivateKey(privateKeyPem);
    if (privateKey.asymmetricKeyType !== 'ec' || !certificate.checkPrivateKey(privateKey)) {
      throw new Error('The private key does not belong to the certificate.');
    }
    return new EndpointIdentity(certificate, privateKey);
  }

  /** The private key as PKCS#8 PEM. For local storage on the endpoint only. */
  exportPrivateKeyPem(): string {
    return this.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
  }

  /** ECDSA P-256 / SHA-256 in the fixed 64-byte r||s form, the encoding JOSE ES256 uses. */
  sign(data: Uint8Array): Uint8Array {
    return new Uint8Array(sign('sha256', data, { key: this.privateKey, dsaEncoding: 'ieee-p1363' }));
  }

  /** The proof that registers this identity together with a login (protocol section 11.3). */
  registration(secret: string, timestamp: number): { identityCertificatePem: string; timestamp: number; identitySignature: string } {
    const proof = Buffer.from(`cz-identity-v1|${sha256Hex(secret)}|${timestamp}|${this.fingerprint}`, 'ascii');
    return { identityCertificatePem: this.certificatePem, timestamp, identitySignature: Buffer.from(this.sign(proof)).toString('base64') };
  }

  /** What `node:tls` needs to present this identity. */
  get tlsCredentials(): { cert: string; key: string } {
    return { cert: this.certificatePem, key: this.exportPrivateKeyPem() };
  }
}

// ---------------------------------------------------------------- trust

/** How an identity came to be trusted. `platform` is the weaker one: nobody on this endpoint checked it. */
export type TrustOrigin = 'manual' | 'pairing' | 'platform';

export interface TrustedIdentity {
  fingerprint: string;
  /** The name the peer is known by here: a device's name, an application's name. */
  peer: string;
  origin: TrustOrigin | string;
  addedAt: string;
}

/**
 * The identities this endpoint trusts, by fingerprint. Nothing the platform says adds to it
 * unless the application allowed that explicitly, and such entries are marked.
 */
export class TrustStore {
  private entries: TrustedIdentity[];

  /** @param persist Called with the whole list after every change, to store it. */
  constructor(
    initial: readonly TrustedIdentity[] = [],
    private readonly persist?: (identities: readonly TrustedIdentity[]) => void,
  ) {
    this.entries = [...initial];
  }

  get identities(): readonly TrustedIdentity[] {
    return [...this.entries];
  }

  pin(fingerprint: string, peer: string, origin: TrustOrigin = 'manual'): TrustedIdentity {
    const normalized = normalizeFingerprint(fingerprint);
    if (!normalized) {
      throw new Error(`'${fingerprint}' is not a valid identity fingerprint.`);
    }
    if (!peer.trim()) {
      throw new Error('A pinned identity needs the name of its peer.');
    }
    const entry: TrustedIdentity = { fingerprint: normalized, peer: peer.trim(), origin, addedAt: new Date().toISOString() };
    this.entries = [...this.entries.filter((known) => !(known.fingerprint === normalized && known.peer === entry.peer)), entry];
    this.persist?.(this.entries);
    return entry;
  }

  remove(fingerprint: string, peer?: string): boolean {
    const normalized = normalizeFingerprint(fingerprint);
    const kept = this.entries.filter((known) => !(known.fingerprint === normalized && (peer === undefined || known.peer === peer)));
    if (kept.length === this.entries.length) {
      return false;
    }
    this.entries = kept;
    this.persist?.(this.entries);
    return true;
  }

  isPinned(fingerprint: string): boolean {
    return this.find(fingerprint, null) !== null;
  }

  /** The entry for a fingerprint, optionally only under one of the given peer names; a locally made pin wins over the platform's. */
  find(fingerprint: string, peerNames: readonly string[] | null): TrustedIdentity | null {
    const matches = this.entries.filter((known) => known.fingerprint === fingerprint && namesMatch(known.peer, peerNames));
    return matches.find((known) => known.origin !== 'platform') ?? matches[0] ?? null;
  }

  hasAnyFor(peerNames: readonly string[] | null): boolean {
    return this.entries.some((known) => namesMatch(known.peer, peerNames));
  }
}

const namesMatch = (peer: string, names: readonly string[] | null): boolean => names === null || names.some((name) => name.toLowerCase() === peer.toLowerCase());

// ---------------------------------------------------------------- the TLS layer

type Verdict = { trust: TrustLevel } | { error: ErrorCode };

/** A ByteStream as the duplex stream `node:tls` runs over. */
function duplexOf(path: ByteStream): Duplex {
  let pumping = false;
  return new Duplex({
    read() {
      if (pumping) {
        return;
      }
      pumping = true;
      void (async () => {
        try {
          for (;;) {
            const chunk = await path.read();
            if (chunk === null) {
              this.push(null);
              return;
            }
            if (!this.push(Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength))) {
              return;
            }
          }
        } catch (error) {
          this.destroy(error instanceof Error ? error : new Error(String(error)));
        } finally {
          pumping = false;
        }
      })();
    },
    write(chunk: Buffer, _encoding, callback) {
      path.write(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)).then(() => callback(), callback);
    },
    final(callback) {
      path.end().then(() => callback(), callback);
    },
    destroy(error, callback) {
      path.close().then(
        () => callback(error),
        () => callback(error),
      );
    },
  });
}

/**
 * Runs the handshake and authenticates the peer by `verify` alone. Certificate chains, host
 * names and revocation lists are deliberately not consulted: no public authority is involved,
 * and the platform must not be able to vouch for a key.
 *
 * `node:tls` has no hook that judges the peer's certificate during the handshake, so the
 * handshake is completed first and the certificate judged before a single byte of the session
 * is sent or accepted. An endpoint that is not trusted has by then seen this endpoint's
 * certificate, which is public, and nothing else.
 */
async function secure(path: ByteStream, identity: EndpointIdentity, isServer: boolean, verify: (certificate: X509Certificate, fingerprint: string) => Verdict): Promise<{ stream: ByteStream; peer: PeerInfo }> {
  const transport = duplexOf(path);
  const common = { ...identity.tlsCredentials, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', ALPNProtocols: [TUNNEL_ALPN], rejectUnauthorized: false } as const;
  const socket = isServer
    ? new tls.TLSSocket(transport, { isServer: true, secureContext: tls.createSecureContext(common), requestCert: true, rejectUnauthorized: false, ALPNProtocols: [TUNNEL_ALPN] })
    : tls.connect({ ...common, socket: transport, servername: TUNNEL_SERVER_NAME, checkServerIdentity: () => undefined });

  const fail = (code: ErrorCode, message: string, cause?: unknown): ConnectivitizerError => {
    socket.destroy();
    return new ConnectivitizerError(code, message, cause === undefined ? undefined : { cause });
  };

  try {
    await new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('The end-to-end handshake timed out.')), HANDSHAKE_TIMEOUT_MS);
      const settle = (error?: Error) => {
        clearTimeout(timer);
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      };
      socket.once(isServer ? 'secure' : 'secureConnect', () => settle());
      socket.once('error', (error) => settle(error));
      socket.once('close', () => settle(new Error('The connection closed during the end-to-end handshake.')));
    });
  } catch (error) {
    throw fail(ErrorCodes.E2eHandshakeFailed, `The end-to-end handshake failed (${error instanceof Error ? error.message : String(error)}).`, error);
  }

  // From here on the peer is authenticated by the verdict below and by nothing else.
  const certificate = socket.getPeerX509Certificate();
  if (!certificate) {
    throw fail(ErrorCodes.E2ePeerNoCertificate, 'The other endpoint presented no certificate.');
  }
  const now = Date.now();
  if (now < Date.parse(certificate.validFrom) || now > Date.parse(certificate.validTo)) {
    throw fail(ErrorCodes.E2ePeerCertificateExpired, "The other endpoint's certificate is outside its validity period.");
  }
  const fingerprint = fingerprintOf(certificate);
  const verdict = verify(certificate, fingerprint);
  if ('error' in verdict) {
    throw fail(verdict.error, `The other endpoint's identity (${fingerprint}) is not trusted here (${verdict.error}).`);
  }
  if (socket.getProtocol() !== 'TLSv1.3' || socket.alpnProtocol !== TUNNEL_ALPN) {
    throw fail(ErrorCodes.E2eProtocolMismatch, 'The end-to-end channel was not established as required (TLS 1.3 with the tunnel protocol).');
  }
  return { stream: socketStream(socket), peer: { fingerprint, name: nameOf(certificate), trust: verdict.trust } };
}

// ---------------------------------------------------------------- what a client or an agent is given

export interface CertificateOptions {
  identity: EndpointIdentity;
  trust: TrustStore;

  /**
   * Accept the identity the platform has on record for a peer when nothing is pinned for it
   * locally. Weaker - the platform could then put itself in the middle - and reported as the
   * trust level `platform-introduced`. Off unless set.
   */
  allowPlatformIntroducedPeers?: boolean;
}

/**
 * The certificate layer for `createClient` and `createAgent` (their `certificates` option).
 *
 * As the calling side, a device is trusted when its fingerprint is pinned under its name. As a
 * device, a caller is trusted when its fingerprint is pinned at all - which caller may reach
 * which service is the platform's decision and the service's allow-list, not the trust store's.
 */
export function certificateSupport(options: CertificateOptions): CertificateSupport & { trusts(fingerprint: string): boolean } {
  const { identity, trust } = options;
  const levelOf = (entry: TrustedIdentity): TrustLevel => (entry.origin === 'platform' ? 'platform-introduced' : 'local-pinned');

  return {
    fingerprint: identity.fingerprint,
    registration: (secret, timestamp) => identity.registration(secret, timestamp),
    hasPinFor: (device) => trust.identities.some((known) => known.origin !== 'platform' && known.peer.toLowerCase() === device.toLowerCase()),

    trusts(fingerprint: string): boolean {
      if (trust.isPinned(fingerprint)) {
        return true;
      }
      if (options.allowPlatformIntroducedPeers && normalizeFingerprint(fingerprint)) {
        trust.pin(fingerprint, fingerprint, 'platform');
        return true;
      }
      return false;
    },

    layerFor(device: string, peer: { id: string; name?: string }, grant: SessionGrant): SecureLayer {
      return (path, role) => {
        if (role === Roles.Device) {
          return secure(path, identity, true, (_certificate, fingerprint) => {
            const pinned = trust.find(fingerprint, null);
            return pinned ? { trust: levelOf(pinned) } : { error: trust.identities.length === 0 ? ErrorCodes.E2eTrustMissing : ErrorCodes.E2ePeerUntrusted };
          });
        }
        const names = [device, peer.id, ...(peer.name ? [peer.name] : [])];
        const locallyPinned = trust.identities.some((known) => known.origin !== 'platform' && namesMatch(known.peer, names));
        if (!locallyPinned && options.allowPlatformIntroducedPeers && grant.dev.fp && normalizeFingerprint(grant.dev.fp)) {
          trust.pin(grant.dev.fp, peer.id, 'platform');
        }
        return secure(path, identity, false, (_certificate, fingerprint) => {
          const pinned = trust.find(fingerprint, names);
          return pinned ? { trust: levelOf(pinned) } : { error: trust.hasAnyFor(names) ? ErrorCodes.E2ePeerUntrusted : ErrorCodes.E2eTrustMissing };
        });
      };
    },
  };
}

/** For tests and tools: the public key of a PEM certificate as its fingerprint. */
export function fingerprintOfPem(certificatePem: string): string {
  return fingerprintOf(new X509Certificate(certificatePem));
}

/** For tools: the public key (PEM) that belongs to a private key (PEM). */
export function publicKeyPemOf(privateKeyPem: string): string {
  return createPublicKey(createPrivateKey(privateKeyPem)).export({ type: 'spki', format: 'pem' }) as string;
}
