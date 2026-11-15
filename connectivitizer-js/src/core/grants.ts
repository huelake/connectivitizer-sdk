import { p256 } from '@noble/curves/nist.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { base64Decode, concat, toHex, utf8Decode, utf8Encode } from './bytes.js';
import { ErrorCodes } from './errors.js';

// Session grants (protocol section 2): the control plane's signed statement that one initiator may
// open one session to one device. An endpoint acts on a grant because its signature checks out,
// not because of the channel it arrived on.

export const ConnectionModes = { Direct: 'direct', E2eRelay: 'e2e-relay', Compatibility: 'compatibility' } as const;
export const E2eMethods = { Tls13: 'tls13', SharedKey: 'shared-key' } as const;
export const Capabilities = {
  E2eTls13: 'e2e.tls13',
  E2eSharedKey: 'e2e.shared-key',
  MuxYamux: 'mux.yamux',
  PathRelayWs: 'path.relay-ws',
  PathTcp: 'path.tcp',
  PathUdpKcp: 'path.udp-kcp',
} as const;
export const Roles = { Initiator: 'initiator', Device: 'device' } as const;
export type Role = (typeof Roles)[keyof typeof Roles];

export interface GrantParty {
  type: string;
  id: string;
  fp?: string | null;
}

export interface SessionGrant {
  iss: string;
  aud: string[];
  /** The session id. */
  jti: string;
  ws: string;
  ini: GrantParty;
  dev: GrantParty;
  svc: string[];
  modes: string[];
  /** The end-to-end layer of the session; absent means certificates. */
  e2e?: string | null;
  relay?: string | null;
  iat: number;
  exp: number;
  lease: number;
}

export const e2eMethodOf = (grant: SessionGrant): string => grant.e2e ?? E2eMethods.Tls13;

export type GrantValidation = { grant: SessionGrant; error?: undefined } | { grant?: undefined; error: string };

const AUDIENCE_AGENT = 'cz-agent';
const CLOCK_SKEW_SECONDS = 30;
const MAX_TOKEN_LENGTH = 16 * 1024;

/** The public keys grants are signed with, by key id: uncompressed P-256 points. */
export type GrantKeys = Map<string, Uint8Array>;

export function parseJwks(document: unknown): GrantKeys {
  const keys: GrantKeys = new Map();
  const list = (document as { keys?: unknown })?.keys;
  if (Array.isArray(list)) {
    for (const jwk of list as Record<string, unknown>[]) {
      if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || typeof jwk.kid !== 'string' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
        continue;
      }
      try {
        const x = base64Decode(jwk.x);
        const y = base64Decode(jwk.y);
        if (x.length === 32 && y.length === 32) {
          keys.set(jwk.kid, concat(Uint8Array.of(4), x, y));
        }
      } catch {
        // A malformed key is as good as an absent one.
      }
    }
  }
  return keys;
}

/** The key id a token names, without verifying anything, so the right key can be fetched first. */
export function readKeyId(token: string): string | null {
  try {
    const header = JSON.parse(utf8Decode(base64Decode(token.substring(0, token.indexOf('.'))))) as { kid?: unknown };
    return typeof header.kid === 'string' && header.kid.length > 0 ? header.kid : null;
  } catch {
    return null;
  }
}

/** SHA-256 (lower-case hex) of a grant token: what the session bind and the shared-key handshake refer to. */
export const hashGrant = (token: string): string => toHex(sha256(utf8Encode(token)));

/**
 * Verifies signature, audience and time of a grant token. `forSessionStart` selects which deadline
 * applies: the short start window (`exp`) or the session lease.
 */
export function validateGrant(token: string, keys: GrantKeys, nowSeconds: number, forSessionStart: boolean): GrantValidation {
  if (!token || token.length > MAX_TOKEN_LENGTH) {
    return { error: ErrorCodes.GrantInvalid };
  }
  const firstDot = token.indexOf('.');
  const lastDot = token.lastIndexOf('.');
  if (firstDot <= 0 || lastDot <= firstDot + 1 || lastDot === token.length - 1) {
    return { error: ErrorCodes.GrantInvalid };
  }

  let grant: SessionGrant;
  try {
    const header = JSON.parse(utf8Decode(base64Decode(token.substring(0, firstDot)))) as { alg?: unknown; kid?: unknown };
    // The algorithm is fixed. Accepting whatever the header names is how "alg" attacks work.
    if (header.alg !== 'ES256' || typeof header.kid !== 'string') {
      return { error: ErrorCodes.GrantInvalid };
    }
    const key = keys.get(header.kid);
    const signature = base64Decode(token.substring(lastDot + 1));
    if (!key || signature.length !== 64 || !p256.verify(signature, utf8Encode(token.substring(0, lastDot)), key, { lowS: false })) {
      return { error: ErrorCodes.GrantInvalid };
    }
    grant = JSON.parse(utf8Decode(base64Decode(token.substring(firstDot + 1, lastDot)))) as SessionGrant;
  } catch {
    return { error: ErrorCodes.GrantInvalid };
  }

  if (!grant || typeof grant.jti !== 'string' || grant.jti.length === 0 || !Array.isArray(grant.aud) || !grant.aud.includes(AUDIENCE_AGENT)
    || !grant.ini || !grant.dev || !Array.isArray(grant.svc) || !Array.isArray(grant.modes)
    || typeof grant.iat !== 'number' || typeof grant.exp !== 'number' || typeof grant.lease !== 'number') {
    return { error: ErrorCodes.GrantInvalid };
  }

  const deadline = forSessionStart ? grant.exp : grant.iat + grant.lease;
  if (nowSeconds > deadline + CLOCK_SKEW_SECONDS || nowSeconds < grant.iat - CLOCK_SKEW_SECONDS) {
    return { error: ErrorCodes.GrantExpired };
  }
  return { grant };
}
