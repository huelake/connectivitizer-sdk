// The Node.js entry point. React Native applications import '@huelake/connectivitizer/react-native'
// instead, which contains nothing that needs Node.js.

import { randomBytes } from 'node:crypto';
import { type AgentOptions, ConnectivitizerAgent } from './core/agent.js';
import { type ClientOptions, ConnectivitizerClient } from './core/client.js';
import { type LinkedApp, type LinkOptions, linkWith } from './core/link.js';
import { generateSharedKey } from './core/noise.js';
import type { Platform } from './core/platform.js';
import { type CertificateOptions, certificateSupport } from './node/certificates.js';
import { type NodePlatformOptions, nodePlatform } from './node/platform.js';

export * from './core/index.js';
export { type CertificateOptions, EndpointIdentity, type TrustedIdentity, type TrustOrigin, TrustStore, certificateSupport, fingerprintOfPem, normalizeFingerprint } from './node/certificates.js';
export { type NodePlatformOptions, nodePlatform, socketStream } from './node/platform.js';
export { type DeviceRegistration, StateDirectory, type WorkspaceLogin, acceptInvitation, agentOptionsFrom, completePairing, createInvitation, enrollDevice } from './node/state.js';
export { type SecretPlace, type SecretWritten, copySecret, writeSecret } from './node/secretFiles.js';
export { type DeviceView, type KeyView, type Reach, type SessionView, Workspace } from './node/workspace.js';

/**
 * What Node.js adds to the options of a client or an agent: the certificate layer. With
 * `identity` and `trust` the endpoint can take part in sessions with endpoints that pin
 * certificates (`cz`, the .NET library); a shared key may be given as well, and the platform then
 * chooses per session what both sides have in common.
 */
type NodeOptions<T extends { platform: Platform }> = Omit<T, 'platform' | 'certificates'> & {
  platform?: Platform;
  node?: NodePlatformOptions;
} & Partial<CertificateOptions>;

function certificatesOf(options: Partial<CertificateOptions>): ReturnType<typeof certificateSupport> | undefined {
  if (!options.identity !== !options.trust) {
    throw new Error('The certificate layer needs both `identity` and `trust`.');
  }
  return options.identity && options.trust
    ? certificateSupport({ identity: options.identity, trust: options.trust, allowPlatformIntroducedPeers: options.allowPlatformIntroducedPeers })
    : undefined;
}

/** An application that connects to devices, running in Node.js. */
export function createClient(options: NodeOptions<ClientOptions>): ConnectivitizerClient {
  const { node, identity, trust, allowPlatformIntroducedPeers, ...rest } = options;
  return new ConnectivitizerClient({ ...rest, platform: rest.platform ?? nodePlatform(node), certificates: certificatesOf({ identity, trust, allowPlatformIntroducedPeers }) });
}

/** A device that exposes local services, running in Node.js. */
export function createAgent(options: NodeOptions<AgentOptions>): ConnectivitizerAgent {
  const { node, identity, trust, allowPlatformIntroducedPeers, ...rest } = options;
  return new ConnectivitizerAgent({ ...rest, platform: rest.platform ?? nodePlatform(node), certificates: certificatesOf({ identity, trust, allowPlatformIntroducedPeers }) });
}

/**
 * Links this program to an account: the person approves it in the web app (`onPrompt` says where)
 * and the program receives an API key of its own, to use as `auth: { apiKey }` from then on.
 */
export function linkApp(options: LinkOptions & { node?: NodePlatformOptions }): Promise<LinkedApp> {
  const { node, ...rest } = options;
  return linkWith(nodePlatform(node), { platformName: `node ${process.version} on ${process.platform}`, ...rest });
}

/** A new shared key (`czs_…`) from the system's random source. Put the same key on both endpoints. */
export function newSharedKey(): string {
  return generateSharedKey((length) => new Uint8Array(randomBytes(length)));
}
