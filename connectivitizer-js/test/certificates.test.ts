import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ConnectivitizerError, ErrorCodes } from '../src/core/errors.js';
import { Roles, type SessionGrant } from '../src/core/grants.js';
import { EndpointIdentity, TrustStore, certificateSupport, fingerprintOfPem, normalizeFingerprint } from '../src/node/certificates.js';
import { StateDirectory, acceptInvitation, completePairing, createInvitation } from '../src/node/state.js';
import { memoryPair } from './support.js';

const text = (value: string) => new TextEncoder().encode(value);

/** A grant as far as the certificate layer looks at it. */
const grantFor = (deviceFingerprint: string, initiatorFingerprint: string) => ({ dev: { fp: deviceFingerprint }, ini: { fp: initiatorFingerprint } }) as unknown as SessionGrant;

function temporaryState(): { state: StateDirectory; remove: () => void } {
  const path = mkdtempSync(join(tmpdir(), 'cz-state-'));
  return { state: new StateDirectory(path), remove: () => rmSync(path, { recursive: true, force: true }) };
}

test('a new identity is a valid self-signed end-entity certificate with the expected fingerprint', () => {
  const identity = EndpointIdentity.create('living-room');
  const certificate = new X509Certificate(identity.certificatePem);

  assert.equal(certificate.subject, 'CN=living-room');
  assert.equal(certificate.issuer, 'CN=living-room');
  assert.equal(certificate.ca, false);
  assert.ok(certificate.verify(certificate.publicKey), 'the certificate is signed with its own key');
  assert.deepEqual(certificate.keyUsage, ['1.3.6.1.5.5.7.3.1', '1.3.6.1.5.5.7.3.2']);
  assert.ok(Date.parse(certificate.validFrom) < Date.now() && Date.parse(certificate.validTo) > Date.now() + 364 * 86_400_000);

  assert.match(identity.fingerprint, /^sha256:[0-9a-f]{64}$/);
  assert.equal(identity.fingerprint, fingerprintOfPem(identity.certificatePem));
  assert.equal(identity.name, 'living-room');

  // Two identities never share a key.
  assert.notEqual(EndpointIdentity.create('living-room').fingerprint, identity.fingerprint);
});

test('an identity survives being stored, and a key that does not belong to the certificate is refused', () => {
  const identity = EndpointIdentity.create('app');
  const loaded = EndpointIdentity.fromPem(identity.certificatePem, identity.exportPrivateKeyPem());
  assert.equal(loaded.fingerprint, identity.fingerprint);
  assert.equal(loaded.sign(text('x')).length, 64);

  const other = EndpointIdentity.create('other');
  assert.throws(() => EndpointIdentity.fromPem(identity.certificatePem, other.exportPrivateKeyPem()), /does not belong/);
});

test('fingerprints are normalised and anything else is refused', () => {
  const fingerprint = 'sha256:' + 'ab'.repeat(32);
  assert.equal(normalizeFingerprint(`  ${fingerprint.toUpperCase().replace('SHA256', 'sha256')} `), fingerprint);
  assert.equal(normalizeFingerprint('sha256:abcd'), null);
  assert.equal(normalizeFingerprint('md5:' + 'ab'.repeat(32)), null);
  assert.equal(normalizeFingerprint(undefined), null);
  assert.throws(() => new TrustStore().pin('not a fingerprint', 'peer'));
});

test('two endpoints that pinned each other get a TLS 1.3 channel and know who is at the other end', async () => {
  const device = EndpointIdentity.create('home-pc');
  const app = EndpointIdentity.create('laptop');
  const deviceTrust = new TrustStore();
  deviceTrust.pin(app.fingerprint, 'laptop', 'pairing');
  const appTrust = new TrustStore();
  appTrust.pin(device.fingerprint, 'home-pc', 'pairing');
  const grant = grantFor(device.fingerprint, app.fingerprint);

  const [appPath, devicePath] = memoryPair();
  const [appSide, deviceSide] = await Promise.all([
    certificateSupport({ identity: app, trust: appTrust }).layerFor('home-pc', { id: 'd1', name: 'Home PC' }, grant)(appPath, Roles.Initiator),
    certificateSupport({ identity: device, trust: deviceTrust }).layerFor('laptop', { id: 'c1' }, grant)(devicePath, Roles.Device),
  ]);

  assert.deepEqual(appSide.peer, { fingerprint: device.fingerprint, name: 'home-pc', trust: 'local-pinned' });
  assert.deepEqual(deviceSide.peer, { fingerprint: app.fingerprint, name: 'laptop', trust: 'local-pinned' });

  await appSide.stream.write(text('ping'));
  assert.equal(new TextDecoder().decode((await deviceSide.stream.read())!), 'ping');
  await deviceSide.stream.write(text('pong'));
  assert.equal(new TextDecoder().decode((await appSide.stream.read())!), 'pong');
  await appSide.stream.close();
  await deviceSide.stream.close();
});

test('nothing pinned, or something else pinned, gives no channel - whatever the grant says', async () => {
  const device = EndpointIdentity.create('home-pc');
  const app = EndpointIdentity.create('laptop');
  const impostor = EndpointIdentity.create('home-pc');
  const grant = grantFor(device.fingerprint, app.fingerprint);
  const deviceTrust = new TrustStore();
  deviceTrust.pin(app.fingerprint, 'laptop');

  const attempt = async (appTrust: TrustStore, presented: EndpointIdentity) => {
    const [appPath, devicePath] = memoryPair();
    const deviceEnd = certificateSupport({ identity: presented, trust: deviceTrust }).layerFor('laptop', { id: 'c1' }, grant)(devicePath, Roles.Device);
    deviceEnd.then((established) => established.stream.close(), () => undefined);
    return certificateSupport({ identity: app, trust: appTrust }).layerFor('home-pc', { id: 'd1' }, grant)(appPath, Roles.Initiator);
  };

  // The application pinned nothing: the platform's word for the device's identity is not enough.
  await assert.rejects(attempt(new TrustStore(), device), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.E2eTrustMissing);

  // The application pinned the real device and meets another key under the same name.
  const pinned = new TrustStore();
  pinned.pin(device.fingerprint, 'home-pc');
  await assert.rejects(attempt(pinned, impostor), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.E2ePeerUntrusted);

  // A pin for another peer does not count for this one.
  const elsewhere = new TrustStore();
  elsewhere.pin(device.fingerprint, 'office-pc');
  await assert.rejects(attempt(elsewhere, device), (error: unknown) => error instanceof ConnectivitizerError && error.code === ErrorCodes.E2eTrustMissing);
});

test('accepting the platform\'s word is an explicit choice and is reported as the weaker trust level', async () => {
  const device = EndpointIdentity.create('home-pc');
  const app = EndpointIdentity.create('laptop');
  const grant = grantFor(device.fingerprint, app.fingerprint);
  const appTrust = new TrustStore();
  const deviceSupport = certificateSupport({ identity: device, trust: new TrustStore(), allowPlatformIntroducedPeers: true });
  assert.ok(deviceSupport.trusts(app.fingerprint));

  const [appPath, devicePath] = memoryPair();
  const [appSide, deviceSide] = await Promise.all([
    certificateSupport({ identity: app, trust: appTrust, allowPlatformIntroducedPeers: true }).layerFor('home-pc', { id: 'd1' }, grant)(appPath, Roles.Initiator),
    deviceSupport.layerFor('laptop', { id: 'c1' }, grant)(devicePath, Roles.Device),
  ]);
  assert.equal(appSide.peer.trust, 'platform-introduced');
  assert.equal(deviceSide.peer.trust, 'platform-introduced');
  assert.equal(appTrust.identities[0].origin, 'platform');
  await appSide.stream.close();
  await deviceSide.stream.close();

  // Without the option the same endpoint refuses.
  assert.equal(certificateSupport({ identity: device, trust: new TrustStore() }).trusts(app.fingerprint), false);
});

test('pairing: three steps, two strings, and each side ends up with the other pinned', () => {
  const device = temporaryState();
  const app = temporaryState();
  try {
    const deviceIdentity = device.state.loadOrCreateIdentity('home-pc');
    const appIdentity = app.state.loadOrCreateIdentity('laptop');
    const deviceTrust = device.state.openTrustStore();
    const appTrust = app.state.openTrustStore();

    const invitation = createInvitation(device.state, deviceIdentity, 'home-pc');
    assert.ok(invitation.startsWith('czp1.'));
    const { response, pinned } = acceptInvitation(invitation, appIdentity, 'laptop', appTrust);
    assert.ok(response.startsWith('czr1.'));
    assert.deepEqual({ fingerprint: pinned.fingerprint, peer: pinned.peer, origin: pinned.origin }, { fingerprint: deviceIdentity.fingerprint, peer: 'home-pc', origin: 'pairing' });

    const completed = completePairing(response, device.state, deviceIdentity, deviceTrust);
    assert.deepEqual({ fingerprint: completed.fingerprint, peer: completed.peer }, { fingerprint: appIdentity.fingerprint, peer: 'laptop' });

    // What was pinned is on disk, in the file cz reads.
    assert.equal(device.state.openTrustStore().isPinned(appIdentity.fingerprint), true);
    assert.equal(JSON.parse(readFileSync(join(app.state.path, 'trust.json'), 'utf8')).identities[0].fingerprint, deviceIdentity.fingerprint);
    // The identity is the same after a restart.
    assert.equal(device.state.loadIdentity().fingerprint, deviceIdentity.fingerprint);

    // An invitation works once.
    assert.throws(() => completePairing(response, device.state, deviceIdentity, deviceTrust), /open invitation/);
  } finally {
    device.remove();
    app.remove();
  }
});

test('pairing: a response made without the invitation\'s secret pins nothing', () => {
  const device = temporaryState();
  const stranger = temporaryState();
  try {
    const deviceIdentity = device.state.loadOrCreateIdentity('home-pc');
    const deviceTrust = device.state.openTrustStore();
    createInvitation(device.state, deviceIdentity, 'home-pc');

    // Someone who knows the device's name and fingerprint, but not the secret, makes up an invitation.
    const forged = 'czp1.' + Buffer.from(JSON.stringify({ peer: 'home-pc', fp: deviceIdentity.fingerprint, k: Buffer.alloc(32, 7).toString('base64url') })).toString('base64url');
    const { response } = acceptInvitation(forged, stranger.state.loadOrCreateIdentity('stranger'), 'stranger', stranger.state.openTrustStore());

    assert.throws(() => completePairing(response, device.state, deviceIdentity, deviceTrust), /open invitation/);
    assert.equal(deviceTrust.identities.length, 0);
    assert.throws(() => acceptInvitation('czr1.abc', deviceIdentity, 'x', deviceTrust), /not a pairing invitation/);
    assert.throws(() => completePairing('nonsense', device.state, deviceIdentity, deviceTrust), /not a pairing response/);
  } finally {
    device.remove();
    stranger.remove();
  }
});

test('the state directory keeps shared keys in the file cz reads', () => {
  const { state, remove } = temporaryState();
  try {
    assert.deepEqual(state.loadSharedKeys(), []);
    const key = 'czs_' + Buffer.alloc(32, 9).toString('base64url');
    state.saveSharedKeys([{ name: 'lamp', key }]);
    const loaded = state.loadSharedKeys();
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].name, 'lamp');
    assert.deepEqual(JSON.parse(readFileSync(join(state.path, 'sharedkeys.json'), 'utf8')), { keys: [{ name: 'lamp', key }] });
    assert.throws(() => state.saveSharedKeys([{ name: 'bad', key: 'czs_short' }]));
  } finally {
    remove();
  }
});
