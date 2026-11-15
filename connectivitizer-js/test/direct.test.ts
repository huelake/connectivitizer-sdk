import assert from 'node:assert/strict';
import { test } from 'node:test';
import { formatAddress, isGlobalIpv6, normalizeHost, parseAddress } from '../src/core/direct/addresses.js';
import { DirectAttempt, type DirectAttemptOptions, type DirectPath, peerReflexiveFor } from '../src/core/direct/attempt.js';
import { Roles } from '../src/core/grants.js';
import { utf8Decode, utf8Encode } from '../src/core/bytes.js';
import { nodePlatform } from '../src/node/platform.js';

const platform = nodePlatform({ includeLoopback: true });

/** An address nothing answers at (TEST-NET-1): what a side behind a symmetric NAT effectively announces. */
const unreachable = ['192.0.2.1:9'];

/** Announces the same port on the IPv6 loopback address instead of everything else. */
const onlyIpv6Loopback = (candidates: string[]) => [`[::1]:${parseAddress(candidates[0])!.port}`];

async function negotiate(grant: string, initiatorOptions: DirectAttemptOptions, deviceOptions: DirectAttemptOptions) {
  const initiator = new DirectAttempt(platform, Roles.Initiator, 'session-1', grant, [], initiatorOptions);
  const device = new DirectAttempt(platform, Roles.Device, 'session-1', grant, [], deviceOptions);
  const fromInitiator = await initiator.gather();
  const fromDevice = await device.gather();
  assert.ok(device.setRemoteCandidates(fromInitiator));
  assert.ok(initiator.setRemoteCandidates(fromDevice));
  const selected = device.waitForSelection();
  selected.catch(() => undefined);
  const opened = await initiator.open(3000);
  const accepted = opened ? await selected : null;
  return { initiator, device, opened, accepted, close: () => { initiator.close(); device.close(); } };
}

async function assertConnected(a: DirectPath, b: DirectPath): Promise<void> {
  await a.stream.write(utf8Encode('ping'));
  assert.equal(utf8Decode((await b.stream.read())!), 'ping');
  await b.stream.write(utf8Encode('pong'));
  assert.equal(utf8Decode((await a.stream.read())!), 'pong');
  a.stream.close();
  b.stream.close();
}

test('candidate addresses: IPv4 and bracketed IPv6, in one canonical spelling', () => {
  assert.deepEqual(parseAddress('192.168.2.176:54249'), { host: '192.168.2.176', port: 54249 });
  assert.deepEqual(parseAddress('[2003:E1:0:0::42]:5000'), { host: '2003:e1::42', port: 5000 });
  assert.deepEqual(parseAddress('[::ffff:192.0.2.1]:7'), { host: '192.0.2.1', port: 7 });
  assert.equal(parseAddress('2003:e1::42:5000'), null);
  assert.equal(parseAddress('192.168.2.300:1'), null);
  assert.equal(parseAddress('[fe80::1%eth0]:1'), null);
  assert.equal(parseAddress('10.0.0.1:0'), null);
  assert.equal(formatAddress({ host: '2003:e1::42', port: 5000 }), '[2003:e1::42]:5000');
  // Java writes IPv6 addresses out in full; they compare equal to the short form.
  assert.equal(normalizeHost('2a01:598:a0:0:0:0:0:1'), '2a01:598:a0::1');
  assert.equal(normalizeHost('2001:db8:0:0:1:0:0:1'), '2001:db8::1:0:0:1');
  assert.equal(normalizeHost('::'), '::');
  assert.equal(normalizeHost('1:2:3:4:5:6:7:8:9'), null);
  assert.ok(isGlobalIpv6('2a01:598:a0::1'));
  assert.ok(!isGlobalIpv6('fe80::1'));
  assert.ok(!isGlobalIpv6('fd00::1'));
  assert.ok(!isGlobalIpv6('192.168.1.1'));
});

test('learned addresses are only allowed where the end-to-end handshake authenticates the peer', () => {
  assert.ok(peerReflexiveFor('shared-key'));
  assert.ok(peerReflexiveFor('tls13'));
  assert.ok(!peerReflexiveFor('none'));
});

test('two endpoints that only announce IPv6 connect over IPv6', async () => {
  const run = await negotiate('grant-v6', { peerReflexive: true, announceFilter: onlyIpv6Loopback }, { peerReflexive: true, announceFilter: onlyIpv6Loopback });
  try {
    assert.ok(run.opened && run.accepted);
    assert.match(run.opened.peerAddress, /^\[::1\]:\d+$/);
    assert.match(run.accepted.peerAddress, /^\[::1\]:\d+$/);
    await assertConnected(run.opened, run.accepted);
  } finally {
    run.close();
  }
});

test('an initiator that announced no usable address is accepted at the address its probes come from', async () => {
  const run = await negotiate('grant-prflx-1', { peerReflexive: true, announceFilter: () => unreachable }, { peerReflexive: true });
  try {
    assert.ok(run.opened && run.accepted);
    assert.notEqual(run.accepted.peerAddress, unreachable[0]);
    await assertConnected(run.opened, run.accepted);
  } finally {
    run.close();
  }
});

test('a device that announced no usable address is reached at the address its probes come from', async () => {
  const run = await negotiate('grant-prflx-2', { peerReflexive: true }, { peerReflexive: true, announceFilter: () => unreachable });
  try {
    assert.ok(run.opened && run.accepted);
    assert.notEqual(run.opened.peerAddress, unreachable[0]);
    await assertConnected(run.opened, run.accepted);
  } finally {
    run.close();
  }
});

test('without peer-reflexive, an address nobody announced is never used', async () => {
  const run = await negotiate('grant-prflx-3', { peerReflexive: false, announceFilter: () => unreachable }, { peerReflexive: false });
  try {
    assert.equal(run.opened, null);
  } finally {
    run.close();
  }
});
