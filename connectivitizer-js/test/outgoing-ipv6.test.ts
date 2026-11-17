import assert from 'node:assert/strict';
import { test } from 'node:test';
import { isGlobalIpv6 } from '../src/core/direct/addresses.js';
import { nodePlatform, outgoingIpv6 } from '../src/node/platform.js';

// The core announces only the first few IPv6 addresses, and the firewalls on the way open only for the
// address the probes come from: that one has to be first (docs/protocol, 6.3).
test('the addresses Node.js offers start with the IPv6 address this machine sends from', async (t) => {
  const outgoing = await outgoingIpv6();
  if (outgoing === undefined) {
    t.skip('this machine has no IPv6 route');
    return;
  }
  const offered = await nodePlatform({}).udp!.localAddresses();
  assert.equal(isGlobalIpv6(outgoing), true);
  assert.equal(
    offered.find((address) => address.includes(':')),
    outgoing,
  );
  assert.equal(offered.filter((address) => address === outgoing).length, 1);
});

test('asking for the outgoing address sends nothing and never throws', async () => {
  const outgoing = await outgoingIpv6();
  assert.ok(outgoing === undefined || isGlobalIpv6(outgoing));
});
