// The state directory and pairing of a Node.js endpoint, driven from the command line for the
// interoperability tests. Every command prints one JSON document.
//
//   node state.mjs init <home> <name>                       create the identity, print its fingerprint
//   node state.mjs invite <home> <name>                     pairing step 1: print an invitation
//   node state.mjs accept <home> <name> <invitation> [as]   pairing step 2: pin the inviter, print the response
//   node state.mjs complete <home> <response>               pairing step 3: pin the responder
//   node state.mjs enroll <home> <api url> <token> <name>   enroll as a device with a one-time token
//   node state.mjs show <home>                              print fingerprint, pinned identities and shared keys

import { StateDirectory, acceptInvitation, completePairing, createInvitation, enrollDevice } from '../dist/index.js';

const [command, home, ...rest] = process.argv.slice(2);
try {
  const state = new StateDirectory(home);
  let result;
  switch (command) {
    case 'init':
      result = { fingerprint: state.loadOrCreateIdentity(rest[0]).fingerprint };
      break;
    case 'invite':
      result = { invitation: createInvitation(state, state.loadIdentity(), rest[0]) };
      break;
    case 'accept': {
      const { response, pinned } = acceptInvitation(rest[1], state.loadIdentity(), rest[0], state.openTrustStore(), rest[2]);
      result = { response, pinned };
      break;
    }
    case 'complete':
      result = { pinned: completePairing(rest[0], state, state.loadIdentity(), state.openTrustStore()) };
      break;
    case 'enroll': {
      const device = await enrollDevice(state, rest[0], rest[1], rest[2], { agentVersion: '0.0.0-interop' });
      result = { device, fingerprint: state.loadIdentity().fingerprint };
      break;
    }
    case 'show':
      result = {
        fingerprint: state.hasIdentity ? state.loadIdentity().fingerprint : null,
        identities: state.openTrustStore().identities,
        sharedKeys: state.loadSharedKeys().map((key) => key.name),
        device: state.loadDevice(),
      };
      break;
    default:
      throw new Error(`Unknown command '${command}'.`);
  }
  process.stdout.write(JSON.stringify(result) + '\n');
} catch (error) {
  process.stdout.write(JSON.stringify({ error: String(error?.message ?? error) }) + '\n');
  process.exitCode = 2;
}
