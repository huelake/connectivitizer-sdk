// A device driven entirely by its environment, for the interoperability tests: it logs in with a
// device key, exposes one local service and serves until it is told to stop (a line on stdin, or
// stdin closing).
//
//   CZ_API_URL, CZ_DEVICE_KEY, CZ_DEVICE_NAME
//   CZ_SHARED_KEY         the key shared with the applications, and/or
//   CZ_HOME               a state directory (as cz uses it) with this device's identity and trust store.
//                         Without CZ_DEVICE_KEY the device also logs in as that directory says
//                         (an enrolled device, with the key it generated).
//   CZ_TARGET             host:port of the local application to expose as CZ_SERVICE (default api)
//   CZ_DIRECT=none        never attempt a peer-to-peer connection
//   CZ_LOOPBACK=true      offer loopback addresses (both endpoints on one machine)
//   CZ_CALL               <device>/<service>: once connected, open a session to that device and GET /hello there
//
// It prints READY once the platform sees it, and its log after that. With CZ_CALL it also prints one line
// CALLED <mode> <body>, or CALL_FAILED <code>, and keeps that session open until it stops.

import { ConnectivitizerError, StateDirectory, agentOptionsFrom, createAgent } from '../dist/index.js';

const env = (name, fallback) => {
  const value = process.env[name];
  if (value) {
    return value;
  }
  if (fallback === undefined) {
    throw new Error(`${name} is not set.`);
  }
  return fallback;
};

let agent;
try {
  const state = process.env.CZ_HOME ? new StateDirectory(process.env.CZ_HOME) : null;
  const login = process.env.CZ_DEVICE_KEY
    ? {
        apiUrl: env('CZ_API_URL'),
        deviceKey: env('CZ_DEVICE_KEY'),
        name: env('CZ_DEVICE_NAME'),
        ...(state ? { identity: state.loadIdentity(), trust: state.openTrustStore() } : {}),
      }
    : // Everything about the device - how it logs in, who it is, whom it trusts - as cz left it.
      agentOptionsFrom(state ?? new StateDirectory(env('CZ_HOME')));
  agent = createAgent({
    ...login,
    sharedKey: process.env.CZ_SHARED_KEY || login.sharedKey,
    services: { [env('CZ_SERVICE', 'api')]: { target: env('CZ_TARGET'), protocol: 'http' } },
    disableDirect: process.env.CZ_DIRECT === 'none',
    node: { includeLoopback: process.env.CZ_LOOPBACK === 'true' },
    agentVersion: '0.0.0-interop',
    log: (message) => console.log(message),
  });
} catch (error) {
  console.error(String(error?.message ?? error));
  process.exit(64);
}

process.stdin.on('data', () => void agent.stop());
process.stdin.on('end', () => void agent.stop());

const running = agent.run();
agent.waitUntilConnected().then(async () => {
  console.log('READY');
  const call = process.env.CZ_CALL;
  if (!call) {
    return;
  }
  try {
    const slash = call.lastIndexOf('/');
    const service = call.substring(slash + 1);
    const session = await agent.connect(call.substring(0, slash), [service]);
    const hello = await session.fetch(service, '/hello');
    console.log(`CALLED ${session.info.mode} ${await hello.text()}`);
  } catch (error) {
    console.log(`CALL_FAILED ${error instanceof ConnectivitizerError ? error.code : String(error?.message ?? error)}`);
  }
}, () => undefined);
try {
  await running;
  process.exit(0);
} catch (error) {
  console.log(`STOPPED ${error instanceof ConnectivitizerError ? error.code : String(error?.message ?? error)}`);
  process.exit(2);
}
