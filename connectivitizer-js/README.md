# Connectivitizer SDK for TypeScript

`@huelake/connectivitizer`: reach a service on a device behind NAT from Node.js or from a React Native app, and run a device in Node.js. Sessions are encrypted end to end with a key only your device and your app hold; they run peer to peer when the networks allow it and through the Connectivitizer relay when they do not.

It is the same protocol the .NET library, `cz` and the ESP32 library speak, so the two sides of a session can be written in different languages.

```ts
import { createClient } from '@huelake/connectivitizer';

const client = createClient({
  apiUrl: 'https://…/api/connectivitizer',
  auth: { apiKey: 'czk_…' },
  sharedKey: 'czs_…',                       // the same key the device has
});

const session = await client.connect('living-room-lamp', ['api']);
const state = await (await session.fetch('api', '/state')).json();

session.info.mode;                // 'direct' or 'e2e-relay'
session.info.endToEndEncrypted;   // established by this endpoint, not claimed by the platform
await session.end();
await client.close();
```

## Install

```
npm install @huelake/connectivitizer
```

The guide with complete examples: [https://connectivitizer.com/guides/typescript.md](https://connectivitizer.com/guides/typescript.md).

ESM only, Node.js 20 or newer. Its only dependencies are `@noble/curves`, `@noble/ciphers` and `@noble/hashes`.

## Calling side

| | |
|---|---|
| `createClient(options)` | `apiUrl`; `auth`; `sharedKey`; `disableDirect: true` to always use the relay |
| `auth: { apiKey }` | An application key of the workspace (`czk_…`): created in the web app, or handed to the app by `linkApp` (below). |
| `auth: { signIn: { workspaceId, client, getAccessToken } }` | For an app that runs the identity provider's sign-in itself and has the user's access token. That needs a client registered at the identity provider for the app; apps without one use `linkApp`. |
| `auth: { getToken }` | Anything else that can produce a token of the control plane. |
| `client.listDevices()` | The devices this application may reach: name, alias, whether they are online, and the services it may use. |
| `client.connect(device, services)` | Opens a session to a device by its name. |
| `session.info` | `mode`, `transport`, `relayed`, `endToEndEncrypted`, `e2eMethod`, `trust`, `peerAddress`, `directFailureReason`: what this endpoint found out about the session. |
| `session.fetch(service, path, init)` | An HTTP request to the device's local service. The answer has `status`, `headers`, `text()`, `json()`, `bytes()`, `chunks()`. |
| `session.webSocket(service, path)` | A WebSocket to the device's local service. |
| `session.openStream(service)` | The raw byte stream, for any other protocol. |
| `session.end()`, `client.close()` | End the session, or everything. |

Errors are `ConnectivitizerError` with a stable `code` (`E2E_SHARED_KEY_MISMATCH`, `DEVICE_OFFLINE`, `FORBIDDEN`, …; see [Error codes](https://connectivitizer.com/guides/errors.md)).

## Linking an app instead of giving it a key

An app for end users should not have a key typed into it, and should not ask for a password either. `linkApp` gets the app a key of its own with the user signing in on the Connectivitizer website:

```ts
import { linkApp } from '@huelake/connectivitizer';              // or '@huelake/connectivitizer/react-native'

const linked = await linkApp({
  apiUrl,
  client: 'Lamp app',                                            // the name the app appears under
  onPrompt: ({ url, code }) => openInBrowser(url),               // the website must show `code`
});
// linked.apiKey is returned this once: keep it in the keystore, and use it from then on
const client = createClient({ apiUrl, auth: { apiKey: linked.apiKey }, sharedKey });
```

The app opens the address it is given (or shows it together with the code, for use on another device), the person signs in there and approves, and `linkApp` resolves. It rejects with `LINK_DENIED` when the person refused and with `LINK_EXPIRED` after ten minutes without a decision; `signal` cancels the wait. Nothing has to be registered for the app anywhere, and no redirect back into the app is involved.

The linked app is listed under *Credentials* in the web app, where it is revoked.

## Device side (Node.js)

```ts
import { createAgent } from '@huelake/connectivitizer';

const agent = createAgent({
  apiUrl: 'https://…/api/connectivitizer',
  deviceKey: 'czd_…',                        // from the workspace
  name: 'home-pc',                           // how apps address this device
  sharedKey: 'czs_…',
  services: { api: '127.0.0.1:8080' },       // nothing else is reachable
});
await agent.run();                           // until agent.stop()
```

The device appears in the workspace the first time it connects. One device key serves any number of devices; the name tells them apart.

## A device that calls another device

A device opens sessions to other devices with `agent.connect`, over the connection to the platform it already has. Two things are needed:

- The device key it logs in with has *Its devices may open sessions to other devices* switched on (web app: *Credentials*). Without it, or for a device or service outside the access rules of the key, the platform refuses with `FORBIDDEN`.
- The device holds the shared key of the other device, in `sharedKey`. With several keys it uses the one named like the other device, else its only one, else the one named `default`.

```ts
import { createAgent } from '@huelake/connectivitizer';

const agent = createAgent({
  apiUrl: 'https://…/api/connectivitizer',
  deviceKey: 'czd_…',                        // a device key that may open sessions
  name: 'door-bell',
  sharedKey: 'czs_…',                        // the key the other device has as well
  services: { api: '127.0.0.1:8080' },
});
const running = agent.run();

const session = await agent.connect('hallway-chime', ['api']);   // waits until the device is connected
await session.fetch('api', '/ring', { method: 'POST' });
await session.end();
```

| | |
|---|---|
| `agent.connect(device, services)` | Opens a session to another device by its name. The session is the same object `client.connect` returns. |
| `agent.listDevices()` | The devices this device may reach, without itself. For devices that log in with a device key. |
| `agent.outgoingSessions` | The sessions this device opened that are still running. `agent.openSessions` are the ones opened to it. |

The device stays reachable while it calls, and `agent.stop()` ends the sessions it opened as well. React Native has no device side, so an app there is a calling application only.

## React Native

Apps use [`@huelake/connectivitizer-react-native`](https://www.npmjs.com/package/@huelake/connectivitizer-react-native), which brings the native parts (UDP, the phone's own addresses) and a secure random source, so the app passes only `apiUrl`, `auth` and `sharedKey`. [The React Native guide](https://connectivitizer.com/guides/react-native.md) has a complete example. Browsers are not supported: a browser's WebSocket cannot send the headers the platform authenticates by.

`@huelake/connectivitizer/react-native` is the entry point underneath: everything without Node.js, plus `reactNativePlatform()`, the adapter for a runtime that brings its own UDP and random source (see below).

## Writing your own platform adapter

The core (`src/core`) contains no runtime code; a `Platform` (`src/core/platform.ts`) supplies random bytes, `fetch`, a WebSocket with request headers and, for peer to peer, UDP. Getting the UDP part right decides whether sessions can be direct:

- **`localAddresses()`** must return the machine's own addresses: its IPv4 address in the local network (else two endpoints in the same Wi-Fi only meet through the router's public address, which many routers do not loop back) and its global IPv6 addresses (else a phone on mobile data cannot reach a device at home directly, since mobile IPv4 goes through carrier NAT). Skip VPN interfaces. Put the IPv6 address the machine sends from first (connect a UDP socket to a global address and read its own address; nothing is sent), and deprecated ones last: the core announces the first four, and the firewalls on the way open only for the address the probes come from. A machine with a temporary and a stable address per prefix, plus those of a prefix its router replaced, has more than four.
- **`bind()`** must report the port the socket is really bound to. `react-native-udp` on Android reports the port that was asked for, so `reactNativePlatform` binds it to a random port in 49152-65535 of its own choosing instead of port 0.
- **The socket should be dual-stack** and say so with `ipv6`; set it false where it is not, so that no IPv6 candidates are announced.
- **Hosts** passed to `onMessage` are canonical: IPv4 dotted, IPv6 in RFC 5952 form (`normalizeHost`), an IPv4 peer on a dual-stack socket as IPv4.
- **`randomBytes`** must be a cryptographically secure source; session keys are made from it.

`reactNativePlatform({ randomBytes, udp, localAddress, udpIpv6 })` builds such a platform from `react-native-udp` and an address function; `@huelake/connectivitizer-react-native` builds one from its own native module.

## Certificates and pairing (Node.js)

The other way two endpoints can trust each other, and the one `cz` and the .NET library use by default: each endpoint makes an identity of its own (an ECDSA key and a certificate), the two pin each other's fingerprint by pairing, and sessions run over mutual TLS 1.3. An endpoint then knows exactly which endpoint it talks to, not just that it holds a key.

```ts
import { StateDirectory, createClient, acceptInvitation } from '@huelake/connectivitizer';

const state = new StateDirectory('<data folder>');          // the same files cz uses
const identity = state.loadOrCreateIdentity('my-app');      // the private key stays here
const trust = state.openTrustStore();

// once: the device shows an invitation (cz pair create), the app answers it
const { response } = acceptInvitation(invitation, identity, 'my-app', trust);
// ... hand `response` to the device (cz pair complete <response>)

const client = createClient({ apiUrl, auth: { apiKey }, identity, trust });
const session = await client.connect('home-pc', ['api']);
session.info.trust;        // 'local-pinned'
```

| | |
|---|---|
| `EndpointIdentity.create(name)`, `.fromPem(...)` | An identity; `fingerprint` is what peers pin. |
| `TrustStore` | The pinned identities. `pin(fingerprint, peer)` adds one by hand. |
| `createInvitation`, `acceptInvitation`, `completePairing` | Pairing in three steps with two strings; the same strings `cz pair` produces and accepts. |
| `StateDirectory` | Identity, trust store, shared keys and pending pairings as files, in the layout of `cz`. A Node.js program and `cz` can share one directory. |
| `enrollDevice(state, apiUrl, token, name)` | Enrolls a device with a one-time token: it makes its own login key and logs in by signing a challenge, without a device key. |
| `agentOptionsFrom(state)` | Everything a state directory says about a device, for `createAgent({ ...agentOptionsFrom(state), services })`. |
| `allowPlatformIntroducedPeers: true` | Accept the identity the platform has on record when nothing is pinned. Weaker, and reported as trust `platform-introduced`. |

An endpoint may have an identity and a shared key at the same time; the platform then picks, per session, a layer both sides have (certificates first when the device is pinned).

This is Node.js only: React Native has no TLS for a stream the app owns.

## Managing a workspace: the command line and the MCP server

The package's command, `connectivitizer`, lists devices and keys, creates keys and sets who may reach what, from a shell or as tools of an AI client. Nothing has to be installed first:

```bash
npx -y @huelake/connectivitizer login                    # the browser opens; an admin of the workspace approves
npx -y @huelake/connectivitizer devices
npx -y @huelake/connectivitizer key create Boards --device --save include/secrets.h:DEVICE_KEY
npx -y @huelake/connectivitizer key update Boards --sessions on
npx -y @huelake/connectivitizer keygen --save include/secrets.h:SHARED_KEY --save app/.env:CZ_SHARED_KEY
npx -y @huelake/connectivitizer sessions --failed
npx -y @huelake/connectivitizer mcp                      # the same as tools (Model Context Protocol, stdio)
```

- **Keys are written, not shown.** A command or tool that makes a key puts it into the file named (`.h`: a `#define`; `.json`: a property; `.ps1`: a variable; anything else: `NAME=value`) and answers with name, prefix and path. A shared key is made locally and never sent anywhere.
- **The sign-in** is a link that asks to manage (`linkApp({ manage: true })`): only an admin can approve it, the key is valid for 30 days, and it can neither create further managing keys nor invite or remove members. It is kept in the state directory (`workspace.json`).
- **Not offered:** revoking keys and revoking or deleting devices. That stays in the web app.
- **In code:** `Workspace` is the class behind the commands (`devices()`, `keys()`, `createKey()`, `updateKey()`, `updateDevice()`, `sessions()`), and `writeSecret` / `copySecret` write the files.

An AI client registers the server as `npx -y @huelake/connectivitizer mcp`, with `CONNECTIVITIZER_API_URL` in its environment for an installation other than connectivitizer.com. `CONNECTIVITIZER_NO_BROWSER=1` keeps the browser closed; the address and the code are in the answer of `sign_in`.

## Shared keys

`npx connectivitizer keygen` prints a new key (`czs_` and 43 characters); the web app's *Credentials* page generates one in the browser. The key goes on the device and into the app, never to Connectivitizer. An endpoint may hold several keys: a device tries each of its keys; a calling app uses the one named like the device, else its only one, else the one named `default`.

## What is in the package

| | |
|---|---|
| `src/core` | Everything that does not depend on a runtime: signaling, grants, the shared-key channel (Noise `NNpsk0`), multiplexing, relay path, STUN and hole punching, KCP, HTTP and WebSocket over a session stream. |
| `src/node` | The Node.js adapter (`node:net`, `node:tls`, `node:dgram`), the certificate layer, the state directory and pairing, and the workspace tools with their MCP server. |
| `src/react-native.ts` | The React Native adapter (built-in `WebSocket` and `fetch`; UDP and random bytes passed in). Apps use `@huelake/connectivitizer-react-native`, which passes them. |
| `interop/` | Programs for the interoperability tests with the other implementations. |

## Checks

```
npm run build
npm test                # the Noise test vector, KCP, multiplexing, HTTP and WebSocket framing, certificates, pairing
```

Each release is also tested against the control plane and the relay with the .NET library on the other side, in both directions, relayed and peer to peer, with a shared key and with certificates.

The MCP server is tested against the control plane by a test that plays the client: sign-in, a device key written to a file, the right switched on, and two devices that then call each other. It has not been tried with a particular AI client.

## Limits

- Certificates and pairing work on Node.js only. A React Native app reaches an endpoint that has only certificates once that endpoint holds the shared key as well (`cz key add`).
- Direct sessions use UDP. Direct connections over TCP are in `cz` and the .NET library only.
- A device run by this SDK cannot be reached in compatibility mode (through the gateway).
