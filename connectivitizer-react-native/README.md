# Connectivitizer for React Native

`@huelake/connectivitizer-react-native`: reach a service on a device behind NAT (an ESP32, a PC, a server) from a React Native app. Sessions are encrypted end to end with a key only the device and the app hold, and run peer to peer when the networks allow it, through the relay otherwise.

The protocol is the TypeScript SDK's ([`@huelake/connectivitizer`](https://www.npmjs.com/package/@huelake/connectivitizer)). This package adds what a phone runtime does not have: UDP sockets and the phone's own addresses (a native module), and a secure random source (`expo-crypto`). The app passes none of that:

```ts
import { createClient, linkApp } from '@huelake/connectivitizer-react-native';

const client = createClient({ apiUrl, auth: { apiKey }, sharedKey });
const session = await client.connect('living-room-lamp', ['api']);
const state = await (await session.fetch('api', '/state')).json();
session.info.mode;   // 'direct' or 'e2e-relay'
```

Everything else (`linkApp`, `ConnectivitizerError`, the types) is re-exported from `@huelake/connectivitizer/react-native`.

## Install

```
npm install @huelake/connectivitizer @huelake/connectivitizer-react-native
npx expo install expo-crypto
```

The guide with a complete example: [https://connectivitizer.com/guides/react-native.md](https://connectivitizer.com/guides/react-native.md).

On Android the app needs a development build (`npx expo run:android`); Expo Go cannot contain the native module.

## What the native module does

| | Android |
|---|---|
| UDP | A dual-stack `DatagramChannel` bound to a port the system picks, which reports the real port. One receiving thread per socket; datagrams go to JavaScript as events. |
| Own addresses | From `ConnectivityManager`: the IPv4 address in Wi-Fi or Ethernet, and global IPv6 addresses on Wi-Fi and mobile data. VPNs are skipped. |

The JavaScript side puts IPv6 addresses into canonical form and hands everything to the SDK's core, which does STUN, hole punching, KCP and the encryption.

| Where | Peer to peer |
|---|---|
| Android, development build | yes |
| Expo Go | no: every session goes through the relay (a warning is logged once) |
| iOS | no: the native module is for Android, so every session goes through the relay |

Relayed sessions are end-to-end encrypted like direct ones. `peerToPeerAvailable()` tells which case applies, for an app that wants to say so.

To check a development build on a phone: a session to a device in the same Wi-Fi reports `session.info.mode` as `direct`.
