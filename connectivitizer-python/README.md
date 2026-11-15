# Connectivitizer SDK for Python

`huelake-connectivitizer` (import `connectivitizer`): reach a service on a device behind NAT from Python, and run a device in Python. Sessions are encrypted end to end with a key only the device and the application hold; they run peer to peer when the networks allow it and through the Connectivitizer relay when they do not.

It speaks the same protocol as the .NET library, `cz`, the TypeScript SDK and the ESP32 library, so the two sides of a session can be written in different languages.

```python
import asyncio
from connectivitizer import Client

async def main():
    async with Client("https://…/api/connectivitizer", api_key="czk_…", shared_key="czs_…") as client:
        session = await client.connect("living-room-lamp", ["api"])
        response = await session.fetch("api", "/state")
        print(response.status, await response.json())
        print(session.info.mode)                  # 'direct' or 'e2e-relay'
        print(session.info.end_to_end_encrypted)  # established by this endpoint, not claimed by the platform

asyncio.run(main())
```

## Install

```
pip install huelake-connectivitizer
```

The guide with complete examples: [https://connectivitizer.com/guides/python.md](https://connectivitizer.com/guides/python.md). Python 3.10 or newer; the only dependency is `cryptography`. Everything else (WebSocket, HTTP, UDP, KCP, the Noise handshake) is in the package and the standard library.

## Calling side

| | |
|---|---|
| `Client(api_url, api_key=…, shared_key=…)` | Also `get_token=` (a coroutine function returning a `TokenResponse`) instead of `api_key`; `disable_direct=True` to always use the relay. Use it as `async with`, or call `close()`. |
| `await client.list_devices()` | The devices this application may reach: name, alias, online, and the services it may use. |
| `await client.connect(device, services)` | Opens a session to a device by its name. |
| `await session.fetch(service, path, method=, headers=, body=, timeout=)` | An HTTP request to the device's local service: `status`, `headers`, `await text()`, `await json()`, `await bytes()`, `async for chunk in chunks()`. |
| `await session.websocket(service, path)` | A WebSocket: `await send(...)`, `await receive()` (None once closed), `async for message in socket`. |
| `await session.open_stream(service)` | The raw byte stream (`read`, `write`, `end`, `close`), for any other protocol. |
| `session.info` | `mode`, `transport`, `end_to_end_encrypted`, `trust`, `peer_address`, `direct_failure_reason`. |
| `await session.close()`, `await client.close()` | End the session, or everything. |

Errors are `ConnectivitizerError` with a stable `code` (`E2E_SHARED_KEY_MISMATCH`, `DEVICE_OFFLINE`, `FORBIDDEN`, …; protocol section 9).

`await link_app(api_url, "Report service", on_prompt)` links a program to an account instead of giving it a key: the person approves in the web app and the program receives an API key of its own (`LINK_DENIED`, `LINK_EXPIRED` when not).

## Device side

```python
from connectivitizer import Agent

agent = Agent(api_url, device_key="czd_…", name="nas", shared_key="czs_…",
              services={"api": "127.0.0.1:8080"}, log=print)
await agent.run()   # until await agent.stop(); reconnects by itself, raises when the key is revoked
```

The device appears in the workspace the first time it connects. `Service(target, protocol, allow=["key:<name>"])` restricts a service to holders of one of the device's keys.

## Direct sessions

Nothing to configure. `Platform` binds a dual-stack UDP socket on a port the system picks and finds the machine's addresses itself (the source address of each default route, the addresses of the host name, and on Linux the kernel's IPv6 list); the SDK then offers the local IPv4 address, global IPv6 addresses and the public address STUN reports, and punches through the routers. `Platform(ssl_context=…)` trusts the certificate authority of a self-hosted installation.

## What is in the package

| | |
|---|---|
| `noise.py`, `mux.py`, `session.py` | The shared-key channel (Noise `NNpsk0`), yamux multiplexing, the session bind and service streams. |
| `signaling.py`, `relay_path.py`, `api.py`, `grants.py` | The control plane, the relay, grant verification (ES256). |
| `direct/` | Addresses, STUN and hole punching, KCP (a port of the reference `ikcp.c`), the KCP path. |
| `http.py`, `websocket.py` | HTTP/1.1 and WebSocket over any byte stream: to the platform and to the device's services. |
| `platform.py` | asyncio sockets, UDP and local addresses. |
| `interop/` | The programs the .NET test suite runs against the other implementations. |

The structure follows the TypeScript SDK (`src/connectivitizer-js/src/core`), which is the reference for this port.

## Checks

```
python -m venv .venv && .venv/Scripts/pip install -e .        # .venv/bin on Linux and macOS
.venv/Scripts/python -m unittest discover -s tests -t .       # the shared vectors in docs/protocol/vectors, and every layer in memory
dotnet test ../Huelake.Connectivitizer.sln --filter "FullyQualifiedName~PythonInteropTests"
```

The last line runs this SDK against the real control plane and relay, with the .NET library and the TypeScript SDK on the other side, in both directions, relayed and peer to peer.

## Not included yet

- Certificates and pairing (the shared key is the only end-to-end layer for now), and enrollment with a one-time token.
- Direct connections over TCP, and compatibility mode.
