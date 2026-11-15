"""A calling application driven entirely by its environment, for the interoperability tests: it connects to a
device, uses its service in every way the SDK offers, and prints one JSON document saying what happened.
The TypeScript and .NET example clients print the same document.

  CZ_API_URL, CZ_API_KEY, CZ_DEVICE (default home-pc), CZ_SERVICE (default api), CZ_SHARED_KEY
  CZ_LIST_DEVICES=true  also report the devices this application may reach
  CZ_DIRECT=none        never attempt a peer-to-peer connection
  CZ_LOOPBACK=true      offer loopback addresses (both endpoints on one machine)
  CZ_HELLO_PATH, CZ_ECHO_PATH, CZ_WS_PATH, CZ_BLOB_PATH   paths of the device's application
  CZ_BLOB_BYTES         additionally download this many bytes
  CZ_HOLD_SECONDS       keep the session open this long and report how it ended
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sys
import time

from connectivitizer import Client, ConnectivitizerError, Platform


def env(name: str, fallback: str | None = None) -> str:
    value = os.environ.get(name)
    if value:
        return value
    if fallback is None:
        raise RuntimeError(f"{name} is not set.")
    return fallback


async def main() -> int:
    report: dict = {}
    exit_code = 0
    client = None
    try:
        device = env("CZ_DEVICE", "home-pc")
        service = env("CZ_SERVICE", "api")
        client = Client(
            env("CZ_API_URL"),
            api_key=env("CZ_API_KEY"),
            shared_key=env("CZ_SHARED_KEY"),
            disable_direct=os.environ.get("CZ_DIRECT") == "none",
            platform=Platform(include_loopback=os.environ.get("CZ_LOOPBACK") == "true"),
        )
        if os.environ.get("CZ_LIST_DEVICES") == "true":
            # What an app shows its user to choose from.
            report["devices"] = [
                {"name": d.name, "slug": d.slug, "alias": d.alias, "online": d.online, "services": d.services} for d in await client.list_devices()
            ]

        session = await client.connect(device, [service])
        # What this endpoint verified about the connection - not what anyone claimed.
        info = session.info
        report["session"] = {
            "id": info.session_id,
            "mode": info.mode,
            "transport": info.transport,
            "relayed": info.relayed,
            "endToEndEncrypted": info.end_to_end_encrypted,
            "platformCanReadPayload": info.platform_can_read_payload,
            "trust": info.trust,
            "e2eMethod": info.e2e_method,
            "peerFingerprint": info.peer_fingerprint,
            "peerName": info.peer_name,
            "directFailureReason": info.direct_failure_reason,
            "peerAddress": info.peer_address,
        }

        # 1. REST.
        hello = await session.fetch(service, env("CZ_HELLO_PATH", "/health"))
        report["helloStatus"] = hello.status
        report["hello"] = await hello.text()
        canary = os.environ.get("CZ_CANARY") or "canary-" + os.urandom(12).hex()
        echoed = await session.fetch(service, env("CZ_ECHO_PATH", "/api/echo"), method="POST", body=canary)
        report["echoMatches"] = await echoed.text() == canary
        large = os.urandom(300_000)
        large_echoed = await session.fetch(service, env("CZ_ECHO_PATH", "/api/echo"), method="POST", body=large, headers={"Content-Type": "application/octet-stream"})
        report["largeEchoMatches"] = await large_echoed.bytes() == large

        # 2. A WebSocket.
        socket = await session.websocket(service, env("CZ_WS_PATH", "/ws"))
        await socket.send("ping over websocket")
        report["webSocketEchoMatches"] = await asyncio.wait_for(socket.receive(), 10) == "ping over websocket"
        await socket.close()

        # 3. Optionally a larger download, to see the throughput of the path in use.
        blob_bytes = int(os.environ.get("CZ_BLOB_BYTES") or "0")
        if blob_bytes > 0:
            started = time.monotonic()
            response = await session.fetch(service, env("CZ_BLOB_PATH", "/api/blob/") + str(blob_bytes), timeout=60)
            digest = hashlib.sha256()
            received = 0
            async for chunk in response.chunks():
                digest.update(chunk)
                received += len(chunk)
            seconds = max(time.monotonic() - started, 0.001)
            report["blob"] = {"bytes": received, "sha256": digest.hexdigest(), "milliseconds": int(seconds * 1000), "megabytesPerSecond": round(received / 1024 / 1024 / seconds, 2)}

        report["bytesSent"] = session.bytes_sent
        report["bytesReceived"] = session.bytes_received
        report["ok"] = True

        # Keep the session open for a while when asked to (lets a test revoke access and watch it end).
        hold = int(os.environ.get("CZ_HOLD_SECONDS") or "0")
        if hold > 0:
            done, _ = await asyncio.wait({session.completion}, timeout=hold)
            report["endedWhileHolding"] = session.completion.result() if done else None
    except Exception as error:
        # Every refusal carries a stable code that says which layer said no.
        report["ok"] = False
        report["error"] = error.code if isinstance(error, ConnectivitizerError) else type(error).__name__
        report["message"] = str(error)
        exit_code = 2
    if client is not None:
        try:
            await client.close()
        except Exception:
            pass
    sys.stdout.write(json.dumps(report, indent=2) + "\n")
    sys.stdout.flush()
    return exit_code


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
