"""A device driven entirely by its environment, for the interoperability tests: it logs in with a device key,
exposes one local service and serves until it is told to stop (a line on stdin, or stdin closing).

  CZ_API_URL, CZ_DEVICE_KEY, CZ_DEVICE_NAME, CZ_SHARED_KEY
  CZ_TARGET             host:port of the local application to expose as CZ_SERVICE (default api)
  CZ_DIRECT=none        never attempt a peer-to-peer connection
  CZ_LOOPBACK=true      offer loopback addresses (both endpoints on one machine)
  CZ_CALL=<device>/<service>   once connected, open a session to that device and GET /hello on that service

It prints READY once the platform sees it, and its log after that. With CZ_CALL it also prints one line
"CALLED <mode> <body>", or "CALL_FAILED <code>", and keeps that session open until it stops.
"""

from __future__ import annotations

import asyncio
import os
import sys
import threading

from connectivitizer import Agent, ConnectivitizerError, Platform, Service


def env(name: str, fallback: str | None = None) -> str:
    value = os.environ.get(name)
    if value:
        return value
    if fallback is None:
        raise RuntimeError(f"{name} is not set.")
    return fallback


def say(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


async def main() -> int:
    try:
        agent = Agent(
            env("CZ_API_URL"),
            device_key=env("CZ_DEVICE_KEY"),
            name=env("CZ_DEVICE_NAME"),
            shared_key=env("CZ_SHARED_KEY"),
            services={env("CZ_SERVICE", "api"): Service(env("CZ_TARGET"), protocol="http")},
            disable_direct=os.environ.get("CZ_DIRECT") == "none",
            agent_version="0.0.0-interop",
            log=say,
            platform=Platform(include_loopback=os.environ.get("CZ_LOOPBACK") == "true"),
        )
    except Exception as error:
        print(str(error), file=sys.stderr)
        return 64

    loop = asyncio.get_running_loop()

    def watch_stdin() -> None:
        # Any line, or the end of stdin, stops the device.
        sys.stdin.readline()
        loop.call_soon_threadsafe(lambda: asyncio.ensure_future(agent.stop()))

    threading.Thread(target=watch_stdin, daemon=True).start()

    async def announce() -> None:
        await agent.wait_until_connected()
        say("READY")
        call = os.environ.get("CZ_CALL")
        if not call:
            return
        try:
            device, _, service = call.partition("/")
            session = await agent.connect(device, [service])
            hello = await session.fetch(service, "/hello")
            say(f"CALLED {session.info.mode} {await hello.text()}")
        except Exception as error:
            say(f"CALL_FAILED {error.code if isinstance(error, ConnectivitizerError) else type(error).__name__}")

    asyncio.ensure_future(announce())
    try:
        await agent.run()
        return 0
    except ConnectivitizerError as error:
        say(f"STOPPED {error.code}")
        return 2
    except Exception as error:
        say(f"STOPPED {error}")
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
