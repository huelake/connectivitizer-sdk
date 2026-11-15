"""The relay path (protocol section 3): each endpoint opens a WebSocket to the relay, the relay pairs the
two and forwards bytes it has no key for."""

from __future__ import annotations

import asyncio
import json
from typing import Optional

from .errors import ConnectivitizerError, ErrorCodes
from .platform import Platform
from .streams import ByteStream, ChunkQueue, new_future, settle, fail, spawn, with_timeout
from .websocket import StreamWebSocket

CONNECT_TIMEOUT = 10.0
PAIR_TIMEOUT = 20.0
"""The relay waits 15 s for the peer; a little longer here so its own answer arrives first."""
MAX_MESSAGE_BYTES = 32 * 1024


class RelayPath(ByteStream):
    def __init__(self, socket: StreamWebSocket) -> None:
        self._socket = socket
        self._incoming = ChunkQueue()
        self._closed = False

    @classmethod
    async def connect(cls, platform: Platform, relay_url: str, grant_token: str, role: str) -> "RelayPath":
        """Connects to the relay with the session's grant and waits until the peer is there too."""
        try:
            socket = await with_timeout(
                platform.connect_websocket(relay_url, {"Authorization": f"Bearer {grant_token}", "Cz-Role": role}),
                CONNECT_TIMEOUT,
                lambda: ConnectivitizerError(ErrorCodes.RELAY_UNREACHABLE, "The relay did not answer in time."),
            )
        except ConnectivitizerError as error:
            # A refusal the adapter could see is passed on; otherwise the relay is simply out of reach.
            if error.code in (ErrorCodes.PATH_CLOSED, ErrorCodes.SIGNALING_UNAVAILABLE):
                raise ConnectivitizerError(ErrorCodes.RELAY_UNREACHABLE, "The relay could not be reached.") from error
            raise
        except Exception as error:
            raise ConnectivitizerError(ErrorCodes.RELAY_UNREACHABLE, "The relay could not be reached.") from error

        path = cls(socket)
        paired: asyncio.Future = new_future()
        spawn(path._receive_loop(paired))
        try:
            await with_timeout(asyncio.shield(paired), PAIR_TIMEOUT, lambda: ConnectivitizerError(ErrorCodes.RELAY_PEER_TIMEOUT, "The peer did not connect to the relay in time."))
        except BaseException:
            await path.close()
            raise
        return path

    async def _receive_loop(self, paired: asyncio.Future) -> None:
        is_paired = False
        while True:
            data = await self._socket.receive()
            if data is None:
                break
            if not isinstance(data, str):
                if is_paired:
                    self._incoming.push(data)
                continue
            # Text frames come from the relay itself. Only the first one matters to an endpoint.
            if not is_paired:
                try:
                    if json.loads(data).get("t") == "paired":
                        is_paired = True
                        settle(paired)
                except (ValueError, AttributeError):
                    pass
        self._closed = True
        code, reason = self._socket.close_code or 1006, self._socket.close_reason
        # The relay names why it ended a session; "the peer left" is the ordinary end of a stream.
        named = code >= 4000 and reason and reason != ErrorCodes.PATH_CLOSED
        error = ConnectivitizerError(reason, f"The relay ended the session ({reason}).") if named else None
        if not is_paired:
            fail(paired, error or ConnectivitizerError(ErrorCodes.RELAY_UNREACHABLE, "The relay closed the connection before the peer arrived."))
        self._incoming.end(error)

    async def read(self) -> Optional[bytes]:
        return await self._incoming.read()

    async def write(self, data: bytes) -> None:
        if self._closed:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The relay path is closed.")
        for offset in range(0, len(data), MAX_MESSAGE_BYTES):
            await self._socket.send(bytes(data[offset : offset + MAX_MESSAGE_BYTES]))

    def renew_lease(self, grant_token: str) -> None:
        """Presents a renewed grant to the relay so that it keeps the session open."""
        if not self._closed and self._socket.is_open:
            spawn(self._socket.send(json.dumps({"t": "lease", "grant": grant_token})))

    async def end(self) -> None:
        await self.close()

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._incoming.end()
        await self._socket.close(1000, "")
