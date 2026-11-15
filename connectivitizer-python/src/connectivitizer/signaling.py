"""The signaling channel (protocol section 8): one WebSocket to the control plane that says who wants to talk
to whom and how to reach them. It never carries application data."""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, Callable, Dict, Optional

from .errors import ConnectivitizerError, ErrorCodes
from .platform import Platform
from .streams import new_future, settle, spawn, with_timeout
from .websocket import StreamWebSocket

HELLO_TIMEOUT = 15.0
PING_INTERVAL = 25.0
SILENCE_LIMIT = 70.0
"""A connection on which nothing arrived for this long is treated as dead."""

Envelope = Dict[str, Any]


class SignalingClient:
    def __init__(self, socket: StreamWebSocket) -> None:
        self._socket = socket
        self.welcome: Dict[str, Any] = {}
        """What the control plane answered to ``hello``."""
        self.on_message: Optional[Callable[[Envelope], None]] = None
        """Called for every message that is not the reply to a request."""
        self._pending: Dict[str, asyncio.Future] = {}
        self._next_id = 1
        self._last_received = time.monotonic()
        self.closed: asyncio.Future = new_future()
        """Resolves with the reason once the connection is over."""
        self._tasks: list = []

    @property
    def is_open(self) -> bool:
        return not self.closed.done()

    @classmethod
    async def connect(cls, platform: Platform, url: str, access_token: str, hello: Dict[str, Any]) -> "SignalingClient":
        try:
            socket = await platform.connect_websocket(url, {"Authorization": f"Bearer {access_token}"})
        except ConnectivitizerError as error:
            # A refusal the adapter could read (the token is not accepted) is passed on as it is.
            if error.code in (ErrorCodes.UNAUTHENTICATED, ErrorCodes.FORBIDDEN):
                raise
            raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel could not be opened.") from error
        except Exception as error:
            raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel could not be opened.") from error

        client = cls(socket)
        client._tasks.append(spawn(client._receive_loop()))
        try:
            reply = await client.request("hello", {k: v for k, v in hello.items() if v is not None}, HELLO_TIMEOUT)
            if reply.get("t") != "welcome" or not isinstance(reply.get("d"), dict):
                raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, "The control plane did not welcome this endpoint.")
            client.welcome = reply["d"]
        except BaseException:
            await client.close()
            raise
        # Some runtimes hide WebSocket pings from the application, so liveness is checked with messages.
        client._tasks.append(spawn(client._keep_alive()))
        return client

    def send(self, message_type: str, data: Dict[str, Any]) -> None:
        """Sends a message that expects no reply."""
        self._write({"t": message_type, "d": data})

    async def request(self, message_type: str, data: Dict[str, Any], timeout: float) -> Envelope:
        """Sends a request and waits for its reply. An ``error`` reply raises with the platform's code."""
        request_id = str(self._next_id)
        self._next_id += 1
        reply: asyncio.Future = new_future()
        self._pending[request_id] = reply
        try:
            self._write({"t": message_type, "id": request_id, "d": data})
            envelope = await with_timeout(
                asyncio.shield(reply), timeout, lambda: ConnectivitizerError(ErrorCodes.SIGNALING_TIMEOUT, f"The control plane did not answer '{message_type}' in time.")
            )
            if envelope.get("t") == "error":
                detail = envelope.get("d") or {}
                code = detail.get("code") if isinstance(detail.get("code"), str) else ErrorCodes.INVALID_REQUEST
                message = detail.get("message") if isinstance(detail.get("message"), str) else f"The control plane refused '{message_type}' ({code})."
                raise ConnectivitizerError(code, message)
            return envelope
        finally:
            self._pending.pop(request_id, None)

    async def close(self) -> None:
        self._finish(ErrorCodes.SESSION_CLOSED)
        await self._socket.close(1000, "")

    def _write(self, envelope: Envelope) -> None:
        if not self.is_open or not self._socket.is_open:
            raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel is closed.")
        spawn(self._socket.send(json.dumps(envelope, separators=(",", ":"))))

    async def _receive_loop(self) -> None:
        try:
            while True:
                data = await self._socket.receive()
                if data is None:
                    break
                self._last_received = time.monotonic()
                try:
                    envelope = json.loads(data if isinstance(data, str) else data.decode("utf-8"))
                except ValueError:
                    continue
                if not isinstance(envelope, dict) or not isinstance(envelope.get("t"), str):
                    continue
                re_id = envelope.get("re")
                if re_id is not None and re_id in self._pending:
                    settle(self._pending[re_id], envelope)
                    continue
                if envelope["t"] == "pong":
                    continue
                if self.on_message is not None:
                    try:
                        self.on_message(envelope)
                    except Exception:
                        pass  # a handler that throws must not take the channel down with it
        finally:
            self._finish(self._socket.close_reason or ErrorCodes.SIGNALING_UNAVAILABLE)

    async def _keep_alive(self) -> None:
        while self.is_open:
            await asyncio.sleep(PING_INTERVAL)
            if not self.is_open:
                return
            if time.monotonic() - self._last_received > SILENCE_LIMIT:
                self._finish(ErrorCodes.SIGNALING_UNAVAILABLE)
                await self._socket.close(1001, "")
                return
            try:
                self._write({"t": "ping", "id": f"k{self._next_id}"})
                self._next_id += 1
            except ConnectivitizerError:
                pass  # the receive loop takes care of the rest

    def _finish(self, reason: str) -> None:
        if self.closed.done():
            return
        settle(self.closed, reason)
        error = ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE if reason == ErrorCodes.SESSION_CLOSED else reason, f"The signaling channel closed ({reason}).")
        for waiter in self._pending.values():
            if not waiter.done():
                waiter.set_exception(error)
        self._pending.clear()
        for task in self._tasks:
            if task is not asyncio.current_task():
                task.cancel()
