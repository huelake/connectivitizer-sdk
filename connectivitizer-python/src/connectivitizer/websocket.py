"""A WebSocket client (RFC 6455) that runs over any byte stream: WebSockets to a device service through a
session, and the connections to the platform (signaling, relay), which need request headers."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import struct
from typing import Callable, Dict, List, Optional, Tuple, Union

from .errors import ConnectivitizerError, ErrorCodes
from .streams import ByteStream, StreamReader, spawn

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
OP_CONTINUATION = 0
OP_TEXT = 1
OP_BINARY = 2
OP_CLOSE = 8
OP_PING = 9
OP_PONG = 10
MAX_HEAD = 16 * 1024

Message = Union[bytes, str]


class WebSocketRefusedError(ConnectivitizerError):
    """The server answered the WebSocket request with an ordinary HTTP response."""

    def __init__(self, status: int, headers: Dict[str, str], body: str) -> None:
        super().__init__(ErrorCodes.RELAY_REJECTED, f"The server refused the WebSocket connection (HTTP {status}).")
        self.status = status
        self.headers = headers
        self.body = body


def parse_head(head: bytes) -> Tuple[str, Dict[str, str]]:
    """The status (or request) line and the headers, names in lower case, repeated headers joined with ", "."""
    lines = head.decode("utf-8", "replace").split("\r\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        colon = line.find(":")
        if colon > 0:
            name = line[:colon].strip().lower()
            value = line[colon + 1 :].strip()
            headers[name] = f"{headers[name]}, {value}" if name in headers else value
    return (lines[0] if lines else ""), headers


class StreamWebSocket:
    """An open WebSocket. ``receive()`` returns the next message (str for text, bytes for binary), or None
    once the connection is closed; ``close_code`` and ``close_reason`` then say why."""

    def __init__(self, stream: ByteStream, reader: StreamReader, random_bytes: Callable[[int], bytes], max_message_bytes: int) -> None:
        self._stream = stream
        self._reader = reader
        self._random_bytes = random_bytes
        self._max_message_bytes = max_message_bytes
        self._messages: "asyncio.Queue[Optional[Message]]" = asyncio.Queue()
        self._writing: Optional[asyncio.Future] = None
        self._close_sent = False
        self._closed_event = asyncio.Event()
        self.protocol = ""
        """The subprotocol the server selected, or an empty string."""
        self.close_code: Optional[int] = None
        self.close_reason = ""

    @classmethod
    async def connect(
        cls,
        stream: ByteStream,
        host: str,
        path: str,
        random_bytes: Callable[[int], bytes],
        headers: Optional[Dict[str, str]] = None,
        protocols: Optional[List[str]] = None,
        max_message_bytes: int = 16 * 1024 * 1024,
    ) -> "StreamWebSocket":
        """Performs the opening handshake over ``stream`` and returns the open connection."""
        key = base64.b64encode(random_bytes(16)).decode("ascii")
        lines = [f"GET {path} HTTP/1.1", f"Host: {host}", "Upgrade: websocket", "Connection: Upgrade", f"Sec-WebSocket-Key: {key}", "Sec-WebSocket-Version: 13"]
        if protocols:
            lines.append(f"Sec-WebSocket-Protocol: {', '.join(protocols)}")
        for name, value in (headers or {}).items():
            if any(c in name + value for c in "\r\n"):
                raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "A header contains a line break.")
            lines.append(f"{name}: {value}")
        await stream.write(("\r\n".join(lines) + "\r\n\r\n").encode("utf-8"))

        reader = StreamReader(stream)
        head = await reader.read_head(MAX_HEAD)
        if head is None:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The connection closed before the WebSocket was established.")
        status_line, response_headers = parse_head(head)
        parts = status_line.split(" ")
        status = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if status != 101:
            body = ""
            try:
                length = int(response_headers.get("content-length", "0"))
                if 0 < length <= 4096:
                    body = ((await reader.read_exact(length)) or b"").decode("utf-8", "replace")
            except (ValueError, EOFError, ConnectivitizerError):
                pass
            await _close_quietly(stream)
            raise WebSocketRefusedError(status, response_headers, body)
        expected = base64.b64encode(hashlib.sha1((key + GUID).encode("ascii")).digest()).decode("ascii")
        if response_headers.get("sec-websocket-accept") != expected or response_headers.get("upgrade", "").lower() != "websocket":
            await _close_quietly(stream)
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The server did not complete the WebSocket handshake correctly.")

        socket = cls(stream, reader, random_bytes, max_message_bytes)
        socket.protocol = response_headers.get("sec-websocket-protocol", "")
        spawn(socket._read_loop())
        return socket

    @property
    def is_open(self) -> bool:
        return self.close_code is None and not self._close_sent

    async def receive(self) -> Optional[Message]:
        """The next message, or None once the connection is closed."""
        if self._messages.empty() and self.close_code is not None:
            return None
        message = await self._messages.get()
        if message is None:
            self._messages.put_nowait(None)  # every later call sees the end as well
        return message

    def __aiter__(self) -> "StreamWebSocket":
        return self

    async def __anext__(self) -> Message:
        message = await self.receive()
        if message is None:
            raise StopAsyncIteration
        return message

    async def send(self, data: Message) -> None:
        """Sends one message: text for a str, binary for bytes."""
        if not self.is_open:
            raise ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The WebSocket is closed.")
        if isinstance(data, str):
            await self._send_frame(OP_TEXT, data.encode("utf-8"))
        else:
            await self._send_frame(OP_BINARY, bytes(data))

    async def close(self, code: int = 1000, reason: str = "") -> None:
        if self.close_code is not None or self._close_sent:
            return
        self._close_sent = True
        payload = struct.pack(">H", code) + reason.encode("utf-8")[:123]
        try:
            await self._send_frame(OP_CLOSE, payload)
            # A server that never answers the close must not keep the stream open forever.
            await asyncio.wait_for(self._closed_event.wait(), 2)
        except (asyncio.TimeoutError, Exception):
            pass
        self._finish(code, reason)

    async def wait_closed(self) -> None:
        await self._closed_event.wait()

    def _send_frame(self, opcode: int, payload: bytes) -> "asyncio.Future[None]":
        mask = self._random_bytes(4)
        length = len(payload)
        if length < 126:
            header = bytes([0x80 | opcode, 0x80 | length])
        elif length < 65536:
            header = bytes([0x80 | opcode, 0x80 | 126]) + struct.pack(">H", length)
        else:
            header = bytes([0x80 | opcode, 0x80 | 127]) + struct.pack(">Q", length)
        masked = bytes(b ^ mask[i & 3] for i, b in enumerate(payload)) if length < 512 else _mask(payload, mask)
        previous = self._writing

        async def write() -> None:
            if previous is not None:
                await asyncio.wait({previous})
            await self._stream.write(header + mask + masked)

        task = asyncio.ensure_future(write())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        self._writing = task
        return task

    async def _read_loop(self) -> None:
        fragments: List[bytes] = []
        fragment_opcode = 0
        fragment_bytes = 0
        try:
            while self.close_code is None:
                header = await self._reader.read_exact(2)
                if header is None:
                    return self._finish(1006, "")
                final = (header[0] & 0x80) != 0
                opcode = header[0] & 0x0F
                masked = (header[1] & 0x80) != 0
                length = header[1] & 0x7F
                if length == 126:
                    extended = await self._reader.read_exact(2)
                    if extended is None:
                        return self._finish(1006, "")
                    length = struct.unpack(">H", extended)[0]
                elif length == 127:
                    extended = await self._reader.read_exact(8)
                    if extended is None:
                        return self._finish(1006, "")
                    length = struct.unpack(">Q", extended)[0]
                if length > self._max_message_bytes:
                    return await self._fail(1009, "message too big")
                mask = await self._reader.read_exact(4) if masked else None
                payload = b"" if length == 0 else await self._reader.read_exact(length)
                if payload is None or (masked and mask is None):
                    return self._finish(1006, "")
                if mask:
                    payload = _mask(payload, mask)

                if opcode == OP_PING:
                    self._send_frame(OP_PONG, payload)
                elif opcode == OP_PONG:
                    pass  # unsolicited pongs are a keep-alive some servers send
                elif opcode == OP_CLOSE:
                    code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 1005
                    reason = payload[2:].decode("utf-8", "replace") if len(payload) > 2 else ""
                    if not self._close_sent:
                        self._close_sent = True
                        try:
                            await self._send_frame(OP_CLOSE, payload[:2])
                        except Exception:
                            pass
                    return self._finish(code, reason)
                elif opcode in (OP_TEXT, OP_BINARY, OP_CONTINUATION):
                    if opcode != OP_CONTINUATION:
                        fragment_opcode, fragments, fragment_bytes = opcode, [], 0
                    fragments.append(payload)
                    fragment_bytes += len(payload)
                    if fragment_bytes > self._max_message_bytes:
                        return await self._fail(1009, "message too big")
                    if final:
                        whole = b"".join(fragments)
                        fragments = []
                        self._messages.put_nowait(whole.decode("utf-8", "replace") if fragment_opcode == OP_TEXT else whole)
                else:
                    return await self._fail(1002, "unknown frame")
        except asyncio.CancelledError:
            self._finish(1006, "")
            raise
        except Exception as error:
            # The reason a path gives for ending (the relay names one) travels as the close reason.
            self._finish(1006, error.code if isinstance(error, ConnectivitizerError) else "")

    async def _fail(self, code: int, reason: str) -> None:
        await self.close(code, reason)
        self._finish(code, reason)

    def _finish(self, code: int, reason: str) -> None:
        if self.close_code is not None:
            return
        self.close_code = code
        self.close_reason = reason
        self._messages.put_nowait(None)
        self._closed_event.set()
        spawn(self._stream.close())


def _mask(payload: bytes, mask: bytes) -> bytes:
    """XORs with the 4-byte mask, fast for large payloads."""
    repeated = (mask * (len(payload) // 4 + 1))[: len(payload)]
    return (int.from_bytes(payload, "little") ^ int.from_bytes(repeated, "little")).to_bytes(len(payload), "little")


async def _close_quietly(stream: ByteStream) -> None:
    try:
        await stream.close()
    except Exception:
        pass
