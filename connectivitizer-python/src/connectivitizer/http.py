"""A small HTTP/1.1 client that runs over one stream: to a device service through a session, and to the
Connectivitizer API. The device's local application sees an ordinary HTTP request on its own port."""

from __future__ import annotations

import json
import re
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Mapping, Optional, Union

from .errors import ConnectivitizerError, ErrorCodes
from .streams import ByteStream, StreamReader, with_timeout
from .websocket import parse_head

MAX_HEAD = 64 * 1024
_STATUS = re.compile(r"^HTTP/1\.[01] (\d{3})(?: (.*))?$")


class TunnelResponse:
    """The answer of the service. The body is read once, by one of the body methods."""

    def __init__(self, status: int, reason: str, headers: Dict[str, str], source: Optional[Callable[[], AsyncIterator[bytes]]]) -> None:
        self.status = status
        self.reason = reason
        self.headers = headers
        """Header names in lower case. Repeated headers are joined with ", "."""
        self.ok = 200 <= status < 300
        self._source = source
        self._consumed = False

    def chunks(self) -> AsyncIterator[bytes]:
        """The body piece by piece, for downloads that should not be held in memory at once."""
        if self._consumed:
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "The body of this response was already read.")
        self._consumed = True
        return self._source() if self._source is not None else _empty()

    async def bytes(self) -> bytes:
        parts = [chunk async for chunk in self.chunks()]
        return b"".join(parts)

    async def text(self) -> str:
        return (await self.bytes()).decode("utf-8", "replace")

    async def json(self) -> Any:
        return json.loads(await self.text())


async def _empty() -> AsyncIterator[bytes]:
    return
    yield b""  # pragma: no cover


async def http_request(
    open_stream: Callable[[], Awaitable[ByteStream]],
    host: str,
    path: str,
    method: str = "GET",
    headers: Optional[Mapping[str, str]] = None,
    body: Union[str, bytes, None] = None,
    timeout: float = 30.0,
) -> TunnelResponse:
    """Sends one request over a freshly opened stream and returns once the response head is there. The
    stream is closed when the body has been read."""
    method = method.upper()
    if not re.fullmatch(r"[A-Z]+", method) or any(c in path for c in "\r\n ") or not path.startswith("/"):
        raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, 'The request needs a method and a path that starts with "/".')
    payload = None if body is None else body.encode("utf-8") if isinstance(body, str) else bytes(body)
    fields: Dict[str, List[str]] = {}

    def put(name: str, value: str) -> None:
        fields[name.lower()] = [name, value]

    put("Host", host)
    put("Accept-Encoding", "identity")
    if isinstance(body, str):
        put("Content-Type", "text/plain; charset=utf-8")
    for name, value in (headers or {}).items():
        if any(c in name for c in "\r\n:") or any(c in value for c in "\r\n"):
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "A header contains a character that is not allowed.")
        put(name, value)
    # One request per stream: streams are cheap, and it keeps the framing unambiguous.
    put("Connection", "close")
    if payload is not None:
        put("Content-Length", str(len(payload)))
    elif method not in ("GET", "HEAD"):
        put("Content-Length", "0")
    head = (f"{method} {path} HTTP/1.1\r\n" + "".join(f"{n}: {v}\r\n" for n, v in fields.values()) + "\r\n").encode("utf-8")

    stream = await open_stream()
    try:

        async def exchange():
            await stream.write(head if payload is None else head + payload)
            reader = StreamReader(stream)
            while True:
                response_head = await reader.read_head(MAX_HEAD)
                if response_head is None:
                    raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service closed the connection without answering.")
                status_line, response_headers = parse_head(response_head)
                match = _STATUS.match(status_line)
                if not match:
                    raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service did not answer with HTTP.")
                status = int(match.group(1))
                if 100 <= status < 200 and status != 101:
                    continue  # an interim response such as 100 Continue; the real one follows
                return reader, status, match.group(2) or "", response_headers

        reader, status, reason, response_headers = await with_timeout(
            exchange(), timeout, lambda: ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service did not answer in time.")
        )
        if method == "HEAD" or status in (204, 304):
            await _close_quietly(stream)
            return TunnelResponse(status, reason, response_headers, None)
        return TunnelResponse(status, reason, response_headers, lambda: _read_body(stream, reader, response_headers))
    except BaseException:
        await _close_quietly(stream)
        raise


async def _read_body(stream: ByteStream, reader: StreamReader, headers: Mapping[str, str]) -> AsyncIterator[bytes]:
    try:
        if "chunked" in headers.get("transfer-encoding", "").lower():
            while True:
                line = await _read_line(reader)
                try:
                    size = int(line.split(";")[0].strip(), 16)
                except ValueError:
                    size = -1
                if size < 0:
                    raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service sent a malformed chunked body.")
                if size == 0:
                    # Trailers, if any, end with an empty line; nothing in them is used.
                    while await _read_line(reader) != "":
                        pass
                    return
                async for chunk in _read_exactly(reader, size):
                    yield chunk
                await _read_line(reader)

        declared = headers.get("content-length")
        if declared is not None:
            try:
                length = int(declared)
            except ValueError:
                length = -1
            if length < 0:
                raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service sent an invalid Content-Length.")
            async for chunk in _read_exactly(reader, length):
                yield chunk
            return

        # Neither: the body runs until the service closes the connection.
        while True:
            chunk = await reader.read_some()
            if chunk is None:
                return
            yield chunk
    finally:
        await _close_quietly(stream)


async def _read_exactly(reader: StreamReader, length: int) -> AsyncIterator[bytes]:
    remaining = length
    while remaining > 0:
        chunk = await reader.read_some()
        if chunk is None:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The connection ended in the middle of the response body.")
        if len(chunk) > remaining:
            reader.unread(chunk[remaining:])
            yield chunk[:remaining]
            return
        remaining -= len(chunk)
        yield chunk


async def _read_line(reader: StreamReader) -> str:
    collected = b""
    while True:
        chunk = await reader.read_some()
        if chunk is None:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The connection ended in the middle of the response body.")
        newline = chunk.find(b"\n")
        if newline >= 0:
            reader.unread(chunk[newline + 1 :])
            collected += chunk[:newline]
            return collected.rstrip(b"\r").decode("utf-8", "replace")
        collected += chunk
        if len(collected) > 8192:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The service sent a malformed chunked body.")


async def _close_quietly(stream: ByteStream) -> None:
    try:
        await stream.close()
    except Exception:
        pass
