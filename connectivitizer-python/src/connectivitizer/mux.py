"""Stream multiplexing with yamux framing (protocol section 5): many independent streams over the one
encrypted channel of a session, each with its own flow control."""

from __future__ import annotations

import asyncio
import struct
from collections import deque
from typing import Dict, Optional

from .errors import ConnectivitizerError, ErrorCodes, code_of
from .streams import ByteStream, ChunkQueue, StreamReader, new_future, settle, spawn

HEADER_SIZE = 12
TYPE_DATA = 0
TYPE_WINDOW_UPDATE = 1
TYPE_PING = 2
TYPE_GO_AWAY = 3
FLAG_SYN = 1
FLAG_ACK = 2
FLAG_FIN = 4
FLAG_RST = 8

INITIAL_WINDOW = 262_144
"""Bytes a stream may have in flight in one direction before the receiver has to make room."""
MAX_DATA = 16_384
MAX_STREAMS = 256


def frame(frame_type: int, flags: int, stream_id: int, length: int, payload: bytes = b"") -> bytes:
    return struct.pack(">BBHII", 0, frame_type, flags, stream_id, length) + payload


class MuxSession:
    def __init__(self, transport: ByteStream, is_initiator: bool) -> None:
        self._transport = transport
        self._is_initiator = is_initiator
        self._streams: Dict[int, MuxStream] = {}
        self._accept_queue: deque[MuxStream] = deque()
        self._accept_waiter: Optional[asyncio.Future] = None
        self._next_id = 1 if is_initiator else 2
        self._last_remote_id = 0
        self._tail: Optional[asyncio.Future] = None
        self._end_reason: Optional[str] = None
        self._closing = False
        self.completion: asyncio.Future = new_future()
        """Resolves with an error code once the session is over, for whatever reason."""

    @property
    def is_ended(self) -> bool:
        return self._end_reason is not None

    def start(self) -> None:
        spawn(self._read_loop())

    def open(self) -> "MuxStream":
        self._ensure_open()
        stream = MuxStream(self, self._next_id, opener=True)
        self._next_id += 2
        self._streams[stream.id] = stream
        # Queued now, so that it goes out before anything written to the stream.
        self.send(frame(TYPE_WINDOW_UPDATE, FLAG_SYN, stream.id, 0))
        return stream

    async def accept(self) -> Optional["MuxStream"]:
        """The next stream the peer opened; None once the session is over."""
        if self._accept_queue:
            return self._accept_queue.popleft()
        if self._end_reason is not None:
            return None
        self._accept_waiter = asyncio.get_running_loop().create_future()
        return await self._accept_waiter

    async def close(self) -> None:
        """Ends the session in an orderly way."""
        if self._end_reason is None:
            # Once this side said goodbye, the path going away is the orderly end and not a failure.
            self._closing = True
            try:
                await self.send(frame(TYPE_GO_AWAY, 0, 0, 0))
            except Exception:
                pass
        self.end(ErrorCodes.SESSION_CLOSED)

    def send(self, data: bytes) -> "asyncio.Future[None]":
        """Frames go out whole and in the order this was called, whether or not the caller awaits it."""
        previous = self._tail

        async def write() -> None:
            if previous is not None:
                await asyncio.wait({previous})
            self._ensure_open()
            await self._transport.write(data)

        task = asyncio.ensure_future(write())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        self._tail = task
        return task

    def forget(self, stream_id: int) -> None:
        self._streams.pop(stream_id, None)

    def end(self, reason: str) -> None:
        if self._end_reason is not None:
            return
        self._end_reason = reason
        error = ConnectivitizerError(reason, f"The session ended ({reason}).")
        for stream in list(self._streams.values()):
            stream._session_ended(error)
        self._streams.clear()
        if self._accept_waiter is not None and not self._accept_waiter.done():
            self._accept_waiter.set_result(None)
        settle(self.completion, reason)
        spawn(self._transport.close())

    def _ensure_open(self) -> None:
        if self._end_reason is not None:
            raise ConnectivitizerError(self._end_reason, f"The session is over ({self._end_reason}).")

    async def _read_loop(self) -> None:
        reader = StreamReader(self._transport)
        try:
            while self._end_reason is None:
                header = await reader.read_exact(HEADER_SIZE)
                if header is None:
                    self.end(ErrorCodes.SESSION_CLOSED if self._closing else ErrorCodes.PATH_CLOSED)
                    return
                version, frame_type, flags, stream_id, length = struct.unpack(">BBHII", header)
                if version != 0:
                    return self.end(ErrorCodes.MUX_PROTOCOL_ERROR)
                if frame_type == TYPE_PING:
                    if flags & FLAG_SYN:
                        self.send(frame(TYPE_PING, FLAG_ACK, 0, length))
                    continue
                if frame_type == TYPE_GO_AWAY:
                    return self.end(ErrorCodes.SESSION_CLOSED if length == 0 else ErrorCodes.MUX_PROTOCOL_ERROR)
                if frame_type not in (TYPE_DATA, TYPE_WINDOW_UPDATE) or stream_id == 0:
                    return self.end(ErrorCodes.MUX_PROTOCOL_ERROR)

                stream = self._streams.get(stream_id)
                if flags & FLAG_SYN:
                    remote_parity = 0 if self._is_initiator else 1
                    if stream is not None or stream_id % 2 != remote_parity or stream_id <= self._last_remote_id:
                        return self.end(ErrorCodes.MUX_PROTOCOL_ERROR)
                    self._last_remote_id = stream_id
                    if len(self._streams) >= MAX_STREAMS:
                        self.send(frame(TYPE_WINDOW_UPDATE, FLAG_RST, stream_id, 0))
                    else:
                        stream = MuxStream(self, stream_id, opener=False)
                        self._streams[stream_id] = stream
                        if self._accept_waiter is not None and not self._accept_waiter.done():
                            waiter, self._accept_waiter = self._accept_waiter, None
                            waiter.set_result(stream)
                        else:
                            self._accept_queue.append(stream)

                if frame_type == TYPE_DATA:
                    if length > INITIAL_WINDOW:
                        return self.end(ErrorCodes.MUX_PROTOCOL_ERROR)
                    payload = b"" if length == 0 else await reader.read_exact(length)
                    if payload is None:
                        return self.end(ErrorCodes.PATH_CLOSED)
                    # Data for a stream that is gone (it was reset here) is read and dropped.
                    if stream is not None and not stream._receive(payload):
                        return self.end(ErrorCodes.MUX_PROTOCOL_ERROR)
                elif stream is not None:
                    stream._window_grew(length)

                if stream is not None and flags & FLAG_RST:
                    stream._remote_reset()
                elif stream is not None and flags & FLAG_FIN:
                    stream._remote_finished()
        except asyncio.CancelledError:
            self.end(ErrorCodes.SESSION_CLOSED)
            raise
        except Exception as error:
            # A path that names its own reason for ending (the relay does) is passed on as such.
            self.end(ErrorCodes.SESSION_CLOSED if self._closing else code_of(error, ErrorCodes.PATH_CLOSED))


class MuxStream(ByteStream):
    """One stream of a session. One reader and one writer at a time."""

    def __init__(self, session: MuxSession, stream_id: int, opener: bool) -> None:
        self._session = session
        self.id = stream_id
        self._incoming = ChunkQueue()
        self._receive_window = INITIAL_WINDOW
        self._consumed = 0
        self._send_window = INITIAL_WINDOW
        self._window_waiter: Optional[asyncio.Future] = None
        self._acknowledged = opener
        self._local_finished = False
        self._remote_done = False
        self._failure: Optional[ConnectivitizerError] = None
        self._closed = False

    async def read(self) -> Optional[bytes]:
        chunk = await self._incoming.read()
        if chunk is not None:
            self._consumed += len(chunk)
            # Make room again once half the window was used up, as the reference implementation does.
            if self._consumed >= INITIAL_WINDOW // 2 and not self._remote_done and not self._closed:
                grant, self._consumed = self._consumed, 0
                self._receive_window += grant
                self._session.send(frame(TYPE_WINDOW_UPDATE, self._first_frame_flags(), self.id, grant))
        return chunk

    async def write(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            if self._failure is not None:
                raise self._failure
            if self._local_finished or self._closed:
                raise ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The stream is closed for sending.")
            if self._send_window == 0:
                self._window_waiter = asyncio.get_running_loop().create_future()
                await self._window_waiter
                continue
            size = min(len(data) - offset, self._send_window, MAX_DATA)
            self._send_window -= size
            await self._session.send(frame(TYPE_DATA, self._first_frame_flags(), self.id, size, bytes(data[offset : offset + size])))
            offset += size

    async def end(self) -> None:
        """Finishes sending; the peer can still send."""
        if self._local_finished or self._closed or self._failure is not None:
            return
        self._local_finished = True
        try:
            await self._session.send(frame(TYPE_WINDOW_UPDATE, FLAG_FIN | self._first_frame_flags(), self.id, 0))
        except Exception:
            pass
        if self._remote_done:
            self._session.forget(self.id)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        abort = self._failure is None and not (self._local_finished and self._remote_done)
        self._incoming.end()
        self._wake_writer()
        self._session.forget(self.id)
        if abort and not self._session.is_ended:
            try:
                await self._session.send(frame(TYPE_WINDOW_UPDATE, FLAG_RST, self.id, 0))
            except Exception:
                pass

    def _receive(self, payload: bytes) -> bool:
        """False when the peer sent more than the window allows."""
        if len(payload) > self._receive_window:
            return False
        self._receive_window -= len(payload)
        self._incoming.push(payload)
        return True

    def _window_grew(self, by: int) -> None:
        self._send_window += by
        self._wake_writer()

    def _remote_finished(self) -> None:
        self._remote_done = True
        self._incoming.end()
        if self._local_finished:
            self._session.forget(self.id)

    def _remote_reset(self) -> None:
        self._remote_done = True
        self._failure = ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The peer reset the stream.")
        # What arrived before the reset can still be read; after that reads fail.
        self._incoming.end(self._failure)
        self._wake_writer()
        self._session.forget(self.id)

    def _session_ended(self, error: ConnectivitizerError) -> None:
        if self._failure is None:
            self._failure = error
        self._incoming.end(None if self._remote_done else error)
        self._wake_writer()

    def _first_frame_flags(self) -> int:
        """The accepting side marks the first frame it sends for a stream."""
        if self._acknowledged:
            return 0
        self._acknowledged = True
        return FLAG_ACK

    def _wake_writer(self) -> None:
        waiter, self._window_waiter = self._window_waiter, None
        if waiter is not None and not waiter.done():
            waiter.set_result(None)
