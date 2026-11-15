"""Byte streams: the one abstraction every layer of a session is built from."""

from __future__ import annotations

import asyncio
from collections import deque
from typing import Awaitable, Callable, Optional, TypeVar

T = TypeVar("T")


class ByteStream:
    """A two-way stream of bytes: a relay connection, a direct path, the encrypted channel on top of
    either, or one stream to a service. Chunk boundaries carry no meaning."""

    async def read(self) -> Optional[bytes]:
        """The next bytes, or None once the other side has finished sending. Raises when the stream broke."""
        raise NotImplementedError

    async def write(self, data: bytes) -> None:
        raise NotImplementedError

    async def end(self) -> None:
        """Finishes sending while still receiving (a half close). Streams that cannot do that close entirely."""
        await self.close()

    async def close(self) -> None:
        """Closes both directions now."""
        raise NotImplementedError


class ChunkQueue:
    """Turns something that delivers chunks whenever it likes (a socket, a WebSocket) into something that
    is read when the reader is ready."""

    def __init__(self) -> None:
        self._chunks: deque[bytes] = deque()
        self._waiter: Optional[asyncio.Future[Optional[bytes]]] = None
        self._ended = False
        self._error: Optional[BaseException] = None
        self.size = 0
        """Bytes pushed and not read yet."""

    @property
    def is_ended(self) -> bool:
        return self._ended

    def push(self, chunk: bytes) -> None:
        if self._ended or not chunk:
            return
        if self._waiter is not None and not self._waiter.done():
            waiter, self._waiter = self._waiter, None
            waiter.set_result(chunk)
        else:
            self._chunks.append(chunk)
            self.size += len(chunk)

    def end(self, error: Optional[BaseException] = None) -> None:
        """No more chunks will come. With ``error``, readers fail once what was queued has been read."""
        if self._ended:
            return
        self._ended = True
        self._error = error
        if self._waiter is not None and not self._waiter.done():
            waiter, self._waiter = self._waiter, None
            if error is not None:
                waiter.set_exception(error)
            else:
                waiter.set_result(None)

    async def read(self) -> Optional[bytes]:
        if self._chunks:
            chunk = self._chunks.popleft()
            self.size -= len(chunk)
            return chunk
        if self._ended:
            if self._error is not None:
                raise self._error
            return None
        if self._waiter is not None:
            raise RuntimeError("A read is already waiting on this stream.")
        self._waiter = asyncio.get_running_loop().create_future()
        return await self._waiter


class StreamReader:
    """Reads exact amounts from a :class:`ByteStream`, keeping what a chunk had left over for the next read."""

    def __init__(self, stream: ByteStream) -> None:
        self._stream = stream
        self._pending = b""
        self._finished = False

    async def read_exact(self, length: int) -> Optional[bytes]:
        """Exactly ``length`` bytes. None when the stream ended before the first of them; raises when it
        ended in the middle."""
        while len(self._pending) < length:
            chunk = None if self._finished else await self._stream.read()
            if chunk is None:
                self._finished = True
                if not self._pending:
                    return None
                raise EOFError("The stream ended in the middle of a message.")
            self._pending += chunk
        result, self._pending = self._pending[:length], self._pending[length:]
        return result

    async def read_some(self) -> Optional[bytes]:
        """Whatever is available next: left-over bytes first, then the stream's next chunk. None at the end."""
        if self._pending:
            result, self._pending = self._pending, b""
            return result
        if self._finished:
            return None
        chunk = await self._stream.read()
        if chunk is None:
            self._finished = True
        return chunk

    def unread(self, data: bytes) -> None:
        """Puts bytes back so that the next read returns them first."""
        self._pending = data + self._pending

    async def read_head(self, max_length: int) -> Optional[bytes]:
        """Reads up to and including ``\\r\\n\\r\\n`` (the head of an HTTP message). None when the stream ended first."""
        while True:
            end = self._pending.find(b"\r\n\r\n")
            if end >= 0:
                head, self._pending = self._pending[: end + 4], self._pending[end + 4 :]
                return head
            if len(self._pending) > max_length:
                raise ValueError("The header is too long.")
            chunk = None if self._finished else await self._stream.read()
            if chunk is None:
                self._finished = True
                return None
            self._pending += chunk


async def with_timeout(work: Awaitable[T], seconds: float, on_timeout: Callable[[], BaseException]) -> T:
    """Runs ``work``, failing with ``on_timeout()`` when it takes longer than ``seconds``."""
    try:
        return await asyncio.wait_for(work, seconds)
    except asyncio.TimeoutError:
        raise on_timeout() from None


async def settled_within(future: "asyncio.Future[object]", seconds: float) -> bool:
    """Waits for ``future``, but no longer than ``seconds``. True when it settled first."""
    if future.done():
        return True
    done, _ = await asyncio.wait({future}, timeout=max(seconds, 0))
    return bool(done)


def new_future() -> "asyncio.Future":
    """A future nobody may wait for: its exception must not be reported as never retrieved."""
    future = asyncio.get_running_loop().create_future()
    future.add_done_callback(lambda f: f.cancelled() or f.exception())
    return future


def settle(future: "asyncio.Future", value: object = None) -> None:
    if not future.done():
        future.set_result(value)


def fail(future: "asyncio.Future", error: BaseException) -> None:
    if not future.done():
        future.set_exception(error)


def spawn(coroutine: Awaitable[object]) -> "asyncio.Task":
    """Runs a coroutine in the background; its failure is not reported as never retrieved."""
    task = asyncio.ensure_future(coroutine)
    task.add_done_callback(lambda t: t.cancelled() or t.exception())
    _background.add(task)
    task.add_done_callback(_background.discard)
    return task


# Tasks must be referenced until they finish, or the event loop may collect them half way.
_background: set = set()
