"""A reliable, ordered byte stream to one peer over UDP (protocol section 6.2). It provides delivery only:
confidentiality and peer authentication come from the end-to-end layer above it."""

from __future__ import annotations

import asyncio
import time
from typing import Callable, Optional

from ..errors import ConnectivitizerError, ErrorCodes
from ..platform import UdpSocket
from ..streams import ByteStream, ChunkQueue, spawn
from .addresses import UdpAddress, format_address
from .kcp import Kcp


class DatagramType:
    """First byte of every datagram exchanged directly between two peers."""

    PROBE = 0xC1
    PROBE_ACK = 0xC2
    KCP = 0xC3
    KEEP_ALIVE = 0xC4
    CLOSE = 0xC5


MAX_DATAGRAM = 1200
UPDATE_INTERVAL = 0.010
KEEP_ALIVE = 15.0
IDLE_TIMEOUT = 45.0
WINDOW = 256
SEND_BACKLOG_SEGMENTS = 512
"""How much may wait to be sent before the writer is made to wait."""
RECEIVE_BACKLOG_BYTES = 256 * 1024
"""How much may wait to be read before KCP closes its window to the peer."""
FLUSH_ON_CLOSE = 2.0
DRAIN_ON_REMOTE_CLOSE = 3.0


def now_ms() -> int:
    return int(time.monotonic() * 1000) & 0xFFFFFFFF


class KcpPath(ByteStream):
    def __init__(self, socket: UdpSocket, remote_host: str, remote_port: int, conversation: int) -> None:
        self._socket = socket
        self._remote_host = remote_host
        self._remote_port = remote_port
        self.peer_address = format_address(UdpAddress(remote_host, remote_port))
        self.on_probe: Optional[Callable[[bytes, str, int], None]] = None
        """Receives hole-punch probes that still arrive from the peer after the path was selected."""
        self._incoming = ChunkQueue()
        self._last_received = time.monotonic()
        self._last_sent = time.monotonic()
        self._close_reason: Optional[str] = None
        self._write_waiter: Optional[asyncio.Future] = None
        self._flush_scheduled = False

        def output(packet: bytes) -> None:
            # One byte in front of every KCP packet says what the datagram is.
            self._last_sent = time.monotonic()
            self._socket.send(bytes([DatagramType.KCP]) + packet, self._remote_host, self._remote_port)

        self._kcp = Kcp(conversation, output)
        self._kcp.stream = True
        self._kcp.set_mtu(MAX_DATAGRAM - 1)
        self._kcp.no_delay(1, int(UPDATE_INTERVAL * 1000), 2, 1)
        self._kcp.wnd_size(WINDOW, WINDOW)
        socket.on_message = self._on_datagram
        self._timer = spawn(self._tick_loop())

    def _on_datagram(self, data: bytes, host: str, port: int) -> None:
        if host != self._remote_host or port != self._remote_port or not data or self._close_reason is not None:
            return
        self._last_received = time.monotonic()
        kind = data[0]
        if kind == DatagramType.KCP:
            self._kcp.input(data[1:])
            self._pump()
            self._schedule_flush()
        elif kind == DatagramType.CLOSE:
            spawn(self._close_after_drain())
        elif kind in (DatagramType.PROBE, DatagramType.PROBE_ACK):
            if self.on_probe is not None:
                self.on_probe(data, host, port)
        # keep-alives only refresh the timestamp

    async def _tick_loop(self) -> None:
        while self._close_reason is None:
            await asyncio.sleep(UPDATE_INTERVAL)
            if self._close_reason is not None:
                return
            now = time.monotonic()
            if now - self._last_received > IDLE_TIMEOUT or self._kcp.state != 0:
                self._close_now(ErrorCodes.PATH_IDLE_TIMEOUT)
                return
            self._kcp.update(now_ms())
            self._pump()
            if now - self._last_sent > KEEP_ALIVE:
                self._last_sent = now
                self._socket.send(bytes([DatagramType.KEEP_ALIVE]), self._remote_host, self._remote_port)
            if self._write_waiter is not None and self._kcp.wait_snd < SEND_BACKLOG_SEGMENTS:
                waiter, self._write_waiter = self._write_waiter, None
                if not waiter.done():
                    waiter.set_result(None)

    def _pump(self) -> None:
        """Hands received data to the reader, but no more than it keeps up with: KCP then closes its window."""
        while self._incoming.size < RECEIVE_BACKLOG_BYTES:
            chunk = self._kcp.recv()
            if chunk is None:
                break
            self._incoming.push(chunk)

    def _schedule_flush(self) -> None:
        if self._flush_scheduled:
            return
        self._flush_scheduled = True

        def flush() -> None:
            self._flush_scheduled = False
            if self._close_reason is None:
                self._kcp.update(now_ms())
                self._kcp.flush()

        asyncio.get_running_loop().call_soon(flush)

    async def read(self) -> Optional[bytes]:
        chunk = await self._incoming.read()
        if chunk is not None and self._close_reason is None:
            # Room was made: fetch what KCP held back meanwhile.
            self._pump()
        return chunk

    async def write(self, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            if self._close_reason is not None:
                raise ConnectivitizerError(self._close_reason, f"The direct path is closed ({self._close_reason}).")
            if self._kcp.wait_snd >= SEND_BACKLOG_SEGMENTS:
                self._write_waiter = asyncio.get_running_loop().create_future()
                await self._write_waiter
                continue
            # KCP takes at most 127 segments per call; hand it pieces well below that.
            size = min(len(data) - offset, 64 * 1024)
            taken = self._kcp.send(data[offset : offset + size])
            if taken < 0:
                raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The direct path did not accept the data.")
            offset += taken
        self._schedule_flush()

    async def _close_after_drain(self) -> None:
        """The peer announced it is done: let the reader take what already arrived, then end the stream."""
        deadline = time.monotonic() + DRAIN_ON_REMOTE_CLOSE
        while self._close_reason is None and time.monotonic() < deadline and (self._kcp.peek_size() >= 0 or self._incoming.size > 0):
            self._pump()
            await asyncio.sleep(0.02)
        self._close_now(ErrorCodes.PATH_CLOSED)

    def _close_now(self, reason: str) -> None:
        if self._close_reason is not None:
            return
        self._close_reason = reason
        if self._timer is not asyncio.current_task():
            self._timer.cancel()
        # Only an orderly close reads as the end of the stream; anything else is an error to the reader.
        self._incoming.end(None if reason == ErrorCodes.PATH_CLOSED else ConnectivitizerError(reason, f"The direct path was lost ({reason})."))
        if self._write_waiter is not None and not self._write_waiter.done():
            self._write_waiter.set_result(None)
        self._write_waiter = None
        self._socket.close()

    async def end(self) -> None:
        await self.close()

    async def close(self) -> None:
        if self._close_reason is not None:
            return
        # Give data that was already written a chance to reach the peer, then tell it we are done.
        deadline = time.monotonic() + FLUSH_ON_CLOSE
        while self._close_reason is None and self._kcp.wait_snd > 0 and time.monotonic() < deadline:
            await asyncio.sleep(0.01)
        if self._close_reason is None:
            for _ in range(2):
                self._socket.send(bytes([DatagramType.CLOSE]), self._remote_host, self._remote_port)
        self._close_now(ErrorCodes.PATH_CLOSED)
