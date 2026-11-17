from __future__ import annotations

import asyncio
import json
import pathlib
from typing import Any, Dict, List, Optional, Tuple

from connectivitizer.streams import ByteStream, ChunkQueue, new_future, settle

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "docs" / "protocol" / "vectors"


def vector(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


class _Side(ByteStream):
    def __init__(self, incoming: ChunkQueue, outgoing: ChunkQueue) -> None:
        self._incoming = incoming
        self._outgoing = outgoing

    async def read(self) -> Optional[bytes]:
        return await self._incoming.read()

    async def write(self, data: bytes) -> None:
        # A copy, as a real transport would make: the writer may reuse its buffer.
        self._outgoing.push(bytes(data))

    async def end(self) -> None:
        self._outgoing.end()

    async def close(self) -> None:
        self._outgoing.end()
        self._incoming.end()


class StubSignaling:
    """Stands in for a signaling connection: records what is sent, and answers a request when the test says so."""

    def __init__(self) -> None:
        self.welcome: Dict[str, Any] = {}
        self.closed: asyncio.Future = new_future()
        self.sent: List[Tuple[str, Dict[str, Any]]] = []
        self.requests: List[Tuple[str, Dict[str, Any]]] = []
        self.closes = 0
        self._replies: List[asyncio.Future] = []

    @property
    def is_open(self) -> bool:
        return not self.closed.done()

    def send(self, message_type: str, data: Dict[str, Any]) -> None:
        self.sent.append((message_type, data))

    async def request(self, message_type: str, data: Dict[str, Any], timeout: float) -> Dict[str, Any]:
        self.requests.append((message_type, data))
        reply: asyncio.Future = new_future()
        self._replies.append(reply)
        return await reply

    def answer_request(self, envelope: Dict[str, Any]) -> None:
        """Answers the oldest request that has no answer yet."""
        self._replies.pop(0).set_result(envelope)

    def fail_request(self, error: BaseException) -> None:
        self._replies.pop(0).set_exception(error)

    async def close(self) -> None:
        self.closes += 1
        settle(self.closed, "SESSION_CLOSED")


def memory_pair() -> Tuple[ByteStream, ByteStream]:
    """An in-memory, two-way byte stream pair: what one end writes, the other reads."""
    a_to_b, b_to_a = ChunkQueue(), ChunkQueue()
    return _Side(b_to_a, a_to_b), _Side(a_to_b, b_to_a)
