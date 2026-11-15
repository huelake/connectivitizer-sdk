from __future__ import annotations

import json
import pathlib
from typing import Optional, Tuple

from connectivitizer.streams import ByteStream, ChunkQueue

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


def memory_pair() -> Tuple[ByteStream, ByteStream]:
    """An in-memory, two-way byte stream pair: what one end writes, the other reads."""
    a_to_b, b_to_a = ChunkQueue(), ChunkQueue()
    return _Side(b_to_a, a_to_b), _Side(a_to_b, b_to_a)
