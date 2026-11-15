import { type ByteStream, ChunkQueue } from '../src/core/streams.js';

/** An in-memory, two-way byte stream pair: what one end writes, the other reads. */
export function memoryPair(): [ByteStream, ByteStream] {
  const aToB = new ChunkQueue();
  const bToA = new ChunkQueue();
  const side = (incoming: ChunkQueue, outgoing: ChunkQueue): ByteStream => ({
    read: () => incoming.read(),
    write: async (data) => {
      // A copy, as a real transport would make: the writer may reuse its buffer.
      outgoing.push(data.slice());
    },
    end: async () => outgoing.end(),
    close: async () => {
      outgoing.end();
      incoming.end();
    },
  });
  return [side(bToA, aToB), side(aToB, bToA)];
}
