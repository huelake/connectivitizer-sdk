package com.huelake.connectivitizer

/**
 * A two-way stream of bytes: a relay connection, a direct path, the encrypted channel on top of either, or
 * one stream to a service. Chunk boundaries carry no meaning.
 */
interface ByteStream {
    /** The next bytes, or null once the other side has finished sending. Throws when the stream broke. */
    suspend fun read(): ByteArray?

    suspend fun write(data: ByteArray)

    /** Finishes sending while still receiving (a half close). Streams that cannot do that close entirely. */
    suspend fun end() = close()

    /** Closes both directions now. */
    suspend fun close()
}
