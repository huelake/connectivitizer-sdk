package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ByteStream
import com.huelake.connectivitizer.ConnectivitizerException
import com.huelake.connectivitizer.ErrorCodes
import com.huelake.connectivitizer.codeOf
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.nio.ByteBuffer

// Stream multiplexing with yamux framing (protocol section 5): many independent streams over the one
// encrypted channel of a session, each with its own flow control.

internal object Yamux {
    const val HEADER_SIZE = 12
    const val TYPE_DATA = 0
    const val TYPE_WINDOW_UPDATE = 1
    const val TYPE_PING = 2
    const val TYPE_GO_AWAY = 3
    const val FLAG_SYN = 1
    const val FLAG_ACK = 2
    const val FLAG_FIN = 4
    const val FLAG_RST = 8

    /** Bytes a stream may have in flight in one direction before the receiver has to make room. */
    const val INITIAL_WINDOW = 262_144
    const val MAX_DATA = 16_384
    const val MAX_STREAMS = 256

    fun frame(type: Int, flags: Int, streamId: Long, length: Long, payload: ByteArray? = null): ByteArray {
        val buffer = ByteBuffer.allocate(HEADER_SIZE + (payload?.size ?: 0))
        buffer.put(0).put(type.toByte()).putShort(flags.toShort()).putInt(streamId.toInt()).putInt(length.toInt())
        if (payload != null) buffer.put(payload)
        return buffer.array()
    }
}

internal class MuxSession(private val transport: ByteStream, private val isInitiator: Boolean, private val scope: CoroutineScope) {
    private val streams = HashMap<Long, MuxStream>()
    private val acceptQueue = Channel<MuxStream>(Channel.UNLIMITED)
    private val outgoing = Channel<Pair<ByteArray, CompletableDeferred<Unit>>>(Channel.UNLIMITED)
    private var nextId: Long = if (isInitiator) 1 else 2
    private var lastRemoteId = 0L
    private var endReason: String? = null
    private var closing = false
    private var writer: kotlinx.coroutines.Job? = null

    /** Completes with an error code once the session is over, for whatever reason. */
    val completion = CompletableDeferred<String>()

    val isEnded: Boolean get() = endReason != null

    fun start() {
        scope.launch { readLoop() }
        writer = scope.launch {
            // Frames go out whole and in the order they were handed over.
            for ((bytes, done) in outgoing) {
                try {
                    transport.write(bytes)
                    done.complete(Unit)
                } catch (e: Throwable) {
                    done.completeExceptionally(e)
                }
            }
        }
    }

    fun open(): MuxStream {
        ensureOpen()
        val stream = MuxStream(this, nextId, opener = true)
        nextId += 2
        streams[stream.id] = stream
        // Queued now, so that it goes out before anything written to the stream.
        send(Yamux.frame(Yamux.TYPE_WINDOW_UPDATE, Yamux.FLAG_SYN, stream.id, 0))
        return stream
    }

    /** The next stream the peer opened; null once the session is over. */
    suspend fun accept(): MuxStream? = acceptQueue.receiveCatching().getOrNull()

    /** Ends the session in an orderly way. */
    suspend fun close() {
        if (endReason == null) {
            // Once this side said goodbye, the path going away is the orderly end and not a failure.
            closing = true
            runCatching { send(Yamux.frame(Yamux.TYPE_GO_AWAY, 0, 0, 0)).await() }
        }
        end(ErrorCodes.SESSION_CLOSED)
    }

    /** Queues a frame; the result completes once it was handed to the transport. */
    fun send(bytes: ByteArray): CompletableDeferred<Unit> {
        val done = CompletableDeferred<Unit>()
        if (outgoing.trySend(bytes to done).isFailure) done.completeExceptionally(ConnectivitizerException(endReason ?: ErrorCodes.SESSION_CLOSED, "The session is over."))
        return done
    }

    fun forget(id: Long) {
        streams.remove(id)
    }

    fun end(reason: String) {
        if (endReason != null) return
        endReason = reason
        val error = ConnectivitizerException(reason, "The session ended ($reason).")
        for (stream in streams.values.toList()) stream.sessionEnded(error)
        streams.clear()
        acceptQueue.close()
        completion.complete(reason)
        // What was queued before the end (a GO_AWAY, an error on the control stream) still goes out first.
        outgoing.close()
        scope.launch {
            writer?.let { completedWithin(it, 2_000) }
            runCatching { transport.close() }
        }
    }

    private fun ensureOpen() {
        endReason?.let { throw ConnectivitizerException(it, "The session is over ($it).") }
    }

    private suspend fun readLoop() {
        val reader = StreamReader(transport)
        try {
            while (endReason == null) {
                val header = reader.readExact(Yamux.HEADER_SIZE)
                if (header == null) {
                    end(if (closing) ErrorCodes.SESSION_CLOSED else ErrorCodes.PATH_CLOSED)
                    return
                }
                val type = header[1].toInt() and 0xff
                val flags = Bytes.readU16(header, 2)
                val streamId = Bytes.readU32(header, 4)
                val length = Bytes.readU32(header, 8)
                if (header[0].toInt() != 0) return end(ErrorCodes.MUX_PROTOCOL_ERROR)
                if (type == Yamux.TYPE_PING) {
                    if (flags and Yamux.FLAG_SYN != 0) send(Yamux.frame(Yamux.TYPE_PING, Yamux.FLAG_ACK, 0, length))
                    continue
                }
                if (type == Yamux.TYPE_GO_AWAY) return end(if (length == 0L) ErrorCodes.SESSION_CLOSED else ErrorCodes.MUX_PROTOCOL_ERROR)
                if ((type != Yamux.TYPE_DATA && type != Yamux.TYPE_WINDOW_UPDATE) || streamId == 0L) return end(ErrorCodes.MUX_PROTOCOL_ERROR)

                var stream = streams[streamId]
                if (flags and Yamux.FLAG_SYN != 0) {
                    val remoteParity = if (isInitiator) 0L else 1L
                    if (stream != null || streamId % 2 != remoteParity || streamId <= lastRemoteId) return end(ErrorCodes.MUX_PROTOCOL_ERROR)
                    lastRemoteId = streamId
                    if (streams.size >= Yamux.MAX_STREAMS) {
                        send(Yamux.frame(Yamux.TYPE_WINDOW_UPDATE, Yamux.FLAG_RST, streamId, 0))
                    } else {
                        stream = MuxStream(this, streamId, opener = false)
                        streams[streamId] = stream
                        acceptQueue.trySend(stream)
                    }
                }

                if (type == Yamux.TYPE_DATA) {
                    if (length > Yamux.INITIAL_WINDOW) return end(ErrorCodes.MUX_PROTOCOL_ERROR)
                    val payload = if (length == 0L) ByteArray(0) else reader.readExact(length.toInt()) ?: return end(ErrorCodes.PATH_CLOSED)
                    // Data for a stream that is gone (it was reset here) is read and dropped.
                    if (stream != null && !stream.receive(payload)) return end(ErrorCodes.MUX_PROTOCOL_ERROR)
                } else {
                    stream?.windowGrew(length)
                }
                if (stream != null && flags and Yamux.FLAG_RST != 0) {
                    stream.remoteReset()
                } else if (stream != null && flags and Yamux.FLAG_FIN != 0) {
                    stream.remoteFinished()
                }
            }
        } catch (e: CancellationException) {
            end(ErrorCodes.SESSION_CLOSED)
            throw e
        } catch (e: Throwable) {
            // A path that names its own reason for ending (the relay does) is passed on as such.
            end(if (closing) ErrorCodes.SESSION_CLOSED else codeOf(e, ErrorCodes.PATH_CLOSED))
        }
    }
}

/** One stream of a session. One reader and one writer at a time. */
internal class MuxStream(private val session: MuxSession, val id: Long, opener: Boolean) : ByteStream {
    private val incoming = ChunkQueue()
    private var receiveWindow = Yamux.INITIAL_WINDOW.toLong()
    private var consumed = 0L
    private var sendWindow = Yamux.INITIAL_WINDOW.toLong()
    private var windowWaiter: CompletableDeferred<Unit>? = null
    private var acknowledged = opener
    private var localFinished = false
    private var remoteDone = false
    private var failure: ConnectivitizerException? = null
    private var closed = false

    override suspend fun read(): ByteArray? {
        val chunk = incoming.read()
        if (chunk != null) {
            consumed += chunk.size
            // Make room again once half the window was used up, as the reference implementation does.
            if (consumed >= Yamux.INITIAL_WINDOW / 2 && !remoteDone && !closed) {
                val grant = consumed
                consumed = 0
                receiveWindow += grant
                session.send(Yamux.frame(Yamux.TYPE_WINDOW_UPDATE, firstFrameFlags(), id, grant))
            }
        }
        return chunk
    }

    override suspend fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            failure?.let { throw it }
            if (localFinished || closed) throw ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "The stream is closed for sending.")
            if (sendWindow == 0L) {
                val waiter = CompletableDeferred<Unit>()
                windowWaiter = waiter
                waiter.await()
                continue
            }
            val size = minOf((data.size - offset).toLong(), sendWindow, Yamux.MAX_DATA.toLong()).toInt()
            sendWindow -= size
            session.send(Yamux.frame(Yamux.TYPE_DATA, firstFrameFlags(), id, size.toLong(), data.copyOfRange(offset, offset + size))).await()
            offset += size
        }
    }

    /** Finishes sending; the peer can still send. */
    override suspend fun end() {
        if (localFinished || closed || failure != null) return
        localFinished = true
        runCatching { session.send(Yamux.frame(Yamux.TYPE_WINDOW_UPDATE, Yamux.FLAG_FIN or firstFrameFlags(), id, 0)).await() }
        if (remoteDone) session.forget(id)
    }

    override suspend fun close() {
        if (closed) return
        closed = true
        val abort = failure == null && !(localFinished && remoteDone)
        incoming.end()
        wakeWriter()
        session.forget(id)
        if (abort && !session.isEnded) runCatching { session.send(Yamux.frame(Yamux.TYPE_WINDOW_UPDATE, Yamux.FLAG_RST, id, 0)).await() }
    }

    /** False when the peer sent more than the window allows. */
    fun receive(payload: ByteArray): Boolean {
        if (payload.size > receiveWindow) return false
        receiveWindow -= payload.size
        incoming.push(payload)
        return true
    }

    fun windowGrew(by: Long) {
        sendWindow += by
        wakeWriter()
    }

    fun remoteFinished() {
        remoteDone = true
        incoming.end()
        if (localFinished) session.forget(id)
    }

    fun remoteReset() {
        remoteDone = true
        val error = ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "The peer reset the stream.")
        failure = error
        // What arrived before the reset can still be read; after that reads fail.
        incoming.end(error)
        wakeWriter()
        session.forget(id)
    }

    fun sessionEnded(error: ConnectivitizerException) {
        if (failure == null) failure = error
        incoming.end(if (remoteDone) null else error)
        wakeWriter()
    }

    /** The accepting side marks the first frame it sends for a stream. */
    private fun firstFrameFlags(): Int {
        if (acknowledged) return 0
        acknowledged = true
        return Yamux.FLAG_ACK
    }

    private fun wakeWriter() {
        windowWaiter?.complete(Unit)
        windowWaiter = null
    }
}
