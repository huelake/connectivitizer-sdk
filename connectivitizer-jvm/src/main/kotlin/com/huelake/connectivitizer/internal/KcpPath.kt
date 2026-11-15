package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ByteStream
import com.huelake.connectivitizer.ConnectivitizerException
import com.huelake.connectivitizer.ErrorCodes
import com.huelake.connectivitizer.UdpSocket
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

/** First byte of every datagram exchanged directly between two peers. */
internal object DatagramType {
    const val PROBE = 0xc1
    const val PROBE_ACK = 0xc2
    const val KCP = 0xc3
    const val KEEP_ALIVE = 0xc4
    const val CLOSE = 0xc5
}

/**
 * A reliable, ordered byte stream to one peer over UDP (protocol section 6.2). It provides delivery only:
 * confidentiality and peer authentication come from the end-to-end layer above it.
 */
internal class KcpPath(private val socket: UdpSocket, private val remoteHost: String, private val remotePort: Int, conversation: Long, private val scope: CoroutineScope) : ByteStream {
    val peerAddress = Addresses.format(UdpAddress(remoteHost, remotePort))

    /** Receives hole-punch probes that still arrive from the peer after the path was selected. */
    var onProbe: ((ByteArray, String, Int) -> Unit)? = null

    private val incoming = ChunkQueue()
    private var lastReceived = System.currentTimeMillis()
    private var lastSent = System.currentTimeMillis()
    private var closeReason: String? = null
    private var writeWaiter: CompletableDeferred<Unit>? = null
    private var flushScheduled = false
    private val kcp = Kcp(conversation) { packet ->
        // One byte in front of every KCP packet says what the datagram is.
        lastSent = System.currentTimeMillis()
        socket.send(byteArrayOf(DatagramType.KCP.toByte()) + packet, remoteHost, remotePort)
    }
    private val timer = scope.launch { tickLoop() }

    init {
        kcp.stream = true
        kcp.setMtu(MAX_DATAGRAM - 1)
        kcp.noDelay(1, UPDATE_INTERVAL.toInt(), 2, 1)
        kcp.wndSize(WINDOW, WINDOW)
        socket.onMessage = ::onDatagram
    }

    private fun onDatagram(data: ByteArray, host: String, port: Int) {
        if (host != remoteHost || port != remotePort || data.isEmpty() || closeReason != null) return
        lastReceived = System.currentTimeMillis()
        when (data[0].toInt() and 0xff) {
            DatagramType.KCP -> {
                kcp.input(data, 1, data.size)
                pump()
                scheduleFlush()
            }
            DatagramType.CLOSE -> scope.launch { closeAfterDrain() }
            DatagramType.PROBE, DatagramType.PROBE_ACK -> onProbe?.invoke(data, host, port)
            // keep-alives only refresh the timestamp
        }
    }

    private suspend fun tickLoop() {
        while (closeReason == null) {
            delay(UPDATE_INTERVAL)
            if (closeReason != null) return
            val now = System.currentTimeMillis()
            if (now - lastReceived > IDLE_TIMEOUT || kcp.state != 0) return closeNow(ErrorCodes.PATH_IDLE_TIMEOUT)
            kcp.update(now)
            pump()
            if (now - lastSent > KEEP_ALIVE) {
                lastSent = now
                socket.send(byteArrayOf(DatagramType.KEEP_ALIVE.toByte()), remoteHost, remotePort)
            }
            if (writeWaiter != null && kcp.waitSnd < SEND_BACKLOG_SEGMENTS) {
                writeWaiter?.complete(Unit)
                writeWaiter = null
            }
        }
    }

    /** Hands received data to the reader, but no more than it keeps up with: KCP then closes its window to the peer. */
    private fun pump() {
        while (incoming.size < RECEIVE_BACKLOG_BYTES) incoming.push(kcp.recv() ?: break)
    }

    private fun scheduleFlush() {
        if (flushScheduled) return
        flushScheduled = true
        scope.launch {
            flushScheduled = false
            if (closeReason == null) {
                kcp.update(System.currentTimeMillis())
                kcp.flush()
            }
        }
    }

    override suspend fun read(): ByteArray? {
        val chunk = incoming.read()
        // Room was made: fetch what KCP held back meanwhile.
        if (chunk != null && closeReason == null) pump()
        return chunk
    }

    override suspend fun write(data: ByteArray) {
        var offset = 0
        while (offset < data.size) {
            closeReason?.let { throw ConnectivitizerException(it, "The direct path is closed ($it).") }
            if (kcp.waitSnd >= SEND_BACKLOG_SEGMENTS) {
                val waiter = CompletableDeferred<Unit>()
                writeWaiter = waiter
                waiter.await()
                continue
            }
            // KCP takes at most 127 segments per call; hand it pieces well below that.
            val end = minOf(data.size, offset + 64 * 1024)
            val taken = kcp.send(data, offset, end)
            if (taken < 0) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The direct path did not accept the data.")
            offset += taken
        }
        scheduleFlush()
    }

    /** The peer announced it is done: let the reader take what already arrived, then end the stream. */
    private suspend fun closeAfterDrain() {
        val deadline = System.currentTimeMillis() + DRAIN_ON_REMOTE_CLOSE
        while (closeReason == null && System.currentTimeMillis() < deadline && (kcp.peekSize() >= 0 || incoming.size > 0)) {
            pump()
            delay(20)
        }
        closeNow(ErrorCodes.PATH_CLOSED)
    }

    private fun closeNow(reason: String) {
        if (closeReason != null) return
        closeReason = reason
        timer.cancel()
        // Only an orderly close reads as the end of the stream; anything else is an error to the reader.
        incoming.end(if (reason == ErrorCodes.PATH_CLOSED) null else ConnectivitizerException(reason, "The direct path was lost ($reason)."))
        writeWaiter?.complete(Unit)
        writeWaiter = null
        socket.close()
    }

    override suspend fun end() = close()

    override suspend fun close() {
        if (closeReason != null) return
        // Give data that was already written a chance to reach the peer, then tell it we are done.
        val deadline = System.currentTimeMillis() + FLUSH_ON_CLOSE
        while (closeReason == null && kcp.waitSnd > 0 && System.currentTimeMillis() < deadline) delay(10)
        if (closeReason == null) repeat(2) { socket.send(byteArrayOf(DatagramType.CLOSE.toByte()), remoteHost, remotePort) }
        closeNow(ErrorCodes.PATH_CLOSED)
    }

    private companion object {
        const val MAX_DATAGRAM = 1200
        const val UPDATE_INTERVAL = 10L
        const val KEEP_ALIVE = 15_000L
        const val IDLE_TIMEOUT = 45_000L
        const val WINDOW = 256
        const val SEND_BACKLOG_SEGMENTS = 512
        const val RECEIVE_BACKLOG_BYTES = 256 * 1024L
        const val FLUSH_ON_CLOSE = 2_000L
        const val DRAIN_ON_REMOTE_CLOSE = 3_000L
    }
}
