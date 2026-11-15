package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ByteStream
import com.huelake.connectivitizer.ConnectivitizerException
import com.huelake.connectivitizer.ErrorCodes
import com.huelake.connectivitizer.Platform
import com.huelake.connectivitizer.StreamWebSocket
import com.huelake.connectivitizer.WebSocketMessage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

// The relay path (protocol section 3): each endpoint opens a WebSocket to the relay, the relay pairs the two
// and forwards bytes it has no key for.

internal class RelayPath private constructor(private val socket: StreamWebSocket, private val scope: CoroutineScope) : ByteStream {
    private val incoming = ChunkQueue()
    private var closed = false

    companion object {
        private const val CONNECT_TIMEOUT = 10_000L
        /** The relay waits 15 s for the peer; a little longer here so its own answer arrives first. */
        private const val PAIR_TIMEOUT = 20_000L
        private const val MAX_MESSAGE_BYTES = 32 * 1024

        /** Connects to the relay with the session's grant and waits until the peer is there too. */
        suspend fun connect(platform: Platform, relayUrl: String, grantToken: String, role: String, scope: CoroutineScope): RelayPath {
            val socket = try {
                withTimeoutOr(CONNECT_TIMEOUT, { ConnectivitizerException(ErrorCodes.RELAY_UNREACHABLE, "The relay did not answer in time.") }) {
                    platform.connectWebSocket(relayUrl, mapOf("Authorization" to "Bearer $grantToken", "Cz-Role" to role), scope)
                }
            } catch (e: ConnectivitizerException) {
                // A refusal the adapter could see is passed on; otherwise the relay is simply out of reach.
                if (e.code == ErrorCodes.PATH_CLOSED || e.code == ErrorCodes.SIGNALING_UNAVAILABLE) throw ConnectivitizerException(ErrorCodes.RELAY_UNREACHABLE, "The relay could not be reached.", e)
                throw e
            } catch (e: Exception) {
                throw ConnectivitizerException(ErrorCodes.RELAY_UNREACHABLE, "The relay could not be reached.", e)
            }
            val path = RelayPath(socket, scope)
            val paired = CompletableDeferred<Unit>()
            scope.launch { path.receiveLoop(paired) }
            try {
                withTimeoutOr(PAIR_TIMEOUT, { ConnectivitizerException(ErrorCodes.RELAY_PEER_TIMEOUT, "The peer did not connect to the relay in time.") }) { paired.await() }
            } catch (e: Throwable) {
                path.close()
                throw e
            }
            return path
        }
    }

    private suspend fun receiveLoop(paired: CompletableDeferred<Unit>) {
        var isPaired = false
        while (true) {
            when (val message = socket.receive() ?: break) {
                is WebSocketMessage.Binary -> if (isPaired) incoming.push(message.bytes)
                is WebSocketMessage.Text -> if (!isPaired) {
                    // Text frames come from the relay itself. Only the first one matters to an endpoint.
                    if (runCatching { Json.parse(message.text).asMap()?.get("t") }.getOrNull() == "paired") {
                        isPaired = true
                        paired.complete(Unit)
                    }
                }
            }
        }
        closed = true
        val code = socket.closeCode ?: 1006
        val reason = socket.closeReason
        // The relay names why it ended a session; "the peer left" is the ordinary end of a stream.
        val error = if (code >= 4000 && reason.isNotEmpty() && reason != ErrorCodes.PATH_CLOSED) ConnectivitizerException(reason, "The relay ended the session ($reason).") else null
        if (!isPaired) paired.completeExceptionally(error ?: ConnectivitizerException(ErrorCodes.RELAY_UNREACHABLE, "The relay closed the connection before the peer arrived."))
        incoming.end(error)
    }

    override suspend fun read(): ByteArray? = incoming.read()

    override suspend fun write(data: ByteArray) {
        if (closed) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The relay path is closed.")
        var offset = 0
        while (offset < data.size) {
            val end = minOf(offset + MAX_MESSAGE_BYTES, data.size)
            socket.send(data.copyOfRange(offset, end))
            offset = end
        }
    }

    /** Presents a renewed grant to the relay so that it keeps the session open. */
    fun renewLease(grantToken: String) {
        if (!closed && socket.isOpen) scope.launch { runCatching { socket.send(Json.write(mapOf("t" to "lease", "grant" to grantToken))) } }
    }

    override suspend fun end() = close()

    override suspend fun close() {
        if (closed) return
        closed = true
        incoming.end()
        socket.close(1000, "")
    }
}
