package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.StreamReader
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.nio.ByteBuffer
import java.security.MessageDigest

/** A WebSocket message: text or binary. */
sealed class WebSocketMessage {
    data class Text(val text: String) : WebSocketMessage()
    class Binary(val bytes: ByteArray) : WebSocketMessage()
}

/** The server answered the WebSocket request with an ordinary HTTP response. */
internal class WebSocketRefusedException(val status: Int, val headers: Map<String, String>, val body: String) :
    Exception("The server refused the WebSocket connection (HTTP $status).")

internal fun parseHead(head: ByteArray): Pair<String, Map<String, String>> {
    val lines = String(head, Charsets.UTF_8).split("\r\n")
    val headers = LinkedHashMap<String, String>()
    for (line in lines.drop(1)) {
        val colon = line.indexOf(':')
        if (colon > 0) {
            val name = line.substring(0, colon).trim().lowercase()
            val value = line.substring(colon + 1).trim()
            headers[name] = headers[name]?.let { "$it, $value" } ?: value
        }
    }
    return (lines.firstOrNull() ?: "") to headers
}

/**
 * A WebSocket (RFC 6455) over any byte stream: to a service of a device through a session, and to the
 * platform. [receive] returns the next message, or null once the connection is closed; [closeCode] and
 * [closeReason] then say why.
 */
class StreamWebSocket internal constructor(
    private val stream: ByteStream,
    private val reader: StreamReader,
    private val random: (Int) -> ByteArray,
    private val maxMessageBytes: Int,
    scope: CoroutineScope,
) {
    private val messages = Channel<WebSocketMessage>(Channel.UNLIMITED)
    private val writing = Mutex()
    private var closeSent = false
    private val closed = CompletableDeferred<Unit>()

    /** The subprotocol the server selected, or an empty string. */
    var protocol: String = ""
        internal set
    var closeCode: Int? = null
        private set
    var closeReason: String = ""
        private set

    init {
        scope.launch { readLoop() }
    }

    val isOpen: Boolean get() = closeCode == null && !closeSent

    /** The next message, or null once the connection is closed. */
    suspend fun receive(): WebSocketMessage? = messages.receiveCatching().getOrNull()

    suspend fun send(text: String) = sendChecked(OP_TEXT, text.toByteArray(Charsets.UTF_8))

    suspend fun send(bytes: ByteArray) = sendChecked(OP_BINARY, bytes)

    private suspend fun sendChecked(opcode: Int, payload: ByteArray) {
        if (!isOpen) throw ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "The WebSocket is closed.")
        sendFrame(opcode, payload)
    }

    suspend fun close(code: Int = 1000, reason: String = "") {
        if (closeCode != null || closeSent) return
        closeSent = true
        val text = reason.toByteArray(Charsets.UTF_8).let { it.copyOf(minOf(it.size, 123)) }
        runCatching { sendFrame(OP_CLOSE, Bytes.u16(code) + text) }
        // A server that never answers the close must not keep the stream open forever.
        withTimeoutOrNull(2_000) { closed.await() }
        finish(code, reason)
    }

    private suspend fun sendFrame(opcode: Int, payload: ByteArray) {
        val mask = random(4)
        val length = payload.size
        val header = when {
            length < 126 -> byteArrayOf((0x80 or opcode).toByte(), (0x80 or length).toByte())
            length < 65536 -> byteArrayOf((0x80 or opcode).toByte(), (0x80 or 126).toByte()) + Bytes.u16(length)
            else -> byteArrayOf((0x80 or opcode).toByte(), (0x80 or 127).toByte()) + ByteBuffer.allocate(8).putLong(length.toLong()).array()
        }
        val masked = ByteArray(length) { (payload[it].toInt() xor mask[it and 3].toInt()).toByte() }
        writing.withLock { stream.write(header + mask + masked) }
    }

    private suspend fun readLoop() {
        var fragments = ArrayList<ByteArray>()
        var fragmentOpcode = 0
        var fragmentBytes = 0L
        try {
            while (closeCode == null) {
                val header = reader.readExact(2) ?: return finish(1006, "")
                val final = header[0].toInt() and 0x80 != 0
                val opcode = header[0].toInt() and 0x0f
                val masked = header[1].toInt() and 0x80 != 0
                var length = (header[1].toInt() and 0x7f).toLong()
                if (length == 126L) {
                    length = Bytes.readU16(reader.readExact(2) ?: return finish(1006, ""), 0).toLong()
                } else if (length == 127L) {
                    length = ByteBuffer.wrap(reader.readExact(8) ?: return finish(1006, "")).long
                }
                if (length < 0 || length > maxMessageBytes) return fail(1009, "message too big")
                val mask = if (masked) reader.readExact(4) ?: return finish(1006, "") else null
                var payload = if (length == 0L) ByteArray(0) else reader.readExact(length.toInt()) ?: return finish(1006, "")
                if (mask != null) payload = ByteArray(payload.size) { (payload[it].toInt() xor mask[it and 3].toInt()).toByte() }
                when (opcode) {
                    OP_PING -> runCatching { sendFrame(OP_PONG, payload) }
                    OP_PONG -> Unit // unsolicited pongs are a keep-alive some servers send
                    OP_CLOSE -> {
                        val code = if (payload.size >= 2) Bytes.readU16(payload, 0) else 1005
                        val reason = if (payload.size > 2) String(payload, 2, payload.size - 2, Charsets.UTF_8) else ""
                        if (!closeSent) {
                            closeSent = true
                            runCatching { sendFrame(OP_CLOSE, payload.copyOf(minOf(payload.size, 2))) }
                        }
                        return finish(code, reason)
                    }
                    OP_TEXT, OP_BINARY, OP_CONTINUATION -> {
                        if (opcode != OP_CONTINUATION) {
                            fragmentOpcode = opcode
                            fragments = ArrayList()
                            fragmentBytes = 0
                        }
                        fragments.add(payload)
                        fragmentBytes += payload.size
                        if (fragmentBytes > maxMessageBytes) return fail(1009, "message too big")
                        if (final) {
                            val whole = if (fragments.size == 1) fragments[0] else fragments.fold(ByteArray(0)) { all, part -> all + part }
                            fragments = ArrayList()
                            messages.trySend(if (fragmentOpcode == OP_TEXT) WebSocketMessage.Text(String(whole, Charsets.UTF_8)) else WebSocketMessage.Binary(whole))
                        }
                    }
                    else -> return fail(1002, "unknown frame")
                }
            }
        } catch (e: CancellationException) {
            finish(1006, "")
            throw e
        } catch (e: Throwable) {
            // The reason a path gives for ending (the relay names one) travels as the close reason.
            finish(1006, (e as? ConnectivitizerException)?.code ?: "")
        }
    }

    private suspend fun fail(code: Int, reason: String) {
        close(code, reason)
        finish(code, reason)
    }

    private suspend fun finish(code: Int, reason: String) {
        if (closeCode != null) return
        closeCode = code
        closeReason = reason
        messages.close()
        closed.complete(Unit)
        runCatching { stream.close() }
    }

    companion object {
        private const val GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        private const val OP_CONTINUATION = 0
        private const val OP_TEXT = 1
        private const val OP_BINARY = 2
        private const val OP_CLOSE = 8
        private const val OP_PING = 9
        private const val OP_PONG = 10
        private const val MAX_HEAD = 16 * 1024

        /** Performs the opening handshake over [stream] and returns the open connection. */
        internal suspend fun connect(
            stream: ByteStream,
            host: String,
            path: String,
            random: (Int) -> ByteArray,
            scope: CoroutineScope,
            headers: Map<String, String> = emptyMap(),
            protocols: List<String> = emptyList(),
            maxMessageBytes: Int = 16 * 1024 * 1024,
        ): StreamWebSocket {
            val key = Bytes.base64(random(16))
            val lines = mutableListOf("GET $path HTTP/1.1", "Host: $host", "Upgrade: websocket", "Connection: Upgrade", "Sec-WebSocket-Key: $key", "Sec-WebSocket-Version: 13")
            if (protocols.isNotEmpty()) lines.add("Sec-WebSocket-Protocol: ${protocols.joinToString(", ")}")
            for ((name, value) in headers) {
                if ((name + value).any { it == '\r' || it == '\n' }) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "A header contains a line break.")
                lines.add("$name: $value")
            }
            stream.write((lines.joinToString("\r\n") + "\r\n\r\n").toByteArray(Charsets.UTF_8))
            val reader = StreamReader(stream)
            val head = reader.readHead(MAX_HEAD) ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection closed before the WebSocket was established.")
            val (statusLine, responseHeaders) = parseHead(head)
            val status = statusLine.split(' ').getOrNull(1)?.toIntOrNull() ?: 0
            if (status != 101) {
                val length = responseHeaders["content-length"]?.toIntOrNull() ?: 0
                val body = if (length in 1..4096) runCatching { reader.readExact(length)?.let { String(it, Charsets.UTF_8) } }.getOrNull() ?: "" else ""
                runCatching { stream.close() }
                throw WebSocketRefusedException(status, responseHeaders, body)
            }
            val expected = Bytes.base64(MessageDigest.getInstance("SHA-1").digest((key + GUID).toByteArray(Charsets.US_ASCII)))
            if (responseHeaders["sec-websocket-accept"] != expected || responseHeaders["upgrade"]?.lowercase() != "websocket") {
                runCatching { stream.close() }
                throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The server did not complete the WebSocket handshake correctly.")
            }
            return StreamWebSocket(stream, reader, random, maxMessageBytes, scope).also { it.protocol = responseHeaders["sec-websocket-protocol"] ?: "" }
        }
    }
}
