package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.StreamReader
import com.huelake.connectivitizer.internal.withTimeoutOr
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.io.ByteArrayOutputStream

/** The answer of a service. The body is read once, by one of the body methods. Header names are lower case. */
class TunnelResponse internal constructor(
    val status: Int,
    val reason: String,
    val headers: Map<String, String>,
    private val source: (suspend (suspend (ByteArray) -> Unit) -> Unit)?,
) {
    val ok: Boolean get() = status in 200..299
    private var consumed = false

    /** The body piece by piece, for downloads that should not be held in memory at once. */
    fun chunks(): Flow<ByteArray> {
        if (consumed) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "The body of this response was already read.")
        consumed = true
        return flow { source?.invoke { emit(it) } }
    }

    suspend fun bytes(): ByteArray {
        val out = ByteArrayOutputStream()
        chunks().collect { out.write(it) }
        return out.toByteArray()
    }

    suspend fun text(): String = String(bytes(), Charsets.UTF_8)
}

/** A small HTTP/1.1 client over one stream: to a service of a device, and to the Connectivitizer API. */
internal object Http {
    private const val MAX_HEAD = 64 * 1024
    private val STATUS = Regex("^HTTP/1\\.[01] (\\d{3})(?: (.*))?$")

    suspend fun request(
        openStream: suspend () -> ByteStream,
        host: String,
        path: String,
        method: String = "GET",
        headers: Map<String, String> = emptyMap(),
        body: ByteArray? = null,
        timeoutMillis: Long = 30_000,
    ): TunnelResponse {
        val verb = method.uppercase()
        if (!verb.all { it in 'A'..'Z' } || verb.isEmpty() || path.any { it == '\r' || it == '\n' || it == ' ' } || !path.startsWith("/")) {
            throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "The request needs a method and a path that starts with \"/\".")
        }
        val fields = LinkedHashMap<String, Pair<String, String>>()
        fun put(name: String, value: String) {
            fields[name.lowercase()] = name to value
        }
        put("Host", host)
        put("Accept-Encoding", "identity")
        for ((name, value) in headers) {
            if (name.any { it == '\r' || it == '\n' || it == ':' } || value.any { it == '\r' || it == '\n' }) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "A header contains a character that is not allowed.")
            put(name, value)
        }
        // One request per stream: streams are cheap, and it keeps the framing unambiguous.
        put("Connection", "close")
        if (body != null) put("Content-Length", body.size.toString()) else if (verb != "GET" && verb != "HEAD") put("Content-Length", "0")
        val head = ("$verb $path HTTP/1.1\r\n" + fields.values.joinToString("") { (n, v) -> "$n: $v\r\n" } + "\r\n").toByteArray(Charsets.UTF_8)

        val stream = openStream()
        try {
            val (reader, status, reason, responseHeaders) = withTimeoutOr(timeoutMillis, { ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service did not answer in time.") }) {
                stream.write(if (body == null) head else head + body)
                val reader = StreamReader(stream)
                while (true) {
                    val responseHead = reader.readHead(MAX_HEAD) ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service closed the connection without answering.")
                    val (statusLine, parsed) = parseHead(responseHead)
                    val match = STATUS.matchEntire(statusLine) ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service did not answer with HTTP.")
                    val code = match.groupValues[1].toInt()
                    if (code in 100..199 && code != 101) continue // an interim response such as 100 Continue
                    return@withTimeoutOr Answer(reader, code, match.groupValues[2], parsed)
                }
                @Suppress("UNREACHABLE_CODE")
                throw IllegalStateException()
            }
            if (verb == "HEAD" || status == 204 || status == 304) {
                runCatching { stream.close() }
                return TunnelResponse(status, reason, responseHeaders, null)
            }
            return TunnelResponse(status, reason, responseHeaders) { emit -> readBody(stream, reader, responseHeaders, emit) }
        } catch (e: Throwable) {
            runCatching { stream.close() }
            throw e
        }
    }

    private data class Answer(val reader: StreamReader, val status: Int, val reason: String, val headers: Map<String, String>)

    private suspend fun readBody(stream: ByteStream, reader: StreamReader, headers: Map<String, String>, emit: suspend (ByteArray) -> Unit) {
        try {
            if (headers["transfer-encoding"]?.lowercase()?.contains("chunked") == true) {
                while (true) {
                    val size = readLine(reader).substringBefore(';').trim().toIntOrNull(16) ?: -1
                    if (size < 0) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service sent a malformed chunked body.")
                    if (size == 0) {
                        // Trailers, if any, end with an empty line; nothing in them is used.
                        while (readLine(reader).isNotEmpty()) Unit
                        return
                    }
                    readExactly(reader, size.toLong(), emit)
                    readLine(reader)
                }
            }
            val declared = headers["content-length"]
            if (declared != null) {
                val length = declared.toLongOrNull()?.takeIf { it >= 0 } ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service sent an invalid Content-Length.")
                readExactly(reader, length, emit)
                return
            }
            // Neither: the body runs until the service closes the connection.
            while (true) emit(reader.readSome() ?: return)
        } finally {
            runCatching { stream.close() }
        }
    }

    private suspend fun readExactly(reader: StreamReader, length: Long, emit: suspend (ByteArray) -> Unit) {
        var remaining = length
        while (remaining > 0) {
            val chunk = reader.readSome() ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection ended in the middle of the response body.")
            if (chunk.size > remaining) {
                reader.unread(chunk.copyOfRange(remaining.toInt(), chunk.size))
                emit(chunk.copyOfRange(0, remaining.toInt()))
                return
            }
            remaining -= chunk.size
            emit(chunk)
        }
    }

    private suspend fun readLine(reader: StreamReader): String {
        val collected = ByteArrayOutputStream()
        while (true) {
            val chunk = reader.readSome() ?: throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection ended in the middle of the response body.")
            val newline = chunk.indexOf(10.toByte())
            if (newline >= 0) {
                reader.unread(chunk.copyOfRange(newline + 1, chunk.size))
                collected.write(chunk, 0, newline)
                return String(collected.toByteArray(), Charsets.UTF_8).trimEnd('\r')
            }
            collected.write(chunk)
            if (collected.size() > 8192) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The service sent a malformed chunked body.")
        }
    }
}
