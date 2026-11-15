package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ByteStream
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeout
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

/**
 * Turns something that delivers chunks whenever it likes (a socket, a WebSocket) into something that is
 * read when the reader is ready. Thread-safe: socket threads push, the SDK's thread reads.
 */
internal class ChunkQueue {
    private val channel = Channel<ByteArray>(Channel.UNLIMITED)
    private val queued = AtomicLong()

    /** Bytes pushed and not read yet. */
    val size: Long get() = queued.get()

    @OptIn(ExperimentalCoroutinesApi::class)
    val isEnded: Boolean get() = channel.isClosedForSend

    fun push(chunk: ByteArray) {
        if (chunk.isEmpty()) return
        if (channel.trySend(chunk).isSuccess) queued.addAndGet(chunk.size.toLong())
    }

    /** No more chunks will come. With [error], readers fail once what was queued has been read. */
    fun end(error: Throwable? = null) {
        channel.close(error)
    }

    suspend fun read(): ByteArray? {
        val result = channel.receiveCatching()
        result.getOrNull()?.let {
            queued.addAndGet(-it.size.toLong())
            return it
        }
        result.exceptionOrNull()?.let { throw it }
        return null
    }
}

/** Reads exact amounts from a [ByteStream], keeping what a chunk had left over for the next read. */
internal class StreamReader(private val stream: ByteStream) {
    private var pending = ByteArray(0)
    private var finished = false

    /** Exactly [length] bytes; null when the stream ended before the first of them; throws when it ended in the middle. */
    suspend fun readExact(length: Int): ByteArray? {
        while (pending.size < length) {
            val chunk = if (finished) null else stream.read()
            if (chunk == null) {
                finished = true
                if (pending.isEmpty()) return null
                throw java.io.EOFException("The stream ended in the middle of a message.")
            }
            pending = if (pending.isEmpty()) chunk else pending + chunk
        }
        val result = pending.copyOfRange(0, length)
        pending = pending.copyOfRange(length, pending.size)
        return result
    }

    /** Whatever is available next: left-over bytes first, then the stream's next chunk. Null at the end. */
    suspend fun readSome(): ByteArray? {
        if (pending.isNotEmpty()) {
            val result = pending
            pending = ByteArray(0)
            return result
        }
        if (finished) return null
        val chunk = stream.read()
        if (chunk == null) finished = true
        return chunk
    }

    fun unread(bytes: ByteArray) {
        pending = bytes + pending
    }

    /** Up to and including `\r\n\r\n` (the head of an HTTP message). Null when the stream ended first. */
    suspend fun readHead(maxLength: Int): ByteArray? {
        var scanned = 0
        while (true) {
            for (i in maxOf(0, scanned - 3) until pending.size - 3) {
                if (pending[i] == 13.toByte() && pending[i + 1] == 10.toByte() && pending[i + 2] == 13.toByte() && pending[i + 3] == 10.toByte()) {
                    val head = pending.copyOfRange(0, i + 4)
                    pending = pending.copyOfRange(i + 4, pending.size)
                    return head
                }
            }
            scanned = pending.size
            if (scanned > maxLength) throw IllegalStateException("The header is too long.")
            val chunk = if (finished) null else stream.read()
            if (chunk == null) {
                finished = true
                return null
            }
            pending = if (pending.isEmpty()) chunk else pending + chunk
        }
    }
}

/** Runs [block], failing with [onTimeout] when it takes longer than [millis]. */
internal suspend fun <T> withTimeoutOr(millis: Long, onTimeout: () -> Throwable, block: suspend CoroutineScope.() -> T): T =
    try {
        withTimeout(millis, block)
    } catch (e: TimeoutCancellationException) {
        throw onTimeout()
    }

/** Waits for [job], but no longer than [millis]. True when it completed first. */
internal suspend fun completedWithin(job: Job, millis: Long): Boolean {
    if (job.isCompleted) return true
    return try {
        withTimeout(maxOf(millis, 1)) { job.join() }
        true
    } catch (e: TimeoutCancellationException) {
        false
    }
}

/** Waits for the first of two deferreds; the result says which. */
internal suspend fun <A, B> firstOf(a: CompletableDeferred<A>, b: CompletableDeferred<B>): Pair<Result<A>?, Result<B>?> = select {
    a.onAwait { Pair(Result.success(it), null) }
    b.onAwait { Pair(null, Result.success(it)) }
}

internal fun CompletableDeferred<*>.isSettled(): Boolean = isCompleted

internal object Bytes {
    fun hex(data: ByteArray): String = data.joinToString("") { "%02x".format(it) }

    fun fromHex(text: String): ByteArray = ByteArray(text.length / 2) { text.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /** Standard or URL-safe base64, padded or not. */
    fun base64Decode(text: String): ByteArray {
        val body = text.trimEnd('=').replace('-', '+').replace('_', '/')
        require(body.all { it.isLetterOrDigit() || it == '+' || it == '/' } && body.length % 4 != 1) { "not base64" }
        return Base64.getDecoder().decode(body + "=".repeat((4 - body.length % 4) % 4))
    }

    fun base64(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    fun base64Url(data: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(data)

    fun sha256(data: ByteArray): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(data)

    fun u16(value: Int): ByteArray = byteArrayOf((value ushr 8).toByte(), value.toByte())

    fun u32(value: Long): ByteArray = byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte())

    fun readU16(data: ByteArray, offset: Int): Int = ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    fun readU32(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xff) shl 24) or ((data[offset + 1].toLong() and 0xff) shl 16) or ((data[offset + 2].toLong() and 0xff) shl 8) or (data[offset + 3].toLong() and 0xff)
}
