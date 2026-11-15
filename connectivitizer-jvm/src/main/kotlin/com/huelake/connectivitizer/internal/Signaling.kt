package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ConnectivitizerException
import com.huelake.connectivitizer.ErrorCodes
import com.huelake.connectivitizer.Platform
import com.huelake.connectivitizer.StreamWebSocket
import com.huelake.connectivitizer.WebSocketMessage
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

// The signaling channel (protocol section 8): one WebSocket to the control plane that says who wants to talk
// to whom and how to reach them. It never carries application data.

internal class Signaling private constructor(private val socket: StreamWebSocket, private val scope: CoroutineScope) {
    /** What the control plane answered to `hello`. */
    var welcome: Map<String, Any?> = emptyMap()
        private set

    /** Called for every message that is not the reply to a request. */
    var onMessage: ((Map<String, Any?>) -> Unit)? = null

    /** Completes with the reason once the connection is over. */
    val closed = CompletableDeferred<String>()
    private val pending = HashMap<String, CompletableDeferred<Map<String, Any?>>>()
    private var nextId = 1
    private var lastReceived = System.currentTimeMillis()
    private val jobs = ArrayList<Job>()

    val isOpen: Boolean get() = !closed.isCompleted

    companion object {
        private const val HELLO_TIMEOUT = 15_000L
        private const val PING_INTERVAL = 25_000L
        private const val SILENCE_LIMIT = 70_000L

        suspend fun connect(platform: Platform, url: String, accessToken: String, hello: Map<String, Any?>, scope: CoroutineScope): Signaling {
            val socket = try {
                platform.connectWebSocket(url, mapOf("Authorization" to "Bearer $accessToken"), scope)
            } catch (e: ConnectivitizerException) {
                // A refusal the adapter could read (the token is not accepted) is passed on as it is.
                if (e.code == ErrorCodes.UNAUTHENTICATED || e.code == ErrorCodes.FORBIDDEN) throw e
                throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel could not be opened.", e)
            } catch (e: Exception) {
                throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel could not be opened.", e)
            }
            val client = Signaling(socket, scope)
            client.jobs.add(scope.launch { client.receiveLoop() })
            try {
                val reply = client.request("hello", hello, HELLO_TIMEOUT)
                if (reply["t"] != "welcome") throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The control plane did not welcome this endpoint.")
                client.welcome = reply.map("d") ?: throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The control plane did not welcome this endpoint.")
            } catch (e: Throwable) {
                client.close()
                throw e
            }
            // Some runtimes hide WebSocket pings from the application, so liveness is checked with messages.
            client.jobs.add(scope.launch { client.keepAlive() })
            return client
        }
    }

    /** Sends a message that expects no reply. */
    fun send(type: String, data: Map<String, Any?>) = write(mapOf("t" to type, "d" to data))

    /** Sends a request and waits for its reply. An `error` reply throws with the platform's code. */
    suspend fun request(type: String, data: Map<String, Any?>, timeoutMillis: Long): Map<String, Any?> {
        val id = (nextId++).toString()
        val reply = CompletableDeferred<Map<String, Any?>>()
        pending[id] = reply
        try {
            write(mapOf("t" to type, "id" to id, "d" to data))
            val envelope = withTimeoutOr(timeoutMillis, { ConnectivitizerException(ErrorCodes.SIGNALING_TIMEOUT, "The control plane did not answer '$type' in time.") }) { reply.await() }
            if (envelope["t"] == "error") {
                val detail = envelope.map("d") ?: emptyMap()
                val code = detail.string("code") ?: ErrorCodes.INVALID_REQUEST
                throw ConnectivitizerException(code, detail.string("message") ?: "The control plane refused '$type' ($code).")
            }
            return envelope
        } finally {
            pending.remove(id)
        }
    }

    suspend fun close() {
        finish(ErrorCodes.SESSION_CLOSED)
        socket.close(1000, "")
    }

    private fun write(envelope: Map<String, Any?>) {
        if (!isOpen || !socket.isOpen) throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "The signaling channel is closed.")
        val text = Json.write(envelope)
        scope.launch { runCatching { socket.send(text) } }
    }

    private suspend fun receiveLoop() {
        try {
            while (true) {
                val message = socket.receive() ?: break
                lastReceived = System.currentTimeMillis()
                val text = when (message) {
                    is WebSocketMessage.Text -> message.text
                    is WebSocketMessage.Binary -> String(message.bytes, Charsets.UTF_8)
                }
                val envelope = runCatching { Json.parse(text).asMap() }.getOrNull() ?: continue
                if (envelope["t"] !is String) continue
                val re = envelope.string("re")
                if (re != null && pending.containsKey(re)) {
                    pending[re]!!.complete(envelope)
                    continue
                }
                if (envelope["t"] == "pong") continue
                // A handler that throws must not take the channel down with it.
                runCatching { onMessage?.invoke(envelope) }
            }
        } finally {
            finish(socket.closeReason.ifEmpty { ErrorCodes.SIGNALING_UNAVAILABLE })
        }
    }

    private suspend fun keepAlive() {
        while (isOpen) {
            delay(PING_INTERVAL)
            if (!isOpen) return
            if (System.currentTimeMillis() - lastReceived > SILENCE_LIMIT) {
                finish(ErrorCodes.SIGNALING_UNAVAILABLE)
                socket.close(1001, "")
                return
            }
            runCatching { write(mapOf("t" to "ping", "id" to "k${nextId++}")) }
        }
    }

    private fun finish(reason: String) {
        if (closed.isCompleted) return
        closed.complete(reason)
        val error = ConnectivitizerException(if (reason == ErrorCodes.SESSION_CLOSED) ErrorCodes.SIGNALING_UNAVAILABLE else reason, "The signaling channel closed ($reason).")
        for (waiter in pending.values) waiter.completeExceptionally(error)
        pending.clear()
        for (job in jobs) job.cancel()
    }
}
