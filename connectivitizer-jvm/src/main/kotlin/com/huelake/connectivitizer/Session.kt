package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.ConnectionModes
import com.huelake.connectivitizer.internal.E2eMethods
import com.huelake.connectivitizer.internal.Grant
import com.huelake.connectivitizer.internal.GrantValidation
import com.huelake.connectivitizer.internal.Grants
import com.huelake.connectivitizer.internal.Json
import com.huelake.connectivitizer.internal.MuxSession
import com.huelake.connectivitizer.internal.MuxStream
import com.huelake.connectivitizer.internal.RelayPath
import com.huelake.connectivitizer.internal.Roles
import com.huelake.connectivitizer.internal.StreamReader
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.completedWithin
import com.huelake.connectivitizer.internal.map
import com.huelake.connectivitizer.internal.string
import com.huelake.connectivitizer.internal.withTimeoutOr
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/** The authenticated other end of a session. */
data class PeerInfo(
    /** A certificate fingerprint, or `key:<name>` for a peer that proved to hold that shared key. */
    val fingerprint: String,
    /** With a shared key: the label the platform gave the peer. */
    val name: String,
    val trust: String,
)

/** The routing and security properties of an established session, as this endpoint observed and verified them - not as anybody claimed. */
data class ConnectionInfo(
    val sessionId: String,
    /** `direct`, `e2e-relay` or `compatibility`. */
    val mode: String,
    /** What carries the bytes: `udp-kcp` for direct sessions, `relay-ws` otherwise. */
    val transport: String,
    val relayed: Boolean,
    /** True when only the two endpoints hold the keys protecting the traffic. */
    val endToEndEncrypted: Boolean,
    val platformCanReadPayload: Boolean,
    val e2eMethod: String,
    val trust: String,
    val peerFingerprint: String,
    val peerName: String,
    /** Direct sessions: the network address this endpoint exchanges packets with. */
    val peerAddress: String?,
    /** Why a direct connection was not used, when the session is relayed and the reason is known. */
    val directFailureReason: String?,
)

internal class SessionParameters(
    val platform: Platform,
    val scope: CoroutineScope,
    val path: ByteStream,
    val role: String,
    val mode: String,
    val transport: String,
    val grantToken: String,
    val grant: Grant,
    val peerLabel: String,
    val nowSeconds: () -> Long,
    val sharedKeys: List<SharedKey>,
    val directFailureReason: String? = null,
    val peerAddress: String? = null,
    val localCandidatesHash: String? = null,
    val remoteCandidatesHash: String? = null,
    val relay: RelayPath? = null,
    val validateRenewedGrant: ((String) -> GrantValidation)? = null,
    /** Device side: (host, port) of a service, or the error code that refuses it. */
    val resolveService: ((String, PeerInfo) -> Any)? = null,
)

private const val MAX_CONTROL_MESSAGE = 64 * 1024

private fun framed(message: Map<String, Any?>, lengthBytes: Int): ByteArray {
    val json = Json.write(message).toByteArray(Charsets.UTF_8)
    return (if (lengthBytes == 2) Bytes.u16(json.size) else Bytes.u32(json.size.toLong())) + json
}

private suspend fun readFramed(reader: StreamReader, lengthBytes: Int): Map<String, Any?>? {
    val prefix = reader.readExact(lengthBytes) ?: return null
    val length = if (lengthBytes == 2) Bytes.readU16(prefix, 0).toLong() else Bytes.readU32(prefix, 0)
    if (length == 0L || length > MAX_CONTROL_MESSAGE) throw ConnectivitizerException(ErrorCodes.MUX_PROTOCOL_ERROR, "Malformed tunnel message.")
    val json = reader.readExact(length.toInt()) ?: return null
    return Json.parse(String(json, Charsets.UTF_8)).asMap() ?: emptyMap()
}

/**
 * An authenticated, end-to-end encrypted session between an initiator and a device, carrying any number of
 * streams to the device's services. Use [fetch], [webSocket] or [openStream]; [info] says how the session runs.
 */
class TunnelSession internal constructor(
    private val parameters: SessionParameters,
    private val mux: MuxSession,
    private val control: MuxStream,
    private val controlReader: StreamReader,
    /** The authenticated remote endpoint. */
    val peer: PeerInfo,
) {
    private val scope = parameters.scope

    /** The SDK's own thread: everything that touches the session's state runs there, whoever calls. */
    private val sdk = parameters.scope.coroutineContext[kotlin.coroutines.ContinuationInterceptor]!!
    private var leaseExpiresAt = parameters.grant.iat + parameters.grant.lease
    private var endReason: String? = null
    private val controlWriting = Mutex()
    private var watchdog: Job? = null

    /** Application bytes this endpoint sent to and received from the peer on service streams. */
    var bytesSent = 0L
        internal set
    var bytesReceived = 0L
        internal set

    /** The verified properties of this session. */
    val info = ConnectionInfo(
        sessionId = parameters.grant.jti,
        mode = parameters.mode,
        transport = parameters.transport,
        relayed = parameters.mode != ConnectionModes.DIRECT,
        endToEndEncrypted = parameters.mode != ConnectionModes.COMPATIBILITY,
        platformCanReadPayload = parameters.mode == ConnectionModes.COMPATIBILITY,
        e2eMethod = parameters.grant.e2eMethod,
        trust = peer.trust,
        peerFingerprint = peer.fingerprint,
        peerName = peer.name,
        peerAddress = parameters.peerAddress,
        directFailureReason = parameters.directFailureReason,
    )

    /** Completes with an error code once the session has ended. */
    val completion = CompletableDeferred<String>()

    init {
        val controlDone = scope.launch { controlLoop() }
        scope.launch {
            val reason = mux.completion.await()
            // A peer that ends the session says why on the control stream and closes the mux right after.
            // Both arrive together, so the control loop reads the reason before the mux's own is taken.
            completedWithin(controlDone, 2_000)
            finish(reason)
        }
        if (parameters.role == Roles.DEVICE) {
            scope.launch { acceptLoop() }
            watchdog = scope.launch { checkLease() }
        }
    }

    /** Unix time until which the session is authorised without a renewed grant. */
    val leaseExpires: Long get() = leaseExpiresAt

    val isEnded: Boolean get() = endReason != null

    internal companion object {
        private const val HANDSHAKE_TIMEOUT = 15_000L
        private const val SERVICE_OPEN_TIMEOUT = 15_000L
        private const val LOCAL_CONNECT_TIMEOUT = 5_000L
        private const val LEASE_GRACE_SECONDS = 30

        /**
         * Runs the end-to-end handshake over an established path - the layer the grant names - and then the
         * session bind that ties the encrypted channel to the grant and to the observed route. Never returns a
         * session that is not fully verified.
         */
        suspend fun establish(parameters: SessionParameters): TunnelSession =
            withTimeoutOr(HANDSHAKE_TIMEOUT, {
                parameters.scope.launch { runCatching { parameters.path.close() } }
                ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The end-to-end handshake timed out.")
            }) { establishCore(parameters) }

        private suspend fun establishCore(parameters: SessionParameters): TunnelSession {
            val grant = parameters.grant
            val isInitiator = parameters.role == Roles.INITIATOR
            val grantHash = Grants.hash(parameters.grantToken)
            // The grant says which end-to-end layer the session uses; an endpoint never picks another one.
            if (grant.e2eMethod != E2eMethods.SHARED_KEY) {
                runCatching { parameters.path.close() }
                throw ConnectivitizerException(ErrorCodes.E2E_NO_COMMON_METHOD, "This endpoint cannot take part in a session with the end-to-end layer '${grant.e2eMethod}'.")
            }
            if (parameters.sharedKeys.isEmpty()) {
                runCatching { parameters.path.close() }
                throw ConnectivitizerException(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "This endpoint has no shared key for the session.")
            }
            val bound = Noise.prologue(grant.jti, grantHash)
            val random = parameters.platform::randomBytes
            val channel = if (isInitiator) Noise.connect(parameters.path, parameters.sharedKeys[0], bound, random) else Noise.accept(parameters.path, parameters.sharedKeys, bound, random)
            // The key proves the peer is a holder; which holder, it cannot tell. The name is the platform's label.
            val peer = PeerInfo("key:${channel.keyName}", parameters.peerLabel, "shared-key")

            val mux = MuxSession(channel.stream, isInitiator, parameters.scope)
            mux.start()
            try {
                val control = (if (isInitiator) mux.open() else mux.accept()) ?: throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the session during the handshake.")
                val reader = StreamReader(control)
                val direct = parameters.mode == ConnectionModes.DIRECT
                val ownBind = mapOf("sid" to grant.jti, "grant" to grantHash, "role" to parameters.role, "mode" to parameters.mode, "cands" to if (direct) parameters.localCandidatesHash else null)
                control.write(framed(mapOf("bind" to ownBind), 4))
                val received = try {
                    readFramed(reader, 4)
                } catch (e: Exception) {
                    val code = codeOf(e, ErrorCodes.E2E_HANDSHAKE_FAILED)
                    throw ConnectivitizerException(if (code == ErrorCodes.PATH_CLOSED) ErrorCodes.E2E_HANDSHAKE_FAILED else code, "The peer ended the session during the handshake.", e)
                } ?: throw ConnectivitizerException(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the session during the handshake; it may not trust this endpoint.")
                received.string("error")?.let { throw ConnectivitizerException(it, "The peer refused the session ($it).") }
                val peerBind = received.map("bind")
                val expectedRole = if (isInitiator) Roles.DEVICE else Roles.INITIATOR
                if (peerBind == null || peerBind["sid"] != ownBind["sid"] || peerBind["grant"] != ownBind["grant"] || peerBind["mode"] != ownBind["mode"] || peerBind["role"] != expectedRole ||
                    // The addresses probed came through the control plane; here the authenticated peer confirms them.
                    (direct && (peerBind.string("cands").isNullOrEmpty() || peerBind["cands"] != parameters.remoteCandidatesHash))
                ) {
                    runCatching { control.write(framed(mapOf("error" to ErrorCodes.E2E_SESSION_BIND_MISMATCH), 4)) }
                    throw ConnectivitizerException(ErrorCodes.E2E_SESSION_BIND_MISMATCH, "The two endpoints do not agree on the session they are part of.")
                }
                return TunnelSession(parameters, mux, control, reader, peer)
            } catch (e: Throwable) {
                mux.close()
                throw e
            }
        }
    }

    /** Opens a raw byte stream to one of the device's services. */
    suspend fun openStream(service: String): ByteStream = withContext(sdk) { openStreamOnSdk(service) }

    private suspend fun openStreamOnSdk(service: String): ByteStream {
        if (parameters.role != Roles.INITIATOR) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "Only the initiating endpoint opens service streams.")
        endReason?.let { throw ConnectivitizerException(it, "The session is over ($it).") }
        val stream = mux.open()
        try {
            val reader = StreamReader(stream)
            val answer = withTimeoutOr(SERVICE_OPEN_TIMEOUT, { ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "Opening service '$service' timed out.") }) {
                stream.write(framed(mapOf("svc" to service), 2))
                readFramed(reader, 2)
            }
            if (answer?.get("ok") != true) {
                val code = answer?.string("error") ?: ErrorCodes.SESSION_CLOSED
                throw ConnectivitizerException(code, "The device did not open service '$service' ($code).")
            }
            return object : ByteStream {
                override suspend fun read(): ByteArray? = withContext(sdk) { reader.readSome()?.also { bytesReceived += it.size } }

                override suspend fun write(data: ByteArray) = withContext(sdk) {
                    stream.write(data)
                    bytesSent += data.size
                }

                override suspend fun end() = withContext(sdk) { stream.end() }

                override suspend fun close() = withContext(sdk) { stream.close() }
            }
        } catch (e: Throwable) {
            stream.close()
            throw if (e is ConnectivitizerException || e is kotlinx.coroutines.CancellationException) e else ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "The session ended while opening the service.", e)
        }
    }

    /**
     * An HTTP request to a service of the device. The device's local application receives it as an ordinary
     * request on its own port, with [service] as the host name.
     */
    @JvmOverloads
    suspend fun fetch(service: String, path: String, method: String = "GET", headers: Map<String, String> = emptyMap(), body: ByteArray? = null, timeoutMillis: Long = 30_000): TunnelResponse =
        Http.request({ openStream(service) }, service, path, method, headers, body, timeoutMillis)

    /** A WebSocket to a service of the device. */
    @JvmOverloads
    suspend fun webSocket(service: String, path: String, protocols: List<String> = emptyList(), headers: Map<String, String> = emptyMap()): StreamWebSocket =
        StreamWebSocket.connect(openStream(service), service, path, parameters.platform::randomBytes, scope, headers, protocols)

    /** [fetch] for Java code that does not use coroutines: the whole response, read. */
    @JvmOverloads
    fun fetchBlocking(service: String, path: String, method: String = "GET", headers: Map<String, String> = emptyMap(), body: ByteArray? = null): BlockingResponse = runBlocking {
        val response = fetch(service, path, method, headers, body)
        BlockingResponse(response.status, response.headers, response.bytes())
    }

    fun closeBlocking() = runBlocking { close() }

    /** Extends the session with a freshly issued grant. */
    internal suspend fun renewLease(grantToken: String, grant: Grant) {
        if (grant.jti != parameters.grant.jti) throw ConnectivitizerException(ErrorCodes.GRANT_INVALID, "The grant belongs to another session.")
        writeControl(mapOf("lease" to mapOf("grant" to grantToken)))
        parameters.relay?.renewLease(grantToken)
        leaseExpiresAt = maxOf(leaseExpiresAt, grant.iat + grant.lease)
    }

    /** Ends the session for [reason] (an error code), telling the peer why. */
    @JvmOverloads
    suspend fun end(reason: String = ErrorCodes.SESSION_CLOSED): Unit = withContext(sdk) { endOnSdk(reason) }

    private suspend fun endOnSdk(reason: String) {
        if (endReason != null) return
        finish(reason)
        withTimeoutOrNull(2_000) { runCatching { writeControl(mapOf("error" to reason)) } }
        mux.close()
    }

    /** Closes the session in an orderly way. */
    suspend fun close() = end(ErrorCodes.SESSION_CLOSED)

    private fun finish(reason: String) {
        if (endReason != null) return
        endReason = reason
        watchdog?.cancel()
        completion.complete(reason)
    }

    private suspend fun writeControl(message: Map<String, Any?>) = controlWriting.withLock { control.write(framed(message, 4)) }

    private suspend fun controlLoop() {
        try {
            while (endReason == null) {
                val message = readFramed(controlReader, 4) ?: return
                message.string("error")?.let {
                    finish(it)
                    mux.close()
                    return
                }
                val lease = message.map("lease")
                if (lease != null && parameters.role == Roles.DEVICE) lease.string("grant")?.let { handleLeaseRenewal(it) }
            }
        } catch (e: Exception) {
            // The mux reports why the session ended.
        }
    }

    private fun handleLeaseRenewal(token: String) {
        val renewed = parameters.validateRenewedGrant?.invoke(token)?.grantOrNull ?: return
        val original = parameters.grant
        // A renewal may only prolong this very session for the same two endpoints; it cannot widen anything.
        if (renewed.jti == original.jti && renewed.ws == original.ws && renewed.ini["id"] == original.ini["id"] && renewed.ini["fp"] == original.ini["fp"] &&
            renewed.dev["id"] == original.dev["id"] && renewed.e2eMethod == original.e2eMethod
        ) {
            leaseExpiresAt = maxOf(leaseExpiresAt, renewed.iat + renewed.lease)
        }
    }

    /** Device side: a session whose authorisation ran out is ended, whatever the platform or the peer say. */
    private suspend fun checkLease() {
        while (endReason == null) {
            delay(5_000)
            if (parameters.nowSeconds() >= leaseExpiresAt + LEASE_GRACE_SECONDS) {
                scope.launch { endOnSdk(ErrorCodes.LEASE_EXPIRED) }
                return
            }
        }
    }

    private suspend fun acceptLoop() {
        while (endReason == null) {
            val stream = mux.accept() ?: return
            scope.launch { serveStream(stream) }
        }
    }

    /** Device side: authorise one service stream, connect it to the local application and copy bytes. */
    private suspend fun serveStream(stream: MuxStream) {
        var local: ByteStream? = null
        try {
            val reader = StreamReader(stream)
            val request = withTimeoutOrNull(SERVICE_OPEN_TIMEOUT) { readFramed(reader, 2) }
            val service = request?.string("svc")?.takeIf { it.isNotEmpty() } ?: return
            // Platform authorisation (the grant) and the device's own configuration both have to agree.
            var refusal: String? = null
            var target: Pair<String, Int>? = null
            if (service !in parameters.grant.services) {
                refusal = ErrorCodes.DENIED_BY_GRANT
            } else {
                when (val resolved = parameters.resolveService?.invoke(service, peer) ?: ErrorCodes.SERVICE_NOT_EXPOSED) {
                    is String -> refusal = resolved
                    is Pair<*, *> -> target = resolved.first as String to resolved.second as Int
                }
            }
            if (target != null) {
                local = withTimeoutOrNull(LOCAL_CONNECT_TIMEOUT) { runCatching { parameters.platform.connectTcp(target.first, target.second, scope) }.getOrNull() }
                if (local == null) refusal = ErrorCodes.TARGET_UNREACHABLE
            }
            stream.write(framed(if (refusal == null) mapOf("ok" to true) else mapOf("ok" to false, "error" to refusal), 2))
            val service0 = local
            if (refusal != null || service0 == null) {
                stream.end()
                return
            }
            listOf(
                scope.async {
                    while (true) {
                        val chunk = reader.readSome() ?: break
                        service0.write(chunk)
                        bytesReceived += chunk.size
                    }
                    service0.end()
                },
                scope.async {
                    while (true) {
                        val chunk = service0.read() ?: break
                        stream.write(chunk)
                        bytesSent += chunk.size
                    }
                    stream.end()
                },
            ).awaitAll()
        } catch (e: Exception) {
            // One stream failing (the local application closed, the peer reset it) does not concern the session.
        } finally {
            local?.let { runCatching { it.close() } }
            runCatching { stream.close() }
        }
    }
}
