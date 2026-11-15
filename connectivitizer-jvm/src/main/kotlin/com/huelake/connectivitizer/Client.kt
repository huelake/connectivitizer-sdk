package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.Capabilities
import com.huelake.connectivitizer.internal.ConnectionModes
import com.huelake.connectivitizer.internal.DirectAttempt
import com.huelake.connectivitizer.internal.DirectFailureReasons
import com.huelake.connectivitizer.internal.E2eMethods
import com.huelake.connectivitizer.internal.RelayPath
import com.huelake.connectivitizer.internal.Roles
import com.huelake.connectivitizer.internal.Signaling
import com.huelake.connectivitizer.internal.asList
import com.huelake.connectivitizer.internal.asMap
import com.huelake.connectivitizer.internal.completedWithin
import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.map
import com.huelake.connectivitizer.internal.peerReflexiveFor
import com.huelake.connectivitizer.internal.string
import com.huelake.connectivitizer.internal.strings
import com.huelake.connectivitizer.internal.withTimeoutOr
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.future.future
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors

/** The SDK's own thread and scope: all protocol state lives there; sockets read on the IO pool. */
internal class SdkRuntime(name: String) {
    private val executor = Executors.newSingleThreadExecutor { Thread(it, name).apply { isDaemon = true } }
    val dispatcher = executor.asCoroutineDispatcher()
    val scope = CoroutineScope(SupervisorJob() + dispatcher + CoroutineExceptionHandler { _, _ -> })

    fun shutdown() {
        scope.cancel()
        executor.shutdown()
    }
}

/**
 * The calling side: an application that connects to services on devices.
 *
 * ```kotlin
 * val client = ConnectivitizerClient.builder(apiUrl).apiKey("czk_…").sharedKey("czs_…").build()
 * val session = client.connect("living-room-lamp", listOf("api"))
 * val response = session.fetch("api", "/state")
 * println("${response.status} ${response.text()} ${session.info.mode}")
 * client.close()
 * ```
 *
 * From Java the same with [connectBlocking] (or [connectAsync]) and [TunnelSession.fetchBlocking].
 */
class ConnectivitizerClient private constructor(private val options: Builder) : AutoCloseable {
    private val runtime = SdkRuntime("connectivitizer-client")
    private val scope = runtime.scope
    private val platform = options.platform ?: Platform()
    private val api = PlatformApi(options.apiUrl, platform, scope)
    private val grants = GrantVerifier(api) { nowSeconds() }
    private val keys = options.keys.toList()
    private val answers = HashMap<String, CompletableDeferred<Pair<Boolean, String?>>>()
    private val candidates = HashMap<String, CompletableDeferred<ByteArray>>()
    private val sessions = HashMap<String, TunnelSession>()
    private var signaling: Signaling? = null
    private val connecting = Mutex()
    private var clockOffset = 0L
    private var closed = false

    init {
        if ((options.apiKey == null) == (options.tokenProvider == null)) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "An application authenticates with an API key or with a token provider.")
        if (keys.isEmpty()) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "An application needs a shared key: without one there is nothing to encrypt end to end with.")
    }

    /** How an application authenticates when it has no API key: a function that returns a fresh token of the control plane. */
    fun interface TokenProvider {
        suspend fun token(): TokenResponse
    }

    class Builder internal constructor(internal val apiUrl: String) {
        internal var apiKey: String? = null
        internal var tokenProvider: TokenProvider? = null
        internal val keys = ArrayList<SharedKey>()
        internal var disableDirect = false
        internal var stunServers: List<String>? = null
        internal var platform: Platform? = null

        /** The application's API key (`czk_…`), created in the web app or handed over by [Link.linkApp]. */
        fun apiKey(value: String) = apply { apiKey = value }

        fun tokenProvider(value: TokenProvider) = apply { tokenProvider = value }

        /** The key the devices hold too (`czs_…`). With several, the one named like the device is used, else the only one, else `default`. */
        @JvmOverloads
        fun sharedKey(text: String, name: String = "default") = apply { keys.add(SharedKey.parse(text, name)) }

        /** Never attempt a peer-to-peer connection; always use the relay. */
        @JvmOverloads
        fun disableDirect(value: Boolean = true) = apply { disableDirect = value }

        /** STUN servers (`host:port`) instead of the ones the platform announces. */
        fun stunServers(value: List<String>) = apply { stunServers = value }

        fun platform(value: Platform) = apply { platform = value }

        fun build() = ConnectivitizerClient(this)
    }

    companion object {
        private const val ANSWER_TIMEOUT = 15_000L
        /** How long a direct path is looked for before the relay is used instead. */
        private const val DIRECT_BUDGET = 3_000L

        @JvmStatic
        fun builder(apiUrl: String) = Builder(apiUrl)
    }

    private fun nowSeconds() = System.currentTimeMillis() / 1000 + clockOffset

    /**
     * Opens a session to [device] (its name or id) for the named services. Throws [ConnectivitizerException];
     * there is no silent fallback to a weaker mode.
     */
    suspend fun connect(device: String, services: List<String>): TunnelSession = withContext(runtime.dispatcher) { connectOnSdk(device, services) }

    fun connectBlocking(device: String, services: List<String>): TunnelSession = runBlocking { connect(device, services) }

    fun connectAsync(device: String, services: List<String>): CompletableFuture<TunnelSession> = scope.future { connectOnSdk(device, services) }

    /** The devices this application may reach: names, whether they are online, and the services it may use. */
    suspend fun listDevices(): List<ReachableDevice> = withContext(runtime.dispatcher) { api.reachableDevices(token().accessToken) }

    fun listDevicesBlocking(): List<ReachableDevice> = runBlocking { listDevices() }

    /** Ends every session and the connection to the platform. */
    suspend fun shutdown() {
        withContext(runtime.dispatcher) {
            if (closed) return@withContext
            closed = true
            for (session in sessions.values.toList()) runCatching { session.close() }
            // Give the end-of-session reports a moment to leave before the channel closes.
            delay(50)
            signaling?.close()
        }
        runtime.shutdown()
    }

    override fun close() = runBlocking { shutdown() }

    private suspend fun connectOnSdk(device: String, services: List<String>): TunnelSession {
        if (closed) throw ConnectivitizerException(ErrorCodes.SESSION_CLOSED, "The client is closed.")
        val sharedKey = selectSharedKey(device) ?: throw ConnectivitizerException(ErrorCodes.E2E_NO_COMMON_METHOD, "No shared key is configured for '$device' (name one after the device, or 'default').")
        val signaling = ensureSignaling()
        val reply = signaling.request("connect.request", mapOf("device" to device, "services" to services, "e2e" to listOf(E2eMethods.SHARED_KEY)), ANSWER_TIMEOUT)
        val granted = reply.map("d") ?: emptyMap()
        val sessionId = granted.string("sid")
        val grantToken = granted.string("grant")
        val peer = granted.map("peer")
        if (reply["t"] != "connect.grant" || sessionId == null || grantToken == null || peer == null) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "The control plane sent an unexpected answer.")

        var attempt: DirectAttempt? = null
        try {
            val (accept, error) = try {
                withTimeoutOr(ANSWER_TIMEOUT, { ConnectivitizerException(ErrorCodes.SIGNALING_TIMEOUT, "The device did not answer the connection request in time.") }) { waiter(answers, sessionId).await() }
            } finally {
                answers.remove(sessionId)
            }
            if (!accept) {
                val code = error ?: ErrorCodes.DEVICE_REJECTED
                throw ConnectivitizerException(code, "The device refused the connection ($code).")
            }
            val validation = grants.validate(grantToken, true)
            val grant = validation.grantOrNull
            if (grant == null || grant.jti != sessionId) throw ConnectivitizerException(validation.errorOrNull ?: ErrorCodes.GRANT_INVALID, "The session grant could not be verified.")
            if (ConnectionModes.COMPATIBILITY in grant.modes) throw ConnectivitizerException(ErrorCodes.NO_PERMITTED_MODE, "The session grant offers a mode this endpoint does not take part in.")
            // The grant names the end-to-end layer; this endpoint must be able to run exactly that one.
            if (grant.e2eMethod != E2eMethods.SHARED_KEY) throw ConnectivitizerException(ErrorCodes.E2E_NO_COMMON_METHOD, "The session was granted with the end-to-end layer '${grant.e2eMethod}', which this application is not set up for.")
            val peerLabel = peer.string("name") ?: device

            fun parameters(path: ByteStream, mode: String, transport: String, relay: RelayPath? = null, directFailure: String? = null, peerAddress: String? = null, local: String? = null, remote: String? = null) =
                SessionParameters(platform, scope, path, Roles.INITIATOR, mode, transport, grantToken, grant, peerLabel, { nowSeconds() }, listOf(sharedKey), directFailure, peerAddress, local, remote, relay)

            val relayPermitted = ConnectionModes.E2E_RELAY in grant.modes && grant.relay != null
            val canDirect = !options.disableDirect && platform.supportsUdp
            val peerSupportsDirect = Capabilities.PATH_UDP_KCP in (peer.strings("caps") ?: emptyList())
            val directPermitted = ConnectionModes.DIRECT in grant.modes && canDirect && peerSupportsDirect
            var directFailure: String? = when {
                directPermitted -> null
                !canDirect || !peerSupportsDirect -> DirectFailureReasons.PEER_NO_DIRECT_SUPPORT
                else -> DirectFailureReasons.POLICY_RELAY_ONLY
            }

            var session: TunnelSession? = null
            if (directPermitted) {
                val stun = options.stunServers ?: signaling.welcome.strings("stunServers") ?: emptyList()
                val current = DirectAttempt(platform, Roles.INITIATOR, sessionId, grantToken, stun, peerReflexiveFor(grant.e2eMethod), scope)
                attempt = current
                scope.launch { runCatching { current.setRemoteCandidates(waiter(candidates, sessionId).await()) } }
                val blob = current.gather()
                signaling.send("path.candidates", mapOf("sid" to sessionId, "blob" to Bytes.base64(blob)))
                val path = current.open(DIRECT_BUDGET)
                if (path == null) {
                    directFailure = current.failureReason()
                    if (relayPermitted) signaling.send("path.fallback", mapOf("sid" to sessionId, "reason" to directFailure))
                } else {
                    // A path exists. From here on a failure is a failure of the session - falling back to the relay
                    // would not make the peer more trustworthy.
                    session = TunnelSession.establish(parameters(path.stream, ConnectionModes.DIRECT, "udp-kcp", peerAddress = path.peerAddress, local = current.localCandidatesHash, remote = current.remoteCandidatesHash))
                }
            }
            if (session == null) {
                // Nothing else is allowed for this session: say so instead of using a path that was not asked for.
                if (!relayPermitted) throw ConnectivitizerException(ErrorCodes.DIRECT_UNAVAILABLE, "A direct connection could not be established ($directFailure) and relaying is not permitted for this session.")
                val relay = RelayPath.connect(platform, grant.relay!!, grantToken, Roles.INITIATOR, scope)
                session = TunnelSession.establish(parameters(relay, ConnectionModes.E2E_RELAY, "relay-ws", relay = relay, directFailure = directFailure))
            }
            sessions[sessionId] = session
            val info = session.info
            report(mapOf("sid" to sessionId, "state" to "established", "mode" to info.mode, "trust" to info.trust, "directFailureReason" to info.directFailureReason, "transport" to info.transport))
            val established = session
            scope.launch { watch(established) }
            scope.launch { renewLeases(established) }
            return session
        } catch (e: Throwable) {
            report(mapOf("sid" to sessionId, "state" to "failed", "error" to codeOf(e)))
            throw e
        } finally {
            candidates.remove(sessionId)?.cancel()
            attempt?.close()
        }
    }

    private fun selectSharedKey(device: String): SharedKey? =
        keys.firstOrNull { it.name.equals(device, ignoreCase = true) } ?: keys.singleOrNull() ?: keys.firstOrNull { it.name.equals("default", ignoreCase = true) }

    private fun <T> waiter(table: HashMap<String, CompletableDeferred<T>>, sessionId: String): CompletableDeferred<T> = table.getOrPut(sessionId) { CompletableDeferred() }

    private suspend fun token(): TokenResponse = options.apiKey?.let { api.credentialToken(it) } ?: options.tokenProvider!!.token()

    private suspend fun ensureSignaling(): Signaling = connecting.withLock {
        signaling?.takeIf { it.isOpen } ?: openSignaling()
    }

    private suspend fun openSignaling(): Signaling {
        val token = token()
        token.serverTime?.let { clockOffset = it - System.currentTimeMillis() / 1000 }
        val caps = arrayListOf(Capabilities.MUX_YAMUX, Capabilities.PATH_RELAY_WS, Capabilities.E2E_SHARED_KEY)
        if (!options.disableDirect && platform.supportsUdp) caps.add(Capabilities.PATH_UDP_KCP)
        val opened = Signaling.connect(platform, api.signalUrl, token.accessToken, mapOf("caps" to caps, "platform" to platform.description), scope)
        opened.welcome.long("serverTime")?.let { clockOffset = it - System.currentTimeMillis() / 1000 }
        opened.onMessage = ::onSignal
        signaling = opened
        return opened
    }

    private fun onSignal(message: Map<String, Any?>) {
        val data = message.map("d") ?: emptyMap()
        val sessionId = data.string("sid")
        when (message["t"]) {
            "connect.answer" -> if (sessionId != null) waiter(answers, sessionId).complete((data["accept"] == true) to data.string("error"))
            "path.candidates" -> if (sessionId != null) data.string("blob")?.let { blob -> runCatching { Bytes.base64Decode(blob) }.getOrNull()?.let { waiter(candidates, sessionId).complete(it) } }
            "revoke" -> {
                val sids = data["sids"].asList()
                val reason = data.string("reason") ?: ErrorCodes.SESSION_REVOKED
                for (session in sessions.values.toList()) if (sids == null || session.info.sessionId in sids) scope.launch { session.end(reason) }
            }
        }
    }

    /** Tells the control plane when and why the session ended, with this endpoint's own traffic count. */
    private suspend fun watch(session: TunnelSession) {
        val reason = session.completion.await()
        sessions.remove(session.info.sessionId)
        report(mapOf("sid" to session.info.sessionId, "state" to "ended", "error" to reason, "bytesSent" to session.bytesSent, "bytesReceived" to session.bytesReceived))
    }

    /** Keeps a running session authorised by fetching a new grant well before the lease ends. */
    private suspend fun renewLeases(session: TunnelSession) {
        while (!session.isEnded && !closed) {
            val remaining = session.leaseExpires - nowSeconds()
            val ended = kotlinx.coroutines.withTimeoutOrNull(maxOf(remaining / 2, 1) * 1000) { session.completion.await() } != null
            if (ended || closed) return
            try {
                val reply = ensureSignaling().request("lease.request", mapOf("sid" to session.info.sessionId), ANSWER_TIMEOUT)
                val token = reply.map("d")?.string("grant")
                if (reply["t"] == "lease.grant" && token != null) {
                    val renewed = grants.validateKnown(token, false).grantOrNull ?: grants.validate(token, false).grantOrNull
                    if (renewed != null) session.renewLease(token, renewed)
                }
            } catch (e: Exception) {
                val code = codeOf(e, "")
                val gone = setOf(ErrorCodes.CREDENTIAL_REVOKED, ErrorCodes.DEVICE_REVOKED, ErrorCodes.FORBIDDEN, ErrorCodes.SERVICE_DISABLED, ErrorCodes.SERVICE_NOT_EXPOSED, ErrorCodes.SESSION_CLOSED, ErrorCodes.NOT_FOUND)
                if (code in gone) {
                    // Authorisation is gone: end the session now instead of letting it run to the end of its lease.
                    session.end(if (code == ErrorCodes.NOT_FOUND || code == ErrorCodes.SESSION_CLOSED) ErrorCodes.SESSION_REVOKED else code)
                    return
                }
                // Control plane unreachable: keep trying until the lease runs out by itself.
            }
        }
    }

    private fun report(update: Map<String, Any?>) {
        // Reporting is best effort; the session itself is unaffected.
        runCatching { signaling?.takeIf { it.isOpen }?.send("session.update", update) }
    }
}

/** A response read completely, as [TunnelSession.fetchBlocking] returns it. */
class BlockingResponse(val status: Int, val headers: Map<String, String>, val body: ByteArray) {
    val ok: Boolean get() = status in 200..299
    fun text(): String = String(body, Charsets.UTF_8)
}
