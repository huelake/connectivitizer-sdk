package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Bytes
import com.huelake.connectivitizer.internal.Capabilities
import com.huelake.connectivitizer.internal.ConnectionModes
import com.huelake.connectivitizer.internal.DirectAttempt
import com.huelake.connectivitizer.internal.DirectPath
import com.huelake.connectivitizer.internal.E2eMethods
import com.huelake.connectivitizer.internal.Grant
import com.huelake.connectivitizer.internal.RelayPath
import com.huelake.connectivitizer.internal.Roles
import com.huelake.connectivitizer.internal.Signaling
import com.huelake.connectivitizer.internal.asList
import com.huelake.connectivitizer.internal.long
import com.huelake.connectivitizer.internal.map
import com.huelake.connectivitizer.internal.peerReflexiveFor
import com.huelake.connectivitizer.internal.string
import com.huelake.connectivitizer.internal.strings
import com.huelake.connectivitizer.internal.withTimeoutOr
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.util.function.Consumer
import kotlin.random.Random

/**
 * The device side: keeps an outbound connection to the platform, and when an authorised application that
 * holds the shared key asks, opens a session and forwards its streams to local services. Nothing is
 * reachable that the device did not declare itself, and no port listens.
 *
 * ```kotlin
 * val agent = ConnectivitizerAgent.builder(apiUrl).deviceKey("czd_…").name("nas").sharedKey("czs_…")
 *     .service("api", "127.0.0.1:8080").log { println(it) }.build()
 * agent.run()   // until agent.stop(); from Java: runBlocking() and stopBlocking()
 * ```
 */
class ConnectivitizerAgent private constructor(private val options: Builder) {
    private val runtime = SdkRuntime("connectivitizer-agent")
    private val scope = runtime.scope
    private val platform = options.platform ?: Platform()
    private val api = PlatformApi(options.apiUrl, platform, scope)
    private val grants = GrantVerifier(api) { nowSeconds() }
    private val keys = options.keys.toList()
    private val services = options.services.mapValues { (_, value) -> parseTarget(value.first) to value.second }
    private val sessions = HashMap<String, TunnelSession>()
    private val candidates = HashMap<String, CompletableDeferred<ByteArray>>()
    private val fallbacks = HashMap<String, CompletableDeferred<String>>()
    private var signaling: Signaling? = null
    private var deviceId: String? = null
    private var clockOffset = 0L
    private var stopped = false
    private val stopSignal = CompletableDeferred<Unit>()
    private var connected = CompletableDeferred<Unit>()

    init {
        if (keys.isEmpty()) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "A device needs a shared key: without one nobody can reach it end to end.")
        if (options.deviceKey == null || options.name == null) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "A device logs in with a device key and its name.")
    }

    class Builder internal constructor(internal val apiUrl: String) {
        internal var deviceKey: String? = null
        internal var name: String? = null
        internal val keys = ArrayList<SharedKey>()
        internal val services = LinkedHashMap<String, Pair<String, String>>()
        internal var disableDirect = false
        internal var stunServers: List<String>? = null
        internal var agentVersion: String? = null
        internal var log: Consumer<String>? = null
        internal var platform: Platform? = null

        /** A device key of the workspace (`czd_…`). The first login under [name] creates the device. */
        fun deviceKey(value: String) = apply { deviceKey = value }

        /** The device's name. It is how the device is addressed, so it does not change. */
        fun name(value: String) = apply { name = value }

        /** A key the applications hold too (`czs_…`). Call again to add more, for example one per application. */
        @JvmOverloads
        fun sharedKey(text: String, name: String = "default") = apply { keys.add(SharedKey.parse(text, name)) }

        /** Makes a local TCP service (`host:port`) reachable under [name]. Nothing else is reachable. */
        @JvmOverloads
        fun service(name: String, target: String, protocol: String = "tcp") = apply { services[name] = target to protocol }

        @JvmOverloads
        fun disableDirect(value: Boolean = true) = apply { disableDirect = value }

        fun stunServers(value: List<String>) = apply { stunServers = value }

        fun agentVersion(value: String) = apply { agentVersion = value }

        /** Receives one line per noteworthy event (connected, session accepted, refused, ...). */
        fun log(value: Consumer<String>) = apply { log = value }

        fun platform(value: Platform) = apply { platform = value }

        fun build() = ConnectivitizerAgent(this)
    }

    companion object {
        private const val PATH_TIMEOUT = 12_000L

        @JvmStatic
        fun builder(apiUrl: String) = Builder(apiUrl)

        private fun parseTarget(target: String): Pair<String, Int> {
            val colon = target.lastIndexOf(':')
            val port = target.substring(colon + 1).toIntOrNull() ?: 0
            if (colon <= 0 || port !in 1..65535) throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "'$target' is not a valid target; expected host:port.")
            return target.substring(0, colon).trim('[', ']') to port
        }
    }

    /** True while the device is connected to the platform and can be reached. */
    val isConnected: Boolean get() = signaling?.isOpen == true

    /** The sessions currently open to this device. */
    val openSessions: List<ConnectionInfo> get() = sessions.values.map { it.info }

    suspend fun waitUntilConnected() = connected.await()

    /**
     * Runs until [stop] is called, reconnecting with back-off whenever the connection to the platform is lost.
     * Throws when the platform no longer accepts this device (its key was revoked): retrying cannot help then.
     */
    suspend fun run() = withContext(runtime.dispatcher) { runOnSdk() }

    fun runBlocking() = runBlocking { run() }

    /** Ends all sessions and disconnects from the platform. */
    suspend fun stop() {
        withContext(runtime.dispatcher) {
            if (stopped) return@withContext
            stopped = true
            for (session in sessions.values.toList()) runCatching { session.close() }
            delay(50)
            signaling?.close()
            stopSignal.complete(Unit)
        }
    }

    fun stopBlocking() = runBlocking { stop() }

    private fun nowSeconds() = System.currentTimeMillis() / 1000 + clockOffset

    private fun log(message: String) {
        options.log?.accept(message)
    }

    private suspend fun runOnSdk() {
        var backoff = 1_000L
        try {
            while (!stopped) {
                try {
                    val token = api.deviceKeyToken(options.deviceKey!!, options.name!!, platform.description, options.agentVersion)
                    deviceId = token.endpointId
                    token.serverTime?.let { clockOffset = it - System.currentTimeMillis() / 1000 }
                    val caps = arrayListOf(Capabilities.MUX_YAMUX, Capabilities.PATH_RELAY_WS, Capabilities.E2E_SHARED_KEY)
                    if (!options.disableDirect && platform.supportsUdp) caps.add(Capabilities.PATH_UDP_KCP)
                    val hello = mapOf(
                        "caps" to caps,
                        "agentVersion" to options.agentVersion,
                        "platform" to platform.description,
                        "services" to services.map { (name, value) -> mapOf("name" to name, "protocol" to value.second, "compat" to false) },
                    )
                    val opened = Signaling.connect(platform, api.signalUrl, token.accessToken, hello, scope)
                    opened.welcome.long("serverTime")?.let { clockOffset = it - System.currentTimeMillis() / 1000 }
                    opened.onMessage = { onSignal(opened, it) }
                    signaling = opened
                    backoff = 1_000
                    connected.complete(Unit)
                    log("connected to ${api.baseUrl} as device ${token.slug ?: options.name}; services: ${services.keys.joinToString(", ").ifEmpty { "(none)" }}")

                    val reason = select<String> {
                        opened.closed.onAwait { it }
                        stopSignal.onAwait { ErrorCodes.SESSION_CLOSED }
                    }
                    connected = CompletableDeferred()
                    if (stopped) break
                    log("disconnected from the platform ($reason)")
                    if (reason == ErrorCodes.DEVICE_REVOKED || reason == ErrorCodes.CREDENTIAL_REVOKED) {
                        for (session in sessions.values.toList()) runCatching { session.end(reason) }
                        throw ConnectivitizerException(reason, if (reason == ErrorCodes.DEVICE_REVOKED) "This device was revoked." else "The device key this device logs in with was revoked.")
                    }
                } catch (e: ConnectivitizerException) {
                    val final = setOf(ErrorCodes.DEVICE_REVOKED, ErrorCodes.CREDENTIAL_REVOKED, ErrorCodes.IDENTITY_NOT_REGISTERED, ErrorCodes.UNAUTHENTICATED, ErrorCodes.INVALID_REQUEST, ErrorCodes.CONFLICT)
                    if (e.code in final) {
                        log("the platform does not accept this device (${e.code})")
                        throw e
                    }
                    log("platform unavailable (${e.code}); retrying in ${backoff / 1000} s")
                }
                if (stopped) break
                // Waits a random time between half and the whole back-off. A fleet refused together (an outage, a restart, the platform
                // shedding load) must not come back together: with only a little jitter it came back in waves 30 s apart that the
                // platform could not take, with nothing to do in between.
                withTimeoutOrNull(backoff / 2 + Random.nextLong(backoff / 2 + 1)) { stopSignal.await() }
                backoff = minOf(backoff * 2, 30_000)
            }
        } finally {
            if (stopped) runtime.shutdown()
        }
    }

    private fun <T> waiter(table: HashMap<String, CompletableDeferred<T>>, sessionId: String): CompletableDeferred<T> = table.getOrPut(sessionId) { CompletableDeferred() }

    private fun onSignal(channel: Signaling, message: Map<String, Any?>) {
        val data = message.map("d") ?: emptyMap()
        val sessionId = data.string("sid")
        when (message["t"]) {
            "connect.offer" -> if (sessionId != null && data.string("grant") != null && data.map("peer") != null) scope.launch { handleOffer(channel, data) }
            "path.candidates" -> if (sessionId != null) data.string("blob")?.let { blob -> runCatching { Bytes.base64Decode(blob) }.getOrNull()?.let { waiter(candidates, sessionId).complete(it) } }
            "path.fallback" -> if (sessionId != null) waiter(fallbacks, sessionId).complete(data.string("reason") ?: "unknown")
            "revoke" -> {
                val sids = data["sids"].asList()
                val reason = data.string("reason") ?: ErrorCodes.SESSION_REVOKED
                for (session in sessions.values.toList()) {
                    if (sids == null || session.info.sessionId in sids) {
                        log("session ${session.info.sessionId} revoked by the platform ($reason)")
                        scope.launch { session.end(reason) }
                    }
                }
            }
        }
    }

    /**
     * The platform says an application wants to connect. The device checks the grant's signature and that the
     * grant is really about this device. Whether the application is trusted is not the platform's to say: the
     * shared-key handshake proves it.
     */
    private suspend fun handleOffer(channel: Signaling, offer: Map<String, Any?>) {
        val validation = grants.validate(offer.string("grant")!!, true)
        val grant = validation.grantOrNull
        val peer = offer.map("peer")!!
        val peerName = peer.string("name") ?: peer.string("id")
        val refusal = if (grant == null) validation.errorOrNull ?: ErrorCodes.GRANT_INVALID else checkOffer(grant, offer, peer)
        try {
            channel.send("connect.answer", mapOf("sid" to offer.string("sid"), "accept" to (refusal == null), "error" to refusal))
        } catch (e: ConnectivitizerException) {
            return
        }
        if (refusal != null || grant == null) {
            log("refused connection from $peerName ($refusal)")
            return
        }
        val sessionId = grant.jti
        try {
            val session = openPathAndEstablish(channel, offer, peer, grant)
            sessions[sessionId] = session
            val info = session.info
            log("session $sessionId established with ${session.peer.name} (${info.mode}, ${info.trust}${info.peerAddress?.let { ", peer at $it" } ?: ""})")
            report(mapOf("sid" to sessionId, "state" to "established", "mode" to info.mode, "trust" to info.trust, "transport" to info.transport))
            scope.launch { watch(session) }
        } catch (e: Exception) {
            val code = codeOf(e)
            log("session $sessionId with $peerName failed ($code)")
            report(mapOf("sid" to sessionId, "state" to "failed", "error" to code))
        } finally {
            candidates.remove(sessionId)?.cancel()
            fallbacks.remove(sessionId)?.cancel()
        }
    }

    /** Null when the offer can be accepted, otherwise the refusal code. */
    private fun checkOffer(grant: Grant, offer: Map<String, Any?>, peer: Map<String, Any?>): String? = when {
        grant.jti != offer.string("sid") || grant.dev["id"] != deviceId -> ErrorCodes.GRANT_INVALID
        // The gateway can read what it forwards; a device run by this SDK never opts in to that.
        ConnectionModes.COMPATIBILITY in grant.modes -> ErrorCodes.COMPATIBILITY_NOT_ENABLED
        grant.e2eMethod != E2eMethods.SHARED_KEY -> ErrorCodes.E2E_NO_COMMON_METHOD
        !(ConnectionModes.E2E_RELAY in grant.modes && grant.relay != null) && !directPossible(grant, peer) -> ErrorCodes.NO_PERMITTED_MODE
        else -> null
    }

    private fun directPossible(grant: Grant, peer: Map<String, Any?>) =
        ConnectionModes.DIRECT in grant.modes && !options.disableDirect && platform.supportsUdp && Capabilities.PATH_UDP_KCP in (peer.strings("caps") ?: emptyList())

    /**
     * Follows the initiator's lead: a direct path if the initiator finds one, the relay if it says so. The device
     * never decides on its own to use a path the initiator did not choose.
     */
    private suspend fun openPathAndEstablish(channel: Signaling, offer: Map<String, Any?>, peer: Map<String, Any?>, grant: Grant): TunnelSession {
        val sessionId = grant.jti
        val grantToken = offer.string("grant")!!
        val peerLabel = peer.string("name") ?: peer.string("id") ?: ""
        fun parameters(path: ByteStream, mode: String, transport: String, relay: RelayPath? = null, peerAddress: String? = null, local: String? = null, remote: String? = null) =
            SessionParameters(
                platform, scope, path, Roles.DEVICE, mode, transport, grantToken, grant, peerLabel, { nowSeconds() }, keys,
                null, peerAddress, local, remote, relay, { grants.validateKnown(it, false) }, ::resolveService,
            )

        if (directPossible(grant, peer)) {
            val stun = options.stunServers ?: channel.welcome.strings("stunServers") ?: emptyList()
            val attempt = DirectAttempt(platform, Roles.DEVICE, sessionId, grantToken, stun, peerReflexiveFor(grant.e2eMethod), scope)
            try {
                scope.launch { runCatching { attempt.setRemoteCandidates(waiter(candidates, sessionId).await()) } }
                val fallback = waiter(fallbacks, sessionId)
                val expired = { ConnectivitizerException(ErrorCodes.SIGNALING_TIMEOUT, "The initiator did not complete the path negotiation in time.") }
                val blob = withTimeoutOr(PATH_TIMEOUT, expired) { attempt.gather() }
                channel.send("path.candidates", mapOf("sid" to sessionId, "blob" to Bytes.base64(blob)))
                val selection = scope.async { attempt.waitForSelection() }
                val first: Any = withTimeoutOr(PATH_TIMEOUT, expired) {
                    select {
                        selection.onAwait { it }
                        fallback.onAwait { it }
                    }
                }
                if (first is DirectPath) {
                    val direct = scope.async {
                        TunnelSession.establish(parameters(first.stream, ConnectionModes.DIRECT, "udp-kcp", peerAddress = first.peerAddress, local = attempt.localCandidatesHash, remote = attempt.remoteCandidatesHash))
                    }
                    // The initiator may have given up on the direct path while this side thought it was selected.
                    val outcome: Any = select {
                        direct.onAwait { it }
                        fallback.onAwait { it }
                    }
                    if (outcome is TunnelSession) return outcome
                    direct.cancel()
                    runCatching { first.stream.close() }
                    log("session $sessionId: no direct path ($outcome), using the relay")
                } else {
                    selection.cancel()
                    log("session $sessionId: no direct path ($first), using the relay")
                }
            } finally {
                attempt.close()
            }
        }
        if (grant.relay == null || ConnectionModes.E2E_RELAY !in grant.modes) throw ConnectivitizerException(ErrorCodes.DIRECT_UNAVAILABLE, "No direct path was found and relaying is not permitted for this session.")
        val relay = RelayPath.connect(platform, grant.relay!!, grantToken, Roles.DEVICE, scope)
        return TunnelSession.establish(parameters(relay, ConnectionModes.E2E_RELAY, "relay-ws", relay = relay))
    }

    /** The device's own, local answer to "may this peer use this service, and where does it go?". */
    private fun resolveService(name: String, peer: PeerInfo): Any {
        val (target, _) = services[name] ?: return ErrorCodes.SERVICE_NOT_EXPOSED
        return target
    }

    private suspend fun watch(session: TunnelSession) {
        val reason = session.completion.await()
        sessions.remove(session.info.sessionId)
        log("session ${session.info.sessionId} ended ($reason)")
        report(mapOf("sid" to session.info.sessionId, "state" to "ended", "error" to reason, "bytesSent" to session.bytesSent, "bytesReceived" to session.bytesReceived))
    }

    private fun report(update: Map<String, Any?>) {
        // Reporting is best effort.
        runCatching { signaling?.takeIf { it.isOpen }?.send("session.update", update) }
    }
}
