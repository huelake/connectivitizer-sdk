package com.huelake.connectivitizer.internal

import com.huelake.connectivitizer.ByteStream
import com.huelake.connectivitizer.Platform
import com.huelake.connectivitizer.UdpSocket
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import java.security.MessageDigest

// One attempt to open a direct path for a session (protocol section 6): discover this endpoint's addresses,
// exchange candidates with the peer through signaling, then punch through the NATs with UDP probes. The
// initiator picks the first path that works.
//
// Probes carry no payload and prove nothing about who sent them - they only find a working path. Everything
// that matters is established afterwards by the end-to-end handshake over that path, and both endpoints then
// confirm in the session bind which candidate lists they used. That is also why an address the peer did not
// announce, learned from where its probes come from, is used only when the session's end-to-end layer
// authenticates the peer (peerReflexive).

internal object DirectFailureReasons {
    const val POLICY_RELAY_ONLY = "policy_relay_only"
    const val PEER_NO_DIRECT_SUPPORT = "peer_no_direct_support"
    const val STUN_UNREACHABLE = "stun_unreachable"
    const val UDP_BLOCKED_LOCAL = "udp_blocked_local"
    const val UDP_BLOCKED_REMOTE = "udp_blocked_remote"
    const val SYMMETRIC_NAT_BOTH = "symmetric_nat_both"
    const val PROBE_TIMEOUT = "probe_timeout"
}

internal class DirectPath(val stream: ByteStream, val peerAddress: String)

internal object Stun {
    const val MAGIC = 0x2112a442L
    private const val BINDING_REQUEST = 0x0001
    private const val BINDING_SUCCESS = 0x0101
    private const val XOR_MAPPED_ADDRESS = 0x0020

    fun request(transactionId: ByteArray): ByteArray = Bytes.u16(BINDING_REQUEST) + Bytes.u16(0) + Bytes.u32(MAGIC) + transactionId

    /** The mapped address from a STUN Binding success response for one of our transactions. */
    fun readSuccess(datagram: ByteArray, transactionId: ByteArray): String? {
        if (datagram.size < 20 || Bytes.readU16(datagram, 0) != BINDING_SUCCESS || Bytes.readU32(datagram, 4) != MAGIC ||
            !MessageDigest.isEqual(datagram.copyOfRange(8, 20), transactionId)
        ) {
            return null
        }
        val length = Bytes.readU16(datagram, 2)
        if (length > datagram.size - 20) return null
        var offset = 20
        val end = 20 + length
        while (end - offset >= 4) {
            val type = Bytes.readU16(datagram, offset)
            val valueLength = Bytes.readU16(datagram, offset + 2)
            if (valueLength > end - offset - 4) return null
            if (type == XOR_MAPPED_ADDRESS && valueLength >= 8 && datagram[offset + 5].toInt() == 0x01) {
                val port = Bytes.readU16(datagram, offset + 6) xor (MAGIC ushr 16).toInt()
                val address = Bytes.readU32(datagram, offset + 8) xor MAGIC
                return "${address ushr 24}.${(address ushr 16) and 255}.${(address ushr 8) and 255}.${address and 255}:$port"
            }
            // Attributes are padded to a multiple of four bytes.
            offset += 4 + ((valueLength + 3) and 3.inv())
        }
        return null
    }
}

internal class DirectAttempt(
    private val platform: Platform,
    private val role: String,
    private val sessionId: String,
    grantToken: String,
    private val stunServers: List<String>,
    private val peerReflexive: Boolean,
    private val scope: CoroutineScope,
    /** Receives one line per step of the attempt (addresses announced, first probe, the count at the end). */
    private val log: ((String) -> Unit)? = null,
) {
    // Both endpoints hold the same grant, so both derive the same tag and KCP conversation id.
    private val digest = Bytes.sha256(grantToken.toByteArray(Charsets.UTF_8))
    private val tag = digest.copyOfRange(0, 8)
    private val conversation = Bytes.readU32(digest, 8) or 1

    /** SHA-256 (hex) of the candidate list this endpoint sent; confirmed inside the encrypted session. */
    var localCandidatesHash: String? = null
        private set

    /** SHA-256 (hex) of the candidate list received from the peer through signaling. */
    var remoteCandidatesHash: String? = null
        private set

    private var socket: UdpSocket? = null
    private var remoteCandidates: List<UdpAddress> = emptyList()
    private var learned: List<UdpAddress> = emptyList()
    private var remoteNat = "unknown"
    private val remoteKnown = CompletableDeferred<Unit>()
    private val validated = CompletableDeferred<UdpAddress>()
    private val validatedLearned = CompletableDeferred<UdpAddress>()
    private val selectAcknowledged = CompletableDeferred<Unit>()
    private val selectedByPeer = CompletableDeferred<KcpPath>()
    private var selected: UdpAddress? = null
    private var path: KcpPath? = null
    private var stun: List<Pair<ByteArray, Array<String?>>> = emptyList()
    private var stunReachable = false
    private var stunSymmetric = false
    private var hasStunServers = false
    private var handedOver = false
    private var closed = false
    private var probesSent = 0L
    private var probesReceived = 0L
    private var answersReceived = 0L
    private var foreignDatagrams = 0L
    private val started = System.nanoTime()

    /** Discovers this endpoint's addresses and returns the candidate list to send to the peer. */
    suspend fun gather(): ByteArray {
        val udp = platform.bindUdp(scope)
        socket = udp
        udp.onMessage = ::onDatagram
        val mapped = discover()
        log?.invoke("UDP socket on port ${udp.port}, IPv6 ${if (udp.ipv6) "yes" else "no"}; STUN: ${if (mapped != null) "$mapped (${if (stunSymmetric) "symmetric NAT" else "cone"})" else "no answer"}")
        val candidates = ArrayList<String>()
        var ipv4 = 0
        var ipv6 = 0
        for (text in runCatching { platform.localAddresses() }.getOrDefault(emptyList())) {
            val host = Addresses.normalizeHost(text) ?: continue
            // IPv4 on every interface; IPv6 only global addresses, and only when the socket has IPv6.
            val usable = if (Addresses.isIpv6(host)) udp.ipv6 && Addresses.isGlobalIpv6(host) && ipv6 < MAX_IPV6_ADDRESSES else ipv4 < MAX_IPV4_ADDRESSES
            val candidate = Addresses.format(UdpAddress(host, udp.port))
            if (usable && candidate !in candidates) {
                candidates.add(candidate)
                if (Addresses.isIpv6(host)) ipv6++ else ipv4++
            }
        }
        if (mapped != null && mapped !in candidates) candidates.add(mapped)
        val nat = if (!stunReachable) "unknown" else if (stunSymmetric) "symmetric" else "cone"
        val blob = Json.write(mapOf("sid" to sessionId, "role" to role, "udp" to candidates, "nat" to nat)).toByteArray(Charsets.UTF_8)
        localCandidatesHash = Bytes.hex(Bytes.sha256(blob))
        log?.invoke("announcing ${join(candidates)}")
        return blob
    }

    /** Takes the peer's candidate list as received through signaling. False when it is not usable. */
    fun setRemoteCandidates(blob: ByteArray): Boolean {
        val list = runCatching { Json.parse(String(blob, Charsets.UTF_8)).asMap() }.getOrNull() ?: return false
        if (list["sid"] != sessionId || list["role"] == role) return false
        val udp = list["udp"].asList() ?: return false
        if (udp.size > MAX_CANDIDATES) return false
        remoteCandidatesHash = Bytes.hex(Bytes.sha256(blob))
        remoteNat = list.string("nat") ?: "unknown"
        val parsed = ArrayList<UdpAddress>()
        for (text in udp) {
            val address = (text as? String)?.let { Addresses.parse(it) } ?: continue
            if (Addresses.usableCandidate(address) && address !in parsed) parsed.add(address)
        }
        remoteCandidates = parsed
        remoteKnown.complete(Unit)
        if (log != null) {
            log.invoke("peer announces ${join(udp.filterIsInstance<String>())}; NAT $remoteNat; after ${elapsed()} ms")
            // Asking the system for a source address may block, so that line is written from a coroutine.
            scope.launch { log.invoke("probing them from: ${join(parsed.map { "${it.host} <- ${platform.sourceAddress(it.host) ?: "no route"}" })}") }
        }
        return true
    }

    private fun learn(address: UdpAddress) {
        if (!peerReflexive || !remoteKnown.isCompleted || address in remoteCandidates || address in learned || learned.size >= MAX_LEARNED) return
        learned = learned + address
    }

    private fun probeTargets(): List<UdpAddress> = remoteCandidates + learned

    /**
     * Initiator: tries the peer's candidates until a path works, then tells the peer which one to use. Returns
     * that path, or null when none worked in time.
     */
    suspend fun open(budgetMillis: Long): DirectPath? {
        val deadline = System.currentTimeMillis() + budgetMillis
        fun remaining() = maxOf(deadline - System.currentTimeMillis(), 1)
        var stop = false
        try {
            withTimeoutOrNull(remaining()) { remoteKnown.await() } ?: return null
            scope.launch { probeLoop(FLAG_PROBE, ::probeTargets) { stop || selected != null } }
            // A learned address is the fallback: selected only if no announced candidate answers in time.
            val fallback = if (peerReflexive) scope.async {
                val address = validatedLearned.await()
                delay(LEARNED_GRACE)
                address
            } else null
            val remote = withTimeoutOrNull(remaining()) {
                select<UdpAddress> {
                    validated.onAwait { it }
                    fallback?.onAwait { it }
                }
            }
            fallback?.cancel()
            remote ?: return null
            selected = remote
            scope.launch { probeLoop(FLAG_SELECT, { listOf(remote) }) { stop } }
            withTimeoutOrNull(remaining()) { selectAcknowledged.await() } ?: return null
            stop = true
            handedOver = true
            val kcpPath = KcpPath(socket!!, remote.host, remote.port, conversation, scope)
            path = kcpPath
            return DirectPath(kcpPath, kcpPath.peerAddress)
        } catch (e: Exception) {
            return null
        } finally {
            stop = true
        }
    }

    /**
     * Device: keeps probing the initiator's candidates (which opens this side's NAT) and waits for the initiator
     * to select a path. Throws when the attempt is closed first.
     */
    suspend fun waitForSelection(): DirectPath {
        scope.launch {
            remoteKnown.await()
            probeLoop(FLAG_PROBE, ::probeTargets) { closed || path != null }
        }
        val selectedPath = selectedByPeer.await()
        return DirectPath(selectedPath, selectedPath.peerAddress)
    }

    /** Why no direct path was found. */
    fun failureReason(): String = when {
        stunSymmetric && remoteNat == "symmetric" -> DirectFailureReasons.SYMMETRIC_NAT_BOTH
        !stunReachable -> if (hasStunServers) DirectFailureReasons.UDP_BLOCKED_LOCAL else DirectFailureReasons.STUN_UNREACHABLE
        remoteNat == "unknown" -> DirectFailureReasons.UDP_BLOCKED_REMOTE
        else -> DirectFailureReasons.PROBE_TIMEOUT
    }

    /** What this side of the attempt sent and saw, for the log when no path was found. */
    fun summary(): String {
        val failed = socket?.sendFailures ?: 0
        val failures = if (failed == 0L) "" else " ($failed not sent by the system, first ${socket?.firstSendFailure})"
        val foreign = if (foreignDatagrams == 0L) "" else ", $foreignDatagrams other datagrams"
        return "after ${elapsed()} ms: sent $probesSent probes$failures to ${join(probeTargets().map { it.toString() })}; received $probesReceived probes and $answersReceived answers$foreign"
    }

    private fun elapsed() = (System.nanoTime() - started) / 1_000_000

    private fun join(items: List<String>) = if (items.isEmpty()) "(none)" else items.joinToString(", ")

    private fun known(address: UdpAddress) = if (address in remoteCandidates) "announced" else if (address in learned) "learned" else "not announced"

    /** Gives up the attempt. A path that was handed to a session is not affected. */
    fun close() {
        if (closed) return
        closed = true
        val error = IllegalStateException("The direct attempt was closed.")
        selectedByPeer.completeExceptionally(error)
        validated.completeExceptionally(error)
        validatedLearned.completeExceptionally(error)
        remoteKnown.completeExceptionally(error)
        selectAcknowledged.completeExceptionally(error)
        if (!handedOver) socket?.close()
    }

    /**
     * Asks the STUN servers how this endpoint's UDP port appears from outside. Different answers from different
     * servers mean the NAT maps each destination separately ("symmetric"), in which case the reported address is
     * of no use to a peer.
     */
    private suspend fun discover(): String? {
        val servers = ArrayList<UdpAddress>()
        for (server in stunServers) {
            val colon = server.lastIndexOf(':')
            val port = server.substring(colon + 1).toIntOrNull() ?: continue
            if (colon <= 0 || port !in 1..65535) continue
            val host = server.substring(0, colon)
            val resolved = Addresses.parse("$host:$port")?.host ?: runCatching { platform.resolve(host) }.getOrNull() ?: continue
            servers.add(UdpAddress(resolved, port))
        }
        hasStunServers = servers.isNotEmpty()
        if (servers.isEmpty()) return null
        stun = servers.map { platform.randomBytes(12) to arrayOfNulls<String>(1) }
        val started = System.currentTimeMillis()
        fun allAnswered() = stun.all { it.second[0] != null }
        // UDP is lossy: repeat the requests a few times until every server has answered.
        for (wait in longArrayOf(0, 200, 400, 800)) {
            while (System.currentTimeMillis() < started + wait && !allAnswered()) delay(20)
            if (allAnswered()) break
            servers.forEachIndexed { index, server -> if (stun[index].second[0] == null) socket!!.send(Stun.request(stun[index].first), server.host, server.port) }
        }
        while (System.currentTimeMillis() < started + STUN_TIMEOUT && !allAnswered()) delay(20)
        val answers = stun.mapNotNull { it.second[0] }
        stunReachable = answers.isNotEmpty()
        stunSymmetric = answers.toSet().size > 1
        return answers.firstOrNull()
    }

    private fun onDatagram(data: ByteArray, host: String, port: Int) {
        if (data.isEmpty()) return
        val kind = data[0].toInt() and 0xff
        if (kind <= 0x03) {
            for ((id, answer) in stun) if (answer[0] == null) answer[0] = Stun.readSuccess(data, id)
            return
        }
        if (kind == DatagramType.PROBE || kind == DatagramType.PROBE_ACK) onProbe(data, host, port) else foreignDatagrams++
    }

    private fun onProbe(data: ByteArray, rawHost: String, port: Int) {
        val udp = socket ?: return
        if (data.size != PROBE_SIZE || !MessageDigest.isEqual(data.copyOfRange(1, 9), tag)) {
            foreignDatagrams++
            return // not for this session
        }
        val host = Addresses.normalizeHost(rawHost) ?: rawHost
        val from = UdpAddress(host, port)
        learn(from)
        val announced = from in remoteCandidates
        val flags = data[9].toInt()
        if ((data[0].toInt() and 0xff) == DatagramType.PROBE) {
            if (probesReceived++ == 0L) log?.invoke("first probe from $from (${known(from)}) after ${elapsed()} ms")
            if (flags == FLAG_SELECT) {
                // Only the initiator selects, and only an address from its own announced list (or, where the
                // session allows it, one learned from its probes) is accepted.
                if (role != Roles.DEVICE || !(announced || from in learned)) return
                if (path == null) {
                    selected = from
                    handedOver = true
                    // The path listens before the selection is acknowledged, so the first packets are not lost.
                    val kcpPath = KcpPath(udp, host, port, conversation, scope)
                    kcpPath.onProbe = ::onProbe
                    path = kcpPath
                    log?.invoke("the peer selected $from after ${elapsed()} ms")
                    selectedByPeer.complete(kcpPath)
                } else if (selected != from) {
                    return
                }
            }
            udp.send(byteArrayOf(DatagramType.PROBE_ACK.toByte()) + data.copyOfRange(1, data.size), host, port)
            return
        }
        if (answersReceived++ == 0L) log?.invoke("first answer from $from (${known(from)}) after ${elapsed()} ms")
        if (role == Roles.INITIATOR && (announced || from in learned)) {
            if (flags == FLAG_PROBE) {
                (if (announced) validated else validatedLearned).complete(from)
            } else if (selected == from) {
                selectAcknowledged.complete(Unit)
            }
        }
    }

    private suspend fun probeLoop(flags: Int, targets: () -> List<UdpAddress>, done: () -> Boolean) {
        while (!done() && !closed) {
            val probe = byteArrayOf(DatagramType.PROBE.toByte()) + tag + byteArrayOf(flags.toByte()) + platform.randomBytes(8)
            for (target in targets()) {
                socket?.send(probe, target.host, target.port)
                probesSent++
            }
            delay(PROBE_INTERVAL)
        }
    }

    private companion object {
        const val PROBE_SIZE = 18
        const val FLAG_PROBE = 0
        const val FLAG_SELECT = 1
        const val MAX_CANDIDATES = 16
        const val MAX_IPV4_ADDRESSES = 6
        const val MAX_IPV6_ADDRESSES = 4
        const val MAX_LEARNED = 4
        const val PROBE_INTERVAL = 100L
        const val STUN_TIMEOUT = 1_500L
        /** How long an announced candidate gets to validate after a learned address did, before the learned one is selected. */
        const val LEARNED_GRACE = 500L
    }
}

/** Whether a session with this end-to-end layer may use learned addresses: only when the layer authenticates the peer. */
internal fun peerReflexiveFor(e2eMethod: String) = e2eMethod == E2eMethods.TLS13 || e2eMethod == E2eMethods.SHARED_KEY
