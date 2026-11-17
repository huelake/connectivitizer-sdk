package com.huelake.connectivitizer

import com.huelake.connectivitizer.internal.Addresses
import com.huelake.connectivitizer.internal.ChunkQueue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.net.Socket
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.security.SecureRandom
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory

/** A TCP or TLS connection as the byte stream the core works with. Reads happen on a thread of the IO pool. */
internal class SocketStream(private val socket: Socket, scope: CoroutineScope) : ByteStream {
    private val incoming = ChunkQueue()
    private val output = socket.getOutputStream()

    init {
        scope.launch(Dispatchers.IO) {
            val input = socket.getInputStream()
            val buffer = ByteArray(64 * 1024)
            try {
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) incoming.push(buffer.copyOf(count))
                }
                incoming.end()
            } catch (e: IOException) {
                incoming.end(if (socket.isClosed) null else ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection broke (${e.message}).", e))
            }
        }
    }

    override suspend fun read(): ByteArray? = incoming.read()

    override suspend fun write(data: ByteArray) {
        if (socket.isClosed) throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection is closed.")
        try {
            withContext(Dispatchers.IO) {
                output.write(data)
                output.flush()
            }
        } catch (e: IOException) {
            throw ConnectivitizerException(ErrorCodes.PATH_CLOSED, "The connection broke (${e.message}).", e)
        }
    }

    override suspend fun end() {
        if (socket.isClosed) return
        try {
            if (socket is SSLSocket) close() else withContext(Dispatchers.IO) { socket.shutdownOutput() }
        } catch (e: IOException) {
            close()
        }
    }

    override suspend fun close() {
        withContext(Dispatchers.IO) { runCatching { socket.close() } }
    }
}

/**
 * One UDP socket for a direct path. Hosts are plain IP addresses in canonical form, an IPv4 peer as IPv4 even
 * on a dual-stack socket. [onMessage] is called on the SDK's thread.
 */
class UdpSocket internal constructor(private val channel: DatagramChannel, val port: Int, val ipv6: Boolean) {
    var onMessage: ((ByteArray, String, Int) -> Unit)? = null

    /** Datagrams the system refused to send (no route, no address of that family, ...). */
    internal var sendFailures = 0L
        private set

    /** The first destination a send failed for and why; null when every send went out. */
    internal var firstSendFailure: String? = null
        private set

    fun send(data: ByteArray, host: String, port: Int) {
        if (Addresses.isIpv6(host) && !ipv6) return // an IPv6 candidate this socket cannot reach
        val bytes = Addresses.ipv4Bytes(host) ?: Addresses.ipv6Bytes(host) ?: return
        try {
            channel.send(ByteBuffer.wrap(data), InetSocketAddress(InetAddress.getByAddress(bytes), port))
        } catch (e: IOException) {
            // No route to that address: just a candidate that does not work.
            sendFailed(host, port, e)
        } catch (e: SecurityException) {
            sendFailed(host, port, e)
        }
    }

    private fun sendFailed(host: String, port: Int, error: Exception) {
        if (++sendFailures == 1L) firstSendFailure = "${if (Addresses.isIpv6(host)) "[$host]:$port" else "$host:$port"}: ${error.message ?: error.javaClass.simpleName}"
    }

    fun close() {
        runCatching { channel.close() }
    }
}

/**
 * What the SDK needs from the machine it runs on: TCP and TLS sockets, UDP, the system's random source, and
 * this machine's own addresses for direct sessions. Nothing here has to be configured; an application never
 * passes addresses or sockets. [sslSocketFactory] trusts the certificate authority of a self-hosted
 * installation; [includeLoopback] offers loopback addresses, which only helps when both endpoints run on one machine.
 */
open class Platform @JvmOverloads constructor(
    private val sslSocketFactory: SSLSocketFactory? = null,
    private val includeLoopback: Boolean = false,
) {
    private val random = SecureRandom()

    open val description: String = "jvm ${System.getProperty("java.version")} ${System.getProperty("os.name")}".trim()

    open val supportsUdp: Boolean = true

    /** Cryptographically secure random bytes. Session keys are made from them. */
    open fun randomBytes(length: Int): ByteArray = ByteArray(length).also { synchronized(random) { random.nextBytes(it) } }

    internal suspend fun openUrl(url: String, scope: CoroutineScope): Triple<ByteStream, String, String> {
        val uri = URI(url)
        val secure = uri.scheme == "https" || uri.scheme == "wss"
        val host = uri.host ?: throw ConnectivitizerException(ErrorCodes.INVALID_REQUEST, "'$url' has no host.")
        val port = if (uri.port > 0) uri.port else if (secure) 443 else 80
        val socket = try {
            withContext(Dispatchers.IO) {
                if (secure) {
                    val tls = (sslSocketFactory ?: SSLSocketFactory.getDefault() as SSLSocketFactory).createSocket(host.trim('[', ']'), port) as SSLSocket
                    // Java checks the certificate chain but not the name unless asked to.
                    tls.sslParameters = tls.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                    tls.startHandshake()
                    tls
                } else {
                    Socket(host.trim('[', ']'), port)
                }.apply { tcpNoDelay = true }
            }
        } catch (e: IOException) {
            throw ConnectivitizerException(ErrorCodes.SIGNALING_UNAVAILABLE, "$host:$port could not be reached (${e.message}).", e)
        }
        val target = (uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/") + (uri.rawQuery?.let { "?$it" } ?: "")
        val authority = if (uri.port > 0) "$host:${uri.port}" else host
        return Triple(SocketStream(socket, scope), authority, target)
    }

    /** An HTTP request to the Connectivitizer API: status and body text. */
    internal open suspend fun fetch(url: String, method: String, headers: Map<String, String>, body: String?, scope: CoroutineScope): Pair<Int, String> {
        val (stream, host, target) = openUrl(url, scope)
        val response = Http.request({ stream }, host, target, method, headers, body?.toByteArray(Charsets.UTF_8))
        return response.status to response.text()
    }

    /** Opens a WebSocket with request headers. A refusal the server names is thrown with its code. */
    internal open suspend fun connectWebSocket(url: String, headers: Map<String, String>, scope: CoroutineScope): StreamWebSocket {
        val (stream, host, target) = openUrl(url, scope)
        try {
            return StreamWebSocket.connect(stream, host, target, ::randomBytes, scope, headers)
        } catch (e: WebSocketRefusedException) {
            // The platform names its reason in a header (the relay) or leaves it to the status (signaling).
            val named = e.headers["cz-error"]
            val code = named ?: when (e.status) {
                401 -> ErrorCodes.UNAUTHENTICATED
                403 -> ErrorCodes.FORBIDDEN
                else -> ErrorCodes.RELAY_REJECTED
            }
            throw ConnectivitizerException(code, "The server refused the connection (HTTP ${e.status}${named?.let { ", $it" } ?: ""}).")
        } catch (e: Throwable) {
            runCatching { stream.close() }
            throw e
        }
    }

    /** Device side: a connection to a local service. */
    internal open suspend fun connectTcp(host: String, port: Int, scope: CoroutineScope): ByteStream {
        val socket = withContext(Dispatchers.IO) { Socket(host, port).apply { tcpNoDelay = true } }
        return SocketStream(socket, scope)
    }

    /** A dual-stack UDP socket on a port the system picks (IPv4 only where the system has no IPv6). */
    internal open suspend fun bindUdp(scope: CoroutineScope): UdpSocket = withContext(Dispatchers.IO) {
        val channel = DatagramChannel.open()
        try {
            channel.bind(InetSocketAddress(0))
        } catch (e: IOException) {
            channel.close()
            throw e
        }
        val local = channel.localAddress as InetSocketAddress
        val socket = UdpSocket(channel, local.port, local.address is Inet6Address)
        scope.launch(Dispatchers.IO) {
            val buffer = ByteBuffer.allocate(65_536)
            try {
                while (channel.isOpen) {
                    buffer.clear()
                    val from = channel.receive(buffer) as? InetSocketAddress ?: continue
                    buffer.flip()
                    val data = ByteArray(buffer.remaining()).also { buffer.get(it) }
                    val host = Addresses.normalizeHost(from.address.hostAddress.substringBefore('%')) ?: continue
                    scope.launch { socket.onMessage?.invoke(data, host, from.port) }
                }
            } catch (e: ClosedChannelException) {
            } catch (e: IOException) {
            }
        }
        socket
    }

    /**
     * This machine's own addresses, offered to the peer: IPv4 on its networks and IPv6 (the core keeps only
     * global ones). VPN interfaces are skipped: traffic to the local network and the internet leaves over the
     * underlying network anyway. The IPv6 address this machine sends from comes first: the core announces
     * only a few, and that one has to be among them (docs/protocol, 6.3).
     */
    internal open suspend fun localAddresses(): List<String> = withContext(Dispatchers.IO) {
        val found = ArrayList<String>()
        outgoingIpv6()?.let { found.add(it) }
        val vpn = Regex("^(tun|tap|ppp|utun|wg|ipsec|zt)\\d*", RegexOption.IGNORE_CASE)
        for (nic in NetworkInterface.getNetworkInterfaces()?.toList() ?: emptyList()) {
            try {
                if (!nic.isUp || vpn.containsMatchIn(nic.name) || (nic.isLoopback && !includeLoopback)) continue
            } catch (e: IOException) {
                continue
            }
            for (address in nic.inetAddresses.toList()) {
                if (address.isLoopbackAddress && !includeLoopback) continue
                if (address !is Inet4Address && address !is Inet6Address) continue
                val host = Addresses.normalizeHost(address.hostAddress.substringBefore('%')) ?: continue
                if (host !in found) found.add(host)
            }
        }
        found
    }

    /**
     * The address this machine sends from to the IPv6 internet, as its routing and address selection decide
     * (RFC 6724; usually a temporary address). Null without IPv6 or without a route.
     */
    private fun outgoingIpv6(): String? {
        // Any global address has the same route; this one is reserved for documentation (RFC 3849).
        val local = outgoingAddress("2001:db8::1") ?: return null
        return if (local is Inet6Address && !local.isLinkLocalAddress) Addresses.normalizeHost(local.hostAddress.substringBefore('%')) else null
    }

    /**
     * The local address the system sends from to reach a host, by its routing table. A UDP socket is given
     * the destination and asked for its own address: nothing is sent. Null without a route.
     */
    private fun outgoingAddress(host: String): InetAddress? {
        val bytes = Addresses.ipv4Bytes(host) ?: Addresses.ipv6Bytes(host) ?: return null
        return try {
            java.net.DatagramSocket().use { socket ->
                socket.connect(InetAddress.getByAddress(bytes), 9)
                socket.localAddress?.takeUnless { it.isAnyLocalAddress }
            }
        } catch (e: Exception) {
            null
        }
    }

    /** The local address this machine sends from to reach a peer's address, for the log; null without a route. */
    internal open suspend fun sourceAddress(host: String): String? = withContext(Dispatchers.IO) {
        outgoingAddress(host)?.let { Addresses.normalizeHost(it.hostAddress.substringBefore('%')) }
    }

    /** The IPv4 address of a host name (for STUN servers given by name). */
    internal open suspend fun resolve(host: String): String = withContext(Dispatchers.IO) {
        InetAddress.getAllByName(host).first { it is Inet4Address }.hostAddress
    }
}
