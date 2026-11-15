package com.huelake.connectivitizer.internal

/**
 * UDP addresses as the candidate lists write them (protocol section 6.3): IPv4 as `a.b.c.d:port`, IPv6 as
 * `[address]:port`. Hosts are kept in one canonical text form (RFC 5952 for IPv6), so that two spellings of
 * the same address compare equal. Parsed here rather than with InetAddress, which would look names up.
 */
internal data class UdpAddress(val host: String, val port: Int) {
    override fun toString(): String = Addresses.format(this)
}

internal object Addresses {
    private val IPV4 = Regex("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$")
    private val GROUP = Regex("^[0-9a-fA-F]{1,4}$")
    private val BRACKETED = Regex("^\\[([^\\]]+)]:(\\d{1,5})$")
    private val DOTTED = Regex("^([\\d.]+):(\\d{1,5})$")

    fun ipv4Bytes(text: String): ByteArray? {
        val match = IPV4.matchEntire(text) ?: return null
        val parts = match.groupValues.drop(1).map { it.toInt() }
        return if (parts.any { it > 255 }) null else ByteArray(4) { parts[it].toByte() }
    }

    /** The 16 bytes of an IPv6 address in text form, or null. Zone ids are not accepted. */
    fun ipv6Bytes(text: String): ByteArray? {
        if (text.length > 45 || !text.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' || it == '.' }) return null
        var body = text
        if (text.contains('.')) {
            // An embedded IPv4 address at the end (`::ffff:192.0.2.1`) stands for the last two groups.
            val lastColon = text.lastIndexOf(':')
            val ipv4 = if (lastColon < 0) null else ipv4Bytes(text.substring(lastColon + 1)) ?: return null
            ipv4 ?: return null
            val high = ((ipv4[0].toInt() and 0xff) shl 8) or (ipv4[1].toInt() and 0xff)
            val low = ((ipv4[2].toInt() and 0xff) shl 8) or (ipv4[3].toInt() and 0xff)
            body = text.substring(0, lastColon + 1) + Integer.toHexString(high) + ":" + Integer.toHexString(low)
        }
        val halves = body.split("::")
        if (halves.size > 2) return null
        fun parse(part: String): List<Int>? {
            if (part.isEmpty()) return emptyList()
            return part.split(":").map { if (GROUP.matches(it)) it.toInt(16) else return null }
        }
        val before = parse(halves[0]) ?: return null
        val after = if (halves.size == 2) parse(halves[1]) ?: return null else emptyList()
        val known = before.size + after.size
        if (if (halves.size == 2) known > 7 else known != 8) return null
        val groups = before + List(8 - known) { 0 } + after
        return ByteArray(16) { index -> (if (index % 2 == 0) groups[index / 2] shr 8 else groups[index / 2] and 0xff).toByte() }
    }

    /** The canonical text of an IPv6 address (RFC 5952: lower case, longest run of zero groups as `::`). */
    fun formatIpv6(bytes: ByteArray): String {
        val groups = IntArray(8) { ((bytes[it * 2].toInt() and 0xff) shl 8) or (bytes[it * 2 + 1].toInt() and 0xff) }
        var bestStart = -1
        var bestLength = 1 // a single zero group is not shortened
        var start = 0
        while (start < 8) {
            if (groups[start] != 0) {
                start++
                continue
            }
            var end = start
            while (end < 8 && groups[end] == 0) end++
            if (end - start > bestLength) {
                bestStart = start
                bestLength = end - start
            }
            start = end
        }
        fun text(from: Int, to: Int) = (from until to).joinToString(":") { Integer.toHexString(groups[it]) }
        return if (bestStart < 0) text(0, 8) else "${text(0, bestStart)}::${text(bestStart + bestLength, 8)}"
    }

    /**
     * A host as the SDK keeps it: IPv4 dotted, IPv6 canonical, and an IPv4-mapped IPv6 address (what a
     * dual-stack socket reports for an IPv4 peer) as the IPv4 address it stands for. Null when not an IP address.
     */
    fun normalizeHost(text: String): String? {
        ipv4Bytes(text)?.let { bytes -> return bytes.joinToString(".") { (it.toInt() and 0xff).toString() } }
        val bytes = ipv6Bytes(text.substringBefore('%')) ?: return null
        val mapped = (0 until 10).all { bytes[it] == 0.toByte() } && bytes[10] == 0xff.toByte() && bytes[11] == 0xff.toByte()
        return if (mapped) (12 until 16).joinToString(".") { (bytes[it].toInt() and 0xff).toString() } else formatIpv6(bytes)
    }

    fun isIpv6(host: String): Boolean = host.contains(':')

    /** A global unicast IPv6 address (2000::/3): reachable from elsewhere without NAT in between. */
    fun isGlobalIpv6(host: String): Boolean {
        val bytes = if (isIpv6(host)) ipv6Bytes(host) else null
        return bytes != null && (bytes[0].toInt() and 0xe0) == 0x20
    }

    fun format(address: UdpAddress): String = if (isIpv6(address.host)) "[${address.host}]:${address.port}" else "${address.host}:${address.port}"

    /** Reads a candidate (`a.b.c.d:port` or `[address]:port`); null when it is neither. */
    fun parse(text: String): UdpAddress? {
        val match = BRACKETED.matchEntire(text) ?: DOTTED.matchEntire(text) ?: return null
        val port = match.groupValues[2].toInt()
        val host = normalizeHost(match.groupValues[1]) ?: return null
        return if (port in 1..65535) UdpAddress(host, port) else null
    }

    /** A peer candidate this endpoint can send to: IPv4, or IPv6 that is neither link-local, multicast nor unspecified. */
    fun usableCandidate(address: UdpAddress): Boolean {
        if (!isIpv6(address.host)) return true
        val bytes = ipv6Bytes(address.host) ?: return false
        val linkLocal = bytes[0] == 0xfe.toByte() && (bytes[1].toInt() and 0xc0) == 0x80
        return !linkLocal && bytes[0] != 0xff.toByte() && bytes.any { it != 0.toByte() }
    }
}
