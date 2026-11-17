package com.huelake.connectivitizer.reactnative

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.system.OsConstants
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import java.io.IOException
import java.net.DatagramSocket
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ClosedChannelException
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * What a phone app needs for peer-to-peer sessions and React Native does not have: UDP sockets, and
 * the phone's own addresses. The SDK's JavaScript does everything else (STUN, hole punching, KCP,
 * encryption); this module only moves datagrams and reads the network configuration.
 */
class ConnectivitizerNativeModule : Module() {
  private val sockets = ConcurrentHashMap<Int, UdpSocket>()
  private val nextId = AtomicInteger(1)

  override fun definition() = ModuleDefinition {
    Name("ConnectivitizerNative")

    Events("onUdpMessage")

    /**
     * A UDP socket on a port the system picks. It is dual-stack: it reaches IPv4 and IPv6 peers, and
     * reports the port it is really bound to (which the SDK announces to the peer).
     */
    AsyncFunction("udpBind") {
      val channel = DatagramChannel.open()
      try {
        channel.bind(InetSocketAddress(0))
      } catch (error: IOException) {
        channel.close()
        throw error
      }
      val local = channel.localAddress as InetSocketAddress
      val id = nextId.getAndIncrement()
      val socket = UdpSocket(id, channel)
      sockets[id] = socket
      socket.start()
      mapOf("id" to id, "port" to local.port, "ipv6" to (local.address is Inet6Address))
    }

    /** Sends one datagram. Hosts are IP addresses, never names: nothing is resolved here. */
    Function("udpSend") { id: Int, data: ByteArray, host: String, port: Int ->
      val socket = sockets[id] ?: return@Function
      try {
        socket.channel.send(ByteBuffer.wrap(data), InetSocketAddress(InetAddress.getByName(host), port))
      } catch (ignored: IOException) {
        // No route (for example IPv6 on a network without it), or the socket is closing. UDP is
        // best effort; the SDK's probes and KCP retransmissions cope with lost datagrams.
      } catch (ignored: SecurityException) {
      }
    }

    Function("udpClose") { id: Int ->
      sockets.remove(id)?.close()
    }

    /**
     * The phone's own addresses, offered to a device as places to reach the phone directly:
     *  - the IPv4 address in its Wi-Fi (or Ethernet), for a device in the same network;
     *  - its global IPv6 addresses, on Wi-Fi and on mobile data. IPv6 has no NAT, so a device at home
     *    can be reached from mobile data where IPv4 has to go through the carrier's NAT.
     * VPNs are skipped (for example a mesh network app): traffic to the local network and to the
     * internet still leaves over the underlying network.
     */
    AsyncFunction("getLocalAddressesAsync") {
      val context = appContext.reactContext ?: return@AsyncFunction emptyList<String>()
      val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
      val ipv4 = mutableListOf<String>()
      val ipv6 = mutableListOf<String>()
      // Addresses the system no longer sends from (their prefix was replaced): announced last, cut first.
      val deprecated = mutableListOf<String>()
      @Suppress("DEPRECATION")
      for (network in manager.allNetworks) {
        val capabilities = manager.getNetworkCapabilities(network) ?: continue
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
          continue
        }
        val local = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
        val mobile = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
        for (link in manager.getLinkProperties(network)?.linkAddresses ?: emptyList()) {
          val address: InetAddress = link.address
          if (address is Inet4Address && local && !address.isLoopbackAddress && !address.isLinkLocalAddress) {
            ipv4.add(address.hostAddress ?: continue)
          } else if (address is Inet6Address && (local || mobile) && isGlobal(address)) {
            val text = address.hostAddress?.substringBefore('%') ?: continue
            if ((link.flags and OsConstants.IFA_F_DEPRECATED) != 0) deprecated.add(text) else ipv6.add(text)
          }
        }
      }
      // First the address the phone sends from: only a few are announced, and the firewalls on the way open
      // only for that one (docs/protocol, 6.3).
      ipv4.distinct().take(2) + (listOfNotNull(outgoingIpv6()) + ipv6 + deprecated).distinct().take(4)
    }

    OnDestroy {
      sockets.values.forEach { it.close() }
      sockets.clear()
    }
  }

  /**
   * The address this phone sends from to the IPv6 internet, as its routing and address selection decide
   * (usually a temporary address of the active network). A UDP socket is given a destination and asked for
   * its own address: nothing is sent. Null without IPv6 or without a route.
   */
  private fun outgoingIpv6(): String? = try {
    DatagramSocket().use { socket ->
      // Any global address has the same route; this one is reserved for documentation (RFC 3849).
      socket.connect(InetAddress.getByName("2001:db8::1"), 9)
      val local = socket.localAddress
      if (local is Inet6Address && isGlobal(local)) local.hostAddress?.substringBefore('%') else null
    }
  } catch (e: Exception) {
    null
  }

  /** A global unicast IPv6 address (2000::/3). */
  private fun isGlobal(address: Inet6Address): Boolean = (address.address[0].toInt() and 0xE0) == 0x20

  /** One socket and the thread that receives on it. Received datagrams go to JavaScript as events. */
  private inner class UdpSocket(val id: Int, val channel: DatagramChannel) {
    private val receiver = Thread({ receive() }, "connectivitizer-udp-$id").apply { isDaemon = true }

    fun start() = receiver.start()

    private fun receive() {
      val buffer = ByteBuffer.allocate(65_536)
      try {
        while (channel.isOpen) {
          buffer.clear()
          val from = channel.receive(buffer) as? InetSocketAddress ?: continue
          buffer.flip()
          val data = ByteArray(buffer.remaining())
          buffer.get(data)
          // An IPv4 peer on the dual-stack socket arrives as an IPv4 address; IPv6 is written out
          // in full here and put into its canonical form by the JavaScript side.
          val host = from.address.hostAddress?.substringBefore('%') ?: continue
          sendEvent("onUdpMessage", mapOf("id" to id, "data" to data, "host" to host, "port" to from.port))
        }
      } catch (ignored: ClosedChannelException) {
        // Closed by udpClose.
      } catch (ignored: IOException) {
        sockets.remove(id)
        close()
      }
    }

    fun close() {
      try {
        channel.close()
      } catch (ignored: IOException) {
      }
    }
  }
}
