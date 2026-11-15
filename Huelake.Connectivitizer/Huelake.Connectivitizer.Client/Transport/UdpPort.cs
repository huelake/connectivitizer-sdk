using System.Net;
using System.Net.Sockets;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Transport;

/// <summary>Receives the datagrams of one class (see <see cref="UdpPort"/>).</summary>
/// <remarks>The buffer is only valid until the returned task completes.</remarks>
internal delegate ValueTask DatagramHandler(ReadOnlyMemory<byte> datagram, IPEndPoint remote);

/// <summary>
/// One local UDP socket shared by everything a direct path needs: STUN discovery, hole-punch
/// probes and the KCP stream all have to use the same local port, because that port is what the
/// NAT mapping (and therefore the peer) sees.
/// </summary>
/// <remarks>
/// Where the system has IPv6 the socket is dual-stack, so one port serves IPv4 and IPv6 peers.
/// Addresses are always handed out in their plain form: an IPv4 peer is an IPv4 endpoint, never
/// an IPv4-mapped IPv6 one.
/// </remarks>
internal sealed class UdpPort : IAsyncDisposable
{
    private const int MaxDatagram = 2048;

    private readonly Socket _socket;
    private readonly CancellationTokenSource _stop = new();
    private readonly Lock _gate = new();
    private readonly Dictionary<IPEndPoint, DatagramHandler> _peerHandlers = [];
    private Task? _receiveLoop;

    public UdpPort(IPEndPoint? bind = null)
    {
        _socket = Open(bind, out bool dualStack);
        SupportsIPv6 = dualStack;
        if (OperatingSystem.IsWindows())
        {
            // Without this an ICMP "port unreachable" for an earlier send makes the next receive
            // fail with WSAECONNRESET, which would kill the socket in the middle of hole punching.
            const int SioUdpConnReset = unchecked((int)0x9800000C);
            _socket.IOControl(SioUdpConnReset, [0], null);
        }
        LocalEndPoint = (IPEndPoint)_socket.LocalEndPoint!;
    }

    private static Socket Open(IPEndPoint? bind, out bool dualStack)
    {
        if (bind is null && Socket.OSSupportsIPv6)
        {
            var socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);
            try
            {
                socket.DualMode = true;
                socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
                dualStack = true;
                return socket;
            }
            catch (SocketException)
            {
                socket.Dispose(); // IPv6 is there but cannot be used: fall back to IPv4 only
            }
        }

        var ipv4 = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        ipv4.Bind(bind ?? new IPEndPoint(IPAddress.Any, 0));
        dualStack = false;
        return ipv4;
    }

    public IPEndPoint LocalEndPoint { get; }

    /// <summary>The socket can send to and receive from IPv6 addresses (besides IPv4).</summary>
    public bool SupportsIPv6 { get; }

    /// <summary>An IPv4-mapped IPv6 endpoint as the IPv4 endpoint it stands for; any other unchanged.</summary>
    public static IPEndPoint Plain(IPEndPoint endpoint)
        => endpoint.Address.IsIPv4MappedToIPv6 ? new IPEndPoint(endpoint.Address.MapToIPv4(), endpoint.Port) : endpoint;

    /// <summary>Handler for STUN messages (first byte 0x00-0x03).</summary>
    public DatagramHandler? StunHandler { get; set; }

    /// <summary>Handler for peer datagrams from an address no path is registered for (probes during hole punching).</summary>
    public DatagramHandler? UnboundPeerHandler { get; set; }

    /// <summary>Test hook: return false to drop an outgoing datagram, simulating packet loss.</summary>
    internal Func<ReadOnlyMemory<byte>, bool>? SendFilter { get; set; }

    public long DatagramsSent => Interlocked.Read(ref _datagramsSent);

    public long DatagramsReceived => Interlocked.Read(ref _datagramsReceived);

    private long _datagramsSent;
    private long _datagramsReceived;

    public void Start()
    {
        lock (_gate)
        {
            _receiveLoop ??= Task.Run(ReceiveLoopAsync);
        }
    }

    /// <summary>Routes all peer datagrams arriving from <paramref name="remote"/> to <paramref name="handler"/>.</summary>
    public void BindPeer(IPEndPoint remote, DatagramHandler handler)
    {
        lock (_gate)
        {
            _peerHandlers[remote] = handler;
        }
    }

    public void UnbindPeer(IPEndPoint remote)
    {
        lock (_gate)
        {
            _peerHandlers.Remove(remote);
        }
    }

    public async ValueTask SendAsync(ReadOnlyMemory<byte> datagram, IPEndPoint remote, CancellationToken cancellationToken = default)
    {
        if (SendFilter is { } filter && !filter(datagram))
        {
            return;
        }

        if (remote.AddressFamily == AddressFamily.InterNetworkV6 && !SupportsIPv6)
        {
            return; // an IPv6 candidate this socket cannot reach
        }

        try
        {
            await _socket.SendToAsync(datagram, SocketFlags.None, remote, cancellationToken).ConfigureAwait(false);
            Interlocked.Increment(ref _datagramsSent);
        }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.HostUnreachable or SocketError.NetworkUnreachable or SocketError.ConnectionRefused or SocketError.MessageSize
            or SocketError.AddressNotAvailable or SocketError.AddressFamilyNotSupported)
        {
            // UDP is best effort; an unreachable candidate is an expected outcome, not an error.
        }
    }

    private async Task ReceiveLoopAsync()
    {
        byte[] buffer = GC.AllocateUninitializedArray<byte>(MaxDatagram, pinned: true);
        EndPoint any = new IPEndPoint(SupportsIPv6 ? IPAddress.IPv6Any : IPAddress.Any, 0);
        CancellationToken stop = _stop.Token;

        while (!stop.IsCancellationRequested)
        {
            SocketReceiveFromResult result;
            try
            {
                result = await _socket.ReceiveFromAsync(buffer.AsMemory(), SocketFlags.None, any, stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            catch (ObjectDisposedException)
            {
                return;
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.MessageSize)
            {
                continue;
            }
            catch (SocketException)
            {
                return;
            }

            if (result.ReceivedBytes == 0)
            {
                continue;
            }

            Interlocked.Increment(ref _datagramsReceived);
            IPEndPoint remote = Plain((IPEndPoint)result.RemoteEndPoint);
            ReadOnlyMemory<byte> datagram = buffer.AsMemory(0, result.ReceivedBytes);
            DatagramHandler? handler = SelectHandler(datagram.Span[0], remote);
            if (handler is null)
            {
                continue;
            }

            try
            {
                await handler(datagram, remote).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                // A handler failure must never stop the socket for the other users of this port.
            }
        }
    }

    private DatagramHandler? SelectHandler(byte first, IPEndPoint remote)
    {
        if (first <= 0x03)
        {
            return StunHandler;
        }

        if (first is < DatagramType.Probe or > DatagramType.Close)
        {
            return null;
        }

        lock (_gate)
        {
            return _peerHandlers.TryGetValue(remote, out DatagramHandler? bound) ? bound : UnboundPeerHandler;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync().ConfigureAwait(false);
        _socket.Dispose();
        if (_receiveLoop is { } loop)
        {
            try
            {
                await loop.ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
            }
        }
        _stop.Dispose();
    }
}
