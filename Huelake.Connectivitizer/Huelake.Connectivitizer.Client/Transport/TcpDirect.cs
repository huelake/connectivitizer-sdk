using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Transport;

/// <summary>A TCP connection between the two endpoints of a session on which both sides have shown the session's tag.</summary>
internal sealed class TcpDirectConnection : IAsyncDisposable
{
    public TcpDirectConnection(Socket socket, string? dialedCandidate)
    {
        Remote = (IPEndPoint)socket.RemoteEndPoint!;
        DialedCandidate = dialedCandidate;
        Socket = socket;
        Stream = new NetworkStream(socket, ownsSocket: true);
    }

    public Socket Socket { get; }

    public NetworkStream Stream { get; }

    public IPEndPoint Remote { get; }

    /// <summary>The peer's candidate this endpoint connected to; null when the peer connected to this endpoint.</summary>
    public string? DialedCandidate { get; }

    public ValueTask DisposeAsync() => Stream.DisposeAsync();
}

/// <summary>
/// The TCP port on which an endpoint accepts direct connections from its peers. One listener
/// serves all of an endpoint's connection attempts, so that a fixed, forwarded port can be used.
/// It listens only while an attempt is in progress, and a connection that does not present the
/// tag of such an attempt within two seconds is closed without an answer.
/// </summary>
internal sealed class TcpDirectListener(int port = 0) : IAsyncDisposable
{
    private const int MaxPendingHandshakes = 32;
    private readonly object _gate = new();
    private readonly Dictionary<ulong, TcpDirectAttempt> _attempts = [];
    private Socket? _socket;
    private CancellationTokenSource? _stop;
    private int _pending;
    private bool _disposed;

    /// <summary>Starts listening if necessary. Returns the port, or 0 when this endpoint cannot listen.</summary>
    public int Register(ulong tag, TcpDirectAttempt attempt)
    {
        lock (_gate)
        {
            if (_disposed || port < 0)
            {
                return 0;
            }
            if (_socket is null)
            {
                var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                try
                {
                    socket.Bind(new IPEndPoint(IPAddress.Any, port));
                    socket.Listen(16);
                }
                catch (SocketException)
                {
                    socket.Dispose();
                    return 0; // the endpoint can still connect outwards
                }
                _socket = socket;
                _stop = new CancellationTokenSource();
                _ = AcceptLoopAsync(socket, _stop.Token);
            }
            _attempts[tag] = attempt;
            return ((IPEndPoint)_socket.LocalEndPoint!).Port;
        }
    }

    public void Unregister(ulong tag)
    {
        lock (_gate)
        {
            if (_attempts.Remove(tag) && _attempts.Count == 0)
            {
                Close();
            }
        }
    }

    /// <summary>True while the port is open.</summary>
    internal bool IsListening
    {
        get
        {
            lock (_gate)
            {
                return _socket is not null;
            }
        }
    }

    private void Close()
    {
        _stop?.Cancel();
        _stop?.Dispose();
        _stop = null;
        _socket?.Dispose();
        _socket = null;
    }

    private async Task AcceptLoopAsync(Socket socket, CancellationToken stop)
    {
        while (!stop.IsCancellationRequested)
        {
            Socket accepted;
            try
            {
                accepted = await socket.AcceptAsync(stop).ConfigureAwait(false);
            }
            catch (SocketException ex) when (ex.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionAborted)
            {
                continue;
            }
            catch (Exception ex) when (ex is OperationCanceledException or SocketException or ObjectDisposedException)
            {
                return;
            }

            if (Interlocked.Increment(ref _pending) > MaxPendingHandshakes)
            {
                Interlocked.Decrement(ref _pending);
                accepted.Dispose();
                continue;
            }
            _ = HandleAsync(accepted, stop);
        }
    }

    private async Task HandleAsync(Socket accepted, CancellationToken stop)
    {
        bool kept = false;
        try
        {
            accepted.NoDelay = true;
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
            timeout.CancelAfter(TcpDirectAttempt.HelloTimeout);
            byte[] hello = new byte[TcpPath.HelloSize];
            await TcpDirectAttempt.ReadExactAsync(accepted, hello, timeout.Token).ConfigureAwait(false);

            TcpDirectAttempt? attempt = null;
            if (hello[0] == TcpPath.Hello)
            {
                lock (_gate)
                {
                    _attempts.TryGetValue(BinaryPrimitives.ReadUInt64BigEndian(hello.AsSpan(1)), out attempt);
                }
            }
            kept = attempt is not null && await attempt.OnAcceptedAsync(accepted, hello[9], timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            Interlocked.Decrement(ref _pending);
            if (!kept)
            {
                accepted.Dispose();
            }
        }
    }

    public ValueTask DisposeAsync()
    {
        lock (_gate)
        {
            _disposed = true;
            _attempts.Clear();
            Close();
        }
        return default;
    }
}

/// <summary>
/// The TCP part of one direct connection attempt: accepts connections from the peer, connects to
/// the peer's candidates, and lets the initiator pick one connection for the session.
/// </summary>
/// <remarks>
/// As with UDP probes, the tag only finds a working connection; it proves nothing about identity.
/// That is established by the TLS handshake on the selected connection, and the session bind then
/// checks that one endpoint really connected to an address the other one announced.
/// </remarks>
internal sealed class TcpDirectAttempt : IAsyncDisposable
{
    internal static readonly TimeSpan HelloTimeout = TimeSpan.FromSeconds(2);
    private const int MaxConnections = 16;
    private const int MaxDialedCandidates = 8;

    private readonly bool _initiator;
    private readonly byte[] _hello = new byte[TcpPath.HelloSize];
    private readonly ulong _tag;
    private readonly TcpDirectListener? _listener;
    private readonly Func<bool> _tryChoose;
    private readonly CancellationTokenSource _stop = new();
    private readonly List<TcpDirectConnection> _connections = [];
    private readonly TaskCompletionSource<TcpDirectConnection> _validated = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<TcpDirectConnection> _selected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private TcpDirectConnection? _handedOver;

    /// <param name="tryChoose">Device side: returns true exactly once per attempt, for the path (UDP or TCP) the initiator selected first.</param>
    public TcpDirectAttempt(string role, ReadOnlySpan<byte> tag, TcpDirectListener? listener, Func<bool> tryChoose)
    {
        _initiator = role == SessionRoles.Initiator;
        _hello[0] = TcpPath.Hello;
        tag[..8].CopyTo(_hello.AsSpan(1));
        _hello[9] = _initiator ? TcpPath.RoleInitiator : TcpPath.RoleDevice;
        _tag = BinaryPrimitives.ReadUInt64BigEndian(tag);
        _listener = listener;
        _tryChoose = tryChoose;
        ListenPort = listener?.Register(_tag, this) ?? 0;
    }

    /// <summary>The port this endpoint accepts the peer's connections on; 0 when it only connects outwards.</summary>
    public int ListenPort { get; }

    /// <summary>Initiator: the first connection on which the peer showed the session's tag.</summary>
    public Task<TcpDirectConnection> Validated => _validated.Task;

    /// <summary>Device: the connection the initiator selected.</summary>
    public Task<TcpDirectConnection> Selected => _selected.Task;

    /// <summary>Connects to the peer's announced candidates.</summary>
    public void Dial(IEnumerable<IPEndPoint> candidates)
    {
        foreach (IPEndPoint candidate in candidates.Take(MaxDialedCandidates))
        {
            _ = DialAsync(candidate);
        }
    }

    private async Task DialAsync(IPEndPoint candidate)
    {
        var socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
        bool kept = false;
        try
        {
            await socket.ConnectAsync(candidate, _stop.Token).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
            timeout.CancelAfter(HelloTimeout);
            await socket.SendAsync(_hello, SocketFlags.None, timeout.Token).ConfigureAwait(false);
            byte[] peer = new byte[TcpPath.HelloSize];
            await ReadExactAsync(socket, peer, timeout.Token).ConfigureAwait(false);
            kept = peer.AsSpan(0, 9).SequenceEqual(_hello.AsSpan(0, 9)) && peer[9] == PeerRole && Add(new TcpDirectConnection(socket, candidate.ToString()));
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }
        finally
        {
            if (!kept)
            {
                socket.Dispose();
            }
        }
    }

    /// <summary>Called by the listener for a connection that presented this attempt's tag.</summary>
    internal async Task<bool> OnAcceptedAsync(Socket socket, byte peerRole, CancellationToken cancellationToken)
    {
        if (peerRole != PeerRole || _stop.IsCancellationRequested)
        {
            return false;
        }
        await socket.SendAsync(_hello, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        return Add(new TcpDirectConnection(socket, dialedCandidate: null));
    }

    private byte PeerRole => _initiator ? TcpPath.RoleDevice : TcpPath.RoleInitiator;

    private bool Add(TcpDirectConnection connection)
    {
        lock (_connections)
        {
            if (_stop.IsCancellationRequested || _connections.Count >= MaxConnections)
            {
                return false;
            }
            _connections.Add(connection);
        }

        connection.Socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
        connection.Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, 30);
        connection.Socket.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, 10);
        if (_initiator)
        {
            _validated.TrySetResult(connection);
        }
        else
        {
            _ = AwaitSelectionAsync(connection);
        }
        return true;
    }

    /// <summary>Initiator: tells the device that this connection carries the session, and waits for its confirmation.</summary>
    public async Task SelectAsync(TcpDirectConnection connection, CancellationToken cancellationToken)
    {
        byte[] select = [TcpPath.Select];
        await connection.Socket.SendAsync(select, SocketFlags.None, cancellationToken).ConfigureAwait(false);
        byte[] answer = new byte[1];
        await ReadExactAsync(connection.Socket, answer, cancellationToken).ConfigureAwait(false);
        if (answer[0] != TcpPath.Select)
        {
            throw new IOException("The peer did not confirm the selected connection.");
        }
        _handedOver = connection;
    }

    private async Task AwaitSelectionAsync(TcpDirectConnection connection)
    {
        try
        {
            byte[] select = new byte[1];
            await ReadExactAsync(connection.Socket, select, _stop.Token).ConfigureAwait(false);
            if (select[0] == TcpPath.Select && _tryChoose())
            {
                await connection.Socket.SendAsync(select, SocketFlags.None, _stop.Token).ConfigureAwait(false);
                _handedOver = connection;
                _selected.TrySetResult(connection);
                return;
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException)
        {
        }

        if (!ReferenceEquals(_handedOver, connection))
        {
            await connection.DisposeAsync().ConfigureAwait(false);
        }
    }

    internal static async Task ReadExactAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        while (buffer.Length > 0)
        {
            int read = await socket.ReceiveAsync(buffer, SocketFlags.None, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                throw new IOException("The connection was closed.");
            }
            buffer = buffer[read..];
        }
    }

    public async ValueTask DisposeAsync()
    {
        TcpDirectConnection[] open;
        lock (_connections)
        {
            if (_stop.IsCancellationRequested)
            {
                return;
            }
            _stop.Cancel();
            open = [.. _connections];
            _connections.Clear();
        }

        _listener?.Unregister(_tag);
        _validated.TrySetCanceled();
        _selected.TrySetCanceled();
        foreach (TcpDirectConnection connection in open)
        {
            if (!ReferenceEquals(connection, _handedOver))
            {
                await connection.DisposeAsync().ConfigureAwait(false);
            }
        }
    }
}
