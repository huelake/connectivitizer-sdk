using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Mux;
using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Client.Transport;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Sessions;

/// <summary>Everything needed to turn an established path into an authenticated session.</summary>
internal sealed record TunnelSessionParameters
{
    /// <summary>The byte stream to the peer (relay WebSocket or direct connection). Owned by the session.</summary>
    public required Stream Path { get; init; }

    /// <summary><see cref="SessionRoles"/> of this endpoint.</summary>
    public required string Role { get; init; }

    /// <summary>The <see cref="ConnectionModes"/> value this endpoint observed for <see cref="Path"/>.</summary>
    public required string Mode { get; init; }

    /// <summary>This endpoint's certificate identity. Needed for a session whose grant names the certificate layer.</summary>
    public EndpointIdentity? Identity { get; init; }

    /// <summary>Local trust decision for the peer of a certificate session.</summary>
    public IPeerVerifier? Verifier { get; init; }

    /// <summary>
    /// The keys for a session whose grant names the shared-key layer. The initiator uses the first;
    /// the device accepts whichever of them the initiator proves to hold.
    /// </summary>
    public IReadOnlyList<SharedKey> SharedKeys { get; init; } = [];

    /// <summary>What the platform calls the peer. A label for logs and for display; it authenticates nothing.</summary>
    public string? PeerLabel { get; init; }

    public required string GrantToken { get; init; }

    public required SessionGrant Grant { get; init; }

    public string? DirectFailureReason { get; init; }

    /// <summary>Direct sessions: the peer's network address on the selected path.</summary>
    public string? PeerAddress { get; init; }

    /// <summary>Direct sessions: hash of the candidate list this endpoint announced.</summary>
    public string? LocalCandidatesHash { get; init; }

    /// <summary>Direct sessions: hash of the candidate list received from the peer through signaling.</summary>
    public string? RemoteCandidatesHash { get; init; }

    /// <summary>One of <see cref="PathTransports"/>.</summary>
    public string? Transport { get; init; }

    /// <summary>Direct TCP sessions: the peer's candidate this endpoint connected to; null when the peer connected to this endpoint.</summary>
    public string? DialedCandidate { get; init; }

    /// <summary>Direct TCP sessions: the TCP candidates this endpoint announced.</summary>
    public IReadOnlyList<string> LocalTcpCandidates { get; init; } = [];

    /// <summary>Set for relayed sessions, so that lease renewals also reach the relay.</summary>
    public RelayPath? Relay { get; init; }

    /// <summary>Device side: verifies a renewed grant offline (signature, audience, lease).</summary>
    public Func<string, GrantValidation>? ValidateRenewedGrant { get; init; }

    /// <summary>Device side: the local service configuration.</summary>
    public IServiceDirectory? Services { get; init; }

    /// <summary>Device side: how long past its lease a session is tolerated before it is ended.</summary>
    public TimeSpan LeaseGrace { get; init; } = TimeSpan.FromSeconds(30);

    public TimeProvider Time { get; init; } = TimeProvider.System;
}

/// <summary>
/// An authenticated, end-to-end encrypted session between an initiator and a device, carrying any
/// number of service streams.
/// </summary>
public sealed class TunnelSession : IAsyncDisposable
{
    private const int MaxControlMessage = 64 * 1024;
    private static readonly TimeSpan HandshakeTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan ServiceOpenTimeout = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan LocalConnectTimeout = TimeSpan.FromSeconds(5);

    private readonly TunnelSessionParameters _parameters;
    private readonly MuxSession _mux;
    private readonly MuxStream _control;
    private readonly SemaphoreSlim _controlWrite = new(1, 1);
    private readonly TaskCompletionSource<string> _completion = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly CancellationTokenSource _stop = new();
    private readonly List<Task> _background = [];
    private long _leaseExpiresAt;
    private long _bytesSent;
    private long _bytesReceived;
    private int _disposed;

    private TunnelSession(TunnelSessionParameters parameters, MuxSession mux, MuxStream control, PeerIdentity peer)
    {
        _parameters = parameters;
        _mux = mux;
        _control = control;
        _leaseExpiresAt = parameters.Grant.LeaseExpiresAt;
        Peer = peer;
        Info = new ConnectionInfo
        {
            SessionId = parameters.Grant.SessionId,
            Mode = parameters.Mode,
            Trust = peer.Trust,
            E2eMethod = parameters.Grant.E2eMethod,
            PeerFingerprint = peer.Fingerprint,
            PeerName = peer.Name,
            DirectFailureReason = parameters.DirectFailureReason,
            PeerAddress = parameters.PeerAddress,
            Transport = parameters.Transport ?? (parameters.Mode == ConnectionModes.Direct ? PathTransports.UdpKcp : PathTransports.RelayWs),
        };

        Task controlLoop = Task.Run(ControlLoopAsync);
        _background.Add(controlLoop);
        // A peer that ends the session says why on the control stream and closes the mux right after.
        // Both arrive together, so the control loop is given the time to read the reason before the
        // session takes the mux's own, less specific one.
        _ = mux.Completion.ContinueWith(async t =>
        {
            try
            {
                await controlLoop.WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is TimeoutException or OperationCanceledException)
            {
            }
            _completion.TrySetResult(t.Result);
        }, TaskScheduler.Default);
        if (parameters.Role == SessionRoles.Device)
        {
            _background.Add(Task.Run(AcceptLoopAsync));
            _background.Add(Task.Run(LeaseWatchdogAsync));
        }
    }

    /// <summary>The verified properties of this session.</summary>
    public ConnectionInfo Info { get; }

    /// <summary>The authenticated remote endpoint.</summary>
    public PeerIdentity Peer { get; }

    /// <summary>Completes with an <see cref="ErrorCodes"/> value when the session has ended.</summary>
    public Task<string> Completion => _completion.Task;

    /// <summary>Application bytes this endpoint sent to the peer on service streams, as counted here.</summary>
    public long BytesSent => Interlocked.Read(ref _bytesSent);

    /// <summary>Application bytes this endpoint received from the peer on service streams, as counted here.</summary>
    public long BytesReceived => Interlocked.Read(ref _bytesReceived);

    /// <summary>Ends the session for <paramref name="reason"/> (an <see cref="ErrorCodes"/> value), telling the peer why.</summary>
    public Task EndAsync(string reason) => EndCoreAsync(reason);

    /// <summary>Unix time until which the session is authorised without a renewed grant.</summary>
    public long LeaseExpiresAt => Interlocked.Read(ref _leaseExpiresAt);

    /// <summary>
    /// Runs the end-to-end handshake over an established path - mutual TLS against local trust, or
    /// the shared-key handshake, whichever the grant names - then the session bind that ties the
    /// encrypted channel to the grant and to the observed route.
    /// Throws <see cref="TunnelException"/> or <see cref="SecureChannelException"/>; never returns
    /// a session that is not fully verified.
    /// </summary>
    internal static async Task<TunnelSession> EstablishAsync(TunnelSessionParameters parameters, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(HandshakeTimeout);
        bool isInitiator = parameters.Role == SessionRoles.Initiator;

        // The grant says which end-to-end layer the session uses; an endpoint never picks another one.
        string method = parameters.Grant.E2eMethod;
        bool sharedKey = method == E2eMethods.SharedKey;
        if (sharedKey ? parameters.SharedKeys.Count == 0 : method != E2eMethods.Tls13 || parameters.Identity is null || parameters.Verifier is null)
        {
            await parameters.Path.DisposeAsync().ConfigureAwait(false);
            throw new TunnelException(sharedKey ? ErrorCodes.E2eSharedKeyMismatch : ErrorCodes.E2eNoCommonMethod,
                sharedKey ? "This endpoint has no shared key for the session." : $"This endpoint cannot take part in a session with the end-to-end layer '{method}'.");
        }

        SecureStream secure;
        try
        {
            if (sharedKey)
            {
                byte[] prologue = SharedKeyChannel.Prologue(parameters.Grant.SessionId, HashGrant(parameters.GrantToken));
                string label = parameters.PeerLabel ?? (isInitiator ? parameters.Grant.Device.Id : parameters.Grant.Initiator.Id);
                secure = isInitiator
                    ? await SharedKeyChannel.ConnectAsync(parameters.Path, parameters.SharedKeys[0], prologue, label, timeout.Token).ConfigureAwait(false)
                    : await SharedKeyChannel.AcceptAsync(parameters.Path, parameters.SharedKeys, prologue, label, timeout.Token).ConfigureAwait(false);
            }
            else
            {
                secure = isInitiator
                    ? await SecureChannel.ConnectAsync(parameters.Path, parameters.Identity!, parameters.Verifier!, timeout.Token).ConfigureAwait(false)
                    : await SecureChannel.AcceptAsync(parameters.Path, parameters.Identity!, parameters.Verifier!, timeout.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            await parameters.Path.DisposeAsync().ConfigureAwait(false);
            throw new TunnelException(ErrorCodes.E2eHandshakeFailed, "The end-to-end handshake timed out.");
        }

        // The platform told us which identity to expect; the handshake showed which one is really there.
        string? expected = sharedKey ? null : isInitiator ? parameters.Grant.Device.Fingerprint : parameters.Grant.Initiator.Fingerprint;
        if (expected is not null && !string.Equals(expected, secure.Peer.Fingerprint, StringComparison.Ordinal))
        {
            await secure.DisposeAsync().ConfigureAwait(false);
            throw new TunnelException(ErrorCodes.E2eSessionBindMismatch, "The peer's identity is not the one named in the session grant.");
        }

        var mux = new MuxSession(secure.Stream, isInitiator);
        mux.Start();
        try
        {
            MuxStream control = isInitiator
                ? await mux.OpenStreamAsync(timeout.Token).ConfigureAwait(false)
                : await mux.AcceptStreamAsync(timeout.Token).ConfigureAwait(false);

            var ownBind = new SessionBind
            {
                SessionId = parameters.Grant.SessionId,
                GrantHash = HashGrant(parameters.GrantToken),
                Role = parameters.Role,
                Mode = parameters.Mode,
                CandidatesHash = parameters.LocalCandidatesHash,
                DialedCandidate = parameters.Transport == PathTransports.Tcp ? parameters.DialedCandidate : null,
            };
            await WriteControlAsync(control, new ControlMessage { Bind = ownBind }, timeout.Token).ConfigureAwait(false);
            ControlMessage? received = await ReadControlAsync(control, timeout.Token).ConfigureAwait(false);

            if (received is null)
            {
                // Each side authenticates the other on its own, and in TLS 1.3 our handshake can finish
                // before the peer's verdict arrives. A peer that does not trust us just closes.
                throw new TunnelException(ErrorCodes.E2eHandshakeFailed, "The peer ended the session during the handshake; it may not trust this endpoint's identity.");
            }
            if (received.Error is { } peerError)
            {
                throw new TunnelException(peerError, $"The peer refused the session ({peerError}).");
            }
            if (received.Bind is not { } peerBind
                || peerBind.SessionId != ownBind.SessionId
                || peerBind.GrantHash != ownBind.GrantHash
                || peerBind.Mode != ownBind.Mode
                || peerBind.Role != (isInitiator ? SessionRoles.Device : SessionRoles.Initiator)
                // The addresses probed came through the control plane; here the authenticated peer confirms them.
                || (parameters.Mode == ConnectionModes.Direct && (peerBind.CandidatesHash is null || peerBind.CandidatesHash != parameters.RemoteCandidatesHash))
                // A TCP connection counts as direct only if one endpoint opened it to an address the other announced.
                || (parameters.Mode == ConnectionModes.Direct && parameters.Transport == PathTransports.Tcp && !(parameters.DialedCandidate is not null
                    ? peerBind.DialedCandidate is null
                    : peerBind.DialedCandidate is not null && parameters.LocalTcpCandidates.Contains(peerBind.DialedCandidate))))
            {
                await TryWriteErrorAsync(control, ErrorCodes.E2eSessionBindMismatch).ConfigureAwait(false);
                throw new TunnelException(ErrorCodes.E2eSessionBindMismatch, "The two endpoints do not agree on the session they are part of.");
            }

            return new TunnelSession(parameters, mux, control, secure.Peer);
        }
        catch (Exception ex)
        {
            await mux.DisposeAsync().ConfigureAwait(false);
            if (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                throw new TunnelException(ErrorCodes.E2eHandshakeFailed, "The session bind timed out.");
            }
            if (ex is IOException and not TunnelException)
            {
                // Each side authenticates the other on its own; a peer that rejected us simply goes away.
                throw new TunnelException(ErrorCodes.E2eHandshakeFailed, "The peer ended the session during the handshake.", ex);
            }
            throw;
        }
    }

    /// <summary>Opens a stream to one of the device's services. Initiator side.</summary>
    public async Task<Stream> OpenStreamAsync(string service, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(service);
        if (_parameters.Role != SessionRoles.Initiator)
        {
            throw new InvalidOperationException("Only the initiating endpoint opens service streams.");
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        timeout.CancelAfter(ServiceOpenTimeout);

        MuxStream stream;
        try
        {
            stream = await _mux.OpenStreamAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (IOException ex)
        {
            throw new TunnelException(ErrorCodes.SessionClosed, "The session is closed.", ex);
        }

        try
        {
            await WriteFramedAsync(stream, new ServiceOpenRequest { Service = service }, ProtocolJsonContext.Default.ServiceOpenRequest, lengthBytes: 2, timeout.Token).ConfigureAwait(false);
            ServiceOpenResponse? response = await ReadFramedAsync(stream, ProtocolJsonContext.Default.ServiceOpenResponse, lengthBytes: 2, timeout.Token).ConfigureAwait(false);
            if (response is not { Ok: true })
            {
                string code = response?.Error ?? ErrorCodes.SessionClosed;
                throw new TunnelException(code, $"The device did not open service '{service}' ({code}).");
            }
            return new CountingStream(stream, this);
        }
        catch (Exception ex)
        {
            await stream.DisposeAsync().ConfigureAwait(false);
            if (ex is OperationCanceledException && !cancellationToken.IsCancellationRequested)
            {
                throw new TunnelException(ErrorCodes.SessionClosed, $"Opening service '{service}' timed out.");
            }
            if (ex is IOException and not TunnelException)
            {
                throw new TunnelException(ErrorCodes.SessionClosed, "The session ended while opening the service.", ex);
            }
            throw;
        }
    }

    /// <summary>
    /// An HTTP handler whose connections are streams to <paramref name="service"/>. Use it with
    /// <see cref="HttpClient"/> or <c>ClientWebSocket.ConnectAsync(uri, invoker, token)</c>; the
    /// host name in request URIs is not used for routing.
    /// </summary>
    public SocketsHttpHandler CreateHttpHandler(string service)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(service);
        return new SocketsHttpHandler
        {
            ConnectCallback = async (_, cancellationToken) => await OpenStreamAsync(service, cancellationToken).ConfigureAwait(false),
            UseProxy = false,
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
        };
    }

    /// <summary>Extends the session with a freshly issued grant. Initiator side.</summary>
    public async Task RenewLeaseAsync(string grantToken, SessionGrant grant, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(grantToken);
        ArgumentNullException.ThrowIfNull(grant);
        if (grant.SessionId != _parameters.Grant.SessionId)
        {
            throw new ArgumentException("The grant belongs to another session.", nameof(grant));
        }

        await WriteControlLockedAsync(new ControlMessage { Lease = new LeaseRenewal { GrantToken = grantToken } }, cancellationToken).ConfigureAwait(false);
        if (_parameters.Relay is { } relay)
        {
            await relay.RenewLeaseAsync(grantToken, cancellationToken).ConfigureAwait(false);
        }
        ExtendLease(grant.LeaseExpiresAt);
    }

    private async Task ControlLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                ControlMessage? message = await ReadControlAsync(_control, _stop.Token).ConfigureAwait(false);
                if (message is null)
                {
                    return;
                }
                if (message.Error is { } error)
                {
                    await EndCoreAsync(error).ConfigureAwait(false);
                    return;
                }
                if (message.Lease is { } lease && _parameters.Role == SessionRoles.Device)
                {
                    HandleLeaseRenewal(lease.GrantToken);
                }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or JsonException)
        {
        }
    }

    private void HandleLeaseRenewal(string token)
    {
        if (_parameters.ValidateRenewedGrant?.Invoke(token) is not { Grant: { } renewed })
        {
            return;
        }

        SessionGrant original = _parameters.Grant;
        // A renewal may only prolong this very session for the same two identities; it cannot widen anything.
        if (renewed.SessionId == original.SessionId
            && renewed.WorkspaceId == original.WorkspaceId
            && renewed.Initiator.Id == original.Initiator.Id
            && renewed.Initiator.Fingerprint == original.Initiator.Fingerprint
            && renewed.E2eMethod == original.E2eMethod
            && renewed.Device.Id == original.Device.Id)
        {
            ExtendLease(renewed.LeaseExpiresAt);
        }
    }

    private void ExtendLease(long leaseExpiresAt)
    {
        long current;
        do
        {
            current = Interlocked.Read(ref _leaseExpiresAt);
            if (leaseExpiresAt <= current)
            {
                return;
            }
        }
        while (Interlocked.CompareExchange(ref _leaseExpiresAt, leaseExpiresAt, current) != current);
    }

    /// <summary>Device side: a session whose authorisation ran out is ended, whatever the platform or the peer say.</summary>
    private async Task LeaseWatchdogAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                long remaining = LeaseExpiresAt + (long)_parameters.LeaseGrace.TotalSeconds - _parameters.Time.GetUtcNow().ToUnixTimeSeconds();
                if (remaining <= 0)
                {
                    await EndCoreAsync(ErrorCodes.LeaseExpired).ConfigureAwait(false);
                    return;
                }
                await Task.Delay(TimeSpan.FromSeconds(Math.Clamp(remaining, 1, 15)), _parameters.Time, _stop.Token).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task AcceptLoopAsync()
    {
        try
        {
            while (!_stop.IsCancellationRequested)
            {
                MuxStream stream = await _mux.AcceptStreamAsync(_stop.Token).ConfigureAwait(false);
                _ = Task.Run(() => ServeStreamAsync(stream));
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
        }
    }

    /// <summary>Device side: authorise one service stream, connect it to the local application and copy bytes.</summary>
    private async Task ServeStreamAsync(MuxStream stream)
    {
        await using (stream.ConfigureAwait(false))
        {
            Socket? local = null;
            try
            {
                using var openTimeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                openTimeout.CancelAfter(ServiceOpenTimeout);
                ServiceOpenRequest? request = await ReadFramedAsync(stream, ProtocolJsonContext.Default.ServiceOpenRequest, lengthBytes: 2, openTimeout.Token).ConfigureAwait(false);
                if (request is null || string.IsNullOrEmpty(request.Service))
                {
                    return;
                }

                // Platform authorisation (the grant) and the device's own configuration both have to agree.
                ServiceLookup lookup = !_parameters.Grant.Services.Contains(request.Service, StringComparer.Ordinal)
                    ? ServiceLookup.Deny(ErrorCodes.DeniedByGrant)
                    : _parameters.Services?.Resolve(request.Service, Peer) ?? ServiceLookup.Deny(ErrorCodes.ServiceNotExposed);

                if (lookup.Target is { } target)
                {
                    local = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
                    try
                    {
                        using var connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                        connectTimeout.CancelAfter(LocalConnectTimeout);
                        await local.ConnectAsync(target.Host, target.Port, connectTimeout.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex) when (ex is SocketException or OperationCanceledException)
                    {
                        lookup = ServiceLookup.Deny(ErrorCodes.TargetUnreachable);
                    }
                }

                var response = new ServiceOpenResponse { Ok = lookup.ErrorCode is null, Error = lookup.ErrorCode };
                await WriteFramedAsync(stream, response, ProtocolJsonContext.Default.ServiceOpenResponse, lengthBytes: 2, openTimeout.Token).ConfigureAwait(false);
                if (!response.Ok || local is null)
                {
                    await stream.CompleteWritesAsync(openTimeout.Token).ConfigureAwait(false);
                    return;
                }

                await using var localStream = new NetworkStream(local, ownsSocket: false);
                Task toLocal = CopyAsync(stream, localStream, () => { local.Shutdown(SocketShutdown.Send); return ValueTask.CompletedTask; },
                    count => Interlocked.Add(ref _bytesReceived, count), _stop.Token);
                Task toPeer = CopyAsync(localStream, stream, () => stream.CompleteWritesAsync(_stop.Token),
                    count => Interlocked.Add(ref _bytesSent, count), _stop.Token);
                await Task.WhenAll(toLocal, toPeer).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or JsonException or ObjectDisposedException)
            {
            }
            finally
            {
                local?.Dispose();
            }
        }
    }

    private static async Task CopyAsync(Stream from, Stream to, Func<ValueTask> endOfStream, Action<int> count, CancellationToken cancellationToken)
    {
        byte[] buffer = System.Buffers.ArrayPool<byte>.Shared.Rent(32 * 1024);
        try
        {
            int read;
            while ((read = await from.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
            {
                await to.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
                count(read);
            }
            await endOfStream().ConfigureAwait(false);
        }
        finally
        {
            System.Buffers.ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>Ends the session for a specific reason, telling the peer why when that is still possible.</summary>
    private async Task EndCoreAsync(string reason)
    {
        if (!_completion.TrySetResult(reason))
        {
            return;
        }
        await TryWriteErrorLockedAsync(reason).ConfigureAwait(false);
        await _stop.CancelAsync().ConfigureAwait(false);
        await _mux.DisposeAsync().ConfigureAwait(false);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        _completion.TrySetResult(ErrorCodes.SessionClosed);
        await _stop.CancelAsync().ConfigureAwait(false);
        await _mux.DisposeAsync().ConfigureAwait(false);
        try
        {
            await Task.WhenAll(_background).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
        }
        _stop.Dispose();
    }

    private async Task WriteControlLockedAsync(ControlMessage message, CancellationToken cancellationToken)
    {
        await _controlWrite.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await WriteControlAsync(_control, message, cancellationToken).ConfigureAwait(false);
        }
        catch (IOException ex) when (ex is not TunnelException)
        {
            throw new TunnelException(ErrorCodes.SessionClosed, "The session is closed.", ex);
        }
        finally
        {
            _controlWrite.Release();
        }
    }

    private async Task TryWriteErrorLockedAsync(string errorCode)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await WriteControlLockedAsync(new ControlMessage { Error = errorCode }, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException)
        {
        }
    }

    private static async Task TryWriteErrorAsync(MuxStream control, string errorCode)
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await WriteControlAsync(control, new ControlMessage { Error = errorCode }, timeout.Token).ConfigureAwait(false);
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException)
        {
        }
    }

    private static Task WriteControlAsync(MuxStream control, ControlMessage message, CancellationToken cancellationToken)
        => WriteFramedAsync(control, message, ProtocolJsonContext.Default.ControlMessage, lengthBytes: 4, cancellationToken);

    private static Task<ControlMessage?> ReadControlAsync(MuxStream control, CancellationToken cancellationToken)
        => ReadFramedAsync(control, ProtocolJsonContext.Default.ControlMessage, lengthBytes: 4, cancellationToken);

    /// <summary>Writes a JSON message prefixed with its big-endian length (2 or 4 bytes).</summary>
    private static async Task WriteFramedAsync<T>(Stream stream, T message, JsonTypeInfo<T> typeInfo, int lengthBytes, CancellationToken cancellationToken)
    {
        byte[] json = JsonSerializer.SerializeToUtf8Bytes(message, typeInfo);
        byte[] frame = new byte[lengthBytes + json.Length];
        if (lengthBytes == 2)
        {
            BinaryPrimitives.WriteUInt16BigEndian(frame, checked((ushort)json.Length));
        }
        else
        {
            BinaryPrimitives.WriteUInt32BigEndian(frame, (uint)json.Length);
        }
        json.CopyTo(frame.AsSpan(lengthBytes));
        await stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Reads one length-prefixed JSON message; returns null at a clean end of stream.</summary>
    private static async Task<T?> ReadFramedAsync<T>(Stream stream, JsonTypeInfo<T> typeInfo, int lengthBytes, CancellationToken cancellationToken)
        where T : class
    {
        byte[] prefix = new byte[lengthBytes];
        int read = await stream.ReadAtLeastAsync(prefix, lengthBytes, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        if (read < lengthBytes)
        {
            return null;
        }

        uint length = lengthBytes == 2 ? BinaryPrimitives.ReadUInt16BigEndian(prefix) : BinaryPrimitives.ReadUInt32BigEndian(prefix);
        if (length is 0 or > MaxControlMessage)
        {
            throw new IOException("Malformed tunnel message.");
        }

        byte[] json = new byte[length];
        await stream.ReadExactlyAsync(json, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize(json, typeInfo);
    }

    /// <summary>A service stream that adds what passes through it to the session's traffic counters.</summary>
    private sealed class CountingStream(MuxStream inner, TunnelSession session) : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            int read = await inner.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            Interlocked.Add(ref session._bytesReceived, read);
            return read;
        }

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await inner.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            Interlocked.Add(ref session._bytesSent, buffer.Length);
        }

        public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
            => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override void Flush()
        {
        }

        public override Task FlushAsync(CancellationToken cancellationToken) => Task.CompletedTask;

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override ValueTask DisposeAsync() => inner.DisposeAsync();

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                inner.Dispose();
            }
            base.Dispose(disposing);
        }
    }

    internal static string HashGrant(string grantToken) => Convert.ToHexStringLower(SHA256.HashData(Encoding.ASCII.GetBytes(grantToken)));
}
