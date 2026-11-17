using System.Collections.Concurrent;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Platform;
using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Client.Sessions;
using Huelake.Connectivitizer.Client.State;
using Huelake.Connectivitizer.Client.Transport;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client;

public sealed class ConnectivitizerClientOptions
{
    /// <summary>Base URL of the Connectivitizer API, e.g. <c>https://api.connectivitizer.com/api/connectivitizer</c>.</summary>
    public required Uri ApiUrl { get; init; }

    /// <summary>The application's API key (<c>czk_…</c>). Either this or <see cref="TokenProvider"/> is needed.</summary>
    public string? ApiKey { get; init; }

    /// <summary>
    /// For an application whose user signs in instead of holding an API key: called whenever a
    /// token is needed, it returns what <see cref="PlatformApi.GetAppTokenAsync"/> answers for the
    /// user's current sign-in. Such an application uses shared keys; its certificate, if it has
    /// one, is not announced, because a client that many users sign in to has no single identity.
    /// </summary>
    public Func<CancellationToken, Task<TokenResponse>>? TokenProvider { get; init; }

    /// <summary>
    /// This application's certificate identity. Its private key stays in this process. Needed to
    /// reach devices by certificate; an application that only uses shared keys leaves it out.
    /// </summary>
    public EndpointIdentity? Identity { get; init; }

    /// <summary>
    /// Keys this application shares with devices. For a device the key named like the device is
    /// used; otherwise the only key, or the one named <c>default</c>. The platform never sees them.
    /// </summary>
    public IReadOnlyList<SharedKey> SharedKeys { get; init; } = [];

    /// <summary>The identities of devices this application trusts.</summary>
    public TrustStore Trust { get; init; } = new();

    /// <summary>
    /// When true, a device that is not pinned locally is accepted with the identity the platform
    /// reports for it, and remembered. Convenient, but it means trusting the platform to introduce
    /// the right device; such sessions report <see cref="TrustLevel.PlatformIntroduced"/>. Off by default.
    /// </summary>
    public bool AllowPlatformIntroducedPeers { get; init; }

    /// <summary>Restricts the connection modes to request. Null requests everything the policies permit.</summary>
    public string[]? Modes { get; init; }

    /// <summary>When true this endpoint never attempts a direct connection and always uses the relay.</summary>
    public bool DisableDirect { get; init; }

    /// <summary>
    /// STUN servers (<c>host:port</c>) to learn this endpoint's public address from. Null uses the
    /// ones the platform announces. Supplying your own means the address an endpoint offers to its
    /// peer does not depend on the platform at all.
    /// </summary>
    public IReadOnlyList<string>? StunServers { get; init; }

    /// <summary>Offer loopback addresses as direct candidates. Only useful when both endpoints run on the same machine.</summary>
    public bool IncludeLoopbackCandidates { get; init; }

    /// <summary>Which kinds of direct path this endpoint attempts. Both by default.</summary>
    public DirectTransports DirectTransports { get; init; } = DirectTransports.All;

    /// <summary>
    /// TCP port on which this endpoint accepts its peer's direct connection while a connection is
    /// being set up. 0 picks a free port each time; a fixed port is needed when a router forwards
    /// it (see <see cref="PublicTcpEndpoints"/>); -1 never listens, so this endpoint only connects outwards.
    /// </summary>
    public int TcpListenPort { get; init; }

    /// <summary>
    /// Addresses (<c>host:port</c>) under which <see cref="TcpListenPort"/> is reachable from the
    /// internet, for example a port forwarded by the router. Announced to the peer of a session
    /// as places to connect to; a peer that cannot be reached itself can then still connect directly.
    /// </summary>
    public IReadOnlyList<string> PublicTcpEndpoints { get; init; } = [];

    public HttpClient? HttpClient { get; init; }

    /// <summary>
    /// Set only by the platform's compatibility gateway: it connects on behalf of the application
    /// whose API key it was given, under its own identity, and all its sessions are compatibility
    /// sessions. Not available to applications.
    /// </summary>
    internal string? GatewaySecret { get; init; }

    /// <summary>
    /// Set by a device that opens sessions itself: its own signaling connection, once it is connected. The
    /// client then logs in nowhere and owns neither that connection nor <see cref="TcpListener"/>.
    /// </summary>
    internal Func<CancellationToken, Task<SignalingClient>>? Signaling { get; init; }

    /// <summary>The device's listener for direct TCP paths, shared with the sessions it opens.</summary>
    internal TcpDirectListener? TcpListener { get; init; }

    /// <summary>Called when the opening of a session is over, whether it succeeded or not.</summary>
    internal Action<string>? Opened { get; init; }

    internal Action<string>? Log { get; init; }
}

/// <summary>
/// The calling side: an application that connects to services on registered devices.
/// </summary>
/// <example>
/// <code>
/// await using var client = new ConnectivitizerClient(options);
/// await using TunnelSession session = await client.ConnectAsync("home-pc", ["api"]);
/// using var http = new HttpClient(session.CreateHttpHandler("api")) { BaseAddress = new Uri("http://api") };
/// string body = await http.GetStringAsync("/health");
/// Console.WriteLine(session.Info.Mode); // direct, e2e-relay or compatibility - as verified by this endpoint
/// </code>
/// </example>
public sealed class ConnectivitizerClient : IAsyncDisposable
{
    private static readonly TimeSpan AnswerTimeout = TimeSpan.FromSeconds(15);

    /// <summary>How long a direct path is looked for before the relay is used instead.</summary>
    private static readonly TimeSpan DirectBudget = TimeSpan.FromSeconds(3);

    private readonly ConnectivitizerClientOptions _options;
    private readonly PlatformApi _api;
    private readonly GrantVerifier _grants;
    private readonly SemaphoreSlim _signalingGate = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<SignalConnectAnswer>> _answers = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<byte[]>> _candidates = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TunnelSession> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, bool> _own = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _stop = new();
    private readonly TcpDirectListener? _tcpListener;
    private SignalingClient? _signaling;
    private int _requesting;
    private int _disposed;

    public ConnectivitizerClient(ConnectivitizerClientOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        if (options.Signaling is null && options.ApiKey is null == options.TokenProvider is null)
        {
            throw new ArgumentException("Set exactly one of ApiKey and TokenProvider.", nameof(options));
        }
        if (options.Identity is null && options.SharedKeys.Count == 0)
        {
            throw new ArgumentException("An application needs a certificate identity, a shared key, or both: without either there is nothing to encrypt end to end with.", nameof(options));
        }
        _api = new PlatformApi(options.ApiUrl, options.HttpClient);
        _grants = new GrantVerifier(_api);
        _tcpListener = options.Signaling is not null ? options.TcpListener
            : !options.DisableDirect && options.DirectTransports.HasFlag(DirectTransports.Tcp) ? new TcpDirectListener(options.TcpListenPort) : null;
    }

    /// <summary>True for a session this client asked for, from the moment the platform granted it until it has ended.</summary>
    internal bool Owns(string sessionId) => _own.ContainsKey(sessionId);

    /// <summary>The sessions this client opened that are still running.</summary>
    internal IReadOnlyCollection<ConnectionInfo> Sessions => _sessions.Values.Select(s => s.Info).ToArray();

    /// <summary>Ends every session this client opened.</summary>
    internal async Task EndAllAsync(string reason)
    {
        foreach (TunnelSession session in _sessions.Values.ToArray())
        {
            await session.EndAsync(reason).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Opens a session to <paramref name="device"/> (id or slug) for the named services.
    /// Throws <see cref="PlatformException"/> when the platform refuses, <see cref="SecureChannelException"/>
    /// or <see cref="TunnelException"/> when the end-to-end requirements are not met. There is no
    /// silent fallback to a weaker mode.
    /// </summary>
    public async Task<TunnelSession> ConnectAsync(string device, IEnumerable<string> services, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(device);
        string[] serviceNames = [.. services];
        SharedKey? sharedKey = SelectSharedKey(device);
        SignalingClient signaling = await EnsureSignalingAsync(cancellationToken).ConfigureAwait(false);

        SignalConnectGrant granted;
        string sessionId;
        Interlocked.Increment(ref _requesting);
        try
        {
            SignalEnvelope reply = await signaling.RequestAsync(SignalTypes.ConnectRequest,
                new SignalConnectRequest
                {
                    Device = device,
                    Services = serviceNames,
                    Modes = _options.GatewaySecret is null ? _options.Modes : [ConnectionModes.Compatibility],
                    E2e = _options.GatewaySecret is null ? AcceptableE2e(device, sharedKey) : null,
                },
                ProtocolJsonContext.Default.SignalConnectRequest, AnswerTimeout, cancellationToken).ConfigureAwait(false);
            granted = SignalingClient.Read(reply, SignalTypes.ConnectGrant, ProtocolJsonContext.Default.SignalConnectGrant);
            sessionId = granted.SessionId;
            _own[sessionId] = true;
        }
        finally
        {
            if (Interlocked.Decrement(ref _requesting) == 0 && _options.Signaling is not null)
            {
                // On a device's connection, candidates of sessions opened to it pass by as well. Those kept while
                // the session id of this request was unknown are dropped.
                foreach (string other in _candidates.Keys.Where(id => !_own.ContainsKey(id)).ToArray())
                {
                    _candidates.TryRemove(other, out _);
                }
            }
        }

        try
        {
            SignalConnectAnswer answer;
            try
            {
                answer = await _answers.GetOrAdd(sessionId, _ => NewAnswerSource()).Task.WaitAsync(AnswerTimeout, cancellationToken).ConfigureAwait(false);
            }
            catch (TimeoutException)
            {
                throw new PlatformException(ErrorCodes.SignalingTimeout, "The device did not answer the connection request in time.");
            }
            finally
            {
                _answers.TryRemove(sessionId, out _);
            }
            if (!answer.Accept)
            {
                string code = answer.Error ?? ErrorCodes.DeviceRejected;
                throw new TunnelException(code, $"The device refused the connection ({code}).");
            }

            GrantValidation validation = await _grants.ValidateAsync(granted.GrantToken, GrantAudiences.Agent, forSessionStart: true, cancellationToken).ConfigureAwait(false);
            if (validation.Grant is not { } grant || grant.SessionId != sessionId)
            {
                throw new TunnelException(validation.ErrorCode ?? ErrorCodes.GrantInvalid, "The session grant could not be verified.");
            }

            // Compatibility is never mixed with another mode, and only the gateway ever runs it.
            bool compatibility = grant.Modes.Contains(ConnectionModes.Compatibility);
            if (compatibility != (_options.GatewaySecret is not null) || (compatibility && grant.Modes.Length != 1))
            {
                throw new TunnelException(ErrorCodes.NoPermittedMode, "The session grant offers a mode this endpoint does not take part in.");
            }

            // The grant names the end-to-end layer; this endpoint must be able to run exactly that one.
            bool bySharedKey = grant.E2eMethod == E2eMethods.SharedKey;
            if (bySharedKey ? sharedKey is null : grant.E2eMethod != E2eMethods.Tls13 || CertificateIdentity is null)
            {
                throw new TunnelException(ErrorCodes.E2eNoCommonMethod, $"The session was granted with the end-to-end layer '{grant.E2eMethod}', which this application is not set up for.");
            }

            IPeerVerifier? verifier = bySharedKey ? null : SelectVerifier(device, granted.Peer, grant);
            IReadOnlyList<SharedKey> sessionKeys = bySharedKey ? [sharedKey!] : [];
            string peerLabel = granted.Peer.Name ?? device;
            bool relayPermitted = (compatibility || grant.Modes.Contains(ConnectionModes.E2eRelay)) && grant.RelayUrl is not null;
            bool udp = _options.DirectTransports.HasFlag(DirectTransports.Udp) && granted.Peer.Capabilities.Contains(Capabilities.PathUdpKcp);
            bool tcp = _options.DirectTransports.HasFlag(DirectTransports.Tcp) && granted.Peer.Capabilities.Contains(Capabilities.PathTcp);
            bool peerSupportsDirect = udp || tcp;
            bool directPermitted = grant.Modes.Contains(ConnectionModes.Direct) && !_options.DisableDirect && peerSupportsDirect;
            string? directFailure = directPermitted || compatibility ? null
                : _options.DisableDirect || !peerSupportsDirect ? DirectFailureReasons.PeerNoDirectSupport
                : DirectFailureReasons.PolicyRelayOnly;

            TunnelSession? session = null;
            if (directPermitted)
            {
                (session, directFailure) = await TryDirectAsync(signaling, granted, grant, verifier, sessionKeys, peerLabel, relayPermitted, udp, tcp, cancellationToken).ConfigureAwait(false);
            }

            if (session is null)
            {
                if (!relayPermitted)
                {
                    // Nothing else is allowed for this session: say so instead of using a path that was not asked for.
                    throw new TunnelException(ErrorCodes.DirectUnavailable, $"A direct connection could not be established ({directFailure}) and relaying is not permitted for this session.");
                }

                RelayPath relay = await RelayPath.ConnectAsync(new Uri(grant.RelayUrl!), granted.GrantToken, SessionRoles.Initiator, cancellationToken).ConfigureAwait(false);
                session = await TunnelSession.EstablishAsync(new TunnelSessionParameters
                {
                    Path = relay.Stream,
                    Relay = relay,
                    Role = SessionRoles.Initiator,
                    Mode = compatibility ? ConnectionModes.Compatibility : ConnectionModes.E2eRelay,
                    Identity = CertificateIdentity,
                    Verifier = verifier,
                    SharedKeys = sessionKeys,
                    PeerLabel = peerLabel,
                    GrantToken = granted.GrantToken,
                    Grant = grant,
                    DirectFailureReason = directFailure,
                    Transport = PathTransports.RelayWs,
                }, cancellationToken).ConfigureAwait(false);
            }

            _sessions[sessionId] = session;
            _options.Log?.Invoke($"session {sessionId} opened to {peerLabel} ({session.Info.Mode}, {TrustLevels.Wire(session.Info.Trust)}"
                + (session.Info.PeerAddress is null ? ")" : $", peer at {session.Info.PeerAddress})"));
            await ReportAsync(new SignalSessionUpdate
            {
                SessionId = sessionId,
                State = SessionStates.Established,
                Mode = session.Info.Mode,
                Trust = TrustLevels.Wire(session.Info.Trust),
                DirectFailureReason = session.Info.DirectFailureReason,
                Transport = session.Info.Transport,
            }).ConfigureAwait(false);
            _ = WatchSessionAsync(session);
            _ = RenewLeasesAsync(session);
            return session;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            string code = ex switch
            {
                TunnelException t => t.ErrorCode,
                SecureChannelException s => s.ErrorCode,
                PathException p => p.ErrorCode,
                PlatformException p => p.ErrorCode,
                _ => ErrorCodes.SessionClosed,
            };
            _own.TryRemove(sessionId, out _);
            await ReportAsync(new SignalSessionUpdate { SessionId = sessionId, State = SessionStates.Failed, Error = code }).ConfigureAwait(false);
            throw;
        }
        finally
        {
            _options.Opened?.Invoke(sessionId);
        }
    }

    /// <summary>
    /// Looks for a direct path. Returns the session when one was found and verified; otherwise the
    /// reason, after telling the device to use the relay (when that is permitted).
    /// </summary>
    private async Task<(TunnelSession? Session, string? Failure)> TryDirectAsync(
        SignalingClient signaling, SignalConnectGrant granted, SessionGrant grant, IPeerVerifier? verifier, IReadOnlyList<SharedKey> sessionKeys, string peerLabel,
        bool relayPermitted, bool udp, bool tcp, CancellationToken cancellationToken)
    {
        string sessionId = grant.SessionId;
        var attempt = new DirectAttempt(SessionRoles.Initiator, sessionId, granted.GrantToken, new DirectAttemptOptions
        {
            StunServers = udp ? await StunClient.ResolveAsync(_options.StunServers ?? signaling.Welcome?.StunServers ?? [], cancellationToken).ConfigureAwait(false) : [],
            IncludeLoopback = _options.IncludeLoopbackCandidates,
            Udp = udp,
            Tcp = tcp,
            TcpListener = _tcpListener,
            PublicTcpEndpoints = tcp ? await StunClient.ResolveAsync(_options.PublicTcpEndpoints, cancellationToken).ConfigureAwait(false) : [],
            PeerReflexive = DirectAttemptOptions.PeerReflexiveFor(grant),
            Log = _options.Log is { } log ? message => log($"session {sessionId}: direct: {message}") : null,
        });
        try
        {
            _ = _candidates.GetOrAdd(sessionId, _ => NewCandidateSource()).Task.ContinueWith(
                received => attempt.SetRemoteCandidates(received.Result), TaskContinuationOptions.OnlyOnRanToCompletion);

            byte[] blob = await attempt.GatherAsync(cancellationToken).ConfigureAwait(false);
            await signaling.SendAsync(SignalTypes.PathCandidates, new SignalPathCandidates { SessionId = sessionId, Blob = Convert.ToBase64String(blob) },
                ProtocolJsonContext.Default.SignalPathCandidates, cancellationToken: cancellationToken).ConfigureAwait(false);

            DirectPath? path = await attempt.OpenAsync(DirectBudget, cancellationToken).ConfigureAwait(false);
            if (path is null)
            {
                string reason = attempt.FailureReason();
                if (relayPermitted)
                {
                    await signaling.SendAsync(SignalTypes.PathFallback, new SignalPathFallback { SessionId = sessionId, Reason = reason },
                        ProtocolJsonContext.Default.SignalPathFallback, cancellationToken: cancellationToken).ConfigureAwait(false);
                }
                return (null, reason);
            }

            // A path exists. From here on a failure is a failure of the session (for example an
            // untrusted identity) - falling back to the relay would not make the peer more trustworthy.
            TunnelSession session = await TunnelSession.EstablishAsync(new TunnelSessionParameters
            {
                Path = path.Stream,
                Role = SessionRoles.Initiator,
                Mode = ConnectionModes.Direct,
                Identity = CertificateIdentity,
                Verifier = verifier,
                SharedKeys = sessionKeys,
                PeerLabel = peerLabel,
                GrantToken = granted.GrantToken,
                Grant = grant,
                LocalCandidatesHash = attempt.LocalCandidatesHash,
                RemoteCandidatesHash = attempt.RemoteCandidatesHash,
                PeerAddress = path.PeerAddress,
                Transport = path.Transport,
                DialedCandidate = path.DialedCandidate,
                LocalTcpCandidates = attempt.LocalTcpCandidates,
            }, cancellationToken).ConfigureAwait(false);
            return (session, null);
        }
        finally
        {
            _candidates.TryRemove(sessionId, out _);
            await attempt.DisposeAsync().ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Chooses how the device will be authenticated. Local pins for this specific device always
    /// win; the platform's word is used only when the application explicitly allowed that.
    /// </summary>
    private IPeerVerifier SelectVerifier(string requestedDevice, SignalPeer peer, SessionGrant grant)
    {
        string[] names = [requestedDevice, peer.Id, .. peer.Name is null ? Array.Empty<string>() : [peer.Name]];
        bool hasLocalPin = _options.Trust.Identities.Any(i => i.Origin != TrustOrigins.Platform && names.Contains(i.Peer, StringComparer.OrdinalIgnoreCase));
        if (!hasLocalPin && _options.AllowPlatformIntroducedPeers && grant.Device.Fingerprint is { } reported)
        {
            _options.Trust.Pin(reported, peer.Id, TrustOrigins.Platform);
        }
        return _options.Trust.VerifierForPeer(names);
    }

    /// <summary>
    /// The certificate this endpoint announces and presents. A client whose users sign in has none
    /// on record with the platform, so it takes part with shared keys only.
    /// </summary>
    private EndpointIdentity? CertificateIdentity => _options.TokenProvider is null ? _options.Identity : null;

    /// <summary>The shared key for a device: the one named like it, else the only one, else the one named "default".</summary>
    private SharedKey? SelectSharedKey(string device)
    {
        IReadOnlyList<SharedKey> keys = _options.SharedKeys;
        return keys.FirstOrDefault(k => string.Equals(k.Name, device, StringComparison.OrdinalIgnoreCase))
            ?? (keys.Count == 1 ? keys[0] : keys.FirstOrDefault(k => string.Equals(k.Name, "default", StringComparison.OrdinalIgnoreCase)));
    }

    /// <summary>
    /// The end-to-end layers to ask for, best first. A pinned certificate of the device is the
    /// strongest statement about who it is; without one, a key shared with it comes first.
    /// </summary>
    private string[] AcceptableE2e(string device, SharedKey? sharedKey)
    {
        bool certificate = CertificateIdentity is not null;
        bool pinned = certificate && (_options.AllowPlatformIntroducedPeers
            || _options.Trust.Identities.Any(i => string.Equals(i.Peer, device, StringComparison.OrdinalIgnoreCase)));
        if (sharedKey is null)
        {
            return [E2eMethods.Tls13];
        }
        return !certificate ? [E2eMethods.SharedKey]
            : pinned ? [E2eMethods.Tls13, E2eMethods.SharedKey]
            : [E2eMethods.SharedKey, E2eMethods.Tls13];
    }

    /// <summary>
    /// The devices this application may open sessions to, with their names, whether they are
    /// online and the services it may use: what an app shows its user to choose from.
    /// </summary>
    public async Task<IReadOnlyList<ReachableDevice>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        TokenResponse token = _options.TokenProvider is { } provider
            ? await provider(cancellationToken).ConfigureAwait(false)
            : await _api.GetCredentialTokenAsync(_options.ApiKey!, null, cancellationToken).ConfigureAwait(false);
        return await _api.GetReachableDevicesAsync(token.AccessToken, cancellationToken).ConfigureAwait(false);
    }

    private async Task<SignalingClient> EnsureSignalingAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(Volatile.Read(ref _disposed) != 0, this);
        if (_options.Signaling is { } current)
        {
            return _signaling = await current(cancellationToken).ConfigureAwait(false);
        }
        await _signalingGate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (_signaling is { Closed.IsCompleted: false } open)
            {
                return open;
            }
            if (_signaling is not null)
            {
                await _signaling.DisposeAsync().ConfigureAwait(false);
                _signaling = null;
            }

            // The gateway does not register its identity as the application's: it is not the application.
            TokenResponse token = _options.TokenProvider is { } provider
                ? await provider(cancellationToken).ConfigureAwait(false)
                : await _api.GetCredentialTokenAsync(_options.ApiKey!, _options.GatewaySecret is null ? _options.Identity : null, cancellationToken).ConfigureAwait(false);
            var signaling = new SignalingClient { OnMessage = OnSignalAsync };
            try
            {
                await signaling.ConnectAsync(_api.SignalUrl, token.AccessToken,
                    new SignalHello
                    {
                        Capabilities = LocalCapabilities.For(_options.DisableDirect, _options.DirectTransports, certificate: CertificateIdentity is not null, sharedKey: _options.SharedKeys.Count > 0),
                        Fingerprint = CertificateIdentity?.Fingerprint,
                    },
                    cancellationToken, _options.GatewaySecret).ConfigureAwait(false);
            }
            catch
            {
                await signaling.DisposeAsync().ConfigureAwait(false);
                throw;
            }
            _signaling = signaling;
            return signaling;
        }
        finally
        {
            _signalingGate.Release();
        }
    }

    /// <summary>Takes a message from the signaling connection. A device passes on what concerns the sessions it opened.</summary>
    internal async Task OnSignalAsync(SignalEnvelope message)
    {
        switch (message.Type)
        {
            case SignalTypes.ConnectAnswer when Deserialize(message, ProtocolJsonContext.Default.SignalConnectAnswer) is { } answer:
                _answers.GetOrAdd(answer.SessionId, _ => NewAnswerSource()).TrySetResult(answer);
                break;

            case SignalTypes.PathCandidates when Deserialize(message, ProtocolJsonContext.Default.SignalPathCandidates) is { } candidates:
                if (_options.Signaling is not null && !_own.ContainsKey(candidates.SessionId) && Volatile.Read(ref _requesting) == 0)
                {
                    break;
                }
                try
                {
                    _candidates.GetOrAdd(candidates.SessionId, _ => NewCandidateSource()).TrySetResult(Convert.FromBase64String(candidates.Blob));
                }
                catch (FormatException)
                {
                }
                break;

            case SignalTypes.Revoke when Deserialize(message, ProtocolJsonContext.Default.SignalRevoke) is { } revoke:
                foreach (TunnelSession session in _sessions.Values.Where(s => revoke.SessionIds is null || revoke.SessionIds.Contains(s.Info.SessionId)).ToArray())
                {
                    await session.EndAsync(revoke.Reason).ConfigureAwait(false);
                }
                break;
        }
    }

    private static T? Deserialize<T>(SignalEnvelope message, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo) where T : class
    {
        try
        {
            return message.Data is { } data ? System.Text.Json.JsonSerializer.Deserialize(data, typeInfo) : null;
        }
        catch (System.Text.Json.JsonException)
        {
            return null;
        }
    }

    private static TaskCompletionSource<SignalConnectAnswer> NewAnswerSource() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    private static TaskCompletionSource<byte[]> NewCandidateSource() => new(TaskCreationOptions.RunContinuationsAsynchronously);

    /// <summary>Tells the control plane when and why the session ended, with this endpoint's own traffic count.</summary>
    private async Task WatchSessionAsync(TunnelSession session)
    {
        string reason = await session.Completion.ConfigureAwait(false);
        _sessions.TryRemove(session.Info.SessionId, out _);
        _own.TryRemove(session.Info.SessionId, out _);
        _options.Log?.Invoke($"session {session.Info.SessionId} ended ({reason})");
        await ReportAsync(new SignalSessionUpdate
        {
            SessionId = session.Info.SessionId,
            State = SessionStates.Ended,
            Error = reason,
            BytesSent = session.BytesSent,
            BytesReceived = session.BytesReceived,
        }).ConfigureAwait(false);
    }

    /// <summary>Keeps a running session authorised by fetching a new grant well before the lease ends.</summary>
    private async Task RenewLeasesAsync(TunnelSession session)
    {
        try
        {
            while (!session.Completion.IsCompleted)
            {
                long remaining = session.LeaseExpiresAt - DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                var delay = TimeSpan.FromSeconds(Math.Max(remaining / 2.0, 1));
                Task finished = await Task.WhenAny(session.Completion, Task.Delay(delay, _stop.Token)).ConfigureAwait(false);
                if (finished == session.Completion)
                {
                    return;
                }

                try
                {
                    SignalingClient signaling = await EnsureSignalingAsync(_stop.Token).ConfigureAwait(false);
                    SignalEnvelope reply = await signaling.RequestAsync(SignalTypes.LeaseRequest, new SignalLeaseRequest { SessionId = session.Info.SessionId },
                        ProtocolJsonContext.Default.SignalLeaseRequest, AnswerTimeout, _stop.Token).ConfigureAwait(false);
                    SignalLeaseGrant lease = SignalingClient.Read(reply, SignalTypes.LeaseGrant, ProtocolJsonContext.Default.SignalLeaseGrant);
                    GrantValidation validation = await _grants.ValidateAsync(lease.GrantToken, GrantAudiences.Agent, forSessionStart: false, _stop.Token).ConfigureAwait(false);
                    if (validation.Grant is { } renewed)
                    {
                        await session.RenewLeaseAsync(lease.GrantToken, renewed, _stop.Token).ConfigureAwait(false);
                    }
                }
                catch (PlatformException ex) when (ex.ErrorCode is ErrorCodes.CredentialRevoked or ErrorCodes.DeviceRevoked or ErrorCodes.Forbidden
                    or ErrorCodes.ServiceDisabled or ErrorCodes.ServiceNotExposed or ErrorCodes.SessionClosed or ErrorCodes.NotFound)
                {
                    // Authorisation is gone: end the session now instead of letting it run to the end of its lease.
                    await session.EndAsync(ex.ErrorCode is ErrorCodes.NotFound or ErrorCodes.SessionClosed ? ErrorCodes.SessionRevoked : ex.ErrorCode).ConfigureAwait(false);
                    return;
                }
                catch (Exception ex) when (ex is PlatformException or IOException)
                {
                    // Control plane unreachable: keep trying until the lease runs out by itself.
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task ReportAsync(SignalSessionUpdate update)
    {
        try
        {
            if (_signaling is { Closed.IsCompleted: false } signaling)
            {
                await signaling.SendAsync(SignalTypes.SessionUpdate, update, ProtocolJsonContext.Default.SignalSessionUpdate).ConfigureAwait(false);
            }
        }
        catch (PlatformException)
        {
            // Reporting is best effort; the session itself is unaffected.
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
        {
            return;
        }

        foreach (TunnelSession session in _sessions.Values.ToArray())
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
        if (_tcpListener is not null && _options.Signaling is null)
        {
            await _tcpListener.DisposeAsync().ConfigureAwait(false);
        }
        // Give the end-of-session reports a moment to leave before the channel closes.
        await Task.Delay(50).ConfigureAwait(false);
        await _stop.CancelAsync().ConfigureAwait(false);
        if (_signaling is not null && _options.Signaling is null)
        {
            await _signaling.DisposeAsync().ConfigureAwait(false);
        }
        _stop.Dispose();
    }
}

/// <summary>Why a session is not direct. Reported in <see cref="ConnectionInfo.DirectFailureReason"/>.</summary>
public static class DirectFailureReasons
{
    public const string PolicyRelayOnly = "policy_relay_only";
    public const string PeerNoDirectSupport = "peer_no_direct_support";
    public const string StunUnreachable = "stun_unreachable";
    public const string UdpBlockedLocal = "udp_blocked_local";
    public const string UdpBlockedRemote = "udp_blocked_remote";
    public const string SymmetricNatBoth = "symmetric_nat_both";
    public const string ProbeTimeout = "probe_timeout";

    /// <summary>Only TCP was available for a direct path, and neither endpoint could reach the other.</summary>
    public const string TcpUnreachable = "tcp_unreachable";
    public const string CandidateSignatureInvalid = "candidate_signature_invalid";
}

/// <summary>The kinds of direct path an endpoint may attempt.</summary>
[Flags]
public enum DirectTransports
{
    None = 0,

    /// <summary>UDP hole punching with a reliable stream on top (works through most NATs).</summary>
    Udp = 1,

    /// <summary>A plain TCP connection in either direction (same network, a forwarded port, or one endpoint publicly reachable).</summary>
    Tcp = 2,

    All = Udp | Tcp,
}

/// <summary>Wire names of <see cref="TrustLevel"/>.</summary>
public static class TrustLevels
{
    public static string Wire(TrustLevel level) => level switch
    {
        TrustLevel.LocalPinned => "local-pinned",
        TrustLevel.WorkspaceCa => "workspace-ca",
        TrustLevel.SharedKey => "shared-key",
        TrustLevel.PlatformIntroduced => "platform-introduced",
        _ => "none",
    };
}
