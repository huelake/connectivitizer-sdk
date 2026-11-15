using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Platform;
using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Client.Sessions;
using Huelake.Connectivitizer.Client.State;
using Huelake.Connectivitizer.Client.Transport;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client;

public sealed class ConnectivitizerAgentOptions
{
    public required Uri ApiUrl { get; init; }

    /// <summary>An enrolled device: the id it received when it was enrolled.</summary>
    public string? DeviceId { get; init; }

    /// <summary>An enrolled device: the key it logs in with (generated on the device at enrollment).</summary>
    public ECDsa? AuthKey { get; init; }

    /// <summary>
    /// Instead of an enrollment: a device key of the workspace (<c>czd_…</c>). The device logs in
    /// with it under <see cref="DeviceName"/>; the first login creates the device.
    /// </summary>
    public string? DeviceKey { get; init; }

    /// <summary>The name a device that uses <see cref="DeviceKey"/> logs in under. It is how the device is addressed.</summary>
    public string? DeviceName { get; init; }

    /// <summary>The device's certificate identity. A device that only uses shared keys has none.</summary>
    public EndpointIdentity? Identity { get; init; }

    /// <summary>The application identities this device accepts connections from.</summary>
    public TrustStore Trust { get; init; } = new();

    /// <summary>
    /// Keys this device shares with applications. An application that proves it holds one of them
    /// is accepted; the platform never sees them.
    /// </summary>
    public IReadOnlyList<SharedKey> SharedKeys { get; init; } = [];

    /// <summary>The services this device exposes, with their local targets. Empty means nothing is reachable.</summary>
    public IReadOnlyList<ServiceEntry> Services { get; init; } = [];

    /// <summary>
    /// When true, an application that is not pinned locally is accepted with the identity the
    /// platform reports for it. Weaker than pinning; off by default.
    /// </summary>
    public bool AllowPlatformIntroducedPeers { get; init; }

    /// <summary>When true this device never attempts a direct connection and always uses the relay.</summary>
    public bool DisableDirect { get; init; }

    /// <summary>STUN servers (<c>host:port</c>) to use instead of the ones the platform announces.</summary>
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

    public string? AgentVersion { get; init; }

    public HttpClient? HttpClient { get; init; }

    /// <summary>Receives one line per noteworthy event (connected, session accepted, refused, …).</summary>
    public Action<string>? Log { get; init; }
}

/// <summary>
/// The device side: keeps an outbound connection to the platform, and when an authorised and
/// locally trusted application asks, opens a session and forwards its streams to local services.
/// Nothing is reachable that the device did not declare itself. No port listens permanently: only
/// while a direct connection is being set up does a TCP port accept the peer of that session, and
/// it answers nothing that does not present that session's tag (switch off with <c>TcpListenPort = -1</c>).
/// </summary>
public sealed class ConnectivitizerAgent : IAsyncDisposable
{
    private readonly ConnectivitizerAgentOptions _options;
    private readonly PlatformApi _api;
    private readonly GrantVerifier _grants;
    private readonly LocalServiceDirectory _services;
    private readonly LocalServiceDirectory _compatibilityServices;
    private static readonly TimeSpan PathTimeout = TimeSpan.FromSeconds(12);

    private readonly ConcurrentDictionary<string, TunnelSession> _sessions = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<byte[]>> _candidates = new(StringComparer.Ordinal);
    private readonly TcpDirectListener? _tcpListener;
    private readonly ConcurrentDictionary<string, TaskCompletionSource<string>> _fallbacks = new(StringComparer.Ordinal);
    private readonly CancellationTokenSource _stop = new();
    private TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private SignalingClient? _signaling;
    private string? _deviceId;

    public ConnectivitizerAgent(ConnectivitizerAgentOptions options)
    {
        _options = options ?? throw new ArgumentNullException(nameof(options));
        bool byKey = options.DeviceKey is not null;
        if (byKey ? string.IsNullOrWhiteSpace(options.DeviceName) : options.DeviceId is null || options.AuthKey is null)
        {
            throw new ArgumentException("A device logs in either with DeviceKey and DeviceName, or with the DeviceId and AuthKey of its enrollment.", nameof(options));
        }
        if (options.Identity is null && options.SharedKeys.Count == 0)
        {
            throw new ArgumentException("A device needs a certificate identity, a shared key, or both: without either nobody can reach it end to end.", nameof(options));
        }
        _deviceId = options.DeviceId;
        _api = new PlatformApi(options.ApiUrl, options.HttpClient);
        _grants = new GrantVerifier(_api);
        _services = StateDirectory.ToDirectory(options.Services);
        // What the gateway may reach: only services with the local opt-in. Their identity allow-lists
        // name end-to-end peers and do not apply to it - the opt-in is the permission.
        _compatibilityServices = StateDirectory.ToDirectory(options.Services.Where(s => s.Compatibility).Select(s => s with { Allow = null }));
        _tcpListener = !options.DisableDirect && options.DirectTransports.HasFlag(DirectTransports.Tcp) ? new TcpDirectListener(options.TcpListenPort) : null;
    }

    /// <summary>True while the device is connected to the platform and can be reached.</summary>
    public bool IsConnected => _signaling is { Closed.IsCompleted: false };

    /// <summary>The sessions currently open to this device.</summary>
    public IReadOnlyCollection<ConnectionInfo> Sessions => _sessions.Values.Select(s => s.Info).ToArray();

    /// <summary>Completes when the agent is connected to the platform.</summary>
    public Task WaitUntilConnectedAsync(CancellationToken cancellationToken = default) => _connected.Task.WaitAsync(cancellationToken);

    /// <summary>
    /// Runs until cancelled, reconnecting with back-off whenever the connection to the platform is
    /// lost. Throws <see cref="PlatformException"/> when the platform no longer accepts this device
    /// (it was revoked), because retrying cannot help then.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _stop.Token);
        CancellationToken stop = linked.Token;
        TimeSpan backoff = TimeSpan.FromSeconds(1);

        while (!stop.IsCancellationRequested)
        {
            try
            {
                TokenResponse token = _options.DeviceKey is { } deviceKey
                    ? await _api.GetDeviceKeyTokenAsync(deviceKey, _options.DeviceName!, _options.Identity, RuntimeInformation.OSDescription, _options.AgentVersion, stop).ConfigureAwait(false)
                    : await _api.GetDeviceTokenAsync(_options.DeviceId!, _options.AuthKey!, stop).ConfigureAwait(false);
                _deviceId = token.EndpointId;
                var signaling = new SignalingClient { OnMessage = OnSignalAsync };
                await using (signaling.ConfigureAwait(false))
                {
                    await signaling.ConnectAsync(_api.SignalUrl, token.AccessToken, new SignalHello
                    {
                        Capabilities = LocalCapabilities.For(_options.DisableDirect, _options.DirectTransports, certificate: _options.Identity is not null, sharedKey: _options.SharedKeys.Count > 0),
                        Fingerprint = _options.Identity?.Fingerprint,
                        AgentVersion = _options.AgentVersion,
                        Platform = RuntimeInformation.OSDescription,
                        Services = [.. _options.Services.Select(s => new ServiceDeclaration { Name = s.Name, Protocol = s.Protocol, Compatibility = s.Compatibility })],
                    }, stop).ConfigureAwait(false);

                    _signaling = signaling;
                    backoff = TimeSpan.FromSeconds(1);
                    _connected.TrySetResult();
                    Log($"connected to {_api.BaseUrl} as device {_options.DeviceName ?? _deviceId}; services: {string.Join(", ", _services.Names.DefaultIfEmpty("(none)"))}");

                    string reason = await signaling.Closed.WaitAsync(stop).ConfigureAwait(false);
                    _connected = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                    Log($"disconnected from the platform ({reason})");
                    if (reason is ErrorCodes.DeviceRevoked or ErrorCodes.CredentialRevoked)
                    {
                        await EndAllSessionsAsync(reason).ConfigureAwait(false);
                        throw new PlatformException(reason, reason == ErrorCodes.DeviceRevoked ? "This device was revoked." : "The device key this device logs in with was revoked.");
                    }
                }
            }
            catch (OperationCanceledException) when (stop.IsCancellationRequested)
            {
                break;
            }
            catch (PlatformException ex) when (ex.ErrorCode is ErrorCodes.DeviceRevoked or ErrorCodes.CredentialRevoked or ErrorCodes.IdentityNotRegistered or ErrorCodes.Unauthenticated)
            {
                Log($"the platform does not accept this device ({ex.ErrorCode})");
                throw;
            }
            catch (PlatformException ex)
            {
                Log($"platform unavailable ({ex.ErrorCode}); retrying in {backoff.TotalSeconds:F0} s");
            }

            try
            {
                // Jitter keeps a fleet of devices from reconnecting in the same instant after an outage.
                await Task.Delay(backoff + TimeSpan.FromMilliseconds(Random.Shared.Next(0, 500)), stop).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 30));
        }
    }

    private async Task OnSignalAsync(SignalEnvelope message)
    {
        try
        {
            switch (message.Type)
            {
                case SignalTypes.ConnectOffer when message.Data is { } data && data.Deserialize(ProtocolJsonContext.Default.SignalConnectGrant) is { } offer:
                    await HandleOfferAsync(offer).ConfigureAwait(false);
                    break;

                case SignalTypes.PathCandidates when message.Data is { } data && data.Deserialize(ProtocolJsonContext.Default.SignalPathCandidates) is { } candidates:
                    try
                    {
                        _candidates.GetOrAdd(candidates.SessionId, _ => new(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult(Convert.FromBase64String(candidates.Blob));
                    }
                    catch (FormatException)
                    {
                    }
                    break;

                case SignalTypes.PathFallback when message.Data is { } data && data.Deserialize(ProtocolJsonContext.Default.SignalPathFallback) is { } fallback:
                    _fallbacks.GetOrAdd(fallback.SessionId, _ => new(TaskCreationOptions.RunContinuationsAsynchronously)).TrySetResult(fallback.Reason);
                    break;

                case SignalTypes.Revoke when message.Data is { } data && data.Deserialize(ProtocolJsonContext.Default.SignalRevoke) is { } revoke:
                    foreach (TunnelSession session in _sessions.Values.Where(s => revoke.SessionIds is null || revoke.SessionIds.Contains(s.Info.SessionId)).ToArray())
                    {
                        Log($"session {session.Info.SessionId} revoked by the platform ({revoke.Reason})");
                        await session.EndAsync(revoke.Reason).ConfigureAwait(false);
                    }
                    break;
            }
        }
        catch (JsonException)
        {
        }
    }

    /// <summary>
    /// The platform says an application wants to connect. The device checks the grant's signature,
    /// that the grant is really about this device and identity, and - independently of anything the
    /// platform claims - that it trusts the application's identity itself.
    /// </summary>
    private async Task HandleOfferAsync(SignalConnectGrant offer)
    {
        SignalingClient? signaling = _signaling;
        if (signaling is null)
        {
            return;
        }

        CancellationToken stop = _stop.Token;
        GrantValidation validation = await _grants.ValidateAsync(offer.GrantToken, GrantAudiences.Agent, forSessionStart: true, stop).ConfigureAwait(false);
        string? refusal = validation.Grant switch
        {
            null => validation.ErrorCode ?? ErrorCodes.GrantInvalid,
            { } g when g.SessionId != offer.SessionId || g.Device.Id != _deviceId => ErrorCodes.GrantInvalid,
            // With a shared key the peer proves itself in the handshake; here the device only checks that it can take part.
            { } g when g.E2eMethod == E2eMethods.SharedKey => _options.SharedKeys.Count == 0 ? ErrorCodes.E2eNoCommonMethod
                : g.Modes.Contains(ConnectionModes.Compatibility) ? ErrorCodes.GrantInvalid
                : CanServe(g, offer.Peer) ? null : ErrorCodes.NoPermittedMode,
            { } g when g.E2eMethod != E2eMethods.Tls13 || _options.Identity is null => ErrorCodes.E2eNoCommonMethod,
            { } g when g.Device.Fingerprint is not null && g.Device.Fingerprint != _options.Identity.Fingerprint => ErrorCodes.E2eSessionBindMismatch,
            { } g when g.Modes.Contains(ConnectionModes.Compatibility) => CheckCompatibility(g),
            { } g when !CanServe(g, offer.Peer) => ErrorCodes.NoPermittedMode,
            { } g => CheckTrust(g, offer.Peer),
        };

        await signaling.SendAsync(SignalTypes.ConnectAnswer, new SignalConnectAnswer { SessionId = offer.SessionId, Accept = refusal is null, Error = refusal },
            ProtocolJsonContext.Default.SignalConnectAnswer, cancellationToken: stop).ConfigureAwait(false);
        if (refusal is not null)
        {
            Log($"refused connection from {offer.Peer.Name ?? offer.Peer.Id} ({refusal})");
            return;
        }

        SessionGrant grant = validation.Grant!;
        try
        {
            TunnelSession session = await OpenPathAndEstablishAsync(signaling, offer, grant, stop).ConfigureAwait(false);
            _sessions[grant.SessionId] = session;
            Log($"session {grant.SessionId} established with {session.Peer.Name} ({session.Info.Mode}, {TrustLevels.Wire(session.Info.Trust)}"
                + (session.Info.PeerAddress is null ? ")" : $", peer at {session.Info.PeerAddress})"));
            await ReportAsync(new SignalSessionUpdate { SessionId = grant.SessionId, State = SessionStates.Established, Mode = session.Info.Mode, Trust = TrustLevels.Wire(session.Info.Trust) }).ConfigureAwait(false);
            _ = WatchSessionAsync(session);
        }
        catch (Exception ex) when (ex is IOException or SecureChannelException or OperationCanceledException)
        {
            string code = ex switch
            {
                TunnelException t => t.ErrorCode,
                SecureChannelException s => s.ErrorCode,
                PathException p => p.ErrorCode,
                _ => ErrorCodes.SessionClosed,
            };
            Log($"session {grant.SessionId} with {offer.Peer.Name ?? offer.Peer.Id} failed ({code})");
            await ReportAsync(new SignalSessionUpdate { SessionId = grant.SessionId, State = SessionStates.Failed, Error = code }).ConfigureAwait(false);
        }
        finally
        {
            _candidates.TryRemove(grant.SessionId, out _);
            _fallbacks.TryRemove(grant.SessionId, out _);
        }
    }

    private bool UdpPossible(SignalPeer peer) => _options.DirectTransports.HasFlag(DirectTransports.Udp) && peer.Capabilities.Contains(Capabilities.PathUdpKcp);

    private bool TcpPossible(SignalPeer peer) => _options.DirectTransports.HasFlag(DirectTransports.Tcp) && peer.Capabilities.Contains(Capabilities.PathTcp);

    private bool DirectPossible(SessionGrant grant, SignalPeer peer)
        => grant.Modes.Contains(ConnectionModes.Direct) && !_options.DisableDirect && (UdpPossible(peer) || TcpPossible(peer));

    private bool CanServe(SessionGrant grant, SignalPeer peer)
        => (grant.Modes.Contains(ConnectionModes.E2eRelay) && grant.RelayUrl is not null) || DirectPossible(grant, peer);

    /// <summary>
    /// Follows the initiator's lead: a direct path if the initiator finds one, the relay if it says
    /// so. The device never decides on its own to use a path the initiator did not choose.
    /// </summary>
    private async Task<TunnelSession> OpenPathAndEstablishAsync(SignalingClient signaling, SignalConnectGrant offer, SessionGrant grant, CancellationToken stop)
    {
        string sessionId = grant.SessionId;
        if (grant.Modes.Contains(ConnectionModes.Compatibility))
        {
            RelayPath toGateway = await RelayPath.ConnectAsync(new Uri(grant.RelayUrl!), offer.GrantToken, SessionRoles.Device, stop).ConfigureAwait(false);
            return await TunnelSession.EstablishAsync(new TunnelSessionParameters
            {
                Path = toGateway.Stream,
                Relay = toGateway,
                Role = SessionRoles.Device,
                Mode = ConnectionModes.Compatibility,
                Identity = _options.Identity,
                Verifier = new PinnedPeerVerifier([grant.Initiator.Fingerprint!], TrustLevel.PlatformIntroduced),
                GrantToken = offer.GrantToken,
                Grant = grant,
                Services = _compatibilityServices,
                ValidateRenewedGrant = token => _grants.Validate(token, GrantAudiences.Agent, forSessionStart: false),
                Transport = PathTransports.RelayWs,
            }, stop).ConfigureAwait(false);
        }

        if (DirectPossible(grant, offer.Peer))
        {
            bool udp = UdpPossible(offer.Peer);
            bool tcp = TcpPossible(offer.Peer);
            var attempt = new DirectAttempt(SessionRoles.Device, sessionId, offer.GrantToken, new DirectAttemptOptions
            {
                StunServers = udp ? await StunClient.ResolveAsync(_options.StunServers ?? signaling.Welcome?.StunServers ?? [], stop).ConfigureAwait(false) : [],
                IncludeLoopback = _options.IncludeLoopbackCandidates,
                Udp = udp,
                Tcp = tcp,
                TcpListener = _tcpListener,
                PublicTcpEndpoints = tcp ? await StunClient.ResolveAsync(_options.PublicTcpEndpoints, stop).ConfigureAwait(false) : [],
                PeerReflexive = DirectAttemptOptions.PeerReflexiveFor(grant),
            });
            using var pathTimeout = CancellationTokenSource.CreateLinkedTokenSource(stop);
            pathTimeout.CancelAfter(PathTimeout);
            try
            {
                _ = _candidates.GetOrAdd(sessionId, _ => new(TaskCreationOptions.RunContinuationsAsynchronously)).Task.ContinueWith(
                    received => attempt.SetRemoteCandidates(received.Result), TaskContinuationOptions.OnlyOnRanToCompletion);
                Task<string> fallback = _fallbacks.GetOrAdd(sessionId, _ => new(TaskCreationOptions.RunContinuationsAsynchronously)).Task;

                byte[] blob = await attempt.GatherAsync(pathTimeout.Token).ConfigureAwait(false);
                await signaling.SendAsync(SignalTypes.PathCandidates, new SignalPathCandidates { SessionId = sessionId, Blob = Convert.ToBase64String(blob) },
                    ProtocolJsonContext.Default.SignalPathCandidates, cancellationToken: pathTimeout.Token).ConfigureAwait(false);

                Task<DirectPath> selection = attempt.WaitForSelectionAsync(pathTimeout.Token);
                if (await Task.WhenAny(selection, fallback).ConfigureAwait(false) == selection)
                {
                    DirectPath path = await selection.ConfigureAwait(false);
                    Task<TunnelSession> direct = TunnelSession.EstablishAsync(new TunnelSessionParameters
                    {
                        Path = path.Stream,
                        Role = SessionRoles.Device,
                        Mode = ConnectionModes.Direct,
                        Identity = _options.Identity,
                        Verifier = _options.Trust.VerifierForAnyPinned(),
                        SharedKeys = _options.SharedKeys,
                        PeerLabel = offer.Peer.Name ?? offer.Peer.Id,
                        GrantToken = offer.GrantToken,
                        Grant = grant,
                        Services = _services,
                        ValidateRenewedGrant = token => _grants.Validate(token, GrantAudiences.Agent, forSessionStart: false),
                        LocalCandidatesHash = attempt.LocalCandidatesHash,
                        RemoteCandidatesHash = attempt.RemoteCandidatesHash,
                        PeerAddress = path.PeerAddress,
                        Transport = path.Transport,
                        DialedCandidate = path.DialedCandidate,
                        LocalTcpCandidates = attempt.LocalTcpCandidates,
                    }, pathTimeout.Token);

                    // The initiator may have given up on the direct path while this side thought it was selected.
                    if (await Task.WhenAny(direct, fallback).ConfigureAwait(false) == direct)
                    {
                        return await direct.ConfigureAwait(false);
                    }
                    await pathTimeout.CancelAsync().ConfigureAwait(false);
                    _ = direct.ContinueWith(t => t.Exception, TaskContinuationOptions.OnlyOnFaulted);
                    await path.DisposeAsync().ConfigureAwait(false);
                }
                Log($"session {sessionId}: no direct path ({await fallback.ConfigureAwait(false)}), using the relay");
            }
            catch (OperationCanceledException) when (!stop.IsCancellationRequested)
            {
                throw new TunnelException(ErrorCodes.SignalingTimeout, "The initiator did not complete the path negotiation in time.");
            }
            finally
            {
                await attempt.DisposeAsync().ConfigureAwait(false);
            }
        }

        if (grant.RelayUrl is null || !grant.Modes.Contains(ConnectionModes.E2eRelay))
        {
            throw new TunnelException(ErrorCodes.DirectUnavailable, "No direct path was found and relaying is not permitted for this session.");
        }

        RelayPath relay = await RelayPath.ConnectAsync(new Uri(grant.RelayUrl), offer.GrantToken, SessionRoles.Device, stop).ConfigureAwait(false);
        return await TunnelSession.EstablishAsync(new TunnelSessionParameters
        {
            Path = relay.Stream,
            Relay = relay,
            Role = SessionRoles.Device,
            Mode = ConnectionModes.E2eRelay,
            Identity = _options.Identity,
            Verifier = _options.Trust.VerifierForAnyPinned(),
            SharedKeys = _options.SharedKeys,
            PeerLabel = offer.Peer.Name ?? offer.Peer.Id,
            GrantToken = offer.GrantToken,
            Grant = grant,
            Services = _services,
            ValidateRenewedGrant = token => _grants.Validate(token, GrantAudiences.Agent, forSessionStart: false),
        }, stop).ConfigureAwait(false);
    }

    /// <summary>
    /// A compatibility session is accepted only for services the owner opted in on this device.
    /// The peer is then the platform's gateway, identified by the fingerprint in the signed grant;
    /// that identity is used for this session alone and never added to the trust store, so it can
    /// not later pass as an end-to-end peer.
    /// </summary>
    private string? CheckCompatibility(SessionGrant grant)
    {
        if (grant.Modes.Length != 1 || grant.RelayUrl is null || string.IsNullOrEmpty(grant.Initiator.Fingerprint))
        {
            return ErrorCodes.GrantInvalid;
        }
        return grant.Services.All(name => _options.Services.Any(s => s.Name == name && s.Compatibility)) ? null : ErrorCodes.CompatibilityNotEnabled;
    }

    /// <summary>Returns null when the application named in the grant is trusted locally, otherwise the refusal code.</summary>
    private string? CheckTrust(SessionGrant grant, SignalPeer peer)
    {
        string? fingerprint = grant.Initiator.Fingerprint;
        if (fingerprint is null)
        {
            return ErrorCodes.E2eTrustMissing;
        }
        if (_options.Trust.IsPinned(fingerprint))
        {
            return null;
        }
        if (_options.AllowPlatformIntroducedPeers)
        {
            _options.Trust.Pin(fingerprint, peer.Name ?? peer.Id, TrustOrigins.Platform);
            return null;
        }
        return _options.Trust.Identities.Count == 0 ? ErrorCodes.E2eTrustMissing : ErrorCodes.E2ePeerUntrusted;
    }

    private async Task WatchSessionAsync(TunnelSession session)
    {
        string reason = await session.Completion.ConfigureAwait(false);
        _sessions.TryRemove(session.Info.SessionId, out _);
        Log($"session {session.Info.SessionId} ended ({reason})");
        await ReportAsync(new SignalSessionUpdate
        {
            SessionId = session.Info.SessionId,
            State = SessionStates.Ended,
            Error = reason,
            BytesSent = session.BytesSent,
            BytesReceived = session.BytesReceived,
        }).ConfigureAwait(false);
        await session.DisposeAsync().ConfigureAwait(false);
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
        }
    }

    private async Task EndAllSessionsAsync(string reason)
    {
        foreach (TunnelSession session in _sessions.Values.ToArray())
        {
            await session.EndAsync(reason).ConfigureAwait(false);
        }
    }

    private void Log(string message) => _options.Log?.Invoke(message);

    public async ValueTask DisposeAsync()
    {
        if (_stop.IsCancellationRequested)
        {
            return;
        }
        foreach (TunnelSession session in _sessions.Values.ToArray())
        {
            await session.DisposeAsync().ConfigureAwait(false);
        }
        if (_tcpListener is not null)
        {
            await _tcpListener.DisposeAsync().ConfigureAwait(false);
        }
        await Task.Delay(50).ConfigureAwait(false);
        await _stop.CancelAsync().ConfigureAwait(false);
    }
}
