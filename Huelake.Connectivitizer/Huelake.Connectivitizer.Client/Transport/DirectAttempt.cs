using System.Buffers.Binary;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Transport;

/// <summary>What an endpoint tells its peer about how it might be reached directly.</summary>
internal sealed record CandidateList
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    [JsonPropertyName("role")] public required string Role { get; init; }

    /// <summary>
    /// <c>ip:port</c> (IPv6 as <c>[ip]:port</c>) of every UDP address the endpoint may be reachable
    /// at: its own interfaces, IPv4 and global IPv6, and its public (reflexive) IPv4 address.
    /// </summary>
    [JsonPropertyName("udp")] public required string[] Udp { get; init; }

    /// <summary><c>cone</c>, <c>symmetric</c> or <c>unknown</c> (no answer from the STUN servers).</summary>
    [JsonPropertyName("nat")] public required string Nat { get; init; }

    /// <summary><c>ip:port</c> of every TCP address the endpoint accepts this session's connection on. Absent when it has none.</summary>
    [JsonPropertyName("tcp"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] public string[]? Tcp { get; init; }
}

/// <summary>What one endpoint is able and allowed to try for a direct path.</summary>
internal sealed record DirectAttemptOptions
{
    public IReadOnlyList<IPEndPoint> StunServers { get; init; } = [];

    public bool IncludeLoopback { get; init; }

    /// <summary>Both endpoints support the UDP path.</summary>
    public bool Udp { get; init; } = true;

    /// <summary>Both endpoints support the TCP path.</summary>
    public bool Tcp { get; init; }

    /// <summary>Where this endpoint accepts TCP connections; null when it only connects outwards.</summary>
    public TcpDirectListener? TcpListener { get; init; }

    /// <summary>Addresses under which <see cref="TcpListener"/> is reachable from outside (for example a forwarded port).</summary>
    public IReadOnlyList<IPEndPoint> PublicTcpEndpoints { get; init; } = [];

    /// <summary>
    /// The UDP path may also use an address of the peer that the peer did not announce, learned
    /// from where its probes arrive from (a "peer-reflexive" address, as behind a symmetric NAT).
    /// Only for sessions whose end-to-end handshake authenticates the peer; see <see cref="PeerReflexiveFor"/>.
    /// </summary>
    public bool PeerReflexive { get; init; }

    /// <summary>Test hook: changes the UDP candidates before they are announced.</summary>
    internal Func<IReadOnlyList<string>, IReadOnlyList<string>>? AnnounceFilter { get; init; }

    /// <summary>
    /// Whether a session of this grant may use learned addresses: only when its end-to-end layer
    /// authenticates the peer (certificates, or a shared key), because nothing but that handshake
    /// vouches for a path through an address neither side announced.
    /// </summary>
    public static bool PeerReflexiveFor(SessionGrant grant) => grant.E2eMethod is E2eMethods.Tls13 or E2eMethods.SharedKey;
}

/// <summary>A direct path that both endpoints agreed to run the session on.</summary>
internal sealed record DirectPath(Stream Stream, string PeerAddress, string Transport, string? DialedCandidate, IAsyncDisposable Owner) : IAsyncDisposable
{
    public ValueTask DisposeAsync() => Owner.DisposeAsync();
}

[JsonSerializable(typeof(CandidateList))]
internal sealed partial class TransportJsonContext : JsonSerializerContext;

/// <summary>
/// One attempt to open a direct path for a session: discover this endpoint's addresses, exchange
/// candidates with the peer through signaling, then punch through the NATs with UDP probes and
/// try plain TCP connections in both directions. The initiator picks the first path that works.
/// </summary>
/// <remarks>
/// Probes and the TCP hello carry no payload and prove nothing about identity - they only find a
/// working path. Everything that matters is established afterwards by the end-to-end handshake
/// over that path, and both endpoints then confirm in the session bind which candidate lists they
/// used. That is also why a learned (peer-reflexive) address is used only when the session's
/// end-to-end layer authenticates the peer (<see cref="DirectAttemptOptions.PeerReflexive"/>).
/// </remarks>
internal sealed class DirectAttempt : IAsyncDisposable
{
    private const int ProbeSize = 18;
    private const byte FlagProbe = 0;
    private const byte FlagSelect = 1;
    private const int MaxCandidates = 16;
    private const int MaxIPv6Addresses = 4;
    private const int MaxLearned = 4;
    private static readonly TimeSpan ProbeInterval = TimeSpan.FromMilliseconds(100);
    private static readonly TimeSpan StunTimeout = TimeSpan.FromMilliseconds(1500);

    /// <summary>How long an announced candidate gets to validate after a learned address did, before the learned one is selected.</summary>
    private static readonly TimeSpan LearnedGrace = TimeSpan.FromMilliseconds(500);

    private readonly string _role;
    private readonly string _sessionId;
    private readonly byte[] _tag;
    private readonly uint _conversation;
    private readonly DirectAttemptOptions _options;
    private readonly UdpPort _port = new();
    private readonly TcpDirectAttempt? _tcp;
    private readonly TaskCompletionSource<IPEndPoint> _validated = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource<IPEndPoint> _validatedLearned = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Lock _learnedGate = new();
    private IPEndPoint[] _learned = [];
    private readonly TaskCompletionSource<IPEndPoint> _selectedByPeer = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _selectAcknowledged = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly TaskCompletionSource _remoteKnown = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private IPEndPoint[] _remoteCandidates = [];
    private StunResult _stun = new(null, false, false);
    private string _remoteNat = "unknown";
    private IPEndPoint? _selected;
    private KcpPath? _path;
    private bool _portHandedOver;
    private int _chosen;

    public DirectAttempt(string role, string sessionId, string grantToken, DirectAttemptOptions options)
    {
        _role = role;
        _sessionId = sessionId;
        _options = options;

        // Both endpoints hold the same grant, so both derive the same tag and KCP conversation id.
        byte[] digest = SHA256.HashData(Encoding.ASCII.GetBytes(grantToken));
        _tag = digest[..8];
        _conversation = BinaryPrimitives.ReadUInt32BigEndian(digest.AsSpan(8)) | 1;
        if (options.Udp)
        {
            _port.UnboundPeerHandler = OnProbeAsync;
        }
        _port.Start();
        if (options.Tcp)
        {
            _tcp = new TcpDirectAttempt(role, _tag, options.TcpListener, TryChoose);
        }
    }

    /// <summary>SHA-256 (hex) of the candidate list this endpoint sent; confirmed inside the encrypted session.</summary>
    public string? LocalCandidatesHash { get; private set; }

    /// <summary>SHA-256 (hex) of the candidate list received from the peer through signaling.</summary>
    public string? RemoteCandidatesHash { get; private set; }

    /// <summary>The TCP candidates this endpoint announced.</summary>
    public IReadOnlyList<string> LocalTcpCandidates { get; private set; } = [];

    /// <summary>Device side: only one path of an attempt is ever handed to the session.</summary>
    private bool TryChoose() => Interlocked.CompareExchange(ref _chosen, 1, 0) == 0;

    /// <summary>Discovers this endpoint's addresses and returns the candidate list to send to the peer.</summary>
    public async Task<byte[]> GatherAsync(CancellationToken cancellationToken)
    {
        var udp = new List<string>();
        if (_options.Udp)
        {
            _stun = await StunClient.DiscoverAsync(_port, _options.StunServers, StunTimeout, cancellationToken).ConfigureAwait(false);
            foreach (IPAddress local in LocalAddresses(ipv6: _port.SupportsIPv6))
            {
                udp.Add(new IPEndPoint(local, _port.LocalEndPoint.Port).ToString());
            }
            if (_stun.Mapped is { } mapped && !udp.Contains(UdpPort.Plain(mapped).ToString()))
            {
                udp.Add(UdpPort.Plain(mapped).ToString());
            }
            if (_options.AnnounceFilter is { } filter)
            {
                udp = [.. filter(udp)];
            }
        }

        List<string>? tcp = null;
        if (_tcp is not null)
        {
            tcp = [];
            if (_tcp.ListenPort != 0)
            {
                foreach (IPAddress local in LocalAddresses(ipv6: false))
                {
                    tcp.Add(new IPEndPoint(local, _tcp.ListenPort).ToString());
                }
                foreach (IPEndPoint configured in _options.PublicTcpEndpoints)
                {
                    if (!tcp.Contains(configured.ToString()))
                    {
                        tcp.Add(configured.ToString());
                    }
                }
            }
            LocalTcpCandidates = tcp;
        }

        byte[] blob = JsonSerializer.SerializeToUtf8Bytes(new CandidateList
        {
            SessionId = _sessionId,
            Role = _role,
            Udp = [.. udp],
            Nat = !_stun.Reachable ? "unknown" : _stun.Symmetric ? "symmetric" : "cone",
            Tcp = tcp is { Count: > 0 } ? [.. tcp] : null,
        }, TransportJsonContext.Default.CandidateList);
        LocalCandidatesHash = Convert.ToHexStringLower(SHA256.HashData(blob));
        return blob;
    }

    /// <summary>Takes the peer's candidate list as received through signaling. Returns false when it is not usable.</summary>
    public bool SetRemoteCandidates(ReadOnlySpan<byte> blob)
    {
        CandidateList? list;
        try
        {
            list = JsonSerializer.Deserialize(blob, TransportJsonContext.Default.CandidateList);
        }
        catch (JsonException)
        {
            return false;
        }
        if (list is null || list.SessionId != _sessionId || list.Role == _role || list.Udp.Length > MaxCandidates || list.Tcp is { Length: > MaxCandidates })
        {
            return false;
        }

        RemoteCandidatesHash = Convert.ToHexStringLower(SHA256.HashData(blob));
        _remoteNat = list.Nat;
        _remoteCandidates = _options.Udp ? Parse(list.Udp, ipv6: _port.SupportsIPv6) : [];
        _remoteKnown.TrySetResult();
        _tcp?.Dial(Parse(list.Tcp ?? [], ipv6: false));
        return true;
    }

    /// <summary>
    /// The candidates this endpoint can use: IPv4, and IPv6 when it has IPv6 itself. IPv6
    /// link-local and multicast addresses are skipped (the first would need an interface to go with
    /// it, the second is never a peer).
    /// </summary>
    private static IPEndPoint[] Parse(string[] candidates, bool ipv6)
    {
        var parsed = new List<IPEndPoint>();
        foreach (string text in candidates)
        {
            if (!IPEndPoint.TryParse(text, out IPEndPoint? endpoint) || endpoint.Port == 0)
            {
                continue;
            }
            endpoint = UdpPort.Plain(endpoint);
            bool usable = endpoint.AddressFamily == AddressFamily.InterNetwork
                || (ipv6 && endpoint.AddressFamily == AddressFamily.InterNetworkV6 && !endpoint.Address.IsIPv6LinkLocal && !endpoint.Address.IsIPv6Multicast
                    && !endpoint.Address.Equals(IPAddress.IPv6Any));
            if (usable && !parsed.Contains(endpoint))
            {
                parsed.Add(endpoint);
            }
        }
        return [.. parsed];
    }

    private bool IsLearned(IPEndPoint remote)
    {
        lock (_learnedGate)
        {
            return _learned.Contains(remote);
        }
    }

    /// <summary>
    /// Remembers an address of the peer that the peer did not announce, because a datagram with
    /// this session's tag came from it. Only once the peer's list is known (so that it is clear the
    /// address is not on it), only for sessions that allow it, and only a few.
    /// </summary>
    private void Learn(IPEndPoint remote)
    {
        if (!_options.PeerReflexive || !_remoteKnown.Task.IsCompleted || _remoteCandidates.Contains(remote))
        {
            return;
        }
        lock (_learnedGate)
        {
            if (_learned.Length < MaxLearned && !_learned.Contains(remote))
            {
                _learned = [.. _learned, remote];
            }
        }
    }

    /// <summary>Where probes go: the peer's candidates, then what was learned.</summary>
    private IPEndPoint[] ProbeTargets()
    {
        lock (_learnedGate)
        {
            return _learned.Length == 0 ? _remoteCandidates : [.. _remoteCandidates, .. _learned];
        }
    }

    /// <summary>A learned address that answered, once an announced candidate has had a moment to answer too.</summary>
    private async Task<IPEndPoint> LearnedFallbackAsync(CancellationToken cancellationToken)
    {
        IPEndPoint learned = await _validatedLearned.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
        await Task.Delay(LearnedGrace, cancellationToken).ConfigureAwait(false);
        return learned;
    }

    /// <summary>
    /// Initiator: tries the peer's candidates until a path works, then tells the peer which one to
    /// use. Returns that path, or null when none worked in time.
    /// </summary>
    public async Task<DirectPath?> OpenAsync(TimeSpan budget, CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(budget);
        Task probing = Task.CompletedTask;
        Task selecting = Task.CompletedTask;
        try
        {
            await _remoteKnown.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            if (_options.Udp)
            {
                probing = ProbeLoopAsync(FlagProbe, ProbeTargets, deadline.Token);
            }

            Task<TcpDirectConnection> tcpValidated = _tcp?.Validated ?? new TaskCompletionSource<TcpDirectConnection>().Task;
            // A learned address is the fallback: it is selected only if no announced candidate answers in time.
            Task<IPEndPoint> learned = _options.PeerReflexive ? LearnedFallbackAsync(deadline.Token) : new TaskCompletionSource<IPEndPoint>().Task;
            Task first = await Task.WhenAny(_validated.Task, tcpValidated, learned).WaitAsync(deadline.Token).ConfigureAwait(false);
            if (first == tcpValidated)
            {
                TcpDirectConnection connection = await tcpValidated.ConfigureAwait(false);
                await _tcp!.SelectAsync(connection, deadline.Token).ConfigureAwait(false);
                return new DirectPath(connection.Stream, connection.Remote.ToString(), PathTransports.Tcp, connection.DialedCandidate, connection);
            }

            IPEndPoint remote = first == learned ? await learned.ConfigureAwait(false) : await _validated.Task.ConfigureAwait(false);
            _selected = remote;
            selecting = ProbeLoopAsync(FlagSelect, () => [remote], deadline.Token);
            await _selectAcknowledged.Task.WaitAsync(deadline.Token).ConfigureAwait(false);
            _portHandedOver = true;
            _path = new KcpPath(_port, remote, _conversation, ownsPort: true);
            return new DirectPath(_path.Stream, remote.ToString(), PathTransports.UdpKcp, null, _path);
        }
        catch (Exception ex) when ((ex is OperationCanceledException && !cancellationToken.IsCancellationRequested) || ex is IOException or SocketException)
        {
            return null;
        }
        finally
        {
            await deadline.CancelAsync().ConfigureAwait(false);
            await Task.WhenAll(Quiet(probing), Quiet(selecting)).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Device: keeps probing the initiator's candidates (which opens this side's NAT) and waits
    /// for the initiator to select a path. A selected UDP path is already listening when the
    /// selection is acknowledged, so the initiator's first packets are not lost.
    /// </summary>
    public async Task<DirectPath> WaitForSelectionAsync(CancellationToken cancellationToken)
    {
        using var stopProbing = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        Task probing = _options.Udp ? ProbeLoopAsync(FlagProbe, ProbeTargets, stopProbing.Token) : Task.CompletedTask;
        try
        {
            Task<TcpDirectConnection> tcpSelected = _tcp?.Selected ?? new TaskCompletionSource<TcpDirectConnection>().Task;
            Task first = await Task.WhenAny(_selectedByPeer.Task, tcpSelected).WaitAsync(cancellationToken).ConfigureAwait(false);
            if (first == tcpSelected)
            {
                TcpDirectConnection connection = await tcpSelected.ConfigureAwait(false);
                // The initiator can connect to this endpoint's listener and select that connection
                // before its own candidate list has arrived here through signaling. The session bind
                // compares against that list, so the path is handed over only once it is known.
                // (A UDP selection is accepted only from an address on the list, or from one learned
                // after the list arrived, so it is known then.)
                await _remoteKnown.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
                return new DirectPath(connection.Stream, connection.Remote.ToString(), PathTransports.Tcp, connection.DialedCandidate, connection);
            }
            await _selectedByPeer.Task.ConfigureAwait(false);
            return new DirectPath(_path!.Stream, _path.RemoteEndPoint.ToString(), PathTransports.UdpKcp, null, _path);
        }
        finally
        {
            await stopProbing.CancelAsync().ConfigureAwait(false);
            await Quiet(probing).ConfigureAwait(false);
        }
    }

    /// <summary>Why no direct path was found (one of <see cref="DirectFailureReasons"/>).</summary>
    public string FailureReason()
    {
        if (!_options.Udp)
        {
            return DirectFailureReasons.TcpUnreachable;
        }
        if (_stun.Symmetric && _remoteNat == "symmetric")
        {
            return DirectFailureReasons.SymmetricNatBoth;
        }
        if (!_stun.Reachable)
        {
            return _options.StunServers.Count == 0 ? DirectFailureReasons.StunUnreachable : DirectFailureReasons.UdpBlockedLocal;
        }
        if (_remoteNat == "unknown")
        {
            return DirectFailureReasons.UdpBlockedRemote;
        }
        return DirectFailureReasons.ProbeTimeout;
    }

    private async Task ProbeLoopAsync(byte flags, Func<IPEndPoint[]> targets, CancellationToken cancellationToken)
    {
        byte[] probe = new byte[ProbeSize];
        probe[0] = DatagramType.Probe;
        _tag.CopyTo(probe, 1);
        probe[9] = flags;
        using var timer = new PeriodicTimer(ProbeInterval);
        do
        {
            RandomNumberGenerator.Fill(probe.AsSpan(10, 8));
            foreach (IPEndPoint target in targets())
            {
                await _port.SendAsync(probe, target, cancellationToken).ConfigureAwait(false);
            }
        }
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false));
    }

    private ValueTask OnProbeAsync(ReadOnlyMemory<byte> datagram, IPEndPoint remote)
    {
        ReadOnlySpan<byte> span = datagram.Span;
        if (span.Length != ProbeSize || !span.Slice(1, 8).SequenceEqual(_tag) || span[0] is not (DatagramType.Probe or DatagramType.ProbeAck))
        {
            return default; // not for this session
        }

        Learn(remote);
        byte flags = span[9];
        if (span[0] == DatagramType.Probe)
        {
            if (flags == FlagSelect)
            {
                // Only the initiator selects, and only an address from its own announced list (or,
                // where the session allows it, one learned from its probes) is accepted.
                if (_role != SessionRoles.Device || !(_remoteCandidates.Contains(remote) || IsLearned(remote)))
                {
                    return default;
                }
                if (_path is null)
                {
                    if (!TryChoose())
                    {
                        return default; // the initiator already selected a TCP connection
                    }
                    _selected = remote;
                    _portHandedOver = true;
                    _path = new KcpPath(_port, remote, _conversation, ownsPort: true) { ProbeHandler = OnProbeAsync };
                    _selectedByPeer.TrySetResult(remote);
                }
                else if (!remote.Equals(_selected))
                {
                    return default;
                }
            }

            byte[] ack = datagram.ToArray();
            ack[0] = DatagramType.ProbeAck;
            return _port.SendAsync(ack, remote);
        }

        bool announced = _remoteCandidates.Contains(remote);
        if (span[0] == DatagramType.ProbeAck && _role == SessionRoles.Initiator && (announced || IsLearned(remote)))
        {
            if (flags == FlagProbe)
            {
                (announced ? _validated : _validatedLearned).TrySetResult(remote);
            }
            else if (remote.Equals(_selected))
            {
                _selectAcknowledged.TrySetResult();
            }
        }
        return default;
    }

    /// <summary>This machine's IPv4 addresses and, if asked for, its global IPv6 addresses (at most a few of each).</summary>
    private IEnumerable<IPAddress> LocalAddresses(bool ipv6)
    {
        var found = new List<IPAddress>();
        var global6 = new List<IPAddress>();
        try
        {
            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }
                bool loopback = nic.NetworkInterfaceType == NetworkInterfaceType.Loopback;
                if (loopback && !_options.IncludeLoopback)
                {
                    continue;
                }
                foreach (UnicastIPAddressInformation address in nic.GetIPProperties().UnicastAddresses)
                {
                    if (address.Address.AddressFamily == AddressFamily.InterNetwork && !found.Contains(address.Address))
                    {
                        found.Add(address.Address);
                    }
                    else if (ipv6 && IsGlobalIPv6(address.Address) && !global6.Contains(address.Address))
                    {
                        global6.Add(address.Address);
                    }
                }
            }
        }
        catch (NetworkInformationException)
        {
        }
        return found.Take(6).Concat(global6.Take(MaxIPv6Addresses));
    }

    /// <summary>A global unicast IPv6 address (2000::/3): one a peer elsewhere on the internet can send to, without NAT in between.</summary>
    internal static bool IsGlobalIPv6(IPAddress address)
        => address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6 && (address.GetAddressBytes()[0] & 0xE0) == 0x20;

    private static async Task Quiet(Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
        }
    }

    public async ValueTask DisposeAsync()
    {
        _selectedByPeer.TrySetCanceled();
        _validated.TrySetCanceled();
        if (_tcp is not null)
        {
            await _tcp.DisposeAsync().ConfigureAwait(false);
        }
        if (!_portHandedOver)
        {
            await _port.DisposeAsync().ConfigureAwait(false);
        }
    }
}

/// <summary>Result of asking the STUN servers how this endpoint's UDP port appears from outside.</summary>
internal sealed record StunResult(IPEndPoint? Mapped, bool Symmetric, bool Reachable);

internal static class StunClient
{
    /// <summary>Turns <c>host:port</c> strings into IPv4 endpoints; entries that cannot be resolved are skipped.</summary>
    public static async Task<IReadOnlyList<IPEndPoint>> ResolveAsync(IEnumerable<string> servers, CancellationToken cancellationToken)
    {
        var resolved = new List<IPEndPoint>();
        foreach (string server in servers)
        {
            int colon = server.LastIndexOf(':');
            if (colon <= 0 || !int.TryParse(server.AsSpan(colon + 1), out int port) || port is < 1 or > 65535)
            {
                continue;
            }

            string host = server[..colon];
            if (IPAddress.TryParse(host, out IPAddress? literal))
            {
                if (literal.AddressFamily == AddressFamily.InterNetwork)
                {
                    resolved.Add(new IPEndPoint(literal, port));
                }
                continue;
            }

            try
            {
                IPAddress[] addresses = await Dns.GetHostAddressesAsync(host, AddressFamily.InterNetwork, cancellationToken).ConfigureAwait(false);
                if (addresses.Length > 0)
                {
                    resolved.Add(new IPEndPoint(addresses[0], port));
                }
            }
            catch (SocketException)
            {
            }
        }
        return resolved;
    }

    /// <summary>
    /// Sends a Binding request to every server from <paramref name="port"/>. Different answers
    /// from different servers mean the NAT maps each destination separately ("symmetric"), in
    /// which case the reported address is of no use to a peer.
    /// </summary>
    public static async Task<StunResult> DiscoverAsync(UdpPort port, IReadOnlyList<IPEndPoint> servers, TimeSpan timeout, CancellationToken cancellationToken)
    {
        if (servers.Count == 0)
        {
            return new StunResult(null, false, false);
        }

        var pending = servers.Select(_ => (Id: RandomNumberGenerator.GetBytes(Stun.TransactionIdSize), Answer: new TaskCompletionSource<IPEndPoint>(TaskCreationOptions.RunContinuationsAsynchronously))).ToArray();
        port.StunHandler = (datagram, _) =>
        {
            foreach ((byte[] id, TaskCompletionSource<IPEndPoint> answer) in pending)
            {
                if (Stun.TryReadBindingSuccess(datagram.Span, id, out IPEndPoint? mapped) && mapped is not null)
                {
                    answer.TrySetResult(mapped);
                }
            }
            return default;
        };

        try
        {
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            deadline.CancelAfter(timeout);
            byte[] request = new byte[Stun.HeaderSize];
            Task all = Task.WhenAll(pending.Select(p => p.Answer.Task));
            // UDP is lossy: repeat the requests a few times until every server has answered.
            foreach (int delay in new[] { 0, 200, 400, 800 })
            {
                try
                {
                    await Task.WhenAny(all, Task.Delay(delay, deadline.Token)).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                if (all.IsCompleted || deadline.IsCancellationRequested)
                {
                    break;
                }
                for (int i = 0; i < servers.Count; i++)
                {
                    if (!pending[i].Answer.Task.IsCompleted)
                    {
                        Stun.WriteBindingRequest(request, pending[i].Id);
                        await port.SendAsync(request, servers[i], cancellationToken).ConfigureAwait(false);
                    }
                }
            }

            try
            {
                await all.WaitAsync(deadline.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
            }
        }
        finally
        {
            port.StunHandler = null;
        }

        IPEndPoint[] answers = pending.Where(p => p.Answer.Task.IsCompletedSuccessfully).Select(p => p.Answer.Task.Result).ToArray();
        return new StunResult(answers.FirstOrDefault(), answers.Distinct().Count() > 1, answers.Length > 0);
    }
}
