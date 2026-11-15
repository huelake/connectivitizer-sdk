using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Sessions;

/// <summary>
/// The actual routing and security properties of an established session, as observed and verified
/// by this endpoint - not as claimed by the platform.
/// </summary>
public sealed record ConnectionInfo
{
    public required string SessionId { get; init; }

    /// <summary>One of <see cref="ConnectionModes"/>.</summary>
    public required string Mode { get; init; }

    /// <summary>True when application traffic passes through Connectivitizer infrastructure.</summary>
    public bool Relayed => Mode != ConnectionModes.Direct;

    /// <summary>True when only the two endpoints hold the keys protecting the application traffic.</summary>
    public bool EndToEndEncrypted => Mode != ConnectionModes.Compatibility;

    /// <summary>True only in compatibility mode, where the gateway terminates the encryption.</summary>
    public bool PlatformCanReadPayload => Mode == ConnectionModes.Compatibility;

    /// <summary>How the remote endpoint's identity was established.</summary>
    public required TrustLevel Trust { get; init; }

    /// <summary>
    /// The end-to-end layer of the session, one of <see cref="E2eMethods"/>: certificates each
    /// endpoint trusts locally, or a key the two endpoints share.
    /// </summary>
    public string E2eMethod { get; init; } = E2eMethods.Tls13;

    /// <summary>
    /// Fingerprint of the remote endpoint's identity, as presented in the TLS handshake. In a
    /// shared-key session: <c>key:</c> followed by this endpoint's name for the key the peer proved to hold.
    /// </summary>
    public required string PeerFingerprint { get; init; }

    /// <summary>The peer's name: from its certificate, or - in a shared-key session - the label the platform gave it.</summary>
    public required string PeerName { get; init; }

    /// <summary>
    /// Direct sessions only: the network address this endpoint exchanges packets with. In a direct
    /// session each endpoint necessarily learns the other's public address; in a relayed session
    /// neither does (both only see the relay).
    /// </summary>
    public string? PeerAddress { get; init; }

    /// <summary>What carries the session's bytes: <c>udp-kcp</c> or <c>tcp</c> for direct sessions, <c>relay-ws</c> otherwise.</summary>
    public string Transport { get; init; } = PathTransports.RelayWs;

    /// <summary>Why a direct connection was not used, when the session is relayed and the reason is known.</summary>
    public string? DirectFailureReason { get; init; }
}

/// <summary>Thrown when a session cannot be established or a service cannot be opened. <see cref="ErrorCode"/> is one of <see cref="ErrorCodes"/>.</summary>
public sealed class TunnelException(string errorCode, string message, Exception? innerException = null) : IOException(message, innerException)
{
    public string ErrorCode { get; } = errorCode;
}

/// <summary>Where a device forwards the streams of one exposed service.</summary>
public sealed record ServiceTarget(string Host, int Port);

/// <summary>Outcome of asking the device's local configuration for a service.</summary>
public readonly record struct ServiceLookup(ServiceTarget? Target, string? ErrorCode)
{
    public static ServiceLookup Allow(ServiceTarget target) => new(target, null);

    public static ServiceLookup Deny(string errorCode) => new(null, errorCode);
}

/// <summary>
/// The device's own, local answer to "may this peer use this service, and where does it go?".
/// Targets exist only here, on the device - the platform never supplies an address to connect to.
/// </summary>
public interface IServiceDirectory
{
    ServiceLookup Resolve(string service, PeerIdentity peer);
}

/// <summary>A fixed set of locally declared services. A service not listed here does not exist for remote peers.</summary>
public sealed class LocalServiceDirectory : IServiceDirectory
{
    private readonly Dictionary<string, Entry> _services = new(StringComparer.Ordinal);

    /// <summary>Exposes a local TCP endpoint under <paramref name="name"/>.</summary>
    /// <param name="allowedFingerprints">
    /// Identities allowed to use this service: certificate fingerprints, and <c>key:&lt;name&gt;</c> for
    /// peers that authenticate with that shared key. Null means any peer that passed the session's
    /// end-to-end authentication.
    /// </param>
    public LocalServiceDirectory Add(string name, string host, int port, IEnumerable<string>? allowedFingerprints = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        ArgumentException.ThrowIfNullOrWhiteSpace(host);
        ArgumentOutOfRangeException.ThrowIfLessThan(port, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(port, 65535);
        _services[name] = new Entry(new ServiceTarget(host, port), allowedFingerprints?.ToHashSet(StringComparer.Ordinal));
        return this;
    }

    public IReadOnlyCollection<string> Names => _services.Keys;

    public ServiceLookup Resolve(string service, PeerIdentity peer)
    {
        if (!_services.TryGetValue(service, out Entry? entry))
        {
            return ServiceLookup.Deny(ErrorCodes.ServiceNotExposed);
        }
        if (entry.Allowed is not null && !entry.Allowed.Contains(peer.Fingerprint))
        {
            return ServiceLookup.Deny(ErrorCodes.DeniedByLocalPolicy);
        }
        return ServiceLookup.Allow(entry.Target);
    }

    private sealed record Entry(ServiceTarget Target, HashSet<string>? Allowed);
}
