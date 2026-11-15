using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Client.Security;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.State;

/// <summary>How an identity got into the local trust store.</summary>
public static class TrustOrigins
{
    /// <summary>Entered by the user (a fingerprint they checked themselves).</summary>
    public const string Manual = "manual";

    /// <summary>Exchanged with a pairing string, verified with a secret the platform never saw.</summary>
    public const string Pairing = "pairing";

    /// <summary>Taken from what the platform reported, without independent verification. Weaker.</summary>
    public const string Platform = "platform";
}

/// <summary>One identity this endpoint trusts.</summary>
public sealed record TrustedIdentity
{
    [JsonPropertyName("fingerprint")] public required string Fingerprint { get; init; }

    /// <summary>
    /// Which peer this identity belongs to: a device id or slug on the calling side, a free label
    /// for applications on the device side. A pin only ever vouches for that one peer.
    /// </summary>
    [JsonPropertyName("peer")] public required string Peer { get; init; }

    [JsonPropertyName("origin")] public string Origin { get; init; } = TrustOrigins.Manual;

    [JsonPropertyName("addedAt")] public DateTimeOffset AddedAt { get; init; }
}

internal sealed record TrustFile
{
    [JsonPropertyName("identities")] public List<TrustedIdentity> Identities { get; init; } = [];
}

/// <summary>
/// The endpoint's own list of identities it accepts. This file, on this machine, is what
/// authenticates the other end of a session - not anything the platform says.
/// </summary>
public sealed class TrustStore
{
    private readonly string? _path;
    private readonly Lock _gate = new();
    private List<TrustedIdentity> _identities;

    /// <summary>An in-memory store (tests, embedded use with trust supplied by the application).</summary>
    public TrustStore()
    {
        _identities = [];
    }

    /// <summary>A store persisted as JSON at <paramref name="path"/>.</summary>
    public TrustStore(string path)
    {
        _path = path;
        _identities = File.Exists(path)
            ? JsonSerializer.Deserialize(File.ReadAllBytes(path), ClientJsonContext.Default.TrustFile)?.Identities ?? []
            : [];
    }

    public IReadOnlyList<TrustedIdentity> Identities
    {
        get
        {
            lock (_gate)
            {
                return _identities.ToArray();
            }
        }
    }

    /// <summary>Trusts <paramref name="fingerprint"/> as the identity of <paramref name="peer"/>.</summary>
    public TrustedIdentity Pin(string fingerprint, string peer, string origin = TrustOrigins.Manual)
    {
        if (!Fingerprints.TryNormalize(fingerprint, out string normalized))
        {
            throw new ArgumentException($"'{fingerprint}' is not a valid identity fingerprint.", nameof(fingerprint));
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(peer);

        var entry = new TrustedIdentity { Fingerprint = normalized, Peer = peer.Trim(), Origin = origin, AddedAt = DateTimeOffset.UtcNow };
        lock (_gate)
        {
            _identities.RemoveAll(i => i.Fingerprint == normalized && i.Peer == entry.Peer);
            _identities.Add(entry);
            Save();
        }
        return entry;
    }

    public bool Remove(string fingerprint, string? peer = null)
    {
        if (!Fingerprints.TryNormalize(fingerprint, out string normalized))
        {
            return false;
        }
        lock (_gate)
        {
            int removed = _identities.RemoveAll(i => i.Fingerprint == normalized && (peer is null || i.Peer == peer));
            if (removed > 0)
            {
                Save();
            }
            return removed > 0;
        }
    }

    /// <summary>
    /// The verifier for a session with one specific peer: only identities pinned for one of
    /// <paramref name="peerNames"/> are accepted (a device is known by its id and its slug).
    /// </summary>
    public IPeerVerifier VerifierForPeer(params string[] peerNames) => new StoreVerifier(this, peerNames);

    /// <summary>The verifier for an endpoint that accepts any identity it has pinned (the device side).</summary>
    public IPeerVerifier VerifierForAnyPinned() => new StoreVerifier(this, null);

    public bool IsPinned(string fingerprint) => Find(fingerprint, null) is not null;

    private TrustedIdentity? Find(string fingerprint, string[]? peerNames)
    {
        lock (_gate)
        {
            return _identities
                .Where(i => i.Fingerprint == fingerprint && (peerNames is null || peerNames.Contains(i.Peer, StringComparer.OrdinalIgnoreCase)))
                // Prefer the strongest origin when the same key was recorded more than once.
                .OrderBy(i => i.Origin == TrustOrigins.Platform ? 1 : 0)
                .FirstOrDefault();
        }
    }

    private bool HasAnyFor(string[]? peerNames)
    {
        lock (_gate)
        {
            return _identities.Any(i => peerNames is null || peerNames.Contains(i.Peer, StringComparer.OrdinalIgnoreCase));
        }
    }

    private void Save()
    {
        if (_path is null)
        {
            return;
        }
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
        File.WriteAllBytes(_path, JsonSerializer.SerializeToUtf8Bytes(new TrustFile { Identities = _identities }, ClientJsonContext.Default.TrustFile));
    }

    private sealed class StoreVerifier(TrustStore store, string[]? peerNames) : IPeerVerifier
    {
        public PeerVerdict Verify(X509Certificate2 certificate, string fingerprint)
        {
            TrustedIdentity? pinned = store.Find(fingerprint, peerNames);
            if (pinned is not null)
            {
                return PeerVerdict.Accept(pinned.Origin == TrustOrigins.Platform ? TrustLevel.PlatformIntroduced : TrustLevel.LocalPinned);
            }
            return PeerVerdict.Reject(store.HasAnyFor(peerNames) ? ErrorCodes.E2ePeerUntrusted : ErrorCodes.E2eTrustMissing);
        }
    }
}
