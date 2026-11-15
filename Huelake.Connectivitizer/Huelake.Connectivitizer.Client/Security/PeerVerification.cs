using System.Security.Cryptography.X509Certificates;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Security;

/// <summary>How the identity of the remote endpoint was established. Ordered from weakest to strongest.</summary>
public enum TrustLevel
{
    /// <summary>The peer is not authenticated end to end (compatibility mode only).</summary>
    None = 0,

    /// <summary>The peer's key was supplied by the platform and accepted without local verification.</summary>
    PlatformIntroduced = 1,

    /// <summary>
    /// The peer proved that it holds a key the user put on both endpoints. The platform never had
    /// that key; what the key cannot tell is which of its holders the peer is.
    /// </summary>
    SharedKey = 2,

    /// <summary>The peer's certificate was issued by a certificate authority the user controls and configured locally.</summary>
    WorkspaceCa = 3,

    /// <summary>The peer's public key fingerprint was pinned locally on this endpoint.</summary>
    LocalPinned = 4,
}

/// <summary>Outcome of checking a remote certificate against local trust.</summary>
public readonly record struct PeerVerdict(bool Accepted, TrustLevel Trust, string? ErrorCode)
{
    public static PeerVerdict Accept(TrustLevel trust) => new(true, trust, null);

    public static PeerVerdict Reject(string errorCode) => new(false, TrustLevel.None, errorCode);
}

/// <summary>Decides whether a remote endpoint's certificate is the identity this endpoint expects.</summary>
public interface IPeerVerifier
{
    PeerVerdict Verify(X509Certificate2 certificate, string fingerprint);
}

/// <summary>
/// The authenticated remote endpoint of an established secure channel. With certificates,
/// <paramref name="Fingerprint"/> is the certificate's fingerprint and <paramref name="Name"/> its
/// subject. With a shared key, <paramref name="Fingerprint"/> is <c>key:&lt;local name of the key&gt;</c>,
/// <paramref name="Name"/> is the label the platform gave the peer and <paramref name="CertificatePem"/> is empty.
/// </summary>
public sealed record PeerIdentity(string Fingerprint, string Name, TrustLevel Trust, string CertificatePem);

/// <summary>Accepts exactly the fingerprints it was given: the locally pinned identities of one specific peer.</summary>
public sealed class PinnedPeerVerifier : IPeerVerifier
{
    private readonly HashSet<string> _fingerprints;
    private readonly TrustLevel _trust;

    public PinnedPeerVerifier(IEnumerable<string> fingerprints, TrustLevel trust = TrustLevel.LocalPinned)
    {
        ArgumentNullException.ThrowIfNull(fingerprints);
        _fingerprints = new HashSet<string>(StringComparer.Ordinal);
        foreach (string value in fingerprints)
        {
            if (!Fingerprints.TryNormalize(value, out string normalized))
            {
                throw new ArgumentException($"'{value}' is not a valid identity fingerprint.", nameof(fingerprints));
            }
            _fingerprints.Add(normalized);
        }
        _trust = trust;
    }

    public PeerVerdict Verify(X509Certificate2 certificate, string fingerprint)
    {
        if (_fingerprints.Count == 0)
        {
            return PeerVerdict.Reject(ErrorCodes.E2eTrustMissing);
        }
        return _fingerprints.Contains(fingerprint)
            ? PeerVerdict.Accept(_trust)
            : PeerVerdict.Reject(ErrorCodes.E2ePeerUntrusted);
    }
}

/// <summary>Thrown when the end-to-end channel cannot be established. <see cref="ErrorCode"/> is one of <see cref="ErrorCodes"/>.</summary>
public sealed class SecureChannelException : Exception
{
    public SecureChannelException(string errorCode, string message, Exception? innerException = null)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }

    public string ErrorCode { get; }
}
