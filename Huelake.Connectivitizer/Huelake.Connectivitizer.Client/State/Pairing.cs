using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Huelake.Connectivitizer.Client.Identity;

namespace Huelake.Connectivitizer.Client.State;

/// <summary>
/// Establishes mutual, locally verified trust between two endpoints with two short strings a
/// person copies between them - without the platform taking part at all.
/// </summary>
/// <remarks>
/// <para>
/// 1. The first endpoint (usually the device) creates an <b>invitation</b>: its name, its identity
/// fingerprint and a fresh random secret. The secret stays in the endpoint's state directory.
/// </para>
/// <para>
/// 2. The second endpoint accepts the invitation: it pins the first endpoint's fingerprint and
/// produces a <b>response</b>: its own name and fingerprint, authenticated with the secret.
/// </para>
/// <para>
/// 3. The first endpoint completes the pairing: the response proves it comes from whoever received
/// the invitation, so its fingerprint is pinned too.
/// </para>
/// The invitation contains a secret and should travel over a channel the user trusts. Even if it
/// is observed, an observer only gains the ability to be pinned by the inviting endpoint; reaching
/// a service additionally needs a platform credential and access rule.
/// </remarks>
public static class Pairing
{
    private const string InvitationPrefix = "czp1.";
    private const string ResponsePrefix = "czr1.";
    public static readonly TimeSpan InvitationLifetime = TimeSpan.FromMinutes(30);

    /// <summary>Creates an invitation for the endpoint whose state is in <paramref name="state"/>.</summary>
    public static string CreateInvitation(StateDirectory state, EndpointIdentity identity, string ownName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownName);
        byte[] secret = RandomNumberGenerator.GetBytes(32);

        List<PendingPairing> pending = state.LoadPendingPairings().Where(p => p.CreatedAt + InvitationLifetime > DateTimeOffset.UtcNow).ToList();
        pending.Add(new PendingPairing { Secret = Base64Url.EncodeToString(secret), CreatedAt = DateTimeOffset.UtcNow });
        state.SavePendingPairings(pending);

        var invitation = new PairingInvitation { Peer = ownName.Trim(), Fingerprint = identity.Fingerprint, Secret = Base64Url.EncodeToString(secret) };
        return InvitationPrefix + Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(invitation, PairingJsonContext.Default.PairingInvitation));
    }

    /// <summary>
    /// Accepts an invitation: pins the inviting endpoint and returns the response to hand back to it.
    /// </summary>
    /// <param name="pinAs">Name to pin the inviting endpoint under; defaults to the name in the invitation (a device's slug).</param>
    public static (string Response, TrustedIdentity Pinned) Accept(string invitation, EndpointIdentity ownIdentity, string ownName, TrustStore trust, string? pinAs = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(ownName);
        PairingInvitation parsed = Decode(invitation, InvitationPrefix, PairingJsonContext.Default.PairingInvitation)
            ?? throw new FormatException("This is not a pairing invitation.");
        if (!Fingerprints.TryNormalize(parsed.Fingerprint, out string peerFingerprint) || string.IsNullOrWhiteSpace(parsed.Peer))
        {
            throw new FormatException("The pairing invitation is damaged.");
        }

        byte[] secret;
        try
        {
            secret = Base64Url.DecodeFromChars(parsed.Secret);
        }
        catch (FormatException)
        {
            throw new FormatException("The pairing invitation is damaged.");
        }

        TrustedIdentity pinned = trust.Pin(peerFingerprint, pinAs ?? parsed.Peer, TrustOrigins.Pairing);
        var response = new PairingResponse
        {
            Peer = ownName.Trim(),
            Fingerprint = ownIdentity.Fingerprint,
            Mac = Base64Url.EncodeToString(ComputeMac(secret, peerFingerprint, ownIdentity.Fingerprint, ownName.Trim())),
        };
        return (ResponsePrefix + Base64Url.EncodeToString(JsonSerializer.SerializeToUtf8Bytes(response, PairingJsonContext.Default.PairingResponse)), pinned);
    }

    /// <summary>
    /// Completes a pairing on the inviting endpoint. The response is only accepted if it was made
    /// with the secret of one of this endpoint's open invitations; that invitation is then used up.
    /// </summary>
    public static TrustedIdentity Complete(string response, StateDirectory state, EndpointIdentity ownIdentity, TrustStore trust)
    {
        PairingResponse parsed = Decode(response, ResponsePrefix, PairingJsonContext.Default.PairingResponse)
            ?? throw new FormatException("This is not a pairing response.");
        if (!Fingerprints.TryNormalize(parsed.Fingerprint, out string peerFingerprint) || string.IsNullOrWhiteSpace(parsed.Peer))
        {
            throw new FormatException("The pairing response is damaged.");
        }

        byte[] presented;
        try
        {
            presented = Base64Url.DecodeFromChars(parsed.Mac);
        }
        catch (FormatException)
        {
            throw new FormatException("The pairing response is damaged.");
        }

        List<PendingPairing> pending = state.LoadPendingPairings();
        PendingPairing? match = pending.FirstOrDefault(p =>
            p.CreatedAt + InvitationLifetime > DateTimeOffset.UtcNow
            && CryptographicOperations.FixedTimeEquals(ComputeMac(Base64Url.DecodeFromChars(p.Secret), ownIdentity.Fingerprint, peerFingerprint, parsed.Peer), presented));
        if (match is null)
        {
            throw new CryptographicException("The response does not belong to an open invitation of this endpoint (it may have expired or already been used).");
        }

        pending.Remove(match);
        state.SavePendingPairings(pending);
        return trust.Pin(peerFingerprint, parsed.Peer, TrustOrigins.Pairing);
    }

    /// <summary>Binds the response to both identities and the responder's name, keyed with the invitation's secret.</summary>
    private static byte[] ComputeMac(byte[] secret, string inviterFingerprint, string responderFingerprint, string responderName)
        => HMACSHA256.HashData(secret, Encoding.UTF8.GetBytes($"cz-pair-v1|{inviterFingerprint}|{responderFingerprint}|{responderName}"));

    private static T? Decode<T>(string text, string prefix, System.Text.Json.Serialization.Metadata.JsonTypeInfo<T> typeInfo) where T : class
    {
        text = text.Trim();
        if (!text.StartsWith(prefix, StringComparison.Ordinal))
        {
            return null;
        }
        try
        {
            return JsonSerializer.Deserialize(Base64Url.DecodeFromChars(text.AsSpan(prefix.Length)), typeInfo);
        }
        catch (Exception ex) when (ex is FormatException or JsonException)
        {
            return null;
        }
    }
}

internal sealed record PairingInvitation
{
    [JsonPropertyName("peer")] public required string Peer { get; init; }
    [JsonPropertyName("fp")] public required string Fingerprint { get; init; }
    [JsonPropertyName("k")] public required string Secret { get; init; }
}

internal sealed record PairingResponse
{
    [JsonPropertyName("peer")] public required string Peer { get; init; }
    [JsonPropertyName("fp")] public required string Fingerprint { get; init; }
    [JsonPropertyName("mac")] public required string Mac { get; init; }
}

/// <summary>An invitation this endpoint issued and is still waiting to complete.</summary>
public sealed record PendingPairing
{
    [JsonPropertyName("secret")] public required string Secret { get; init; }
    [JsonPropertyName("createdAt")] public required DateTimeOffset CreatedAt { get; init; }
}

internal sealed record PendingPairingsFile
{
    [JsonPropertyName("pending")] public List<PendingPairing> Pending { get; init; } = [];
}

[JsonSerializable(typeof(PairingInvitation))]
[JsonSerializable(typeof(PairingResponse))]
[JsonSerializable(typeof(PendingPairingsFile))]
internal sealed partial class PairingJsonContext : JsonSerializerContext;
