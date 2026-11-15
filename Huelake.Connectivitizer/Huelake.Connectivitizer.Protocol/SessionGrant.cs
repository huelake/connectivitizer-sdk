using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>How application traffic of a session travels and who can read it.</summary>
public static class ConnectionModes
{
    /// <summary>Peer to peer. No Connectivitizer server is in the data path.</summary>
    public const string Direct = "direct";

    /// <summary>Through the relay, end-to-end encrypted. The relay forwards ciphertext it has no key for.</summary>
    public const string E2eRelay = "e2e-relay";

    /// <summary>Through the compatibility gateway, which terminates TLS and can read the traffic.</summary>
    public const string Compatibility = "compatibility";
}

/// <summary>Audiences a session grant is issued for.</summary>
public static class GrantAudiences
{
    public const string Relay = "cz-relay";
    public const string Agent = "cz-agent";
}

/// <summary>Role a connection plays in a session.</summary>
public static class SessionRoles
{
    public const string Initiator = "initiator";
    public const string Device = "device";
}

/// <summary>
/// A session grant: the control plane's signed statement that one initiator may open one session
/// to one device for the listed services and modes. It authorises; it does not authenticate the
/// endpoints to each other - that is done end to end with locally trusted identities, and the
/// fingerprints named here are cross-checked against what the TLS handshake actually presented.
/// </summary>
public sealed record SessionGrant
{
    [JsonPropertyName("iss")] public required string Issuer { get; init; }

    [JsonPropertyName("aud")] public required string[] Audiences { get; init; }

    /// <summary>The session id.</summary>
    [JsonPropertyName("jti")] public required string SessionId { get; init; }

    [JsonPropertyName("ws")] public required string WorkspaceId { get; init; }

    [JsonPropertyName("ini")] public required GrantParty Initiator { get; init; }

    [JsonPropertyName("dev")] public required GrantParty Device { get; init; }

    /// <summary>Names of the device services this session may open.</summary>
    [JsonPropertyName("svc")] public required string[] Services { get; init; }

    /// <summary>Permitted <see cref="ConnectionModes"/>.</summary>
    [JsonPropertyName("modes")] public required string[] Modes { get; init; }

    /// <summary>
    /// The end-to-end layer of this session, one of <see cref="E2eMethods"/>. Absent in grants of
    /// control planes that predate the choice, where it means <see cref="E2eMethods.Tls13"/>.
    /// </summary>
    [JsonPropertyName("e2e")] public string? E2e { get; init; }

    [JsonIgnore] public string E2eMethod => E2e ?? E2eMethods.Tls13;

    /// <summary>Relay endpoint for this session, when relaying is permitted.</summary>
    [JsonPropertyName("relay")] public string? RelayUrl { get; init; }

    [JsonPropertyName("iat")] public required long IssuedAt { get; init; }

    /// <summary>Unix time until which the grant may be used to start the session.</summary>
    [JsonPropertyName("exp")] public required long ExpiresAt { get; init; }

    /// <summary>Seconds after <see cref="IssuedAt"/> for which a running session stays authorised without a fresh grant.</summary>
    [JsonPropertyName("lease")] public required int LeaseSeconds { get; init; }

    [JsonIgnore] public long LeaseExpiresAt => IssuedAt + LeaseSeconds;
}

/// <summary>One endpoint named in a grant.</summary>
public sealed record GrantParty
{
    /// <summary><c>device</c>, <c>credential</c> or <c>gateway</c>.</summary>
    [JsonPropertyName("type")] public required string Type { get; init; }

    [JsonPropertyName("id")] public required string Id { get; init; }

    /// <summary>Fingerprint of the end-to-end identity the platform has on record for this endpoint.</summary>
    [JsonPropertyName("fp")] public string? Fingerprint { get; init; }
}

/// <summary>Result of checking a grant token.</summary>
public readonly record struct GrantValidation(SessionGrant? Grant, string? ErrorCode)
{
    public bool IsValid => Grant is not null;
}

public static class SessionGrantToken
{
    /// <summary>Tolerated clock difference between the control plane and whoever verifies a grant.</summary>
    public static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    public static string Issue(SessionGrant grant, ECDsa signingKey, string keyId)
        => CompactJws.Sign(JsonSerializer.SerializeToUtf8Bytes(grant, ProtocolJsonContext.Default.SessionGrant), signingKey, keyId);

    /// <summary>
    /// Verifies signature, audience and time. <paramref name="forSessionStart"/> selects which
    /// deadline applies: the short start window (<c>exp</c>) or the session lease.
    /// </summary>
    public static GrantValidation Validate(string? token, Func<string, ECDsa?> resolveKey, string audience, DateTimeOffset now, bool forSessionStart = true)
    {
        if (!CompactJws.TryVerify(token, resolveKey, out byte[] payload))
        {
            return new GrantValidation(null, ErrorCodes.GrantInvalid);
        }

        SessionGrant? grant;
        try
        {
            grant = JsonSerializer.Deserialize(payload, ProtocolJsonContext.Default.SessionGrant);
        }
        catch (JsonException)
        {
            return new GrantValidation(null, ErrorCodes.GrantInvalid);
        }

        if (grant is null || string.IsNullOrEmpty(grant.SessionId) || !grant.Audiences.Contains(audience, StringComparer.Ordinal))
        {
            return new GrantValidation(null, ErrorCodes.GrantInvalid);
        }

        long unixNow = now.ToUnixTimeSeconds();
        long skew = (long)ClockSkew.TotalSeconds;
        long deadline = forSessionStart ? grant.ExpiresAt : grant.LeaseExpiresAt;
        if (unixNow > deadline + skew || unixNow < grant.IssuedAt - skew)
        {
            return new GrantValidation(null, ErrorCodes.GrantExpired);
        }

        return new GrantValidation(grant, null);
    }
}
