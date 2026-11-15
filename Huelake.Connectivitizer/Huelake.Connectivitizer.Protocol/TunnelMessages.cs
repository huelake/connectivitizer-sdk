using System.Text.Json.Serialization;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>
/// First message each endpoint sends on the control stream once the end-to-end TLS handshake is
/// done. Both sides compare it with what they know themselves; any difference ends the session.
/// It ties the encrypted channel to one specific grant and makes each side state the path it
/// actually observed, so neither a spliced session nor a mislabelled route goes unnoticed.
/// </summary>
public sealed record SessionBind
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    /// <summary>SHA-256 (lower-case hex) of the grant token this endpoint is acting on.</summary>
    [JsonPropertyName("grant")] public required string GrantHash { get; init; }

    /// <summary><see cref="SessionRoles"/> of the sender.</summary>
    [JsonPropertyName("role")] public required string Role { get; init; }

    /// <summary>The <see cref="ConnectionModes"/> value the sender observed locally for this session.</summary>
    [JsonPropertyName("mode")] public required string Mode { get; init; }

    /// <summary>
    /// Direct sessions only: SHA-256 (hex) of the candidate list the sender announced. The receiver
    /// compares it with the list it was handed through signaling, so candidates altered in transit
    /// are noticed inside the authenticated channel.
    /// </summary>
    [JsonPropertyName("cands")] public string? CandidatesHash { get; init; }

    /// <summary>
    /// Direct TCP sessions only, and only from the endpoint that opened the TCP connection: the
    /// candidate (<c>ip:port</c>) it connected to. The accepting endpoint checks that this is an
    /// address it announced itself. A session in which neither endpoint connected to the other -
    /// two inbound connections joined by someone in between - is thereby refused.
    /// </summary>
    [JsonPropertyName("dial")] public string? DialedCandidate { get; init; }
}

/// <summary>Sent by the initiator on the control stream to extend a running session with a fresh grant.</summary>
public sealed record LeaseRenewal
{
    [JsonPropertyName("grant")] public required string GrantToken { get; init; }
}

/// <summary>A message on the control stream (mux stream 1). Exactly one member is set.</summary>
public sealed record ControlMessage
{
    [JsonPropertyName("bind")] public SessionBind? Bind { get; init; }

    [JsonPropertyName("lease")] public LeaseRenewal? Lease { get; init; }

    /// <summary>An <see cref="ErrorCodes"/> value: the sender is ending the session for this reason.</summary>
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>First message on every service stream: which of the device's services the initiator wants.</summary>
public sealed record ServiceOpenRequest
{
    [JsonPropertyName("svc")] public required string Service { get; init; }
}

/// <summary>The device's answer to a <see cref="ServiceOpenRequest"/>. After a refusal the stream is closed.</summary>
public sealed record ServiceOpenResponse
{
    [JsonPropertyName("ok")] public required bool Ok { get; init; }

    /// <summary>An <see cref="ErrorCodes"/> value when <see cref="Ok"/> is false.</summary>
    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>The single text frame the relay sends once both ends of a session are connected.</summary>
public sealed record RelayPaired
{
    [JsonPropertyName("t")] public string Type { get; init; } = "paired";
}

/// <summary>
/// A text frame an endpoint sends to the relay itself (it is never forwarded): a fresh grant that
/// extends the lease of the running session.
/// </summary>
public sealed record RelayLeaseRenewal
{
    [JsonPropertyName("t")] public string Type { get; init; } = "lease";

    [JsonPropertyName("grant")] public required string GrantToken { get; init; }
}

[JsonSourceGenerationOptions(DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull)]
[JsonSerializable(typeof(JwsHeader))]
[JsonSerializable(typeof(SessionGrant))]
[JsonSerializable(typeof(ControlMessage))]
[JsonSerializable(typeof(ServiceOpenRequest))]
[JsonSerializable(typeof(ServiceOpenResponse))]
[JsonSerializable(typeof(RelayPaired))]
[JsonSerializable(typeof(RelayLeaseRenewal))]
[JsonSerializable(typeof(SignalEnvelope))]
[JsonSerializable(typeof(SignalHello))]
[JsonSerializable(typeof(SignalWelcome))]
[JsonSerializable(typeof(SignalServicesSync))]
[JsonSerializable(typeof(SignalConnectRequest))]
[JsonSerializable(typeof(SignalConnectGrant))]
[JsonSerializable(typeof(SignalConnectAnswer))]
[JsonSerializable(typeof(SignalSessionUpdate))]
[JsonSerializable(typeof(SignalLeaseRequest))]
[JsonSerializable(typeof(SignalLeaseGrant))]
[JsonSerializable(typeof(SignalRevoke))]
[JsonSerializable(typeof(SignalPathCandidates))]
[JsonSerializable(typeof(SignalPathFallback))]
[JsonSerializable(typeof(SignalError))]
[JsonSerializable(typeof(EnrollRequest))]
[JsonSerializable(typeof(EnrollResponse))]
[JsonSerializable(typeof(DeviceChallengeRequest))]
[JsonSerializable(typeof(DeviceChallengeResponse))]
[JsonSerializable(typeof(DeviceTokenRequest))]
[JsonSerializable(typeof(CredentialTokenRequest))]
[JsonSerializable(typeof(DeviceKeyTokenRequest))]
[JsonSerializable(typeof(AppTokenRequest))]
[JsonSerializable(typeof(LinkStartRequest))]
[JsonSerializable(typeof(LinkStartResponse))]
[JsonSerializable(typeof(LinkTokenRequest))]
[JsonSerializable(typeof(LinkTokenResponse))]
[JsonSerializable(typeof(ReachableDevice[]))]
[JsonSerializable(typeof(TokenResponse))]
[JsonSerializable(typeof(MachineToken))]
[JsonSerializable(typeof(ApiError))]
[JsonSerializable(typeof(System.Text.Json.JsonElement))]
public sealed partial class ProtocolJsonContext : JsonSerializerContext;
