using System.Text.Json;
using System.Text.Json.Serialization;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>Capabilities an endpoint announces in its <c>hello</c>.</summary>
public static class Capabilities
{
    public const string E2eTls13 = "e2e.tls13";
    public const string E2eSharedKey = "e2e.shared-key";
    public const string MuxYamux = "mux.yamux";
    public const string PathRelayWs = "path.relay-ws";
    public const string PathTcp = "path.tcp";
    public const string PathUdpKcp = "path.udp-kcp";
}

/// <summary>
/// The end-to-end layers of the protocol. A session uses exactly one, named in its grant; both
/// keep the platform out: one authenticates the endpoints with certificates each side pinned
/// locally, the other with a key only the two endpoints hold.
/// </summary>
public static class E2eMethods
{
    /// <summary>Mutual TLS 1.3 with locally trusted certificates (protocol section 4).</summary>
    public const string Tls13 = "tls13";

    /// <summary>A handshake keyed with a secret the user put on both endpoints (protocol section 4a).</summary>
    public const string SharedKey = "shared-key";

    /// <summary>Order of preference when an initiator does not state one.</summary>
    public static readonly string[] Preference = [Tls13, SharedKey];

    public static string? CapabilityOf(string method) => method switch
    {
        Tls13 => Capabilities.E2eTls13,
        SharedKey => Capabilities.E2eSharedKey,
        _ => null,
    };
}

/// <summary>HTTP headers of the signaling channel beyond the bearer token.</summary>
public static class SignalingHeaders
{
    /// <summary>
    /// Presented by the platform's compatibility gateway, together with the calling application's
    /// own token. Only a connection carrying it can obtain <see cref="ConnectionModes.Compatibility"/>
    /// sessions - and it can obtain nothing else.
    /// </summary>
    public const string GatewaySecret = "Cz-Gateway-Secret";
}

/// <summary>What carries a session's bytes between the endpoints.</summary>
public static class PathTransports
{
    public const string RelayWs = "relay-ws";
    public const string UdpKcp = "udp-kcp";
    public const string Tcp = "tcp";
}

/// <summary>Message types of the signaling channel (the <c>t</c> member of the envelope).</summary>
public static class SignalTypes
{
    public const string Hello = "hello";
    public const string Welcome = "welcome";
    public const string Ping = "ping";
    public const string Pong = "pong";
    public const string ServicesSync = "services.sync";
    public const string ConnectRequest = "connect.request";
    public const string ConnectGrant = "connect.grant";
    public const string ConnectOffer = "connect.offer";
    public const string ConnectAnswer = "connect.answer";
    public const string PathCandidates = "path.candidates";
    public const string PathFallback = "path.fallback";
    public const string SessionUpdate = "session.update";
    public const string LeaseRequest = "lease.request";
    public const string LeaseGrant = "lease.grant";
    public const string Revoke = "revoke";
    public const string Error = "error";
}

/// <summary>
/// One signaling message. Signaling carries who wants to talk to whom and how to reach them -
/// never application data.
/// </summary>
public sealed record SignalEnvelope
{
    [JsonPropertyName("t")] public required string Type { get; init; }

    /// <summary>Set by the sender when it expects a reply.</summary>
    [JsonPropertyName("id")] public string? Id { get; init; }

    /// <summary>The <see cref="Id"/> of the message this one answers.</summary>
    [JsonPropertyName("re")] public string? ReplyTo { get; init; }

    [JsonPropertyName("d")] public JsonElement? Data { get; init; }
}

public sealed record ServiceDeclaration
{
    [JsonPropertyName("name")] public required string Name { get; init; }

    /// <summary><c>http</c>, <c>ws</c> or <c>tcp</c>. Informational; every service is carried as a byte stream.</summary>
    [JsonPropertyName("protocol")] public string Protocol { get; init; } = "tcp";

    /// <summary>
    /// The device's own configuration allows compatibility mode for this service. Reported so that
    /// the owner can see it in the web app; what counts is the device's check of every grant.
    /// </summary>
    [JsonPropertyName("compat")] public bool Compatibility { get; init; }
}

public sealed record SignalHello
{
    [JsonPropertyName("caps")] public required string[] Capabilities { get; init; }

    /// <summary>
    /// Fingerprint of the end-to-end identity this endpoint will present. Required of an endpoint
    /// that announces <see cref="Capabilities.E2eTls13"/>, absent for one that has no certificate.
    /// </summary>
    [JsonPropertyName("fp")] public string? Fingerprint { get; init; }

    [JsonPropertyName("agentVersion")] public string? AgentVersion { get; init; }

    [JsonPropertyName("platform")] public string? Platform { get; init; }

    /// <summary>Device only: names of the services declared locally. Targets are never sent.</summary>
    [JsonPropertyName("services")] public ServiceDeclaration[]? Services { get; init; }
}

public sealed record SignalWelcome
{
    [JsonPropertyName("endpointType")] public required string EndpointType { get; init; }

    [JsonPropertyName("endpointId")] public required string EndpointId { get; init; }

    [JsonPropertyName("workspaceId")] public required string WorkspaceId { get; init; }

    [JsonPropertyName("heartbeatSeconds")] public int HeartbeatSeconds { get; init; } = 25;

    /// <summary><c>host:port</c> of the STUN endpoints for reflexive address discovery.</summary>
    [JsonPropertyName("stunServers")] public string[] StunServers { get; init; } = [];

    /// <summary>The control plane's clock (Unix seconds), for endpoints without one of their own.</summary>
    [JsonPropertyName("serverTime")] public long? ServerTime { get; init; }
}

public sealed record SignalServicesSync
{
    [JsonPropertyName("services")] public required ServiceDeclaration[] Services { get; init; }
}

public sealed record SignalConnectRequest
{
    /// <summary>Id or slug of the device.</summary>
    [JsonPropertyName("device")] public required string Device { get; init; }

    [JsonPropertyName("services")] public required string[] Services { get; init; }

    /// <summary>Connection modes the initiator is willing to use. Empty means every mode the policy permits.</summary>
    [JsonPropertyName("modes")] public string[]? Modes { get; init; }

    /// <summary>
    /// End-to-end layers the initiator is prepared to use for this device, most preferred first
    /// (see <see cref="E2eMethods"/>). Absent means every layer it announced.
    /// </summary>
    [JsonPropertyName("e2e")] public string[]? E2e { get; init; }
}

/// <summary>One end of a session as described to the other end. The fingerprint is a hint to find the local pin.</summary>
public sealed record SignalPeer
{
    [JsonPropertyName("type")] public required string Type { get; init; }

    [JsonPropertyName("id")] public required string Id { get; init; }

    [JsonPropertyName("name")] public string? Name { get; init; }

    [JsonPropertyName("fp")] public string? Fingerprint { get; init; }

    [JsonPropertyName("caps")] public string[] Capabilities { get; init; } = [];
}

/// <summary>Reply to <see cref="SignalConnectRequest"/>, and the offer sent to the device.</summary>
public sealed record SignalConnectGrant
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    [JsonPropertyName("grant")] public required string GrantToken { get; init; }

    [JsonPropertyName("peer")] public required SignalPeer Peer { get; init; }
}

public sealed record SignalConnectAnswer
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    [JsonPropertyName("accept")] public required bool Accept { get; init; }

    [JsonPropertyName("error")] public string? Error { get; init; }
}

/// <summary>What an endpoint reports about a session. Metadata only.</summary>
public sealed record SignalSessionUpdate
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    /// <summary><c>established</c>, <c>failed</c> or <c>ended</c>.</summary>
    [JsonPropertyName("state")] public required string State { get; init; }

    [JsonPropertyName("mode")] public string? Mode { get; init; }

    [JsonPropertyName("trust")] public string? Trust { get; init; }

    [JsonPropertyName("directFailureReason")] public string? DirectFailureReason { get; init; }

    /// <summary>One of <see cref="PathTransports"/>.</summary>
    [JsonPropertyName("transport")] public string? Transport { get; init; }

    [JsonPropertyName("error")] public string? Error { get; init; }

    /// <summary>Bytes of application traffic this endpoint sent and received, as counted by itself.</summary>
    [JsonPropertyName("bytesSent")] public long? BytesSent { get; init; }

    [JsonPropertyName("bytesReceived")] public long? BytesReceived { get; init; }
}

public sealed record SignalLeaseRequest
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }
}

public sealed record SignalLeaseGrant
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    [JsonPropertyName("grant")] public required string GrantToken { get; init; }
}

/// <summary>
/// One endpoint's candidate addresses for a direct path, passed to the peer through the control
/// plane. The list is opaque to the control plane; the endpoints later confirm inside the
/// encrypted session that the list each of them received is the one the other sent.
/// </summary>
public sealed record SignalPathCandidates
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    /// <summary>Base64 of the candidate list bytes exactly as the sender produced them.</summary>
    [JsonPropertyName("blob")] public required string Blob { get; init; }
}

/// <summary>The initiator tells the device that no direct path was found and the relay is to be used.</summary>
public sealed record SignalPathFallback
{
    [JsonPropertyName("sid")] public required string SessionId { get; init; }

    [JsonPropertyName("reason")] public required string Reason { get; init; }
}

/// <summary>The control plane withdrew authorisation: the endpoint must end the named sessions (or all of them).</summary>
public sealed record SignalRevoke
{
    [JsonPropertyName("sids")] public string[]? SessionIds { get; init; }

    [JsonPropertyName("reason")] public required string Reason { get; init; }
}

public sealed record SignalError
{
    [JsonPropertyName("code")] public required string Code { get; init; }

    [JsonPropertyName("message")] public string? Message { get; init; }
}

public static class SessionStates
{
    public const string Requested = "requested";
    public const string Established = "established";
    public const string Failed = "failed";
    public const string Ended = "ended";
}
