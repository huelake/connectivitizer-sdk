using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Serialization;

namespace Huelake.Connectivitizer.Protocol;

/// <summary>Kinds of non-human endpoints.</summary>
public static class EndpointTypes
{
    public const string Device = "device";
    public const string Credential = "credential";
    public const string Gateway = "gateway";
}

/// <summary>Scopes of machine access tokens.</summary>
public static class MachineScopes
{
    /// <summary>Open the signaling channel and take part in sessions.</summary>
    public const string Connect = "connect";

    /// <summary>Manage the workspace through the REST API (devices, credentials, policies).</summary>
    public const string Manage = "manage";

    /// <summary>
    /// The key belongs to a linked app. One that manages does so for devices and keys; who is a
    /// member of the workspace stays with people and with keys a person created.
    /// </summary>
    public const string Linked = "linked";
}

/// <summary>
/// The exact byte strings endpoints sign to prove possession of a key. Fixed formats, so every
/// language builds the same bytes: ASCII, fields joined with '|'.
/// </summary>
public static class ProofStrings
{
    public static byte[] Enrollment(string enrollmentToken, long timestamp, string authPublicKeyPem, string identityFingerprint)
        => Encoding.ASCII.GetBytes($"cz-enroll-v1|{Sha256Hex(enrollmentToken)}|{timestamp}|{PublicKeyHash(authPublicKeyPem)}|{identityFingerprint}");

    public static byte[] DeviceLogin(string challenge) => Encoding.ASCII.GetBytes($"cz-device-auth-v1|{challenge}");

    public static byte[] CredentialIdentity(string apiKey, long timestamp, string identityFingerprint)
        => Encoding.ASCII.GetBytes($"cz-identity-v1|{Sha256Hex(apiKey)}|{timestamp}|{identityFingerprint}");

    public static string Sha256Hex(string value) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));

    /// <summary>SHA-256 (hex) of the DER SubjectPublicKeyInfo of a PEM public key.</summary>
    public static string PublicKeyHash(string publicKeyPem)
    {
        using ECDsa key = ECDsa.Create();
        key.ImportFromPem(publicKeyPem);
        return Convert.ToHexStringLower(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
    }
}

public sealed record EnrollRequest
{
    /// <summary>The one-time enrollment token created in the workspace.</summary>
    [JsonPropertyName("token")] public required string Token { get; init; }

    [JsonPropertyName("name")] public required string Name { get; init; }

    [JsonPropertyName("platform")] public string? Platform { get; init; }

    [JsonPropertyName("agentVersion")] public string? AgentVersion { get; init; }

    /// <summary>Public half of the key the device will log in with. The private half never leaves the device.</summary>
    [JsonPropertyName("authPublicKeyPem")] public required string AuthPublicKeyPem { get; init; }

    /// <summary>The device's end-to-end identity certificate (public).</summary>
    [JsonPropertyName("identityCertificatePem")] public required string IdentityCertificatePem { get; init; }

    [JsonPropertyName("timestamp")] public required long Timestamp { get; init; }

    /// <summary>Base64 signature over <see cref="ProofStrings.Enrollment"/> made with the login key.</summary>
    [JsonPropertyName("authSignature")] public required string AuthSignature { get; init; }

    /// <summary>Base64 signature over the same bytes made with the identity key.</summary>
    [JsonPropertyName("identitySignature")] public required string IdentitySignature { get; init; }
}

public sealed record EnrollResponse
{
    [JsonPropertyName("deviceId")] public required string DeviceId { get; init; }

    [JsonPropertyName("workspaceId")] public required string WorkspaceId { get; init; }

    [JsonPropertyName("name")] public required string Name { get; init; }

    [JsonPropertyName("slug")] public required string Slug { get; init; }
}

public sealed record DeviceChallengeRequest
{
    [JsonPropertyName("deviceId")] public required string DeviceId { get; init; }
}

public sealed record DeviceChallengeResponse
{
    [JsonPropertyName("challenge")] public required string Challenge { get; init; }

    [JsonPropertyName("expiresIn")] public required int ExpiresIn { get; init; }
}

public sealed record DeviceTokenRequest
{
    [JsonPropertyName("deviceId")] public required string DeviceId { get; init; }

    [JsonPropertyName("challenge")] public required string Challenge { get; init; }

    /// <summary>Base64 signature over <see cref="ProofStrings.DeviceLogin"/> made with the device's login key.</summary>
    [JsonPropertyName("signature")] public required string Signature { get; init; }
}

public sealed record CredentialTokenRequest
{
    [JsonPropertyName("apiKey")] public required string ApiKey { get; init; }

    /// <summary>
    /// Optional: the application's end-to-end identity certificate, so the platform can name it in
    /// grants and show it in the UI. Devices still decide for themselves whether they trust it.
    /// </summary>
    [JsonPropertyName("identityCertificatePem")] public string? IdentityCertificatePem { get; init; }

    [JsonPropertyName("timestamp")] public long? Timestamp { get; init; }

    /// <summary>Base64 signature over <see cref="ProofStrings.CredentialIdentity"/> made with the identity key.</summary>
    [JsonPropertyName("identitySignature")] public string? IdentitySignature { get; init; }
}

/// <summary>
/// A device logs in with a device key and the name it was given. The first login under a name
/// creates the device; later ones are the same device again.
/// </summary>
public sealed record DeviceKeyTokenRequest
{
    [JsonPropertyName("key")] public required string Key { get; init; }

    /// <summary>The device's name. It is the device's identity within the workspace, so it does not change.</summary>
    [JsonPropertyName("name")] public required string Name { get; init; }

    [JsonPropertyName("platform")] public string? Platform { get; init; }

    [JsonPropertyName("agentVersion")] public string? AgentVersion { get; init; }

    /// <summary>Optional, for a device that also has a certificate: registered exactly as in <see cref="CredentialTokenRequest"/>.</summary>
    [JsonPropertyName("identityCertificatePem")] public string? IdentityCertificatePem { get; init; }

    [JsonPropertyName("timestamp")] public long? Timestamp { get; init; }

    /// <summary>Base64 signature over <see cref="ProofStrings.CredentialIdentity"/> (with the device key in place of the API key) made with the identity key.</summary>
    [JsonPropertyName("identitySignature")] public string? IdentitySignature { get; init; }
}

/// <summary>An app asks to be linked to somebody's account (protocol section 11.5).</summary>
public sealed record LinkStartRequest
{
    /// <summary>The name the app appears under in the workspace, for example "Lamp app".</summary>
    [JsonPropertyName("client")] public required string Client { get; init; }

    /// <summary>What the app runs on, for example "android". Shown to the person who approves.</summary>
    [JsonPropertyName("platform")] public string? Platform { get; init; }

    /// <summary>
    /// The app asks to manage the workspace as well: keys, devices, who may reach what. Only an admin
    /// can approve such a link, and the key it leads to expires.
    /// </summary>
    [JsonPropertyName("manage")] public bool? Manage { get; init; }
}

public sealed record LinkStartResponse
{
    /// <summary>The short code the person compares, e.g. <c>KQTR-7MPL</c>.</summary>
    [JsonPropertyName("userCode")] public required string UserCode { get; init; }

    /// <summary>The app's own secret for this link. It never leaves the app.</summary>
    [JsonPropertyName("deviceCode")] public required string DeviceCode { get; init; }

    /// <summary>The page of the web app where the person approves.</summary>
    [JsonPropertyName("verificationUrl")] public required string VerificationUrl { get; init; }

    /// <summary>The same page with the code already filled in: what the app opens.</summary>
    [JsonPropertyName("verificationUrlComplete")] public required string VerificationUrlComplete { get; init; }

    [JsonPropertyName("expiresIn")] public required int ExpiresIn { get; init; }

    /// <summary>Seconds the app waits between two questions.</summary>
    [JsonPropertyName("interval")] public required int Interval { get; init; }
}

public sealed record LinkTokenRequest
{
    [JsonPropertyName("deviceCode")] public required string DeviceCode { get; init; }
}

public static class LinkStatuses
{
    public const string Pending = "pending";
    public const string Approved = "approved";
}

/// <summary>Either "pending", or "approved" together with the app's API key - which is returned exactly once.</summary>
public sealed record LinkTokenResponse
{
    [JsonPropertyName("status")] public required string Status { get; init; }

    [JsonPropertyName("apiKey")] public string? ApiKey { get; init; }

    [JsonPropertyName("workspaceId")] public string? WorkspaceId { get; init; }

    [JsonPropertyName("workspaceName")] public string? WorkspaceName { get; init; }

    /// <summary>Whether the key may manage the workspace.</summary>
    [JsonPropertyName("manage")] public bool? Manage { get; init; }

    /// <summary>When the key stops working, if it does.</summary>
    [JsonPropertyName("expiresAt")] public DateTime? ExpiresAt { get; init; }

    [JsonPropertyName("credentialId")] public string? CredentialId { get; init; }

    /// <summary>The name the app got in the workspace (the one it asked for, made distinct if needed).</summary>
    [JsonPropertyName("client")] public string? Client { get; init; }
}

/// <summary>A device an application may open sessions to (<c>GET v1/devices</c>).</summary>
public sealed record ReachableDevice
{
    [JsonPropertyName("id")] public required string Id { get; init; }

    /// <summary>What the device calls itself.</summary>
    [JsonPropertyName("name")] public required string Name { get; init; }

    /// <summary>The name sessions are opened to.</summary>
    [JsonPropertyName("slug")] public required string Slug { get; init; }

    /// <summary>A name people gave the device in the web app.</summary>
    [JsonPropertyName("alias")] public string? Alias { get; init; }

    [JsonPropertyName("online")] public required bool Online { get; init; }

    /// <summary>What the device's software announced; empty while it is offline.</summary>
    [JsonPropertyName("capabilities")] public string[] Capabilities { get; init; } = [];

    /// <summary>The services of the device this application may use.</summary>
    [JsonPropertyName("services")] public string[] Services { get; init; } = [];
}

/// <summary>
/// An application whose user is signed in asks for a token to connect with. The request is
/// authenticated with the user's own token; the body says in which workspace and as which client.
/// </summary>
public sealed record AppTokenRequest
{
    [JsonPropertyName("workspaceId")] public required string WorkspaceId { get; init; }

    /// <summary>Name of the client the application is, as shown in the workspace (for example "Example app").</summary>
    [JsonPropertyName("client")] public required string Client { get; init; }
}

public sealed record TokenResponse
{
    [JsonPropertyName("accessToken")] public required string AccessToken { get; init; }

    [JsonPropertyName("expiresIn")] public required int ExpiresIn { get; init; }

    [JsonPropertyName("endpointType")] public required string EndpointType { get; init; }

    [JsonPropertyName("endpointId")] public required string EndpointId { get; init; }

    [JsonPropertyName("workspaceId")] public required string WorkspaceId { get; init; }

    /// <summary>The control plane's clock (Unix seconds), for endpoints without one of their own.</summary>
    [JsonPropertyName("serverTime")] public long? ServerTime { get; init; }

    /// <summary>Device logins: the name devices are addressed by in <c>connect.request</c>.</summary>
    [JsonPropertyName("slug")] public string? Slug { get; init; }
}

/// <summary>Claims of a machine access token (a compact JWS, audience <see cref="Audience"/>).</summary>
public sealed record MachineToken
{
    public const string Audience = "cz-api";

    [JsonPropertyName("iss")] public required string Issuer { get; init; }

    [JsonPropertyName("aud")] public required string Aud { get; init; }

    /// <summary>The endpoint id.</summary>
    [JsonPropertyName("sub")] public required string Subject { get; init; }

    /// <summary>One of <see cref="EndpointTypes"/>.</summary>
    [JsonPropertyName("typ")] public required string EndpointType { get; init; }

    [JsonPropertyName("ws")] public required string WorkspaceId { get; init; }

    [JsonPropertyName("name")] public string? Name { get; init; }

    [JsonPropertyName("scopes")] public string[] Scopes { get; init; } = [];

    [JsonPropertyName("iat")] public required long IssuedAt { get; init; }

    [JsonPropertyName("exp")] public required long ExpiresAt { get; init; }
}

/// <summary>Error body of the REST API.</summary>
public sealed record ApiError
{
    [JsonPropertyName("error")] public required string Error { get; init; }

    [JsonPropertyName("message")] public string? Message { get; init; }
}
