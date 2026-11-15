using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Huelake.Connectivitizer.Client.Identity;
using Huelake.Connectivitizer.Protocol;

namespace Huelake.Connectivitizer.Client.Platform;

/// <summary>An error answer from the Connectivitizer API. <see cref="ErrorCode"/> is one of <see cref="ErrorCodes"/>.</summary>
public sealed class PlatformException(string errorCode, string message, Exception? innerException = null) : Exception(message, innerException)
{
    public string ErrorCode { get; } = errorCode;
}

/// <summary>The machine-facing REST calls of the control plane: enrollment and token exchange.</summary>
public sealed class PlatformApi
{
    private readonly HttpClient _http;
    private readonly Uri _baseUrl;

    /// <param name="apiUrl">Base URL of the API, e.g. <c>https://api.connectivitizer.com/api/connectivitizer</c>.</param>
    public PlatformApi(Uri apiUrl, HttpClient? http = null)
    {
        _baseUrl = new Uri(apiUrl.AbsoluteUri.TrimEnd('/') + "/");
        _http = http ?? new HttpClient();
    }

    public Uri BaseUrl => _baseUrl;

    /// <summary>The signaling endpoint that belongs to this API.</summary>
    public Uri SignalUrl
    {
        get
        {
            var builder = new UriBuilder(new Uri(_baseUrl, "v1/signal"));
            builder.Scheme = builder.Scheme == Uri.UriSchemeHttps ? "wss" : "ws";
            return builder.Uri;
        }
    }

    /// <summary>
    /// Enrolls this machine as a device. Both keys are generated locally by the caller; only their
    /// public halves and proofs of possession are sent.
    /// </summary>
    public Task<EnrollResponse> EnrollAsync(string enrollmentToken, string name, ECDsa authKey, EndpointIdentity identity, string? platform, string? agentVersion, CancellationToken cancellationToken)
    {
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        string authPublicKeyPem = authKey.ExportSubjectPublicKeyInfoPem();
        byte[] proof = ProofStrings.Enrollment(enrollmentToken, timestamp, authPublicKeyPem, identity.Fingerprint);
        var request = new EnrollRequest
        {
            Token = enrollmentToken,
            Name = name,
            Platform = platform,
            AgentVersion = agentVersion,
            AuthPublicKeyPem = authPublicKeyPem,
            IdentityCertificatePem = identity.ExportCertificatePem(),
            Timestamp = timestamp,
            AuthSignature = Convert.ToBase64String(authKey.SignData(proof, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)),
            IdentitySignature = Convert.ToBase64String(identity.Sign(proof)),
        };
        return PostAsync("v1/devices/enroll", request, ProtocolJsonContext.Default.EnrollRequest, ProtocolJsonContext.Default.EnrollResponse, cancellationToken);
    }

    /// <summary>Logs a device in by signing a server challenge with its login key.</summary>
    public async Task<TokenResponse> GetDeviceTokenAsync(string deviceId, ECDsa authKey, CancellationToken cancellationToken)
    {
        DeviceChallengeResponse challenge = await PostAsync("v1/auth/device/challenge", new DeviceChallengeRequest { DeviceId = deviceId },
            ProtocolJsonContext.Default.DeviceChallengeRequest, ProtocolJsonContext.Default.DeviceChallengeResponse, cancellationToken).ConfigureAwait(false);
        byte[] signature = authKey.SignData(ProofStrings.DeviceLogin(challenge.Challenge), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return await PostAsync("v1/auth/device/token", new DeviceTokenRequest { DeviceId = deviceId, Challenge = challenge.Challenge, Signature = Convert.ToBase64String(signature) },
            ProtocolJsonContext.Default.DeviceTokenRequest, ProtocolJsonContext.Default.TokenResponse, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Exchanges an API key for an access token and registers the application's public identity.</summary>
    public Task<TokenResponse> GetCredentialTokenAsync(string apiKey, EndpointIdentity? identity, CancellationToken cancellationToken)
    {
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var request = new CredentialTokenRequest
        {
            ApiKey = apiKey,
            IdentityCertificatePem = identity?.ExportCertificatePem(),
            Timestamp = identity is null ? null : timestamp,
            IdentitySignature = identity is null ? null : Convert.ToBase64String(identity.Sign(ProofStrings.CredentialIdentity(apiKey, timestamp, identity.Fingerprint))),
        };
        return PostAsync("v1/auth/credential/token", request, ProtocolJsonContext.Default.CredentialTokenRequest, ProtocolJsonContext.Default.TokenResponse, cancellationToken);
    }

    /// <summary>
    /// Logs a device in with a device key and its name. The first login under a name creates the
    /// device. A device that also has a certificate registers its public half with the same call.
    /// </summary>
    public Task<TokenResponse> GetDeviceKeyTokenAsync(string deviceKey, string name, EndpointIdentity? identity, string? platform, string? agentVersion, CancellationToken cancellationToken)
    {
        long timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var request = new DeviceKeyTokenRequest
        {
            Key = deviceKey,
            Name = name,
            Platform = platform,
            AgentVersion = agentVersion,
            IdentityCertificatePem = identity?.ExportCertificatePem(),
            Timestamp = identity is null ? null : timestamp,
            IdentitySignature = identity is null ? null : Convert.ToBase64String(identity.Sign(ProofStrings.CredentialIdentity(deviceKey, timestamp, identity.Fingerprint))),
        };
        return PostAsync("v1/auth/device-key/token", request, ProtocolJsonContext.Default.DeviceKeyTokenRequest, ProtocolJsonContext.Default.TokenResponse, cancellationToken);
    }

    /// <summary>
    /// For an application whose user is signed in: exchanges the user's access token for a token to
    /// connect with, as the client <paramref name="client"/> of the workspace.
    /// </summary>
    public async Task<TokenResponse> GetAppTokenAsync(string userAccessToken, string workspaceId, string client, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_baseUrl, "v1/auth/app/token"))
        {
            Content = JsonContent.Create(new AppTokenRequest { WorkspaceId = workspaceId, Client = client }, ProtocolJsonContext.Default.AppTokenRequest),
        };
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", userAccessToken);
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync(ProtocolJsonContext.Default.TokenResponse, cancellationToken).ConfigureAwait(false)
            ?? throw new PlatformException(ErrorCodes.InvalidRequest, "The API returned an empty response.");
    }

    /// <summary>An application asks to be linked to somebody's account. Nothing is granted until that person approves in the web app.</summary>
    public Task<LinkStartResponse> StartLinkAsync(string client, string? platform, CancellationToken cancellationToken)
        => PostAsync("v1/auth/link", new LinkStartRequest { Client = client, Platform = platform }, ProtocolJsonContext.Default.LinkStartRequest, ProtocolJsonContext.Default.LinkStartResponse, cancellationToken);

    /// <summary>
    /// Asks whether a link was approved. The answer is "pending", or "approved" with the API key -
    /// once. A refused link fails with <see cref="ErrorCodes.LinkDenied"/>, an expired or used one
    /// with <see cref="ErrorCodes.LinkExpired"/>.
    /// </summary>
    public Task<LinkTokenResponse> PollLinkAsync(string deviceCode, CancellationToken cancellationToken)
        => PostAsync("v1/auth/link/token", new LinkTokenRequest { DeviceCode = deviceCode }, ProtocolJsonContext.Default.LinkTokenRequest, ProtocolJsonContext.Default.LinkTokenResponse, cancellationToken);

    /// <summary>The devices the application behind <paramref name="accessToken"/> may open sessions to.</summary>
    public async Task<ReachableDevice[]> GetReachableDevicesAsync(string accessToken, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, new Uri(_baseUrl, "v1/devices"));
        request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync(ProtocolJsonContext.Default.ReachableDeviceArray, cancellationToken).ConfigureAwait(false) ?? [];
    }

    /// <summary>The public keys session grants are signed with (JWKS).</summary>
    public async Task<Dictionary<string, ECDsa>> GetGrantKeysAsync(CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await SendAsync(new HttpRequestMessage(HttpMethod.Get, new Uri(_baseUrl, ".well-known/jwks.json")), cancellationToken).ConfigureAwait(false);
        using JsonDocument document = JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false));
        var keys = new Dictionary<string, ECDsa>(StringComparer.Ordinal);
        if (document.RootElement.TryGetProperty("keys", out JsonElement list) && list.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement jwk in list.EnumerateArray())
            {
                if (Text(jwk, "kty") != "EC" || Text(jwk, "crv") != "P-256" || Text(jwk, "kid") is not { Length: > 0 } kid
                    || Text(jwk, "x") is not { } x || Text(jwk, "y") is not { } y)
                {
                    continue;
                }
                keys[kid] = ECDsa.Create(new ECParameters
                {
                    Curve = ECCurve.NamedCurves.nistP256,
                    Q = new ECPoint { X = System.Buffers.Text.Base64Url.DecodeFromChars(x), Y = System.Buffers.Text.Base64Url.DecodeFromChars(y) },
                });
            }
        }
        return keys;

        static string? Text(JsonElement element, string name) => element.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
    }

    private async Task<TResponse> PostAsync<TRequest, TResponse>(string path, TRequest body, JsonTypeInfo<TRequest> requestType, JsonTypeInfo<TResponse> responseType, CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(_baseUrl, path)) { Content = JsonContent.Create(body, requestType) };
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        return await response.Content.ReadFromJsonAsync(responseType, cancellationToken).ConfigureAwait(false)
            ?? throw new PlatformException(ErrorCodes.InvalidRequest, "The API returned an empty response.");
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        HttpResponseMessage response;
        try
        {
            response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new PlatformException(ErrorCodes.SignalingUnavailable, $"The Connectivitizer API at {_baseUrl} could not be reached.", ex);
        }

        if (response.IsSuccessStatusCode)
        {
            return response;
        }

        using (response)
        {
            ApiError? error = null;
            try
            {
                error = await response.Content.ReadFromJsonAsync(ProtocolJsonContext.Default.ApiError, cancellationToken).ConfigureAwait(false);
            }
            catch (Exception ex) when (ex is JsonException or NotSupportedException)
            {
            }
            string code = error?.Error ?? ((int)response.StatusCode == 401 ? ErrorCodes.Unauthenticated : ErrorCodes.InvalidRequest);
            throw new PlatformException(code, error?.Message ?? $"The API refused the request ({(int)response.StatusCode} {code}).");
        }
    }
}
