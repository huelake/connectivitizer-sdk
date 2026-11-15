namespace Huelake.Connectivitizer.Protocol;

/// <summary>
/// Stable, machine-readable error codes. They appear in API responses, signaling messages,
/// SDK exceptions and the UIs, so a failure can be traced to authentication, authorization,
/// connectivity, endpoint trust or the local application.
/// </summary>
public static class ErrorCodes
{
    // Endpoint trust (end-to-end layer)
    public const string E2ePeerNoCertificate = "E2E_PEER_NO_CERTIFICATE";
    public const string E2ePeerCertificateExpired = "E2E_PEER_CERTIFICATE_EXPIRED";
    public const string E2ePeerUntrusted = "E2E_PEER_UNTRUSTED";
    public const string E2eTrustMissing = "E2E_TRUST_MISSING";
    public const string E2eHandshakeFailed = "E2E_HANDSHAKE_FAILED";
    public const string E2eProtocolMismatch = "E2E_PROTOCOL_MISMATCH";
    public const string E2eSessionBindMismatch = "E2E_SESSION_BIND_MISMATCH";
    public const string E2eSharedKeyMismatch = "E2E_SHARED_KEY_MISMATCH";
    public const string E2eNoCommonMethod = "E2E_NO_COMMON_METHOD";

    // Connectivity
    public const string PathClosed = "PATH_CLOSED";
    public const string PathIdleTimeout = "PATH_IDLE_TIMEOUT";
    public const string DirectUnavailable = "DIRECT_UNAVAILABLE";
    public const string RelayUnreachable = "RELAY_UNREACHABLE";
    public const string RelayPeerTimeout = "RELAY_PEER_TIMEOUT";
    public const string RelayRejected = "RELAY_REJECTED";
    public const string SessionClosed = "SESSION_CLOSED";
    public const string MuxProtocolError = "MUX_PROTOCOL_ERROR";

    // Authorization
    public const string GrantInvalid = "GRANT_INVALID";
    public const string GrantExpired = "GRANT_EXPIRED";
    public const string LeaseExpired = "LEASE_EXPIRED";
    public const string SessionRevoked = "SESSION_REVOKED";
    public const string ServiceNotExposed = "SERVICE_NOT_EXPOSED";
    public const string DeniedByGrant = "DENIED_BY_GRANT";
    public const string DeniedByLocalPolicy = "DENIED_BY_LOCAL_POLICY";

    public const string Unauthenticated = "UNAUTHENTICATED";
    public const string Forbidden = "FORBIDDEN";
    public const string CredentialRevoked = "CREDENTIAL_REVOKED";
    public const string DeviceRevoked = "DEVICE_REVOKED";
    public const string DeviceNotFound = "DEVICE_NOT_FOUND";
    public const string DeviceOffline = "DEVICE_OFFLINE";
    public const string ServiceDisabled = "SERVICE_DISABLED";
    public const string DeviceRejected = "DEVICE_REJECTED";
    public const string EnrollmentTokenInvalid = "ENROLLMENT_TOKEN_INVALID";
    public const string ProofInvalid = "PROOF_INVALID";
    public const string IdentityNotRegistered = "IDENTITY_NOT_REGISTERED";
    public const string PrivateKeyRejected = "PRIVATE_KEY_REJECTED";
    public const string PlanLimitReached = "PLAN_LIMIT_REACHED";
    public const string RelayQuotaExceeded = "RELAY_QUOTA_EXCEEDED";
    public const string NoPermittedMode = "NO_PERMITTED_MODE";
    public const string CompatibilityNotEnabled = "COMPATIBILITY_NOT_ENABLED";
    public const string PlanFeatureUnavailable = "PLAN_FEATURE_UNAVAILABLE";
    public const string InvalidRequest = "INVALID_REQUEST";
    public const string NotFound = "NOT_FOUND";
    public const string Conflict = "CONFLICT";

    /// <summary>The link an app started was not approved in time, is unknown, or was already used.</summary>
    public const string LinkExpired = "LINK_EXPIRED";

    /// <summary>The person refused to link the app.</summary>
    public const string LinkDenied = "LINK_DENIED";
    public const string SignalingTimeout = "SIGNALING_TIMEOUT";
    public const string SignalingUnavailable = "SIGNALING_UNAVAILABLE";

    // Local application on the device
    public const string TargetUnreachable = "TARGET_UNREACHABLE";
}
