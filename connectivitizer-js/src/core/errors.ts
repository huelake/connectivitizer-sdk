/**
 * Stable, machine-readable error codes. They are the same in every Connectivitizer SDK, in API
 * responses and in the web app, so a failure can be traced to authentication, authorization,
 * connectivity, endpoint trust or the local application.
 */
export const ErrorCodes = {
  // Endpoint trust (end-to-end layer)
  E2ePeerNoCertificate: 'E2E_PEER_NO_CERTIFICATE',
  E2ePeerCertificateExpired: 'E2E_PEER_CERTIFICATE_EXPIRED',
  E2ePeerUntrusted: 'E2E_PEER_UNTRUSTED',
  E2eTrustMissing: 'E2E_TRUST_MISSING',
  E2eHandshakeFailed: 'E2E_HANDSHAKE_FAILED',
  E2eProtocolMismatch: 'E2E_PROTOCOL_MISMATCH',
  E2eSessionBindMismatch: 'E2E_SESSION_BIND_MISMATCH',
  E2eSharedKeyMismatch: 'E2E_SHARED_KEY_MISMATCH',
  E2eNoCommonMethod: 'E2E_NO_COMMON_METHOD',
  LinkExpired: 'LINK_EXPIRED',
  LinkDenied: 'LINK_DENIED',

  // Connectivity
  PathClosed: 'PATH_CLOSED',
  PathIdleTimeout: 'PATH_IDLE_TIMEOUT',
  DirectUnavailable: 'DIRECT_UNAVAILABLE',
  RelayUnreachable: 'RELAY_UNREACHABLE',
  RelayPeerTimeout: 'RELAY_PEER_TIMEOUT',
  RelayRejected: 'RELAY_REJECTED',
  SessionClosed: 'SESSION_CLOSED',
  MuxProtocolError: 'MUX_PROTOCOL_ERROR',
  SignalingTimeout: 'SIGNALING_TIMEOUT',
  SignalingUnavailable: 'SIGNALING_UNAVAILABLE',
  DeviceOffline: 'DEVICE_OFFLINE',

  // Authorization
  GrantInvalid: 'GRANT_INVALID',
  GrantExpired: 'GRANT_EXPIRED',
  LeaseExpired: 'LEASE_EXPIRED',
  SessionRevoked: 'SESSION_REVOKED',
  ServiceNotExposed: 'SERVICE_NOT_EXPOSED',
  ServiceDisabled: 'SERVICE_DISABLED',
  DeniedByGrant: 'DENIED_BY_GRANT',
  DeniedByLocalPolicy: 'DENIED_BY_LOCAL_POLICY',
  Forbidden: 'FORBIDDEN',
  NoPermittedMode: 'NO_PERMITTED_MODE',
  CompatibilityNotEnabled: 'COMPATIBILITY_NOT_ENABLED',
  DeviceRejected: 'DEVICE_REJECTED',
  DeviceNotFound: 'DEVICE_NOT_FOUND',
  DeviceRevoked: 'DEVICE_REVOKED',
  CredentialRevoked: 'CREDENTIAL_REVOKED',
  PlanLimitReached: 'PLAN_LIMIT_REACHED',
  RelayQuotaExceeded: 'RELAY_QUOTA_EXCEEDED',

  // Authentication and requests
  Unauthenticated: 'UNAUTHENTICATED',
  IdentityNotRegistered: 'IDENTITY_NOT_REGISTERED',
  EnrollmentTokenInvalid: 'ENROLLMENT_TOKEN_INVALID',
  ProofInvalid: 'PROOF_INVALID',
  InvalidRequest: 'INVALID_REQUEST',
  NotFound: 'NOT_FOUND',
  Conflict: 'CONFLICT',

  // Local application on the device
  TargetUnreachable: 'TARGET_UNREACHABLE',
} as const;

export type ErrorCode = (typeof ErrorCodes)[keyof typeof ErrorCodes] | (string & {});

/**
 * Every failure of the SDK. `code` says what went wrong in a form programs can act on; it is one
 * of {@link ErrorCodes} or a code the platform added since this SDK was built.
 */
export class ConnectivitizerError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message?: string, options?: { cause?: unknown }) {
    super(message ?? code, options);
    this.name = 'ConnectivitizerError';
    this.code = code;
  }
}

/** The code of an error, or `fallback` for anything that is not a {@link ConnectivitizerError}. */
export function codeOf(error: unknown, fallback: ErrorCode = ErrorCodes.SessionClosed): ErrorCode {
  return error instanceof ConnectivitizerError ? error.code : fallback;
}
