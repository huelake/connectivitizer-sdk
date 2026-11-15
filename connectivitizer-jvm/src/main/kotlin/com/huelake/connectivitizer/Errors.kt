package com.huelake.connectivitizer

/**
 * Stable, machine-readable error codes. They are the same in every Connectivitizer SDK, in API responses and
 * in the web app, so a failure can be traced to authentication, authorization, connectivity, endpoint trust
 * or the local application.
 */
object ErrorCodes {
    // Endpoint trust (end-to-end layer)
    const val E2E_PEER_NO_CERTIFICATE = "E2E_PEER_NO_CERTIFICATE"
    const val E2E_PEER_UNTRUSTED = "E2E_PEER_UNTRUSTED"
    const val E2E_TRUST_MISSING = "E2E_TRUST_MISSING"
    const val E2E_HANDSHAKE_FAILED = "E2E_HANDSHAKE_FAILED"
    const val E2E_SESSION_BIND_MISMATCH = "E2E_SESSION_BIND_MISMATCH"
    const val E2E_SHARED_KEY_MISMATCH = "E2E_SHARED_KEY_MISMATCH"
    const val E2E_NO_COMMON_METHOD = "E2E_NO_COMMON_METHOD"
    const val LINK_EXPIRED = "LINK_EXPIRED"
    const val LINK_DENIED = "LINK_DENIED"

    // Connectivity
    const val PATH_CLOSED = "PATH_CLOSED"
    const val PATH_IDLE_TIMEOUT = "PATH_IDLE_TIMEOUT"
    const val DIRECT_UNAVAILABLE = "DIRECT_UNAVAILABLE"
    const val RELAY_UNREACHABLE = "RELAY_UNREACHABLE"
    const val RELAY_PEER_TIMEOUT = "RELAY_PEER_TIMEOUT"
    const val RELAY_REJECTED = "RELAY_REJECTED"
    const val SESSION_CLOSED = "SESSION_CLOSED"
    const val MUX_PROTOCOL_ERROR = "MUX_PROTOCOL_ERROR"
    const val SIGNALING_TIMEOUT = "SIGNALING_TIMEOUT"
    const val SIGNALING_UNAVAILABLE = "SIGNALING_UNAVAILABLE"
    const val DEVICE_OFFLINE = "DEVICE_OFFLINE"

    // Authorization
    const val GRANT_INVALID = "GRANT_INVALID"
    const val GRANT_EXPIRED = "GRANT_EXPIRED"
    const val LEASE_EXPIRED = "LEASE_EXPIRED"
    const val SESSION_REVOKED = "SESSION_REVOKED"
    const val SERVICE_NOT_EXPOSED = "SERVICE_NOT_EXPOSED"
    const val SERVICE_DISABLED = "SERVICE_DISABLED"
    const val DENIED_BY_GRANT = "DENIED_BY_GRANT"
    const val DENIED_BY_LOCAL_POLICY = "DENIED_BY_LOCAL_POLICY"
    const val FORBIDDEN = "FORBIDDEN"
    const val NO_PERMITTED_MODE = "NO_PERMITTED_MODE"
    const val COMPATIBILITY_NOT_ENABLED = "COMPATIBILITY_NOT_ENABLED"
    const val DEVICE_REJECTED = "DEVICE_REJECTED"
    const val DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    const val DEVICE_REVOKED = "DEVICE_REVOKED"
    const val CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    const val PLAN_LIMIT_REACHED = "PLAN_LIMIT_REACHED"
    const val RELAY_QUOTA_EXCEEDED = "RELAY_QUOTA_EXCEEDED"

    // Authentication and requests
    const val UNAUTHENTICATED = "UNAUTHENTICATED"
    const val IDENTITY_NOT_REGISTERED = "IDENTITY_NOT_REGISTERED"
    const val INVALID_REQUEST = "INVALID_REQUEST"
    const val NOT_FOUND = "NOT_FOUND"
    const val CONFLICT = "CONFLICT"

    // Local application on the device
    const val TARGET_UNREACHABLE = "TARGET_UNREACHABLE"
}

/** Every failure of the SDK. [code] is one of [ErrorCodes], or a code the platform added since. */
class ConnectivitizerException(val code: String, message: String? = null, cause: Throwable? = null) :
    Exception(message ?: code, cause)

/** The code of an error, or [fallback] for anything that is not a [ConnectivitizerException]. */
internal fun codeOf(error: Throwable, fallback: String = ErrorCodes.SESSION_CLOSED): String =
    (error as? ConnectivitizerException)?.code ?: fallback
