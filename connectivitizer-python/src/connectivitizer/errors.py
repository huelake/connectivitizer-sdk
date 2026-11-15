"""Stable, machine-readable error codes.

They are the same in every Connectivitizer SDK, in API responses and in the web app, so a failure can be
traced to authentication, authorization, connectivity, endpoint trust or the local application.
"""

from __future__ import annotations


class ErrorCodes:
    # Endpoint trust (end-to-end layer)
    E2E_PEER_NO_CERTIFICATE = "E2E_PEER_NO_CERTIFICATE"
    E2E_PEER_CERTIFICATE_EXPIRED = "E2E_PEER_CERTIFICATE_EXPIRED"
    E2E_PEER_UNTRUSTED = "E2E_PEER_UNTRUSTED"
    E2E_TRUST_MISSING = "E2E_TRUST_MISSING"
    E2E_HANDSHAKE_FAILED = "E2E_HANDSHAKE_FAILED"
    E2E_PROTOCOL_MISMATCH = "E2E_PROTOCOL_MISMATCH"
    E2E_SESSION_BIND_MISMATCH = "E2E_SESSION_BIND_MISMATCH"
    E2E_SHARED_KEY_MISMATCH = "E2E_SHARED_KEY_MISMATCH"
    E2E_NO_COMMON_METHOD = "E2E_NO_COMMON_METHOD"
    LINK_EXPIRED = "LINK_EXPIRED"
    LINK_DENIED = "LINK_DENIED"

    # Connectivity
    PATH_CLOSED = "PATH_CLOSED"
    PATH_IDLE_TIMEOUT = "PATH_IDLE_TIMEOUT"
    DIRECT_UNAVAILABLE = "DIRECT_UNAVAILABLE"
    RELAY_UNREACHABLE = "RELAY_UNREACHABLE"
    RELAY_PEER_TIMEOUT = "RELAY_PEER_TIMEOUT"
    RELAY_REJECTED = "RELAY_REJECTED"
    SESSION_CLOSED = "SESSION_CLOSED"
    MUX_PROTOCOL_ERROR = "MUX_PROTOCOL_ERROR"
    SIGNALING_TIMEOUT = "SIGNALING_TIMEOUT"
    SIGNALING_UNAVAILABLE = "SIGNALING_UNAVAILABLE"
    DEVICE_OFFLINE = "DEVICE_OFFLINE"

    # Authorization
    GRANT_INVALID = "GRANT_INVALID"
    GRANT_EXPIRED = "GRANT_EXPIRED"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    SESSION_REVOKED = "SESSION_REVOKED"
    SERVICE_NOT_EXPOSED = "SERVICE_NOT_EXPOSED"
    SERVICE_DISABLED = "SERVICE_DISABLED"
    DENIED_BY_GRANT = "DENIED_BY_GRANT"
    DENIED_BY_LOCAL_POLICY = "DENIED_BY_LOCAL_POLICY"
    FORBIDDEN = "FORBIDDEN"
    NO_PERMITTED_MODE = "NO_PERMITTED_MODE"
    COMPATIBILITY_NOT_ENABLED = "COMPATIBILITY_NOT_ENABLED"
    DEVICE_REJECTED = "DEVICE_REJECTED"
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    CREDENTIAL_REVOKED = "CREDENTIAL_REVOKED"
    PLAN_LIMIT_REACHED = "PLAN_LIMIT_REACHED"
    RELAY_QUOTA_EXCEEDED = "RELAY_QUOTA_EXCEEDED"

    # Authentication and requests
    UNAUTHENTICATED = "UNAUTHENTICATED"
    IDENTITY_NOT_REGISTERED = "IDENTITY_NOT_REGISTERED"
    ENROLLMENT_TOKEN_INVALID = "ENROLLMENT_TOKEN_INVALID"
    PROOF_INVALID = "PROOF_INVALID"
    INVALID_REQUEST = "INVALID_REQUEST"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"

    # Local application on the device
    TARGET_UNREACHABLE = "TARGET_UNREACHABLE"


class ConnectivitizerError(Exception):
    """Every failure of the SDK. ``code`` is one of :class:`ErrorCodes`, or a code the platform added since."""

    def __init__(self, code: str, message: str | None = None) -> None:
        super().__init__(message or code)
        self.code = code


def code_of(error: BaseException, fallback: str = ErrorCodes.SESSION_CLOSED) -> str:
    """The code of an error, or ``fallback`` for anything that is not a :class:`ConnectivitizerError`."""
    return error.code if isinstance(error, ConnectivitizerError) else fallback
