"""Session grants (protocol section 2): the control plane's signed statement that one initiator may open
one session to one device. An endpoint acts on a grant because its signature checks out, not because of
the channel it arrived on."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .encoding import b64decode
from .errors import ErrorCodes


class ConnectionModes:
    DIRECT = "direct"
    E2E_RELAY = "e2e-relay"
    COMPATIBILITY = "compatibility"


class E2eMethods:
    TLS13 = "tls13"
    SHARED_KEY = "shared-key"


class Capabilities:
    E2E_TLS13 = "e2e.tls13"
    E2E_SHARED_KEY = "e2e.shared-key"
    MUX_YAMUX = "mux.yamux"
    PATH_RELAY_WS = "path.relay-ws"
    PATH_TCP = "path.tcp"
    PATH_UDP_KCP = "path.udp-kcp"


class Roles:
    INITIATOR = "initiator"
    DEVICE = "device"


AUDIENCE_AGENT = "cz-agent"
CLOCK_SKEW_SECONDS = 30
MAX_TOKEN_LENGTH = 16 * 1024

# A grant is kept as the parsed JSON object (keys as in the protocol: jti, ws, ini, dev, svc, modes, ...).
Grant = Dict[str, Any]
GrantKeys = Dict[str, ec.EllipticCurvePublicKey]


def e2e_method_of(grant: Grant) -> str:
    """The end-to-end layer of the session; absent means certificates."""
    return grant.get("e2e") or E2eMethods.TLS13


def parse_jwks(document: Any) -> GrantKeys:
    keys: GrantKeys = {}
    entries = document.get("keys") if isinstance(document, dict) else None
    if not isinstance(entries, list):
        return keys
    for jwk in entries:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
            continue
        kid, x, y = jwk.get("kid"), jwk.get("x"), jwk.get("y")
        if not isinstance(kid, str) or not isinstance(x, str) or not isinstance(y, str):
            continue
        try:
            xb, yb = b64decode(x), b64decode(y)
            if len(xb) == 32 and len(yb) == 32:
                keys[kid] = ec.EllipticCurvePublicNumbers(int.from_bytes(xb, "big"), int.from_bytes(yb, "big"), ec.SECP256R1()).public_key()
        except ValueError:
            # A malformed key is as good as an absent one.
            continue
    return keys


def read_key_id(token: str) -> Optional[str]:
    """The key id a token names, without verifying anything, so the right key can be fetched first."""
    try:
        header = json.loads(b64decode(token[: token.index(".")]))
        kid = header.get("kid")
        return kid if isinstance(kid, str) and kid else None
    except (ValueError, AttributeError):
        return None


def hash_grant(token: str) -> str:
    """SHA-256 (lower-case hex) of a grant token: what the session bind and the shared-key handshake refer to."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def validate_grant(token: str, keys: GrantKeys, now_seconds: int, for_session_start: bool) -> Tuple[Optional[Grant], Optional[str]]:
    """Verifies signature, audience and time of a grant token. ``for_session_start`` selects which deadline
    applies: the short start window (``exp``) or the session lease. Returns (grant, None) or (None, code)."""
    if not token or len(token) > MAX_TOKEN_LENGTH:
        return None, ErrorCodes.GRANT_INVALID
    first, last = token.find("."), token.rfind(".")
    if first <= 0 or last <= first + 1 or last == len(token) - 1:
        return None, ErrorCodes.GRANT_INVALID
    try:
        header = json.loads(b64decode(token[:first]))
        # The algorithm is fixed. Accepting whatever the header names is how "alg" attacks work.
        if not isinstance(header, dict) or header.get("alg") != "ES256" or not isinstance(header.get("kid"), str):
            return None, ErrorCodes.GRANT_INVALID
        key = keys.get(header["kid"])
        signature = b64decode(token[last + 1 :])
        if key is None or len(signature) != 64:
            return None, ErrorCodes.GRANT_INVALID
        der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
        key.verify(der, token[:last].encode("ascii"), ec.ECDSA(hashes.SHA256()))
        grant = json.loads(b64decode(token[first + 1 : last]))
    except (ValueError, InvalidSignature, UnicodeError):
        return None, ErrorCodes.GRANT_INVALID

    def number(name: str) -> bool:
        return isinstance(grant.get(name), (int, float)) and not isinstance(grant.get(name), bool)

    if (
        not isinstance(grant, dict)
        or not isinstance(grant.get("jti"), str)
        or not grant["jti"]
        or not isinstance(grant.get("aud"), list)
        or AUDIENCE_AGENT not in grant["aud"]
        or not isinstance(grant.get("ini"), dict)
        or not isinstance(grant.get("dev"), dict)
        or not isinstance(grant.get("svc"), list)
        or not isinstance(grant.get("modes"), list)
        or not number("iat")
        or not number("exp")
        or not number("lease")
    ):
        return None, ErrorCodes.GRANT_INVALID

    deadline = grant["exp"] if for_session_start else grant["iat"] + grant["lease"]
    if now_seconds > deadline + CLOCK_SKEW_SECONDS or now_seconds < grant["iat"] - CLOCK_SKEW_SECONDS:
        return None, ErrorCodes.GRANT_EXPIRED
    return grant, None
