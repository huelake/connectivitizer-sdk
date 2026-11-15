"""The machine-facing REST calls of the control plane (protocol section 11), and grant verification with the
control plane's published keys."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from .errors import ConnectivitizerError, ErrorCodes
from .grants import Grant, GrantKeys, parse_jwks, read_key_id, validate_grant
from .platform import Platform


@dataclass
class TokenResponse:
    access_token: str
    expires_in: int
    endpoint_type: str
    endpoint_id: str
    workspace_id: str
    server_time: Optional[int] = None
    """The control plane's clock, Unix seconds."""
    slug: Optional[str] = None
    """Device logins: the name the device is addressed by."""

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> "TokenResponse":
        return cls(
            access_token=data["accessToken"],
            expires_in=int(data.get("expiresIn", 0)),
            endpoint_type=data.get("endpointType", ""),
            endpoint_id=data.get("endpointId", ""),
            workspace_id=data.get("workspaceId", ""),
            server_time=data.get("serverTime"),
            slug=data.get("slug"),
        )


@dataclass
class ReachableDevice:
    """A device an application may open sessions to."""

    id: str
    name: str
    """What the device calls itself."""
    slug: str
    """The name sessions are opened to."""
    online: bool
    alias: Optional[str] = None
    """A name people gave the device in the web app."""
    capabilities: List[str] = field(default_factory=list)
    """What the device's software announced; ``path.udp-kcp`` means it offers peer to peer."""
    services: List[str] = field(default_factory=list)
    """The services of the device this application may use."""


class PlatformApi:
    def __init__(self, api_url: str, platform: Platform) -> None:
        self.base_url = api_url.rstrip("/") + "/"
        self._platform = platform

    @property
    def signal_url(self) -> str:
        """The signaling endpoint that belongs to this API."""
        return "ws" + self.base_url[4:] + "v1/signal" if self.base_url.startswith("http") else self.base_url + "v1/signal"

    async def credential_token(self, api_key: str, identity: Optional[Dict[str, Any]] = None) -> TokenResponse:
        """Exchanges an application's API key for an access token, registering its certificate if it has one."""
        return TokenResponse.from_json(await self._post("v1/auth/credential/token", {"apiKey": api_key, **(identity or {})}))

    async def device_key_token(self, key: str, name: str, platform_name: Optional[str], agent_version: Optional[str], identity: Optional[Dict[str, Any]] = None) -> TokenResponse:
        """Logs a device in with a device key and its name. The first login under a name creates the device."""
        body = {"key": key, "name": name, "platform": platform_name, "agentVersion": agent_version, **(identity or {})}
        return TokenResponse.from_json(await self._post("v1/auth/device-key/token", body))

    async def app_token(self, user_access_token: str, workspace_id: str, client: str) -> TokenResponse:
        """For an application whose user is signed in: a token to connect with, as the client ``client``."""
        return TokenResponse.from_json(await self._post("v1/auth/app/token", {"workspaceId": workspace_id, "client": client}, user_access_token))

    async def enroll(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Enrolls a device with a one-time token (protocol section 11.2)."""
        return await self._post("v1/devices/enroll", request)

    async def device_challenge(self, device_id: str) -> Dict[str, Any]:
        return await self._post("v1/auth/device/challenge", {"deviceId": device_id})

    async def device_token(self, device_id: str, challenge: str, signature: str) -> TokenResponse:
        return TokenResponse.from_json(await self._post("v1/auth/device/token", {"deviceId": device_id, "challenge": challenge, "signature": signature}))

    async def start_link(self, client: str, platform_name: Optional[str]) -> Dict[str, Any]:
        return await self._post("v1/auth/link", {"client": client, "platform": platform_name})

    async def poll_link(self, device_code: str) -> Dict[str, Any]:
        return await self._post("v1/auth/link/token", {"deviceCode": device_code})

    async def reachable_devices(self, access_token: str) -> List[ReachableDevice]:
        """The devices the application behind ``access_token`` may open sessions to."""
        data = await self._request("GET", "v1/devices", None, access_token)
        return [
            ReachableDevice(
                id=entry.get("id", ""),
                name=entry.get("name", ""),
                slug=entry.get("slug", ""),
                online=bool(entry.get("online")),
                alias=entry.get("alias"),
                capabilities=list(entry.get("capabilities") or []),
                services=list(entry.get("services") or []),
            )
            for entry in data
        ]

    async def grant_keys(self) -> GrantKeys:
        """The public keys session grants are signed with."""
        return parse_jwks(await self._request("GET", ".well-known/jwks.json"))

    async def _post(self, path: str, body: Any, bearer: Optional[str] = None) -> Any:
        return await self._request("POST", path, body, bearer)

    async def _request(self, method: str, path: str, body: Any = None, bearer: Optional[str] = None) -> Any:
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        try:
            status, text = await self._platform.fetch(self.base_url + path, method, headers, None if body is None else json.dumps({k: v for k, v in body.items() if v is not None}))
        except Exception as error:
            raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, f"The Connectivitizer API at {self.base_url} could not be reached.") from error
        try:
            parsed = json.loads(text) if text else None
        except ValueError:
            parsed = None
        # Only the API names its refusals. An answer without a code comes from something in between (a proxy while
        # the API restarts, a captive portal) and is a passing failure: devices keep retrying instead of giving up.
        if 200 <= status < 300:
            if parsed is None:
                raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, "The API returned an empty response.")
            return parsed
        failure = parsed if isinstance(parsed, dict) else {}
        code = failure.get("error") if isinstance(failure.get("error"), str) else ErrorCodes.UNAUTHENTICATED if status == 401 else ErrorCodes.SIGNALING_UNAVAILABLE
        message = failure.get("message") if isinstance(failure.get("message"), str) else f"The API refused the request ({status} {code})."
        raise ConnectivitizerError(code, message)


class GrantVerifier:
    """Verifies grants offline with the control plane's published keys, fetching them when a new key id appears."""

    MIN_REFRESH_SECONDS = 30

    def __init__(self, api: PlatformApi, now_seconds: Callable[[], int]) -> None:
        self._api = api
        self._now_seconds = now_seconds
        self._keys: GrantKeys = {}
        self._last_refresh = float("-inf")
        self._refreshing: Optional[asyncio.Future] = None

    async def validate(self, token: str, for_session_start: bool) -> Tuple[Optional[Grant], Optional[str]]:
        key_id = read_key_id(token)
        if key_id is None:
            return None, ErrorCodes.GRANT_INVALID
        if key_id not in self._keys:
            await self._refresh()
        return self.validate_known(token, for_session_start)

    def validate_known(self, token: str, for_session_start: bool) -> Tuple[Optional[Grant], Optional[str]]:
        """Validates with the keys already known (for in-session lease renewals, which must not wait on the network)."""
        return validate_grant(token, self._keys, self._now_seconds(), for_session_start)

    async def _refresh(self) -> None:
        if self._refreshing is not None:
            await asyncio.shield(self._refreshing)
            return
        if time.monotonic() - self._last_refresh < self.MIN_REFRESH_SECONDS:
            return
        self._last_refresh = time.monotonic()

        async def fetch() -> None:
            try:
                self._keys = await self._api.grant_keys()
            except Exception:
                pass  # without keys the grant simply does not validate; the caller reports GRANT_INVALID
            finally:
                self._refreshing = None

        self._refreshing = asyncio.ensure_future(fetch())
        await asyncio.shield(self._refreshing)
