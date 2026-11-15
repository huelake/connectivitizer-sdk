"""The calling side: an application that connects to services on devices."""

from __future__ import annotations

import asyncio
import base64
import time
from typing import Any, Awaitable, Callable, Dict, List, Optional, Sequence, Union

from .api import GrantVerifier, PlatformApi, ReachableDevice, TokenResponse
from .direct.attempt import DirectAttempt, DirectFailureReasons, peer_reflexive_for
from .errors import ConnectivitizerError, ErrorCodes, code_of
from .grants import Capabilities, ConnectionModes, E2eMethods, Grant, Roles, e2e_method_of
from .noise import SharedKey, parse_shared_key
from .platform import Platform
from .relay_path import RelayPath
from .session import SessionParameters, TunnelSession
from .signaling import Envelope, SignalingClient
from .streams import fail, new_future, settle, settled_within, spawn, with_timeout

ANSWER_TIMEOUT = 15.0
DIRECT_BUDGET = 3.0
"""How long a direct path is looked for before the relay is used instead."""

SharedKeys = Union[str, SharedKey, Sequence[SharedKey], None]


def to_keys(value: SharedKeys) -> List[SharedKey]:
    if value is None:
        return []
    if isinstance(value, str):
        return [parse_shared_key(value)]
    if isinstance(value, SharedKey):
        return [value]
    return list(value)


class ConnectivitizerClient:
    """The calling side.

    ``auth`` is one of: an API key (``api_key=...``), or ``get_token``, a coroutine function returning a
    :class:`TokenResponse` (for anything else). The shared key (or keys) is held by the devices too; with
    several, the one named like the device is used, else the only one, else the one named ``default``.

    ::

        async with ConnectivitizerClient(api_url, api_key="czk_...", shared_key="czs_...") as client:
            session = await client.connect("living-room-lamp", ["api"])
            response = await session.fetch("api", "/state")
            print(response.status, await response.json(), session.info.mode)
    """

    def __init__(
        self,
        api_url: str,
        *,
        api_key: Optional[str] = None,
        get_token: Optional[Callable[[], Awaitable[TokenResponse]]] = None,
        shared_key: SharedKeys = None,
        disable_direct: bool = False,
        stun_servers: Optional[Sequence[str]] = None,
        platform: Optional[Platform] = None,
    ) -> None:
        if (api_key is None) == (get_token is None):
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "An application authenticates with api_key or with get_token.")
        self._keys = to_keys(shared_key)
        if not self._keys:
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "An application needs a shared key: without one there is nothing to encrypt end to end with.")
        self._api_key = api_key
        self._get_token = get_token
        self._disable_direct = disable_direct
        self._stun_servers = list(stun_servers) if stun_servers is not None else None
        self._platform = platform or Platform()
        self._api = PlatformApi(api_url, self._platform)
        self._grants = GrantVerifier(self._api, self._now_seconds)
        self._answers: Dict[str, asyncio.Future] = {}
        self._candidates: Dict[str, asyncio.Future] = {}
        self._sessions: Dict[str, TunnelSession] = {}
        self._signaling: Optional[SignalingClient] = None
        self._connecting: Optional[asyncio.Future] = None
        self._clock_offset = 0
        self._closed = False

    async def __aenter__(self) -> "ConnectivitizerClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    def _now_seconds(self) -> int:
        """The current time by the control plane's clock, which is what grants are judged against."""
        return int(time.time()) + self._clock_offset

    async def connect(self, device: str, services: List[str]) -> TunnelSession:
        """Opens a session to ``device`` (its name or id) for the named services. Raises
        :class:`ConnectivitizerError`; there is no silent fallback to a weaker mode."""
        if self._closed:
            raise ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The client is closed.")
        shared_key = self._select_shared_key(device)
        if shared_key is None:
            raise ConnectivitizerError(ErrorCodes.E2E_NO_COMMON_METHOD, f"No shared key is configured for '{device}' (name one after the device, or 'default').")
        signaling = await self._ensure_signaling()

        reply = await signaling.request("connect.request", {"device": device, "services": services, "e2e": [E2eMethods.SHARED_KEY]}, ANSWER_TIMEOUT)
        granted = reply.get("d") or {}
        if reply.get("t") != "connect.grant" or not granted.get("sid") or not granted.get("grant") or not isinstance(granted.get("peer"), dict):
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "The control plane sent an unexpected answer.")
        session_id: str = granted["sid"]
        grant_token: str = granted["grant"]
        peer: Dict[str, Any] = granted["peer"]

        attempt: Optional[DirectAttempt] = None
        try:
            try:
                answer = await with_timeout(
                    asyncio.shield(self._waiter(self._answers, session_id)),
                    ANSWER_TIMEOUT,
                    lambda: ConnectivitizerError(ErrorCodes.SIGNALING_TIMEOUT, "The device did not answer the connection request in time."),
                )
            finally:
                self._answers.pop(session_id, None)
            if not answer.get("accept"):
                code = answer.get("error") or ErrorCodes.DEVICE_REJECTED
                raise ConnectivitizerError(code, f"The device refused the connection ({code}).")

            grant, error = await self._grants.validate(grant_token, True)
            if grant is None or grant["jti"] != session_id:
                raise ConnectivitizerError(error or ErrorCodes.GRANT_INVALID, "The session grant could not be verified.")
            if ConnectionModes.COMPATIBILITY in grant["modes"]:
                raise ConnectivitizerError(ErrorCodes.NO_PERMITTED_MODE, "The session grant offers a mode this endpoint does not take part in.")
            # The grant names the end-to-end layer; this endpoint must be able to run exactly that one.
            method = e2e_method_of(grant)
            if method != E2eMethods.SHARED_KEY:
                raise ConnectivitizerError(ErrorCodes.E2E_NO_COMMON_METHOD, f"The session was granted with the end-to-end layer '{method}', which this application is not set up for.")

            peer_label = peer.get("name") or device

            def parameters(**path: Any) -> SessionParameters:
                return SessionParameters(
                    platform=self._platform,
                    role=Roles.INITIATOR,
                    grant_token=grant_token,
                    grant=grant,
                    peer_label=peer_label,
                    now_seconds=self._now_seconds,
                    shared_keys=[shared_key],
                    **path,
                )

            relay_permitted = ConnectionModes.E2E_RELAY in grant["modes"] and bool(grant.get("relay"))
            can_direct = not self._disable_direct and self._platform.supports_udp
            peer_supports_direct = Capabilities.PATH_UDP_KCP in (peer.get("caps") or [])
            direct_permitted = ConnectionModes.DIRECT in grant["modes"] and can_direct and peer_supports_direct
            direct_failure: Optional[str] = (
                None if direct_permitted else DirectFailureReasons.PEER_NO_DIRECT_SUPPORT if not can_direct or not peer_supports_direct else DirectFailureReasons.POLICY_RELAY_ONLY
            )

            session: Optional[TunnelSession] = None
            if direct_permitted:
                stun = self._stun_servers if self._stun_servers is not None else (signaling.welcome.get("stunServers") or [])
                attempt = DirectAttempt(self._platform, Roles.INITIATOR, session_id, grant_token, stun, peer_reflexive=peer_reflexive_for(method))
                current = attempt
                spawn(self._apply_candidates(session_id, current))
                blob = await attempt.gather()
                signaling.send("path.candidates", {"sid": session_id, "blob": base64.b64encode(blob).decode("ascii")})
                path = await attempt.open(DIRECT_BUDGET)
                if path is None:
                    direct_failure = attempt.failure_reason()
                    if relay_permitted:
                        signaling.send("path.fallback", {"sid": session_id, "reason": direct_failure})
                else:
                    # A path exists. From here on a failure is a failure of the session - falling back to the
                    # relay would not make the peer more trustworthy.
                    session = await TunnelSession.establish(
                        parameters(
                            path=path.stream,
                            mode=ConnectionModes.DIRECT,
                            transport="udp-kcp",
                            peer_address=path.peer_address,
                            local_candidates_hash=attempt.local_candidates_hash,
                            remote_candidates_hash=attempt.remote_candidates_hash,
                        )
                    )

            if session is None:
                if not relay_permitted:
                    # Nothing else is allowed for this session: say so instead of using a path that was not asked for.
                    raise ConnectivitizerError(ErrorCodes.DIRECT_UNAVAILABLE, f"A direct connection could not be established ({direct_failure}) and relaying is not permitted for this session.")
                relay = await RelayPath.connect(self._platform, grant["relay"], grant_token, Roles.INITIATOR)
                session = await TunnelSession.establish(parameters(path=relay, relay=relay, mode=ConnectionModes.E2E_RELAY, transport="relay-ws", direct_failure_reason=direct_failure))

            self._sessions[session_id] = session
            info = session.info
            self._report({"sid": session_id, "state": "established", "mode": info.mode, "trust": info.trust, "directFailureReason": info.direct_failure_reason, "transport": info.transport})
            spawn(self._watch(session))
            spawn(self._renew_leases(session))
            return session
        except BaseException as error:
            self._report({"sid": session_id, "state": "failed", "error": code_of(error)})
            raise
        finally:
            waiting = self._candidates.pop(session_id, None)
            if waiting is not None:
                fail(waiting, ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The path negotiation is over."))
            if attempt is not None:
                attempt.close()

    async def list_devices(self) -> List[ReachableDevice]:
        """The devices this application may open sessions to: names, whether they are online, and the
        services it may use - what an app shows its user to choose from."""
        token = await self._token()
        return await self._api.reachable_devices(token.access_token)

    async def close(self) -> None:
        """Ends every session and the connection to the platform."""
        if self._closed:
            return
        self._closed = True
        await asyncio.gather(*(session.close() for session in list(self._sessions.values())), return_exceptions=True)
        # Give the end-of-session reports a moment to leave before the channel closes.
        await asyncio.sleep(0.05)
        if self._signaling is not None:
            await self._signaling.close()

    def _select_shared_key(self, device: str) -> Optional[SharedKey]:
        lower = device.lower()
        for key in self._keys:
            if key.name.lower() == lower:
                return key
        if len(self._keys) == 1:
            return self._keys[0]
        return next((key for key in self._keys if key.name.lower() == "default"), None)

    def _waiter(self, table: Dict[str, asyncio.Future], session_id: str) -> asyncio.Future:
        if session_id not in table:
            table[session_id] = new_future()
        return table[session_id]

    async def _apply_candidates(self, session_id: str, attempt: DirectAttempt) -> None:
        blob = await asyncio.shield(self._waiter(self._candidates, session_id))
        attempt.set_remote_candidates(blob)

    async def _token(self) -> TokenResponse:
        if self._api_key is not None:
            return await self._api.credential_token(self._api_key)
        return await self._get_token()  # type: ignore[misc]

    async def _ensure_signaling(self) -> SignalingClient:
        if self._signaling is not None and self._signaling.is_open:
            return self._signaling
        if self._connecting is None:
            self._connecting = asyncio.ensure_future(self._open_signaling())
        try:
            return await asyncio.shield(self._connecting)
        finally:
            if self._connecting is not None and self._connecting.done():
                self._connecting = None

    async def _open_signaling(self) -> SignalingClient:
        token = await self._token()
        if token.server_time is not None:
            self._clock_offset = int(token.server_time) - int(time.time())
        caps = [Capabilities.MUX_YAMUX, Capabilities.PATH_RELAY_WS, Capabilities.E2E_SHARED_KEY]
        if not self._disable_direct and self._platform.supports_udp:
            caps.append(Capabilities.PATH_UDP_KCP)
        signaling = await SignalingClient.connect(self._platform, self._api.signal_url, token.access_token, {"caps": caps, "platform": self._platform.description})
        if isinstance(signaling.welcome.get("serverTime"), (int, float)):
            self._clock_offset = int(signaling.welcome["serverTime"]) - int(time.time())
        signaling.on_message = self._on_signal
        self._signaling = signaling
        return signaling

    def _on_signal(self, message: Envelope) -> None:
        data = message.get("d") or {}
        session_id = data.get("sid") if isinstance(data.get("sid"), str) else None
        kind = message.get("t")
        if kind == "connect.answer" and session_id:
            settle(self._waiter(self._answers, session_id), {"accept": data.get("accept") is True, "error": data.get("error") if isinstance(data.get("error"), str) else None})
        elif kind == "path.candidates" and session_id and isinstance(data.get("blob"), str):
            try:
                settle(self._waiter(self._candidates, session_id), base64.b64decode(data["blob"], validate=True))
            except ValueError:
                pass  # not base64: as good as no candidates
        elif kind == "revoke":
            sids = data.get("sids") if isinstance(data.get("sids"), list) else None
            reason = data.get("reason") if isinstance(data.get("reason"), str) else ErrorCodes.SESSION_REVOKED
            for session in list(self._sessions.values()):
                if sids is None or session.info.session_id in sids:
                    spawn(session.end(reason))

    async def _watch(self, session: TunnelSession) -> None:
        """Tells the control plane when and why the session ended, with this endpoint's own traffic count."""
        reason = await session.completion
        self._sessions.pop(session.info.session_id, None)
        self._report({"sid": session.info.session_id, "state": "ended", "error": reason, "bytesSent": session.bytes_sent, "bytesReceived": session.bytes_received})

    async def _renew_leases(self, session: TunnelSession) -> None:
        """Keeps a running session authorised by fetching a new grant well before the lease ends."""
        while not session.is_ended and not self._closed:
            remaining = session.lease_expires - self._now_seconds()
            if await settled_within(session.completion, max(remaining / 2, 1)) or self._closed:
                return
            try:
                signaling = await self._ensure_signaling()
                reply = await signaling.request("lease.request", {"sid": session.info.session_id}, ANSWER_TIMEOUT)
                token = (reply.get("d") or {}).get("grant")
                if reply.get("t") == "lease.grant" and isinstance(token, str):
                    renewed = self._grants.validate_known(token, False)[0] or (await self._grants.validate(token, False))[0]
                    if renewed is not None:
                        await session.renew_lease(token, renewed)
            except Exception as error:
                code = code_of(error, "")
                gone = (ErrorCodes.CREDENTIAL_REVOKED, ErrorCodes.DEVICE_REVOKED, ErrorCodes.FORBIDDEN, ErrorCodes.SERVICE_DISABLED, ErrorCodes.SERVICE_NOT_EXPOSED, ErrorCodes.SESSION_CLOSED, ErrorCodes.NOT_FOUND)
                if code in gone:
                    # Authorisation is gone: end the session now instead of letting it run to the end of its lease.
                    await session.end(ErrorCodes.SESSION_REVOKED if code in (ErrorCodes.NOT_FOUND, ErrorCodes.SESSION_CLOSED) else code)
                    return
                # Control plane unreachable: keep trying until the lease runs out by itself.

    def _report(self, update: Dict[str, Any]) -> None:
        try:
            if self._signaling is not None and self._signaling.is_open:
                self._signaling.send("session.update", {k: v for k, v in update.items() if v is not None})
        except Exception:
            pass  # reporting is best effort; the session itself is unaffected
