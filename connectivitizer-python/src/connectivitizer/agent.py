"""The device side: keeps an outbound connection to the platform, and when an authorised application that
holds the shared key asks, opens a session and forwards its streams to local services. Nothing is reachable
that the device did not declare itself, and no port listens. A device can also open sessions to other devices,
over the same connection to the platform, when the device key it logs in with has the right to connect."""

from __future__ import annotations

import asyncio
import base64
import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .api import GrantVerifier, PlatformApi, ReachableDevice, TokenResponse
from .client import ConnectivitizerClient, SharedKeys, to_keys
from .direct.attempt import DirectAttempt, peer_reflexive_for
from .errors import ConnectivitizerError, ErrorCodes, code_of
from .grants import Capabilities, ConnectionModes, E2eMethods, Grant, Roles, e2e_method_of
from .platform import Platform
from .relay_path import RelayPath
from .session import ConnectionInfo, PeerInfo, SessionParameters, TunnelSession
from .signaling import Envelope, SignalingClient
from .streams import fail, new_future, settle, settled_within, spawn, with_timeout

PATH_TIMEOUT = 12.0


@dataclass
class Service:
    """A local service a device exposes. The target never leaves the device."""

    target: str
    """``host:port`` of the local application."""
    protocol: str = "tcp"
    """``http``, ``ws`` or ``tcp``. Informational; every service is carried as a byte stream."""
    allow: Optional[List[str]] = None
    """Who may use the service: ``key:<name>`` for holders of that shared key. None: every peer the device trusts."""


def _parse_target(target: str) -> Tuple[str, int]:
    colon = target.rfind(":")
    try:
        port = int(target[colon + 1 :])
    except ValueError:
        port = 0
    if colon <= 0 or port < 1 or port > 65535:
        raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, f"'{target}' is not a valid target; expected host:port.")
    return target[:colon].strip("[]"), port


class ConnectivitizerAgent:
    """A device that exposes local services.

    ::

        agent = ConnectivitizerAgent(api_url, device_key="czd_...", name="nas", shared_key="czs_...",
                                     services={"api": "127.0.0.1:8080"}, log=print)
        await agent.run()   # until agent.stop()

    While it runs, the device can open sessions to other devices with :meth:`connect`.
    """

    def __init__(
        self,
        api_url: str,
        *,
        device_key: str,
        name: str,
        shared_key: SharedKeys,
        services: Mapping[str, Union[str, Service]],
        disable_direct: bool = False,
        stun_servers: Optional[Sequence[str]] = None,
        agent_version: Optional[str] = None,
        log: Optional[Callable[[str], None]] = None,
        platform: Optional[Platform] = None,
    ) -> None:
        self._keys = to_keys(shared_key)
        if not self._keys:
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "A device needs a shared key: without one nobody can reach it end to end.")
        if not device_key or not name:
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "A device logs in with a device key and its name.")
        self._device_key = device_key
        self._name = name
        self._services: Dict[str, Tuple[str, int, str, Optional[List[str]]]] = {}
        for service_name, value in services.items():
            service = Service(value) if isinstance(value, str) else value
            host, port = _parse_target(service.target)
            self._services[service_name] = (host, port, service.protocol, service.allow)
        self._disable_direct = disable_direct
        self._stun_servers = list(stun_servers) if stun_servers is not None else None
        self._agent_version = agent_version
        self._log_sink = log
        self._platform = platform or Platform()
        self._api = PlatformApi(api_url, self._platform)
        self._grants = GrantVerifier(self._api, self._now_seconds)
        self._sessions: Dict[str, TunnelSession] = {}
        self._candidates: Dict[str, asyncio.Future] = {}
        self._fallbacks: Dict[str, asyncio.Future] = {}
        self._signaling: Optional[SignalingClient] = None
        self._device_id: Optional[str] = None
        self._clock_offset = 0
        self._stopped = False
        self._stop_signal: Optional[asyncio.Future] = None
        self._connected = asyncio.Event()
        self._halted = asyncio.Event()
        """Set once the device is stopped or the platform refused it for good."""
        self._halt_code: str = ErrorCodes.SESSION_CLOSED
        # The calling half. It uses the device's signaling connection instead of logging in itself.
        self._caller = ConnectivitizerClient(
            api_url,
            shared_key=self._keys,
            disable_direct=disable_direct,
            stun_servers=stun_servers,
            platform=self._platform,
            _signaling=self._current_signaling,
            _opened=self._forget_negotiation,
            _log=log,
            _now_seconds=self._now_seconds,
        )

    @property
    def is_connected(self) -> bool:
        """True while the device is connected to the platform and can be reached."""
        return self._signaling is not None and self._signaling.is_open

    @property
    def open_sessions(self) -> List[ConnectionInfo]:
        """The sessions currently open to this device."""
        return [session.info for session in self._sessions.values()]

    @property
    def outgoing_sessions(self) -> List[ConnectionInfo]:
        """The sessions this device opened to other devices that are still running."""
        return self._caller._open_sessions

    async def wait_until_connected(self) -> None:
        await self._connected.wait()

    async def connect(self, device: str, services: List[str]) -> TunnelSession:
        """Opens a session from this device to ``device`` (its name or id) for the named services, over the
        device's own connection to the platform; it waits until the device is connected. The platform refuses
        with ``FORBIDDEN`` unless the device key this device logs in with may connect and its access rules
        cover the request. The shared key is chosen as an application chooses it: the one named like the
        other device, else the only one, else the one named ``default``. Raises :class:`ConnectivitizerError`
        like :meth:`ConnectivitizerClient.connect`."""
        return await self._caller.connect(device, services)

    async def list_devices(self) -> List[ReachableDevice]:
        """The devices this device may open sessions to, with the services it may use. Needs a device key
        that may connect."""
        token = await self._api.device_key_token(self._device_key, self._name, self._platform.description, self._agent_version)
        return await self._api.reachable_devices(token.access_token)

    async def _current_signaling(self) -> SignalingClient:
        """The device's signaling connection, once it is connected. Raises when the device is stopped or the
        platform does not accept it, because no connection will come then."""
        while True:
            if self._halted.is_set():
                raise ConnectivitizerError(self._halt_code, "The device is not running, so it cannot open sessions.")
            if self._connected.is_set() and self._signaling is not None and self._signaling.is_open:
                return self._signaling
            if self._connected.is_set():
                await asyncio.sleep(0.05)  # the connection closed a moment ago; run() notices next
                continue
            waits = [asyncio.ensure_future(self._connected.wait()), asyncio.ensure_future(self._halted.wait())]
            try:
                await asyncio.wait(waits, return_when=asyncio.FIRST_COMPLETED)
            finally:
                for waiting in waits:
                    waiting.cancel()

    def _forget_negotiation(self, session_id: str) -> None:
        """The opening of a session this device asked for is over: what its signals left behind is dropped."""
        self._candidates.pop(session_id, None)
        self._fallbacks.pop(session_id, None)

    async def run(self) -> None:
        """Runs until :meth:`stop` is called, reconnecting with back-off whenever the connection to the platform
        is lost. Raises when the platform no longer accepts this device (its key was revoked), because
        retrying cannot help then."""
        self._stop_signal = new_future()
        backoff = 1.0
        while not self._stopped:
            try:
                token = await self._api.device_key_token(self._device_key, self._name, self._platform.description, self._agent_version)
                self._device_id = token.endpoint_id
                if token.server_time is not None:
                    self._clock_offset = int(token.server_time) - int(time.time())
                caps = [Capabilities.MUX_YAMUX, Capabilities.PATH_RELAY_WS, Capabilities.E2E_SHARED_KEY]
                if not self._disable_direct and self._platform.supports_udp:
                    caps.append(Capabilities.PATH_UDP_KCP)
                hello = {
                    "caps": caps,
                    "agentVersion": self._agent_version,
                    "platform": self._platform.description,
                    "services": [{"name": name, "protocol": protocol, "compat": False} for name, (_, _, protocol, _) in self._services.items()],
                }
                signaling = await SignalingClient.connect(self._platform, self._api.signal_url, token.access_token, hello)
                if isinstance(signaling.welcome.get("serverTime"), (int, float)):
                    self._clock_offset = int(signaling.welcome["serverTime"]) - int(time.time())
                signaling.on_message = lambda message, s=signaling: self._on_signal(s, message)
                self._signaling = signaling
                backoff = 1.0
                self._connected.set()
                self._log(f"connected to {self._api.base_url} as device {token.slug or self._name}; services: {', '.join(self._services) or '(none)'}")

                done, _ = await asyncio.wait({signaling.closed, self._stop_signal}, return_when=asyncio.FIRST_COMPLETED)
                self._connected.clear()
                if self._stopped:
                    break
                reason = signaling.closed.result() if signaling.closed.done() else ErrorCodes.SESSION_CLOSED
                self._log(f"disconnected from the platform ({reason})")
                if reason in (ErrorCodes.DEVICE_REVOKED, ErrorCodes.CREDENTIAL_REVOKED):
                    await self._end_all_sessions(reason)
                    await self._caller._end_all(reason)
                    raise ConnectivitizerError(reason, "This device was revoked." if reason == ErrorCodes.DEVICE_REVOKED else "The device key this device logs in with was revoked.")
            except ConnectivitizerError as error:
                final = (ErrorCodes.DEVICE_REVOKED, ErrorCodes.CREDENTIAL_REVOKED, ErrorCodes.IDENTITY_NOT_REGISTERED, ErrorCodes.UNAUTHENTICATED, ErrorCodes.INVALID_REQUEST, ErrorCodes.CONFLICT)
                if error.code in final:
                    self._log(f"the platform does not accept this device ({error.code})")
                    self._halt_code = error.code
                    self._halted.set()
                    raise
                self._log(f"platform unavailable ({error.code}); retrying in {round(backoff)} s")
            except (OSError, ValueError) as error:
                self._log(f"platform unavailable ({error}); retrying in {round(backoff)} s")
            if self._stopped:
                break
            # Waits a random time between half and the whole back-off. A fleet refused together (an outage, a restart, the platform
            # shedding load) must not come back together: with only a little jitter it came back in waves 30 s apart that the
            # platform could not take, with nothing to do in between.
            await settled_within(self._stop_signal, backoff / 2 + random.random() * backoff / 2)
            backoff = min(backoff * 2, 30.0)

    async def stop(self) -> None:
        """Ends all sessions and disconnects from the platform."""
        if self._stopped:
            return
        self._stopped = True
        self._halted.set()
        await asyncio.gather(*(session.close() for session in list(self._sessions.values())), return_exceptions=True)
        await self._caller.close()  # ends the sessions this device opened; the connection stays the device's
        await asyncio.sleep(0.05)
        if self._signaling is not None:
            await self._signaling.close()
        if self._stop_signal is not None:
            settle(self._stop_signal)

    def _now_seconds(self) -> int:
        return int(time.time()) + self._clock_offset

    def _log(self, message: str) -> None:
        if self._log_sink is not None:
            self._log_sink(message)

    def _waiter(self, table: Dict[str, asyncio.Future], session_id: str) -> asyncio.Future:
        if session_id not in table:
            table[session_id] = new_future()
        return table[session_id]

    def _on_signal(self, signaling: SignalingClient, message: Envelope) -> None:
        data = message.get("d") or {}
        session_id = data.get("sid") if isinstance(data.get("sid"), str) else None
        kind = message.get("t")
        if kind == "connect.offer" and session_id and isinstance(data.get("grant"), str) and isinstance(data.get("peer"), dict):
            spawn(self._handle_offer(signaling, data))
        elif kind == "connect.answer":
            self._caller._on_signal(message)
        elif kind == "path.candidates" and session_id and isinstance(data.get("blob"), str):
            # The candidates of a session this device opened belong to the calling half.
            self._caller._on_signal(message)
            if self._caller._owns(session_id):
                return
            try:
                settle(self._waiter(self._candidates, session_id), base64.b64decode(data["blob"], validate=True))
            except ValueError:
                pass  # not base64: as good as no candidates
        elif kind == "path.fallback" and session_id:
            settle(self._waiter(self._fallbacks, session_id), data.get("reason") if isinstance(data.get("reason"), str) else "unknown")
        elif kind == "revoke":
            self._caller._on_signal(message)
            sids = data.get("sids") if isinstance(data.get("sids"), list) else None
            reason = data.get("reason") if isinstance(data.get("reason"), str) else ErrorCodes.SESSION_REVOKED
            for session in list(self._sessions.values()):
                if sids is None or session.info.session_id in sids:
                    self._log(f"session {session.info.session_id} revoked by the platform ({reason})")
                    spawn(session.end(reason))

    async def _handle_offer(self, signaling: SignalingClient, offer: Dict[str, Any]) -> None:
        """The platform says an application wants to connect. The device checks the grant's signature and
        that the grant is really about this device. Whether the application is trusted is not the
        platform's to say: the shared-key handshake proves it."""
        grant, error = await self._grants.validate(offer["grant"], True)
        peer = offer["peer"]
        peer_name = peer.get("name") or peer.get("id")
        refusal = (error or ErrorCodes.GRANT_INVALID) if grant is None else self._check_offer(grant, offer)
        try:
            signaling.send("connect.answer", {"sid": offer["sid"], "accept": refusal is None, "error": refusal})
        except ConnectivitizerError:
            return
        if refusal is not None or grant is None:
            self._log(f"refused connection from {peer_name} ({refusal})")
            return
        session_id = grant["jti"]
        try:
            session = await self._open_path_and_establish(signaling, offer, grant)
            self._sessions[session_id] = session
            info = session.info
            where = f", peer at {info.peer_address}" if info.peer_address else ""
            self._log(f"session {session_id} established with {session.peer.name} ({info.mode}, {info.trust}{where})")
            self._report({"sid": session_id, "state": "established", "mode": info.mode, "trust": info.trust, "transport": info.transport})
            spawn(self._watch(session))
        except Exception as failure:
            code = code_of(failure)
            self._log(f"session {session_id} with {peer_name} failed ({code})")
            self._report({"sid": session_id, "state": "failed", "error": code})
        finally:
            for table in (self._candidates, self._fallbacks):
                waiting = table.pop(session_id, None)
                if waiting is not None:
                    fail(waiting, ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The path negotiation is over."))

    def _check_offer(self, grant: Grant, offer: Dict[str, Any]) -> Optional[str]:
        """None when the offer can be accepted, otherwise the refusal code."""
        if grant["jti"] != offer["sid"] or grant["dev"].get("id") != self._device_id:
            return ErrorCodes.GRANT_INVALID
        if ConnectionModes.COMPATIBILITY in grant["modes"]:
            # The gateway can read what it forwards; a device run by this SDK never opts in to that.
            return ErrorCodes.COMPATIBILITY_NOT_ENABLED
        if e2e_method_of(grant) != E2eMethods.SHARED_KEY:
            return ErrorCodes.E2E_NO_COMMON_METHOD
        return None if self._can_serve(grant, offer["peer"]) else ErrorCodes.NO_PERMITTED_MODE

    def _direct_possible(self, grant: Grant, peer: Dict[str, Any]) -> bool:
        return (
            ConnectionModes.DIRECT in grant["modes"]
            and not self._disable_direct
            and self._platform.supports_udp
            and Capabilities.PATH_UDP_KCP in (peer.get("caps") or [])
        )

    def _can_serve(self, grant: Grant, peer: Dict[str, Any]) -> bool:
        return (ConnectionModes.E2E_RELAY in grant["modes"] and bool(grant.get("relay"))) or self._direct_possible(grant, peer)

    async def _open_path_and_establish(self, signaling: SignalingClient, offer: Dict[str, Any], grant: Grant) -> TunnelSession:
        """Follows the initiator's lead: a direct path if the initiator finds one, the relay if it says so. The
        device never decides on its own to use a path the initiator did not choose."""
        session_id = grant["jti"]
        peer = offer["peer"]
        peer_label = peer.get("name") or peer.get("id")

        def parameters(**path: Any) -> SessionParameters:
            return SessionParameters(
                platform=self._platform,
                role=Roles.DEVICE,
                grant_token=offer["grant"],
                grant=grant,
                peer_label=peer_label,
                now_seconds=self._now_seconds,
                shared_keys=self._keys,
                validate_renewed_grant=lambda token: self._grants.validate_known(token, False),
                resolve_service=self._resolve_service,
                **path,
            )

        if self._direct_possible(grant, peer):
            stun = self._stun_servers if self._stun_servers is not None else (signaling.welcome.get("stunServers") or [])
            attempt = DirectAttempt(
                self._platform,
                Roles.DEVICE,
                session_id,
                offer["grant"],
                stun,
                peer_reflexive=peer_reflexive_for(e2e_method_of(grant)),
                log=lambda message: self._log(f"session {session_id}: direct: {message}"),
            )
            try:

                async def apply_candidates() -> None:
                    attempt.set_remote_candidates(await asyncio.shield(self._waiter(self._candidates, session_id)))

                spawn(apply_candidates())
                fallback = self._waiter(self._fallbacks, session_id)

                def expired() -> ConnectivitizerError:
                    return ConnectivitizerError(ErrorCodes.SIGNALING_TIMEOUT, "The initiator did not complete the path negotiation in time.")

                blob = await with_timeout(attempt.gather(), PATH_TIMEOUT, expired)
                signaling.send("path.candidates", {"sid": session_id, "blob": base64.b64encode(blob).decode("ascii")})

                selection = asyncio.ensure_future(attempt.wait_for_selection())
                selection.add_done_callback(lambda t: t.cancelled() or t.exception())
                done, _ = await asyncio.wait({selection, fallback}, timeout=PATH_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
                if not done:
                    selection.cancel()
                    raise expired()
                if selection in done and selection.exception() is None:
                    path = selection.result()
                    direct = asyncio.ensure_future(
                        TunnelSession.establish(
                            parameters(
                                path=path.stream,
                                mode=ConnectionModes.DIRECT,
                                transport="udp-kcp",
                                peer_address=path.peer_address,
                                local_candidates_hash=attempt.local_candidates_hash,
                                remote_candidates_hash=attempt.remote_candidates_hash,
                            )
                        )
                    )
                    direct.add_done_callback(lambda t: t.cancelled() or t.exception())
                    # The initiator may have given up on the direct path while this side thought it was selected.
                    await asyncio.wait({direct, fallback}, return_when=asyncio.FIRST_COMPLETED)
                    if direct.done() and direct.exception() is None:
                        return direct.result()
                    if not fallback.done():
                        raise direct.exception()  # type: ignore[misc]
                    direct.cancel()
                    try:
                        await path.stream.close()
                    except Exception:
                        pass
                    self._log(f"session {session_id}: no direct path ({fallback.result()}), using the relay")
                    self._log(f"session {session_id}: direct: {attempt.summary()}")
                elif fallback.done() and fallback.exception() is None:
                    selection.cancel()
                    self._log(f"session {session_id}: no direct path ({fallback.result()}), using the relay")
                    self._log(f"session {session_id}: direct: {attempt.summary()}")
                else:
                    raise selection.exception() or expired()  # type: ignore[misc]
            finally:
                attempt.close()

        if not grant.get("relay") or ConnectionModes.E2E_RELAY not in grant["modes"]:
            raise ConnectivitizerError(ErrorCodes.DIRECT_UNAVAILABLE, "No direct path was found and relaying is not permitted for this session.")
        relay = await RelayPath.connect(self._platform, grant["relay"], offer["grant"], Roles.DEVICE)
        return await TunnelSession.establish(parameters(path=relay, relay=relay, mode=ConnectionModes.E2E_RELAY, transport="relay-ws"))

    def _resolve_service(self, name: str, peer: PeerInfo) -> Union[Tuple[str, int], str]:
        """The device's own, local answer to "may this peer use this service, and where does it go?"."""
        service = self._services.get(name)
        if service is None:
            return ErrorCodes.SERVICE_NOT_EXPOSED
        host, port, _, allow = service
        if allow is not None and peer.fingerprint not in allow:
            return ErrorCodes.DENIED_BY_LOCAL_POLICY
        return host, port

    async def _watch(self, session: TunnelSession) -> None:
        reason = await session.completion
        self._sessions.pop(session.info.session_id, None)
        self._log(f"session {session.info.session_id} ended ({reason})")
        self._report({"sid": session.info.session_id, "state": "ended", "error": reason, "bytesSent": session.bytes_sent, "bytesReceived": session.bytes_received})

    def _report(self, update: Dict[str, Any]) -> None:
        try:
            if self._signaling is not None and self._signaling.is_open:
                self._signaling.send("session.update", {k: v for k, v in update.items() if v is not None})
        except Exception:
            pass  # reporting is best effort

    async def _end_all_sessions(self, reason: str) -> None:
        await asyncio.gather(*(session.end(reason) for session in list(self._sessions.values())), return_exceptions=True)
