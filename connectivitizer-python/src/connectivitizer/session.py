"""A session: the end-to-end channel over one path, the bind that ties it to its grant, and the streams to
services inside it (protocol sections 4 and 5)."""

from __future__ import annotations

import asyncio
import json
import struct
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Sequence, Tuple, Union

from .errors import ConnectivitizerError, ErrorCodes, code_of
from .grants import ConnectionModes, E2eMethods, Grant, Roles, e2e_method_of, hash_grant
from .http import TunnelResponse, http_request
from .mux import MuxSession, MuxStream
from .noise import SharedKey, accept_shared_key, connect_shared_key, prologue
from .platform import Platform
from .streams import ByteStream, StreamReader, new_future, settle, settled_within, spawn, with_timeout
from .websocket import StreamWebSocket

HANDSHAKE_TIMEOUT = 15.0
SERVICE_OPEN_TIMEOUT = 15.0
LOCAL_CONNECT_TIMEOUT = 5.0
LEASE_GRACE_SECONDS = 30
MAX_CONTROL_MESSAGE = 64 * 1024


@dataclass
class PeerInfo:
    """The authenticated other end of a session."""

    fingerprint: str
    """A certificate fingerprint, or ``key:<name>`` for a peer that proved to hold that shared key."""
    name: str
    """From the certificate, or - with a shared key - the label the platform gave the peer."""
    trust: str
    """``none``, ``platform-introduced``, ``shared-key``, ``workspace-ca`` or ``local-pinned``."""


@dataclass
class ConnectionInfo:
    """The routing and security properties of an established session, as this endpoint observed and
    verified them - not as anybody claimed."""

    session_id: str
    mode: str
    """``direct``, ``e2e-relay`` or ``compatibility``."""
    transport: str
    """What carries the bytes: ``udp-kcp`` for direct sessions, ``relay-ws`` otherwise."""
    relayed: bool
    end_to_end_encrypted: bool
    """True when only the two endpoints hold the keys protecting the traffic."""
    platform_can_read_payload: bool
    e2e_method: str
    trust: str
    peer_fingerprint: str
    peer_name: str
    peer_address: Optional[str] = None
    """Direct sessions: the network address this endpoint exchanges packets with."""
    direct_failure_reason: Optional[str] = None
    """Why a direct connection was not used, when the session is relayed and the reason is known."""


SecureLayer = Callable[[ByteStream, str], Awaitable[Tuple[ByteStream, PeerInfo]]]
"""An end-to-end layer: turns a path into an encrypted stream to an authenticated peer."""


@dataclass
class SessionParameters:
    platform: Platform
    path: ByteStream
    role: str
    mode: str
    transport: str
    grant_token: str
    grant: Grant
    peer_label: str
    now_seconds: Callable[[], int]
    shared_keys: Sequence[SharedKey] = ()
    certificate_layer: Optional[SecureLayer] = None
    direct_failure_reason: Optional[str] = None
    peer_address: Optional[str] = None
    local_candidates_hash: Optional[str] = None
    remote_candidates_hash: Optional[str] = None
    relay: Any = None
    validate_renewed_grant: Optional[Callable[[str], Tuple[Optional[Grant], Optional[str]]]] = None
    resolve_service: Optional[Callable[[str, PeerInfo], Union[Tuple[str, int], str]]] = None
    """Device side: (host, port) of a service, or the error code that refuses it."""


def _framed(message: Mapping[str, Any], length_bytes: int) -> bytes:
    data = json.dumps({k: v for k, v in message.items() if v is not None}, separators=(",", ":")).encode("utf-8")
    return (struct.pack(">H", len(data)) if length_bytes == 2 else struct.pack(">I", len(data))) + data


async def _read_framed(reader: StreamReader, length_bytes: int) -> Optional[Dict[str, Any]]:
    prefix = await reader.read_exact(length_bytes)
    if prefix is None:
        return None
    length = int.from_bytes(prefix, "big")
    if length == 0 or length > MAX_CONTROL_MESSAGE:
        raise ConnectivitizerError(ErrorCodes.MUX_PROTOCOL_ERROR, "Malformed tunnel message.")
    data = await reader.read_exact(length)
    if data is None:
        return None
    parsed = json.loads(data.decode("utf-8"))
    return parsed if isinstance(parsed, dict) else {}


class TunnelSession:
    """An authenticated, end-to-end encrypted session between an initiator and a device, carrying any number
    of streams to the device's services."""

    def __init__(self, parameters: SessionParameters, mux: MuxSession, control: MuxStream, control_reader: StreamReader, peer: PeerInfo) -> None:
        self._parameters = parameters
        self._mux = mux
        self._control = control
        self._control_reader = control_reader
        self.peer = peer
        """The authenticated remote endpoint."""
        self.bytes_sent = 0
        self.bytes_received = 0
        grant = parameters.grant
        self._lease_expires_at: int = grant["iat"] + grant["lease"]
        self._end_reason: Optional[str] = None
        self._control_writing: Optional[asyncio.Future] = None
        mode = parameters.mode
        self.info = ConnectionInfo(
            session_id=grant["jti"],
            mode=mode,
            transport=parameters.transport,
            relayed=mode != ConnectionModes.DIRECT,
            end_to_end_encrypted=mode != ConnectionModes.COMPATIBILITY,
            platform_can_read_payload=mode == ConnectionModes.COMPATIBILITY,
            e2e_method=e2e_method_of(grant),
            trust=peer.trust,
            peer_fingerprint=peer.fingerprint,
            peer_name=peer.name,
            peer_address=parameters.peer_address,
            direct_failure_reason=parameters.direct_failure_reason,
        )
        """The verified properties of this session."""
        self.completion: asyncio.Future = new_future()
        """Resolves with an error code once the session has ended."""
        control_done = spawn(self._control_loop())

        async def mux_ended() -> None:
            reason = await mux.completion
            # A peer that ends the session says why on the control stream and closes the mux right after.
            # Both arrive together, so the control loop reads the reason before the mux's own is taken.
            await settled_within(control_done, 2.0)
            self._finish(reason)

        spawn(mux_ended())
        self._watchdog: Optional[asyncio.Task] = None
        if parameters.role == Roles.DEVICE:
            spawn(self._accept_loop())
            self._watchdog = spawn(self._check_lease())

    @property
    def lease_expires(self) -> int:
        """Unix time until which the session is authorised without a renewed grant."""
        return self._lease_expires_at

    @property
    def is_ended(self) -> bool:
        return self._end_reason is not None

    async def __aenter__(self) -> "TunnelSession":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    @classmethod
    async def establish(cls, parameters: SessionParameters) -> "TunnelSession":
        """Runs the end-to-end handshake over an established path - the layer the grant names - and then the
        session bind that ties the encrypted channel to the grant and to the observed route. Never returns a
        session that is not fully verified."""

        def timed_out() -> ConnectivitizerError:
            spawn(parameters.path.close())
            return ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The end-to-end handshake timed out.")

        return await with_timeout(cls._establish(parameters), HANDSHAKE_TIMEOUT, timed_out)

    @classmethod
    async def _establish(cls, parameters: SessionParameters) -> "TunnelSession":
        grant, role = parameters.grant, parameters.role
        is_initiator = role == Roles.INITIATOR
        method = e2e_method_of(grant)
        grant_hash = hash_grant(parameters.grant_token)

        # The grant says which end-to-end layer the session uses; an endpoint never picks another one.
        if method == E2eMethods.SHARED_KEY:
            keys = list(parameters.shared_keys)
            if not keys:
                await _close_quietly(parameters.path)
                raise ConnectivitizerError(ErrorCodes.E2E_SHARED_KEY_MISMATCH, "This endpoint has no shared key for the session.")
            bound = prologue(grant["jti"], grant_hash)
            channel = (
                await connect_shared_key(parameters.path, keys[0], bound, parameters.platform.random_bytes)
                if is_initiator
                else await accept_shared_key(parameters.path, keys, bound, parameters.platform.random_bytes)
            )
            # The key proves the peer is a holder; which holder, it cannot tell. The name is the platform's label.
            stream, peer = channel.stream, PeerInfo(f"key:{channel.key_name}", parameters.peer_label, "shared-key")
        elif method == E2eMethods.TLS13 and parameters.certificate_layer is not None:
            stream, peer = await parameters.certificate_layer(parameters.path, role)
            # The platform said which identity to expect; the handshake showed which one is really there.
            expected = ((grant.get("dev") if is_initiator else grant.get("ini")) or {}).get("fp")
            if expected and expected != peer.fingerprint:
                await _close_quietly(stream)
                raise ConnectivitizerError(ErrorCodes.E2E_SESSION_BIND_MISMATCH, "The peer's identity is not the one named in the session grant.")
        else:
            await _close_quietly(parameters.path)
            raise ConnectivitizerError(ErrorCodes.E2E_NO_COMMON_METHOD, f"This endpoint cannot take part in a session with the end-to-end layer '{method}'.")

        mux = MuxSession(stream, is_initiator)
        mux.start()
        try:
            control = mux.open() if is_initiator else await mux.accept()
            if control is None:
                raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the session during the handshake.")
            reader = StreamReader(control)
            direct = parameters.mode == ConnectionModes.DIRECT
            own_bind = {"sid": grant["jti"], "grant": grant_hash, "role": role, "mode": parameters.mode, "cands": parameters.local_candidates_hash if direct else None}
            await control.write(_framed({"bind": {k: v for k, v in own_bind.items() if v is not None}}, 4))
            try:
                received = await _read_framed(reader, 4)
            except Exception as error:
                code = code_of(error, ErrorCodes.E2E_HANDSHAKE_FAILED)
                raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED if code == ErrorCodes.PATH_CLOSED else code, "The peer ended the session during the handshake.") from error
            if received is None:
                raise ConnectivitizerError(ErrorCodes.E2E_HANDSHAKE_FAILED, "The peer ended the session during the handshake; it may not trust this endpoint.")
            if isinstance(received.get("error"), str):
                raise ConnectivitizerError(received["error"], f"The peer refused the session ({received['error']}).")
            peer_bind = received.get("bind") if isinstance(received.get("bind"), dict) else None
            expected_role = Roles.DEVICE if is_initiator else Roles.INITIATOR
            if (
                peer_bind is None
                or peer_bind.get("sid") != own_bind["sid"]
                or peer_bind.get("grant") != own_bind["grant"]
                or peer_bind.get("mode") != own_bind["mode"]
                or peer_bind.get("role") != expected_role
                # The addresses probed came through the control plane; here the authenticated peer confirms them.
                or (direct and (not peer_bind.get("cands") or peer_bind.get("cands") != parameters.remote_candidates_hash))
            ):
                try:
                    await control.write(_framed({"error": ErrorCodes.E2E_SESSION_BIND_MISMATCH}, 4))
                except Exception:
                    pass
                raise ConnectivitizerError(ErrorCodes.E2E_SESSION_BIND_MISMATCH, "The two endpoints do not agree on the session they are part of.")
            return cls(parameters, mux, control, reader, peer)
        except BaseException:
            await mux.close()
            raise

    # -- initiator side ------------------------------------------------------------------------------------

    async def open_stream(self, service: str) -> ByteStream:
        """Opens a raw byte stream to one of the device's services."""
        if self._parameters.role != Roles.INITIATOR:
            raise ConnectivitizerError(ErrorCodes.INVALID_REQUEST, "Only the initiating endpoint opens service streams.")
        if self._end_reason is not None:
            raise ConnectivitizerError(self._end_reason, f"The session is over ({self._end_reason}).")
        stream = self._mux.open()
        try:
            reader = StreamReader(stream)

            async def ask() -> Optional[Dict[str, Any]]:
                await stream.write(_framed({"svc": service}, 2))
                return await _read_framed(reader, 2)

            answer = await with_timeout(ask(), SERVICE_OPEN_TIMEOUT, lambda: ConnectivitizerError(ErrorCodes.SESSION_CLOSED, f"Opening service '{service}' timed out."))
            if not answer or answer.get("ok") is not True:
                code = (answer or {}).get("error") or ErrorCodes.SESSION_CLOSED
                raise ConnectivitizerError(code, f"The device did not open service '{service}' ({code}).")
            return _CountingStream(self, stream, reader)
        except BaseException as error:
            await stream.close()
            if isinstance(error, (ConnectivitizerError, asyncio.CancelledError)):
                raise
            raise ConnectivitizerError(ErrorCodes.SESSION_CLOSED, "The session ended while opening the service.") from error

    async def fetch(self, service: str, path: str, method: str = "GET", headers: Optional[Mapping[str, str]] = None, body: Union[str, bytes, None] = None, timeout: float = 30.0) -> TunnelResponse:
        """An HTTP request to a service of the device. The device's local application receives it as an
        ordinary request on its own port, with ``service`` as the host name."""
        return await http_request(lambda: self.open_stream(service), service, path, method=method, headers=headers, body=body, timeout=timeout)

    async def websocket(self, service: str, path: str, protocols: Optional[List[str]] = None, headers: Optional[Dict[str, str]] = None) -> StreamWebSocket:
        """A WebSocket to a service of the device."""
        stream = await self.open_stream(service)
        return await StreamWebSocket.connect(stream, service, path, self._parameters.platform.random_bytes, headers=headers, protocols=protocols)

    async def renew_lease(self, grant_token: str, grant: Grant) -> None:
        """Extends the session with a freshly issued grant."""
        if grant.get("jti") != self._parameters.grant["jti"]:
            raise ConnectivitizerError(ErrorCodes.GRANT_INVALID, "The grant belongs to another session.")
        await self._write_control({"lease": {"grant": grant_token}})
        if self._parameters.relay is not None:
            self._parameters.relay.renew_lease(grant_token)
        self._lease_expires_at = max(self._lease_expires_at, grant["iat"] + grant["lease"])

    async def end(self, reason: str = ErrorCodes.SESSION_CLOSED) -> None:
        """Ends the session for ``reason`` (an error code), telling the peer why."""
        if self._end_reason is not None:
            return
        self._finish(reason)
        try:
            await asyncio.wait_for(self._write_control({"error": reason}), 2)
        except Exception:
            pass
        await self._mux.close()

    async def close(self) -> None:
        """Closes the session in an orderly way."""
        await self.end(ErrorCodes.SESSION_CLOSED)

    # -- internals -----------------------------------------------------------------------------------------

    def _finish(self, reason: str) -> None:
        if self._end_reason is not None:
            return
        self._end_reason = reason
        if self._watchdog is not None and self._watchdog is not asyncio.current_task():
            self._watchdog.cancel()
        settle(self.completion, reason)

    def _write_control(self, message: Mapping[str, Any]) -> "asyncio.Future[None]":
        previous = self._control_writing

        async def write() -> None:
            if previous is not None:
                await asyncio.wait({previous})
            await self._control.write(_framed(message, 4))

        task = asyncio.ensure_future(write())
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        self._control_writing = task
        return task

    async def _control_loop(self) -> None:
        try:
            while self._end_reason is None:
                message = await _read_framed(self._control_reader, 4)
                if message is None:
                    return
                if isinstance(message.get("error"), str):
                    self._finish(message["error"])
                    await self._mux.close()
                    return
                lease = message.get("lease")
                if isinstance(lease, dict) and self._parameters.role == Roles.DEVICE and isinstance(lease.get("grant"), str):
                    self._handle_lease_renewal(lease["grant"])
        except Exception:
            pass  # the mux reports why the session ended

    def _handle_lease_renewal(self, token: str) -> None:
        validate = self._parameters.validate_renewed_grant
        renewed = validate(token)[0] if validate is not None else None
        original = self._parameters.grant
        # A renewal may only prolong this very session for the same two endpoints; it cannot widen anything.
        if (
            renewed is not None
            and renewed["jti"] == original["jti"]
            and renewed.get("ws") == original.get("ws")
            and renewed["ini"].get("id") == original["ini"].get("id")
            and renewed["ini"].get("fp") == original["ini"].get("fp")
            and renewed["dev"].get("id") == original["dev"].get("id")
            and e2e_method_of(renewed) == e2e_method_of(original)
        ):
            self._lease_expires_at = max(self._lease_expires_at, renewed["iat"] + renewed["lease"])

    async def _check_lease(self) -> None:
        """Device side: a session whose authorisation ran out is ended, whatever the platform or the peer say."""
        while self._end_reason is None:
            await asyncio.sleep(5)
            if self._parameters.now_seconds() >= self._lease_expires_at + LEASE_GRACE_SECONDS:
                await self.end(ErrorCodes.LEASE_EXPIRED)
                return

    async def _accept_loop(self) -> None:
        while self._end_reason is None:
            stream = await self._mux.accept()
            if stream is None:
                return
            spawn(self._serve_stream(stream))

    async def _serve_stream(self, stream: MuxStream) -> None:
        """Device side: authorise one service stream, connect it to the local application and copy bytes."""
        local: Optional[ByteStream] = None
        try:
            reader = StreamReader(stream)
            request = await asyncio.wait_for(_read_framed(reader, 2), SERVICE_OPEN_TIMEOUT)
            service = (request or {}).get("svc")
            if not isinstance(service, str) or not service:
                return

            # Platform authorisation (the grant) and the device's own configuration both have to agree.
            refusal: Optional[str] = None
            target: Optional[Tuple[str, int]] = None
            if service not in self._parameters.grant.get("svc", []):
                refusal = ErrorCodes.DENIED_BY_GRANT
            else:
                resolve = self._parameters.resolve_service
                resolved = resolve(service, self.peer) if resolve is not None else ErrorCodes.SERVICE_NOT_EXPOSED
                if isinstance(resolved, str):
                    refusal = resolved
                else:
                    target = resolved
            if target is not None:
                try:
                    local = await asyncio.wait_for(self._parameters.platform.connect_tcp(*target), LOCAL_CONNECT_TIMEOUT)
                except Exception:
                    refusal = ErrorCodes.TARGET_UNREACHABLE

            await stream.write(_framed({"ok": True} if refusal is None else {"ok": False, "error": refusal}, 2))
            if refusal is not None or local is None:
                await stream.end()
                return

            service_stream = local

            async def to_local() -> None:
                while True:
                    chunk = await reader.read_some()
                    if chunk is None:
                        break
                    await service_stream.write(chunk)
                    self.bytes_received += len(chunk)
                await service_stream.end()

            async def to_peer() -> None:
                while True:
                    chunk = await service_stream.read()
                    if chunk is None:
                        break
                    await stream.write(chunk)
                    self.bytes_sent += len(chunk)
                await stream.end()

            await asyncio.gather(to_local(), to_peer())
        except Exception:
            pass  # one stream failing (the local application closed, the peer reset it) does not concern the session
        finally:
            if local is not None:
                await _close_quietly(local)
            await _close_quietly(stream)


class _CountingStream(ByteStream):
    """A service stream on the initiator's side, counting the application bytes for the session report."""

    def __init__(self, session: TunnelSession, stream: MuxStream, reader: StreamReader) -> None:
        self._session = session
        self._stream = stream
        self._reader = reader

    async def read(self) -> Optional[bytes]:
        chunk = await self._reader.read_some()
        if chunk:
            self._session.bytes_received += len(chunk)
        return chunk

    async def write(self, data: bytes) -> None:
        await self._stream.write(data)
        self._session.bytes_sent += len(data)

    async def end(self) -> None:
        await self._stream.end()

    async def close(self) -> None:
        await self._stream.close()


async def _close_quietly(stream: ByteStream) -> None:
    try:
        await stream.close()
    except Exception:
        pass
