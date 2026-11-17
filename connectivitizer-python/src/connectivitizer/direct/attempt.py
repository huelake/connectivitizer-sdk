"""One attempt to open a direct path for a session (protocol section 6): discover this endpoint's addresses,
exchange candidates with the peer through signaling, then punch through the NATs with UDP probes. The
initiator picks the first path that works.

Probes carry no payload and prove nothing about who sent them - they only find a working path. Everything
that matters is established afterwards by the end-to-end handshake over that path, and both endpoints then
confirm in the session bind which candidate lists they used. That is also why an address the peer did not
announce, learned from where its probes come from, is used only when the session's end-to-end layer
authenticates the peer (``peer_reflexive``)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import struct
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Sequence

from ..grants import Roles
from ..platform import Platform, UdpSocket
from ..streams import ByteStream, fail, new_future, settle, spawn
from .addresses import UdpAddress, format_address, is_global_ipv6, is_ipv6, normalize_host, parse_address, usable_candidate
from .kcp_path import DatagramType, KcpPath


class DirectFailureReasons:
    POLICY_RELAY_ONLY = "policy_relay_only"
    PEER_NO_DIRECT_SUPPORT = "peer_no_direct_support"
    STUN_UNREACHABLE = "stun_unreachable"
    UDP_BLOCKED_LOCAL = "udp_blocked_local"
    UDP_BLOCKED_REMOTE = "udp_blocked_remote"
    SYMMETRIC_NAT_BOTH = "symmetric_nat_both"
    PROBE_TIMEOUT = "probe_timeout"


def peer_reflexive_for(e2e_method: str) -> bool:
    """Whether a session with this end-to-end layer may use learned addresses: only when the layer
    authenticates the peer, because nothing but that handshake vouches for such a path."""
    return e2e_method in ("tls13", "shared-key")


@dataclass
class DirectPath:
    stream: ByteStream
    peer_address: str
    """``ip:port`` of the peer on the selected path."""


PROBE_SIZE = 18
FLAG_PROBE = 0
FLAG_SELECT = 1
MAX_CANDIDATES = 16
MAX_IPV4_ADDRESSES = 6
MAX_IPV6_ADDRESSES = 4
MAX_LEARNED = 4
PROBE_INTERVAL = 0.100
STUN_TIMEOUT = 1.5
LEARNED_GRACE = 0.5
"""How long an announced candidate gets to validate after a learned address did, before the learned one is selected."""
STUN_MAGIC = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
STUN_XOR_MAPPED_ADDRESS = 0x0020


def stun_request(transaction_id: bytes) -> bytes:
    return struct.pack(">HHI", STUN_BINDING_REQUEST, 0, STUN_MAGIC) + transaction_id


def read_stun_success(datagram: bytes, transaction_id: bytes) -> Optional[str]:
    """Reads the mapped address from a STUN Binding success response for one of our transactions."""
    if len(datagram) < 20:
        return None
    kind, length, magic = struct.unpack_from(">HHI", datagram, 0)
    if kind != STUN_BINDING_SUCCESS or magic != STUN_MAGIC or not hmac.compare_digest(datagram[8:20], transaction_id):
        return None
    if length > len(datagram) - 20:
        return None
    offset, end = 20, 20 + length
    while end - offset >= 4:
        attribute, value_length = struct.unpack_from(">HH", datagram, offset)
        if value_length > end - offset - 4:
            return None
        if attribute == STUN_XOR_MAPPED_ADDRESS and value_length >= 8 and datagram[offset + 5] == 0x01:
            port = struct.unpack_from(">H", datagram, offset + 6)[0] ^ (STUN_MAGIC >> 16)
            address = struct.unpack_from(">I", datagram, offset + 8)[0] ^ STUN_MAGIC
            return f"{address >> 24}.{(address >> 16) & 255}.{(address >> 8) & 255}.{address & 255}:{port}"
        # Attributes are padded to a multiple of four bytes.
        offset += 4 + ((value_length + 3) & ~3)
    return None


def _join(items: Sequence[str]) -> str:
    return ", ".join(items) or "(none)"


class DirectAttempt:
    def __init__(
        self,
        platform: Platform,
        role: str,
        session_id: str,
        grant_token: str,
        stun_servers: Sequence[str],
        peer_reflexive: bool = False,
        announce_filter: Optional[Callable[[List[str]], List[str]]] = None,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        """``log`` receives one line per step of the attempt (addresses announced, first probe, the count at
        the end)."""
        self._platform = platform
        self._role = role
        self._session_id = session_id
        self._stun_servers = list(stun_servers)
        self._peer_reflexive = peer_reflexive
        self._announce_filter = announce_filter
        self._log_sink = log
        # Both endpoints hold the same grant, so both derive the same tag and KCP conversation id.
        digest = hashlib.sha256(grant_token.encode("utf-8")).digest()
        self._tag = digest[:8]
        self._conversation = struct.unpack_from(">I", digest, 8)[0] | 1
        self.local_candidates_hash: Optional[str] = None
        """SHA-256 (hex) of the candidate list this endpoint sent; confirmed inside the encrypted session."""
        self.remote_candidates_hash: Optional[str] = None
        """SHA-256 (hex) of the candidate list received from the peer through signaling."""
        self._socket: Optional[UdpSocket] = None
        self._remote_candidates: List[UdpAddress] = []
        self._learned: List[UdpAddress] = []
        self._remote_nat = "unknown"
        self._remote_known = new_future()
        self._validated = new_future()
        self._validated_learned = new_future()
        self._select_acknowledged = new_future()
        self._selected_by_peer = new_future()
        self._selected: Optional[UdpAddress] = None
        self._path: Optional[KcpPath] = None
        self._stun: List[List] = []  # [transaction id, answer]
        self._stun_reachable = False
        self._stun_symmetric = False
        self._has_stun_servers = False
        self._handed_over = False
        self._closed = False
        self._started = time.monotonic()
        self._probes_sent = 0
        self._probes_received = 0
        self._answers_received = 0
        self._foreign_datagrams = 0

    async def gather(self) -> bytes:
        """Discovers this endpoint's addresses and returns the candidate list to send to the peer."""
        self._socket = await self._platform.bind_udp()
        self._socket.on_message = self._on_datagram
        mapped = await self._discover()
        self._log(
            f"UDP socket on port {self._socket.port}, IPv6 {'yes' if self._socket.ipv6 else 'no'}; STUN: "
            + (f"{mapped} ({'symmetric NAT' if self._stun_symmetric else 'cone'})" if mapped else "no answer")
        )
        candidates: List[str] = []
        ipv4 = ipv6 = 0
        try:
            local = await self._platform.local_addresses()
        except Exception:
            local = []
        for text in local:
            host = normalize_host(text)
            if host is None:
                continue
            # IPv4 on every interface; IPv6 only global addresses, and only when the socket has IPv6.
            usable = (self._socket.ipv6 and is_global_ipv6(host) and ipv6 < MAX_IPV6_ADDRESSES) if is_ipv6(host) else ipv4 < MAX_IPV4_ADDRESSES
            candidate = format_address(UdpAddress(host, self._socket.port))
            if usable and candidate not in candidates:
                candidates.append(candidate)
                if is_ipv6(host):
                    ipv6 += 1
                else:
                    ipv4 += 1
        if mapped and mapped not in candidates:
            candidates.append(mapped)
        if self._announce_filter is not None:
            candidates = self._announce_filter(candidates)
        nat = "unknown" if not self._stun_reachable else "symmetric" if self._stun_symmetric else "cone"
        blob = json.dumps({"sid": self._session_id, "role": self._role, "udp": candidates, "nat": nat}, separators=(",", ":")).encode("utf-8")
        self.local_candidates_hash = hashlib.sha256(blob).hexdigest()
        self._log(f"announcing {_join(candidates)}")
        return blob

    def set_remote_candidates(self, blob: bytes) -> bool:
        """Takes the peer's candidate list as received through signaling. False when it is not usable."""
        try:
            data = json.loads(blob.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        if not isinstance(data, dict) or data.get("sid") != self._session_id or data.get("role") == self._role:
            return False
        udp = data.get("udp")
        if not isinstance(udp, list) or len(udp) > MAX_CANDIDATES:
            return False
        self.remote_candidates_hash = hashlib.sha256(blob).hexdigest()
        self._remote_nat = data["nat"] if isinstance(data.get("nat"), str) else "unknown"
        parsed: List[UdpAddress] = []
        for text in udp:
            address = parse_address(text) if isinstance(text, str) else None
            if address is not None and usable_candidate(address) and address not in parsed:
                parsed.append(address)
        self._remote_candidates = parsed
        settle(self._remote_known)
        if self._log_sink is not None:
            self._log(f"peer announces {_join([text for text in udp if isinstance(text, str)])}; NAT {self._remote_nat}; after {self._elapsed()} ms")
            self._log("probing them from: " + _join([f"{target.host} <- {self._platform.source_address(target.host) or 'no route'}" for target in parsed]))
        return True

    def _learn(self, address: UdpAddress) -> None:
        """Remembers an address of the peer that the peer did not announce, because a datagram with this
        session's tag came from it. Only once the peer's list is known, only where allowed, and only a few."""
        if (
            not self._peer_reflexive
            or not self._remote_known.done()
            or address in self._remote_candidates
            or address in self._learned
            or len(self._learned) >= MAX_LEARNED
        ):
            return
        self._learned = self._learned + [address]

    def _probe_targets(self) -> List[UdpAddress]:
        return self._remote_candidates + self._learned

    async def open(self, budget: float) -> Optional[DirectPath]:
        """Initiator: tries the peer's candidates until a path works, then tells the peer which one to use.
        Returns that path, or None when none worked in time."""
        deadline = time.monotonic() + budget
        stop = False

        def remaining() -> float:
            return max(deadline - time.monotonic(), 0.001)

        try:
            await asyncio.wait_for(asyncio.shield(self._remote_known), remaining())
            spawn(self._probe_loop(FLAG_PROBE, self._probe_targets, lambda: stop or self._selected is not None))

            # A learned address is the fallback: selected only if no announced candidate answers in time.
            waits = [asyncio.ensure_future(asyncio.shield(self._validated))]
            if self._peer_reflexive:
                waits.append(asyncio.ensure_future(self._learned_fallback()))
            done, pending = await asyncio.wait(waits, timeout=remaining(), return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            remote = next((task.result() for task in done if not task.cancelled() and task.exception() is None), None)
            if remote is None:
                return None
            self._selected = remote
            spawn(self._probe_loop(FLAG_SELECT, lambda: [remote], lambda: stop))
            await asyncio.wait_for(asyncio.shield(self._select_acknowledged), remaining())
            stop = True
            self._handed_over = True
            self._path = KcpPath(self._socket, remote.host, remote.port, self._conversation)  # type: ignore[arg-type]
            return DirectPath(self._path, self._path.peer_address)
        except (asyncio.TimeoutError, Exception):
            return None
        finally:
            stop = True

    async def _learned_fallback(self) -> UdpAddress:
        learned = await asyncio.shield(self._validated_learned)
        await asyncio.sleep(LEARNED_GRACE)
        return learned

    async def wait_for_selection(self) -> DirectPath:
        """Device: keeps probing the initiator's candidates (which opens this side's NAT) and waits for the
        initiator to select a path. Raises when the attempt is closed first."""

        async def probe_when_known() -> None:
            await asyncio.shield(self._remote_known)
            await self._probe_loop(FLAG_PROBE, self._probe_targets, lambda: self._closed or self._path is not None)

        spawn(probe_when_known())
        path: KcpPath = await asyncio.shield(self._selected_by_peer)
        return DirectPath(path, path.peer_address)

    def failure_reason(self) -> str:
        """Why no direct path was found."""
        if self._stun_symmetric and self._remote_nat == "symmetric":
            return DirectFailureReasons.SYMMETRIC_NAT_BOTH
        if not self._stun_reachable:
            return DirectFailureReasons.UDP_BLOCKED_LOCAL if self._has_stun_servers else DirectFailureReasons.STUN_UNREACHABLE
        if self._remote_nat == "unknown":
            return DirectFailureReasons.UDP_BLOCKED_REMOTE
        return DirectFailureReasons.PROBE_TIMEOUT

    def summary(self) -> str:
        """What this side of the attempt sent and saw, for the log when no path was found."""
        failed = self._socket.send_failures if self._socket is not None else 0
        failures = f" ({failed} not sent by the system, first {self._socket.first_send_failure})" if failed and self._socket is not None else ""
        foreign = f", {self._foreign_datagrams} other datagrams" if self._foreign_datagrams else ""
        return (
            f"after {self._elapsed()} ms: sent {self._probes_sent} probes{failures} to {_join([format_address(target) for target in self._probe_targets()])}; "
            f"received {self._probes_received} probes and {self._answers_received} answers{foreign}"
        )

    def _log(self, message: str) -> None:
        if self._log_sink is not None:
            self._log_sink(message)

    def _elapsed(self) -> int:
        """Milliseconds since the attempt was created."""
        return int((time.monotonic() - self._started) * 1000)

    def _known(self, source: UdpAddress) -> str:
        return "announced" if source in self._remote_candidates else "learned" if source in self._learned else "not announced"

    def close(self) -> None:
        """Gives up the attempt. A path that was handed to a session is not affected."""
        if self._closed:
            return
        self._closed = True
        closed = RuntimeError("The direct attempt was closed.")
        for future in (self._selected_by_peer, self._validated, self._validated_learned, self._remote_known, self._select_acknowledged):
            fail(future, closed)
        if not self._handed_over and self._socket is not None:
            self._socket.close()

    async def _discover(self) -> Optional[str]:
        """Asks the STUN servers how this endpoint's UDP port appears from outside. Different answers from
        different servers mean the NAT maps each destination separately ("symmetric"), in which case the
        reported address is of no use to a peer."""
        servers: List[UdpAddress] = []
        for server in self._stun_servers:
            colon = server.rfind(":")
            try:
                port = int(server[colon + 1 :])
            except ValueError:
                continue
            if colon <= 0 or port < 1 or port > 65535:
                continue
            host = server[:colon]
            try:
                parsed = parse_address(f"{host}:{port}")
                servers.append(UdpAddress(parsed.host if parsed else await self._platform.resolve(host), port))
            except Exception:
                continue  # a server that cannot be resolved is skipped
        self._has_stun_servers = bool(servers)
        if not servers:
            return None
        self._stun = [[self._platform.random_bytes(12), None] for _ in servers]
        started = time.monotonic()

        def all_answered() -> bool:
            return all(entry[1] is not None for entry in self._stun)

        # UDP is lossy: repeat the requests a few times until every server has answered.
        for wait in (0, 0.2, 0.4, 0.8):
            while time.monotonic() < started + wait and not all_answered():
                await asyncio.sleep(0.02)
            if all_answered():
                break
            for server, entry in zip(servers, self._stun):
                if entry[1] is None:
                    self._socket.send(stun_request(entry[0]), server.host, server.port)  # type: ignore[union-attr]
        while time.monotonic() < started + STUN_TIMEOUT and not all_answered():
            await asyncio.sleep(0.02)
        answers = [entry[1] for entry in self._stun if entry[1] is not None]
        self._stun_reachable = bool(answers)
        self._stun_symmetric = len(set(answers)) > 1
        return answers[0] if answers else None

    def _on_datagram(self, data: bytes, host: str, port: int) -> None:
        if not data:
            return
        if data[0] <= 0x03:
            for entry in self._stun:
                if entry[1] is None:
                    entry[1] = read_stun_success(data, entry[0])
            return
        if data[0] in (DatagramType.PROBE, DatagramType.PROBE_ACK):
            self._on_probe(data, host, port)
        else:
            self._foreign_datagrams += 1

    def _on_probe(self, data: bytes, raw_host: str, port: int) -> None:
        if len(data) != PROBE_SIZE or not hmac.compare_digest(data[1:9], self._tag) or self._socket is None:
            self._foreign_datagrams += 1
            return  # not for this session
        host = normalize_host(raw_host) or raw_host
        source = UdpAddress(host, port)
        self._learn(source)
        announced = source in self._remote_candidates
        flags = data[9]
        if data[0] == DatagramType.PROBE:
            self._probes_received += 1
            if self._probes_received == 1:
                self._log(f"first probe from {format_address(source)} ({self._known(source)}) after {self._elapsed()} ms")
        else:
            self._answers_received += 1
            if self._answers_received == 1:
                self._log(f"first answer from {format_address(source)} ({self._known(source)}) after {self._elapsed()} ms")
        if data[0] == DatagramType.PROBE:
            if flags == FLAG_SELECT:
                # Only the initiator selects, and only an address from its own announced list (or, where the
                # session allows it, one learned from its probes) is accepted.
                if self._role != Roles.DEVICE or not (announced or source in self._learned):
                    return
                if self._path is None:
                    self._selected = source
                    self._handed_over = True
                    # The path listens before the selection is acknowledged, so the first packets are not lost.
                    self._path = KcpPath(self._socket, host, port, self._conversation)
                    self._path.on_probe = self._on_probe
                    self._log(f"the peer selected {format_address(source)} after {self._elapsed()} ms")
                    settle(self._selected_by_peer, self._path)
                elif self._selected != source:
                    return
            self._socket.send(bytes([DatagramType.PROBE_ACK]) + data[1:], host, port)
            return

        if self._role == Roles.INITIATOR and (announced or source in self._learned):
            if flags == FLAG_PROBE:
                settle(self._validated if announced else self._validated_learned, source)
            elif self._selected is not None and self._selected == source:
                settle(self._select_acknowledged)

    async def _probe_loop(self, flags: int, targets: Callable[[], List[UdpAddress]], done: Callable[[], bool]) -> None:
        while not done() and not self._closed:
            probe = bytes([DatagramType.PROBE]) + self._tag + bytes([flags]) + self._platform.random_bytes(8)
            for target in targets():
                if self._socket is not None:
                    self._socket.send(probe, target.host, target.port)
                    self._probes_sent += 1
            await asyncio.sleep(PROBE_INTERVAL)
