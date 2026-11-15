"""What the SDK needs from the machine it runs on, and the asyncio implementation of it: TCP and TLS
sockets, UDP, the system's random source, and this machine's own addresses for direct sessions. Nothing
here has to be configured: an application never passes addresses or sockets."""

from __future__ import annotations

import asyncio
import ipaddress
import os
import platform as system
import secrets
import socket
import ssl
import sys
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

from .direct.addresses import is_ipv6, normalize_host
from .errors import ConnectivitizerError, ErrorCodes
from .http import http_request
from .streams import ByteStream
from .websocket import StreamWebSocket, WebSocketRefusedError

READ_SIZE = 64 * 1024


class SocketStream(ByteStream):
    """A TCP or TLS connection as the byte stream the core works with."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._ended = False

    async def read(self) -> Optional[bytes]:
        try:
            chunk = await self._reader.read(READ_SIZE)
        except (ConnectionError, OSError) as error:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, f"The connection broke ({error}).") from error
        return chunk or None

    async def write(self, data: bytes) -> None:
        if self._writer.is_closing():
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, "The connection is closed.")
        try:
            self._writer.write(data)
            await self._writer.drain()
        except (ConnectionError, OSError) as error:
            raise ConnectivitizerError(ErrorCodes.PATH_CLOSED, f"The connection broke ({error}).") from error

    async def end(self) -> None:
        if self._ended or self._writer.is_closing():
            return
        self._ended = True
        try:
            if self._writer.can_write_eof():
                self._writer.write_eof()
            else:
                await self.close()
        except (OSError, RuntimeError):
            await self.close()

    async def close(self) -> None:
        if not self._writer.is_closing():
            self._writer.close()
        try:
            await self._writer.wait_closed()
        except (OSError, ssl.SSLError, asyncio.CancelledError, ConnectionError):
            pass


class UdpSocket:
    """One UDP socket for a direct path. Hosts are plain IP addresses in canonical form, an IPv4 peer as IPv4
    even on a dual-stack socket."""

    def __init__(self, transport: asyncio.DatagramTransport, port: int, ipv6: bool) -> None:
        self._transport = transport
        self.port = port
        """The local port the socket is really bound to."""
        self.ipv6 = ipv6
        """The socket can also reach IPv6 addresses."""
        self.on_message: Optional[Callable[[bytes, str, int], None]] = None

    def send(self, data: bytes, host: str, port: int) -> None:
        if is_ipv6(host) and not self.ipv6:
            return  # an IPv6 candidate this socket cannot reach
        # A dual-stack socket reaches an IPv4 peer by its IPv4-mapped address.
        # The full IPv6 address tuple: Windows' proactor refuses a (host, port) pair on an IPv6 socket.
        target = (f"::ffff:{host}" if not is_ipv6(host) else host, port, 0, 0) if self.ipv6 else (host, port)
        try:
            self._transport.sendto(data, target)
        except (OSError, ValueError):
            pass  # no route to that address: just a candidate that does not work

    def close(self) -> None:
        self._transport.close()


class _UdpProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.socket: Optional[UdpSocket] = None

    def datagram_received(self, data: bytes, address: Tuple) -> None:
        if self.socket is not None and self.socket.on_message is not None:
            host = normalize_host(address[0]) or address[0]
            self.socket.on_message(data, host, address[1])

    def error_received(self, exc: Exception) -> None:
        pass  # ICMP errors for one candidate say nothing about the others


class Platform:
    """The asyncio platform. Subclass it to run the SDK elsewhere; the defaults need nothing from the caller.

    ``ssl_context`` is used for the connections to the Connectivitizer API (``https``/``wss``), for example
    to trust the certificate authority of a self-hosted installation. ``include_loopback`` offers loopback
    addresses for direct sessions, which only helps when both endpoints run on the same machine."""

    def __init__(self, ssl_context: Optional[ssl.SSLContext] = None, include_loopback: bool = False) -> None:
        self._ssl = ssl_context
        self._include_loopback = include_loopback
        self.description = f"python {system.python_version()} {sys.platform}"
        self.supports_udp = True

    # -- randomness ---------------------------------------------------------------------------------------

    def random_bytes(self, length: int) -> bytes:
        """Cryptographically secure random bytes. Session keys are made from them."""
        return secrets.token_bytes(length)

    # -- the Connectivitizer API ----------------------------------------------------------------------------

    async def _open(self, url: str) -> Tuple[ByteStream, str, str]:
        parts = urlsplit(url)
        secure = parts.scheme in ("https", "wss")
        host = parts.hostname or ""
        port = parts.port or (443 if secure else 80)
        context = None
        if secure:
            context = self._ssl or ssl.create_default_context()
        try:
            reader, writer = await asyncio.open_connection(host, port, ssl=context, server_hostname=host if secure else None)
        except (OSError, ssl.SSLError) as error:
            raise ConnectivitizerError(ErrorCodes.SIGNALING_UNAVAILABLE, f"{host}:{port} could not be reached ({error}).") from error
        sock = writer.get_extra_info("socket")
        if sock is not None:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
        target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        return SocketStream(reader, writer), parts.netloc, target

    async def fetch(self, url: str, method: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, str]:
        """An HTTP request to the Connectivitizer API: (status, body text)."""
        stream, host, target = await self._open(url)
        opened = False

        async def open_stream() -> ByteStream:
            nonlocal opened
            opened = True
            return stream

        try:
            response = await http_request(open_stream, host, target, method=method, headers=headers, body=body)
            return response.status, await response.text()
        finally:
            if not opened:
                await stream.close()

    async def connect_websocket(self, url: str, headers: Dict[str, str]) -> StreamWebSocket:
        """Opens a WebSocket with request headers. A refusal the server names is raised with its code."""
        stream, host, target = await self._open(url)
        try:
            return await StreamWebSocket.connect(stream, host, target, self.random_bytes, headers=headers)
        except WebSocketRefusedError as error:
            # The platform names its reason in a header (the relay) or leaves it to the status (signaling).
            named = error.headers.get("cz-error")
            code = named or (ErrorCodes.UNAUTHENTICATED if error.status == 401 else ErrorCodes.FORBIDDEN if error.status == 403 else ErrorCodes.RELAY_REJECTED)
            raise ConnectivitizerError(code, f"The server refused the connection (HTTP {error.status}{', ' + named if named else ''}).") from None
        except BaseException:
            await stream.close()
            raise

    # -- the device's local services ----------------------------------------------------------------------

    async def connect_tcp(self, host: str, port: int) -> ByteStream:
        reader, writer = await asyncio.open_connection(host, port)
        return SocketStream(reader, writer)

    # -- UDP, for direct sessions ---------------------------------------------------------------------------

    async def bind_udp(self) -> UdpSocket:
        """A dual-stack socket where the system has IPv6, else IPv4 only; bound to a port the system picks."""
        loop = asyncio.get_running_loop()
        sock: Optional[socket.socket] = None
        ipv6 = False
        if socket.has_ipv6:
            try:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                sock.bind(("::", 0))
                ipv6 = True
            except OSError:
                if sock is not None:
                    sock.close()
                sock = None
        if sock is None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(("0.0.0.0", 0))
        sock.setblocking(False)
        port = sock.getsockname()[1]
        protocol = _UdpProtocol()
        transport, _ = await loop.create_datagram_endpoint(lambda: protocol, sock=sock)
        udp = UdpSocket(transport, port, ipv6)  # type: ignore[arg-type]
        protocol.socket = udp
        return udp

    async def local_addresses(self) -> List[str]:
        """This machine's own addresses, offered to the peer: IPv4 on its networks, and IPv6 (the core keeps
        only global ones). Found without extra packages: the source address of each default route, the
        addresses the host name resolves to, and on Linux the kernel's IPv6 list."""
        return await asyncio.get_running_loop().run_in_executor(None, self._local_addresses)

    def _local_addresses(self) -> List[str]:
        found: List[str] = []

        def add(text: str) -> None:
            host = normalize_host(text)
            if host is None or host in found:
                return
            address = ipaddress.ip_address(host)
            if address.is_unspecified or (address.is_loopback and not self._include_loopback):
                return
            found.append(host)

        # Connecting a UDP socket sends nothing; it only asks the system which address it would use.
        for family, probe in ((socket.AF_INET, ("192.0.2.1", 9)), (socket.AF_INET6, ("2001:db8::1", 9))):
            try:
                with socket.socket(family, socket.SOCK_DGRAM) as sock:
                    sock.connect(probe)
                    add(sock.getsockname()[0])
            except OSError:
                pass
        try:
            for entry in socket.getaddrinfo(socket.gethostname(), None, 0, socket.SOCK_DGRAM):
                add(str(entry[4][0]))
        except OSError:
            pass
        if os.path.exists("/proc/net/if_inet6"):
            try:
                with open("/proc/net/if_inet6", encoding="ascii") as listing:
                    for line in listing:
                        fields = line.split()
                        if len(fields) >= 6 and fields[5] != "lo":
                            add(":".join(fields[0][i : i + 4] for i in range(0, 32, 4)))
            except OSError:
                pass
        if self._include_loopback:
            add("127.0.0.1")
        return found

    async def resolve(self, host: str) -> str:
        """The IPv4 address of a host name (for STUN servers given by name)."""
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_DGRAM)
        return str(infos[0][4][0])
