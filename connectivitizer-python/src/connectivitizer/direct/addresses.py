"""Hosts and UDP candidates (protocol section 6.4), in the one spelling every implementation compares."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class UdpAddress:
    host: str
    port: int


def normalize_host(text: str) -> Optional[str]:
    """A host as the SDK keeps it: IPv4 dotted, IPv6 canonical (RFC 5952), and an IPv4-mapped IPv6 address
    (what a dual-stack socket reports for an IPv4 peer) as the IPv4 address it stands for. None when the
    text is not an IP address."""
    try:
        address = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return None
    if isinstance(address, ipaddress.IPv6Address):
        if address.ipv4_mapped is not None:
            return str(address.ipv4_mapped)
        return address.compressed
    return str(address)


def is_ipv6(host: str) -> bool:
    return ":" in host


def is_global_ipv6(host: str) -> bool:
    """A global unicast IPv6 address (2000::/3): reachable from elsewhere without NAT in between."""
    if not is_ipv6(host):
        return False
    try:
        return (ipaddress.IPv6Address(host).packed[0] & 0xE0) == 0x20
    except ValueError:
        return False


def format_address(address: UdpAddress) -> str:
    """``a.b.c.d:port`` or ``[address]:port``, as written in candidate lists."""
    return f"[{address.host}]:{address.port}" if is_ipv6(address.host) else f"{address.host}:{address.port}"


_BRACKETED = re.compile(r"^\[([^\]]+)\]:(\d{1,5})$")
_DOTTED = re.compile(r"^([\d.]+):(\d{1,5})$")


def parse_address(text: str) -> Optional[UdpAddress]:
    """Reads a candidate (``a.b.c.d:port`` or ``[address]:port``); None when it is neither."""
    match = _BRACKETED.match(text) or _DOTTED.match(text)
    if not match:
        return None
    port = int(match.group(2))
    host = normalize_host(match.group(1))
    if host is None or port < 1 or port > 65535:
        return None
    return UdpAddress(host, port)


def usable_candidate(address: UdpAddress) -> bool:
    """A peer candidate this endpoint can send to: IPv4, or IPv6 that is neither link-local, multicast nor unspecified."""
    if not is_ipv6(address.host):
        return True
    packed = ipaddress.IPv6Address(address.host).packed
    link_local = packed[0] == 0xFE and (packed[1] & 0xC0) == 0x80
    return not link_local and packed[0] != 0xFF and any(packed)
