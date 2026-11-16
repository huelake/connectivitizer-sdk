"""Connectivitizer for Python: reach a service on a device behind NAT, end-to-end encrypted, peer to peer
when the networks allow it and through the relay otherwise; and run a device that exposes local services.

Calling side::

    from connectivitizer import Client

    async with Client(api_url, api_key="czk_...", shared_key="czs_...") as client:
        session = await client.connect("living-room-lamp", ["api"])
        response = await session.fetch("api", "/state")
        print(response.status, await response.json())
        print(session.info.mode, session.info.end_to_end_encrypted)

Device side::

    from connectivitizer import Agent

    agent = Agent(api_url, device_key="czd_...", name="nas", shared_key="czs_...", services={"api": "127.0.0.1:8080"})
    await agent.run()
"""

from .agent import ConnectivitizerAgent, Service
from .api import ReachableDevice, TokenResponse
from .client import ConnectivitizerClient
from .direct.attempt import DirectFailureReasons
from .errors import ConnectivitizerError, ErrorCodes
from .grants import Capabilities, ConnectionModes, E2eMethods
from .http import TunnelResponse
from .link import LinkedApp, LinkPrompt, link_app
from .noise import SharedKey, generate_shared_key, parse_shared_key
from .platform import Platform
from .session import ConnectionInfo, PeerInfo, TunnelSession
from .streams import ByteStream
from .websocket import StreamWebSocket

Client = ConnectivitizerClient
Agent = ConnectivitizerAgent


def new_shared_key() -> str:
    """A new shared key (``czs_...``) from the system's random source. Put the same key on both endpoints."""
    return generate_shared_key()


__version__ = "1.0.50"

__all__ = [
    "Agent",
    "ByteStream",
    "Capabilities",
    "Client",
    "ConnectionInfo",
    "ConnectionModes",
    "ConnectivitizerAgent",
    "ConnectivitizerClient",
    "ConnectivitizerError",
    "DirectFailureReasons",
    "E2eMethods",
    "ErrorCodes",
    "LinkPrompt",
    "LinkedApp",
    "PeerInfo",
    "Platform",
    "ReachableDevice",
    "Service",
    "SharedKey",
    "StreamWebSocket",
    "TokenResponse",
    "TunnelResponse",
    "TunnelSession",
    "generate_shared_key",
    "link_app",
    "new_shared_key",
    "parse_shared_key",
]
