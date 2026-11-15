"""Linking an application to somebody's account without a login inside it (protocol section 11.5)."""

from __future__ import annotations

import asyncio
import inspect
import time
from dataclasses import dataclass
from typing import Awaitable, Callable, Optional, Union

from .api import PlatformApi
from .errors import ConnectivitizerError, ErrorCodes
from .platform import Platform


@dataclass
class LinkPrompt:
    url: str
    """The page of the web app to send the person to, with the code already filled in."""
    page: str
    """The same page without the code, for showing it next to the code."""
    code: str
    """The short code the page must show, e.g. ``KQTR-7MPL``."""
    expires_in: int
    """Seconds the person has to approve."""


@dataclass
class LinkedApp:
    """What a linked application holds from then on. The API key exists only here: store it where only the
    application can read it."""

    api_key: str
    workspace_id: str
    workspace_name: str
    client: str
    """The name the application got in the workspace."""
    credential_id: str

    def __repr__(self) -> str:  # never print the key itself
        return f"LinkedApp(workspace_name={self.workspace_name!r}, client={self.client!r})"


async def link_app(
    api_url: str,
    client: str,
    on_prompt: Callable[[LinkPrompt], Union[None, Awaitable[None]]],
    platform_name: Optional[str] = None,
    cancelled: Optional[asyncio.Event] = None,
    platform: Optional[Platform] = None,
) -> LinkedApp:
    """Links this application to an account: the person signs in to the web app in a browser and approves,
    and the application receives an API key of its own. Raises ``LINK_DENIED`` when the person refused, and
    ``LINK_EXPIRED`` when nobody decided in time or ``cancelled`` was set.

    ::

        linked = await link_app(api_url, "Report service", lambda p: print(f"Open {p.url} and confirm {p.code}"))
    """
    runtime = platform or Platform()
    api = PlatformApi(api_url, runtime)
    link = await api.start_link(client, platform_name or runtime.description)
    prompted = on_prompt(LinkPrompt(link["verificationUrlComplete"], link["verificationUrl"], link["userCode"], int(link["expiresIn"])))
    if inspect.isawaitable(prompted):
        await prompted

    deadline = time.monotonic() + int(link["expiresIn"])
    interval = min(max(int(link.get("interval", 5)), 1), 30)
    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        if cancelled is not None and cancelled.is_set():
            raise ConnectivitizerError(ErrorCodes.LINK_EXPIRED, "Linking was cancelled.")
        answer = await api.poll_link(link["deviceCode"])
        if answer.get("status") == "approved" and answer.get("apiKey"):
            return LinkedApp(
                api_key=answer["apiKey"],
                workspace_id=answer.get("workspaceId", ""),
                workspace_name=answer.get("workspaceName", ""),
                client=answer.get("client") or client,
                credential_id=answer.get("credentialId", ""),
            )
    raise ConnectivitizerError(ErrorCodes.LINK_EXPIRED, "Nobody approved the link in time.")
