"""An application that links itself to an account, for the interoperability tests.

  CZ_API_URL, CZ_CLIENT (default "Python app")

It prints "PROMPT <json>" when the person has to approve in the web app, and at the end "LINKED <json>"
with the API key it received, or "FAILED <code>".
"""

from __future__ import annotations

import asyncio
import json
import os
import sys

from connectivitizer import ConnectivitizerError, link_app


def say(line: str) -> None:
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


async def main() -> int:
    try:
        linked = await link_app(
            os.environ["CZ_API_URL"],
            os.environ.get("CZ_CLIENT", "Python app"),
            lambda prompt: say("PROMPT " + json.dumps({"url": prompt.url, "page": prompt.page, "code": prompt.code, "expiresIn": prompt.expires_in})),
        )
        say("LINKED " + json.dumps({"apiKey": linked.api_key, "workspaceId": linked.workspace_id, "workspaceName": linked.workspace_name, "client": linked.client, "credentialId": linked.credential_id}))
        return 0
    except ConnectivitizerError as error:
        say(f"FAILED {error.code}")
        return 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
