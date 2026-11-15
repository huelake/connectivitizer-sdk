"""Base64 as the protocol writes it: both alphabets accepted, with or without padding."""

from __future__ import annotations

import base64
import binascii
import re

_BASE64 = re.compile(r"^[A-Za-z0-9+/\-_]*={0,2}$")


def b64decode(text: str) -> bytes:
    """Decodes standard or URL-safe base64, padded or not. Raises ValueError on anything else."""
    if not _BASE64.match(text) or len(text.rstrip("=")) % 4 == 1:
        raise ValueError("not base64")
    body = text.rstrip("=").replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(body + "=" * (-len(body) % 4), validate=True)
    except binascii.Error as error:
        raise ValueError("not base64") from error


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64url(data: bytes) -> str:
    """URL-safe base64 without padding."""
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")
