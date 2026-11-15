"""``python -m connectivitizer keygen`` (or ``connectivitizer keygen``): prints a new shared key."""

from __future__ import annotations

import sys

from .noise import generate_shared_key


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] == ["keygen"]:
        print(generate_shared_key())
        print("Put the same key on the device and in the application. It is never sent to Connectivitizer.", file=sys.stderr)
        return 0
    print("usage: connectivitizer keygen     prints a new shared key (czs_...)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
