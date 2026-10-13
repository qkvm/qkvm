"""What is running: this program's version and licence, and the libraries it stands on, each with its own."""

from __future__ import annotations

import platform
import sys
from importlib import metadata

from ._version import __version__

LICENCE = "AGPL-3.0-only"  # as in pyproject.toml
# The libraries QKVM is built on and brings along; the last two only where JetKVM support is installed.
LIBRARIES = ("fastapi", "starlette", "uvicorn", "pydantic", "httpx", "httpcore", "h11", "anyio", "websockets", "cryptography", "aiortc", "av")


def _licence(said: metadata.PackageMetadata) -> str:
    """A library's licence, by name: as it states it, or as it files itself; never the text of it."""
    stated = said.get("License-Expression") or ""
    if not stated:
        filed = [entry.rsplit(" :: ", 1)[-1] for entry in said.get_all("Classifier") or [] if entry.startswith("License :: ")]
        stated = ", ".join(dict.fromkeys(filed))
    if not stated:
        first = (said.get("License") or "").strip().splitlines()[:1]
        stated = first[0].strip() if first and len(first[0]) <= 60 else ""  # some put the whole licence in that field
    return stated[:80] or "see the library"


def libraries() -> list[dict[str, str]]:
    """The installed ones of LIBRARIES: name, version, licence. Reads the disk: not for the thread that serves everybody."""
    found = []
    for name in LIBRARIES:
        try:
            said = metadata.metadata(name)
        except metadata.PackageNotFoundError:
            continue
        found.append({"name": said.get("Name") or name, "version": said.get("Version") or "", "licence": _licence(said)})
    return found


def running() -> dict[str, object]:
    """Everything an admin is shown under About."""
    return {
        "version": __version__,
        "licence": LICENCE,
        "python": platform.python_version(),
        "system": f"{platform.system()} {platform.machine()}".strip() or sys.platform,
        "libraries": libraries(),
    }
