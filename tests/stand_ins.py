"""The names the stand-ins of a test listen under (fake_alerts.py), and nothing else: conftest reads it for every test."""

from __future__ import annotations

import itertools

STAND_INS: dict[str, int] = {}  # name -> port on 127.0.0.1, for this test
_numbers = itertools.count(1)


def stand_in(port: int) -> str:
    """A name of its own for a stand-in listening on this port of 127.0.0.1."""
    name = f"stand-in-{next(_numbers)}.invalid"
    STAND_INS[name] = port
    return name
