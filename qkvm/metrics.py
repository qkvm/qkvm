"""What a monitoring system can collect from QKVM: the Prometheus text format, at /metrics.

Off until an admin makes a token for it (Settings -> Metrics). The token is what a collector sends
(`Authorization: Bearer ...`); QKVM keeps only its hash. What is told is what the wall shows: how many
devices are in which state, and for each one whether it answers, whether it has a picture, when it was
last heard from, and how warm it is. Nothing that could be used to reach or to operate a device.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable
from typing import Any

from ._version import __version__

STATES = ("online", "no_signal", "offline", "auth", "error", "busy", "connecting")  # every state a tile can be in
ANSWERING = ("online", "no_signal", "auth", "busy")  # states in which the device itself is there
CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def new_token() -> tuple[str, str]:
    """A token to give to the collector, and what is kept of it: enough to recognise it, not to use it."""
    token = "qkvm_" + secrets.token_urlsafe(32)
    return token, kept(token)


def kept(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def label(value: object) -> str:
    """A label's value as the format wants it written: backslash, quote and line break escaped."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(*, started: float, unlocked: bool, sessions: int, devices: Iterable[tuple[Any, dict[str, Any] | None]], update_available: bool) -> str:
    """Everything, as text. `devices`: each saved device with its status, or with None where that is not known."""
    lines: list[str] = []

    def metric(name: str, kind: str, about: str, values: Iterable[tuple[str, float]]) -> None:
        lines.append(f"# HELP {name} {about}")
        lines.append(f"# TYPE {name} {kind}")
        lines.extend(f"{name}{labels} {value:g}" if isinstance(value, float) and not value.is_integer() else f"{name}{labels} {int(value)}" for labels, value in values)

    devices = list(devices)
    metric("qkvm_info", "gauge", "The version of QKVM that is running.", [(f'{{version="{label(__version__)}"}}', 1)])
    metric("qkvm_start_time_seconds", "gauge", "When this copy of QKVM was started, in seconds since 1970.", [("", int(started))])
    metric("qkvm_unlocked", "gauge", "1 while QKVM can talk to its devices: somebody has signed in since it was started.", [("", int(unlocked))])
    metric("qkvm_sessions", "gauge", "Browsers that are signed in.", [("", sessions)])
    metric("qkvm_update_available", "gauge", "1 when a newer version of QKVM has been published.", [("", int(update_available))])
    metric("qkvm_devices_configured", "gauge", "Devices on the wall.", [("", len(devices))])

    known = [(record, status) for record, status in devices if status is not None]
    tally = dict.fromkeys(STATES, 0)
    for _, status in known:
        if status.get("state") in tally:
            tally[status["state"]] += 1
    metric("qkvm_devices", "gauge", "Devices by the state their tile shows.", [(f'{{state="{state}"}}', count) for state, count in tally.items()])

    def named(record: Any) -> str:
        # The id as well as the name: two devices may be called the same, and no two lines may claim to be one thing.
        return f'id="{label(record.id)}",device="{label(record.name)}",kind="{label(record.kind)}",group="{label(record.group)}"'

    settled = [(record, status) for record, status in known if status.get("state") != "connecting"]
    metric("qkvm_device_up", "gauge", "1 while the device answers, 0 while it does not.", [
        (f"{{{named(record)}}}", int(status.get("state") in ANSWERING)) for record, status in settled
    ])  # fmt: skip
    metric("qkvm_device_picture", "gauge", "1 while the device shows a picture (for a server: while it is switched on).", [
        (f"{{{named(record)}}}", int(status.get("state") == "online")) for record, status in settled
    ])  # fmt: skip
    metric("qkvm_device_last_seen_seconds", "gauge", "Seconds since the device last answered.", [
        (f"{{{named(record)}}}", float(status["last_seen_ago"])) for record, status in known if isinstance(status.get("last_seen_ago"), (int, float))
    ])  # fmt: skip

    readings: dict[str, float] = {}  # by what they are called: a controller with two sensors of one name gets one line
    healthy: list[tuple[str, float]] = []
    for record, status in known:
        own = (status.get("health") or {}).get("temp")
        if isinstance(own, (int, float)) and not isinstance(own, bool):
            readings[f'{{{named(record)},sensor="device"}}'] = float(own)
        server = status.get("server") or {}
        for sensor in server.get("temperatures") or []:
            celsius = sensor.get("celsius")
            if isinstance(celsius, (int, float)) and not isinstance(celsius, bool):
                readings.setdefault(f'{{{named(record)},sensor="{label(sensor.get("name") or "")}"}}', float(celsius))
        if server.get("health"):
            healthy.append((f"{{{named(record)}}}", int(server["health"] == "OK")))
    metric("qkvm_device_temperature_celsius", "gauge", "Temperatures a device reports: its own, and for a server each of its sensors.", readings.items())
    metric("qkvm_server_healthy", "gauge", "1 while a server's management controller calls it healthy.", healthy)
    return "\n".join(lines) + "\n"

