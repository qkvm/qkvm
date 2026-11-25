"""The Compose files of qKVM beside Tailscale and beside NetBird: shown whole in the guide, no key of anybody's in them,
qKVM's container as locked down as in docker-compose.yml, and what qKVM looks for where the files put it.

(Read as text, line by line: there is no reader of YAML among qKVM's libraries. `docker compose config` reads both as
valid; that was looked at by hand when they were written.)
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.conftest import THE_COMPUTERS_OWN

APP = Path(__file__).resolve().parent.parent
GUIDE = (APP / "GUIDE.md").read_text(encoding="utf-8")
FILES = ("docker-compose.tailscale.yml", "docker-compose.netbird.yml")
IMAGE_ACCOUNT = re.search(r"useradd --uid (\d+)", (APP / "Dockerfile").read_text(encoding="utf-8"))


def text(name: str) -> str:
    return (APP / name).read_text(encoding="utf-8")


def service(name: str, which: str) -> str:
    """The lines of one service of a Compose file, up to the next one (or the volumes)."""
    body = text(name).split("\nservices:\n", 1)[1]
    found = re.search(rf"(?ms)^  {which}:\n(.*?)(?=^  [a-z]+:\n|^volumes:)", body)
    assert found, f"{name} has no service {which}"
    return found.group(1)


def setting_lines(block: str) -> list[str]:
    """The lines that say something, without the comments."""
    return [line for line in block.splitlines() if line.strip() and not line.strip().startswith("#")]


@pytest.mark.parametrize("name", FILES)
def test_each_is_shown_whole_in_the_guide(name: str) -> None:
    shown = re.findall(r"```yaml\n(.*?)```", GUIDE.split("\n## Over Tailscale or NetBird\n", 1)[1].split("\n## ", 1)[0], re.S)
    assert text(name) in shown


@pytest.mark.parametrize("name", FILES)
def test_no_key_or_token_of_anybody_is_in_it(name: str) -> None:
    said = text(name)
    assert not re.search(r"tskey-[a-z]+-[A-Za-z0-9]{4,}", said), "a Tailscale auth key"
    assert not re.search(r"nbp_[A-Za-z0-9]{8,}", said), "a NetBird token"
    assert not re.search(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", said), "a NetBird setup key"
    # Taken from the environment (a .env file beside it), and empty where it is not there.
    keys = re.findall(r"^\s+(TS_AUTHKEY|NB_SETUP_KEY): (.+)$", said, re.M)
    assert keys and all(value == f"${{{key}:-}}" for key, value in keys)


@pytest.mark.parametrize("name", FILES)
def test_qkvms_container_is_as_locked_down_as_in_the_plain_file(name: str) -> None:
    plain = setting_lines(service("docker-compose.yml", "qkvm"))
    beside = setting_lines(service(name, "qkvm"))
    for line in ("    read_only: true", "      - ALL", "      - no-new-privileges:true", "      - qkvm-data:/data", "      - qkvm-keys:/keys", "      - /tmp"):
        assert line in plain and line in beside, line
    assert next(line for line in beside if line.startswith("    command:")).count('"--https", "--setup-code"') == 1
    assert not any(line.strip().startswith(("ports:", "privileged:", "cap_add:")) for line in beside)


@pytest.mark.parametrize(("name", "tailnet_service"), [("docker-compose.tailscale.yml", "tailscale"), ("docker-compose.netbird.yml", "netbird")])
def test_qkvm_shares_the_tailnets_network_and_nothing_is_published_on_this_machines(name: str, tailnet_service: str) -> None:
    assert f"    network_mode: service:{tailnet_service}" in setting_lines(service(name, "qkvm"))
    assert not any(line.strip().startswith("ports:") for line in setting_lines(service(name, tailnet_service)))


def test_beside_tailscale_qkvm_finds_its_local_api_and_may_ask_for_its_certificate() -> None:
    tailscale, qkvm = setting_lines(service(FILES[0], "tailscale")), setting_lines(service(FILES[0], "qkvm"))
    # Where the program looks for it, as the program has it (every test's own tailnet.SOCKETS is empty: conftest).
    socket = THE_COMPUTERS_OWN["sockets"][0]
    folder = socket.rsplit("/", 1)[0]
    assert f"      TS_SOCKET: {socket}" in tailscale
    assert f"      - tailscale-socket:{folder}" in tailscale
    assert f"      - tailscale-socket:{folder}:ro" in qkvm  # (read-only: a socket is spoken to all the same)
    assert IMAGE_ACCOUNT and f'      TS_PERMIT_CERT_UID: "{IMAGE_ACCOUNT.group(1)}"' in tailscale
    assert '"--tls-tailscale"' in next(line for line in qkvm if line.startswith("    command:"))
    assert '      TS_USERSPACE: "false"' in tailscale  # (a network of its own, which qKVM's container shares: not a proxy)


@pytest.mark.parametrize("name", FILES)
def test_every_image_but_qkvms_own_is_pinned_by_its_digest_and_says_its_version(name: str) -> None:
    # The containers beside qKVM's hold the tailnet's identity of the machine and hand over the key of its certificate: what
    # runs there is the image looked at when the file was written, not whatever a tag points to the day it is pulled.
    lines = text(name).splitlines()
    images = [(at, line.split("image:", 1)[1].strip()) for at, line in enumerate(lines) if line.strip().startswith("image:")]
    assert len(images) == 2
    plain = re.search(r"(?m)^\s+image: (\S+)$", text("docker-compose.yml"))
    for at, image in images:
        if image == (plain.group(1) if plain else None):
            continue  # qKVM's own, as docker-compose.yml takes it (updated by docker compose pull)
        pinned = re.fullmatch(r"([a-z0-9]+(?:/[a-z0-9._-]+)+):(v?[0-9]+(?:\.[0-9]+){2})@sha256:[0-9a-f]{64}", image)
        assert pinned, f"{image} is not pinned by a digest, with its version as its tag"
        assert pinned.group(2) in lines[at - 1] and lines[at - 1].strip().startswith("#"), "the line above it says the version"


@pytest.mark.parametrize("name", FILES)
def test_funnel_and_serve_are_never_set_up(name: str) -> None:
    lines = "\n".join(setting_lines(text(name))).lower()
    assert "funnel" not in lines and "ts_serve_config" not in lines
