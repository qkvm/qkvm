"""A change of a machine's virtual media is refused where its tile's machine has moved since the images were listed.

Found by the desktop app's wave-1 review (the desktop app's finding 21): the media routes act on a machine by its tile's id,
and the page's Media box stays open across an edit of that tile. A box opened for KVM A whose tile was then edited to KVM
B's address sent its mount, its unmount, its deletion or its upload to B, wherever B had an image of the same name. Each
change now carries what the box was shown (`listed`, GET .../media's mark of the machine it was made of) and is refused
where that is no longer so: 409 `moved`, and nothing is asked of either machine. A client that sends nothing of it (one
before 0.3.2, as the Desktop App 0.1.x) is served as before.
"""

from __future__ import annotations

import dataclasses
import json
import re
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import httpx
import pytest

from qkvm import kvm, server
from qkvm.kvm import MEDIA_NOTES, DeviceSpec
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Wall
from tests.test_virtual_media_on_a_kvm import images, pieces
from tests.test_wall import wait_until

DEBIAN, ALPINE, ONLY_THERE = "debian-13.iso", "alpine-3.21.iso", "only-on-the-second.iso"
MOUNTED = {"image": DEBIAN, "connected": True, "cdrom": True, "rw": False}
CHANGES = ["mount", "unmount", "delete", "upload"]


@pytest.fixture(autouse=True)
def forgotten(monkeypatch: pytest.MonkeyPatch) -> None:
    MEDIA_NOTES.mounted.clear()
    MEDIA_NOTES.hashes.clear()
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "MSD_EVERY", 0)


@pytest.fixture
def two_kvms() -> Iterator[tuple[FakeKvm, FakeKvm]]:
    """Two kvmd KVMs with their drives on, and images of the same names: the second one has one more."""
    first = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700_000_000, ALPINE: 62_000_000}))).start()
    second = FakeKvm(FakeState(msd=True, msd_images=images({DEBIAN: 700_000_000, ALPINE: 62_000_000, ONLY_THERE: 1_000_000}))).start()
    yield first, second
    first.stop()
    second.stop()


def media(device: str) -> str:
    return f"/api/v1/devices/{device}/media"


def listing(admin: httpx.Client, device: str, *names: str) -> dict[str, Any]:
    """What a Media box is shown: GET .../media, once the images named are in it."""
    shown: dict[str, Any] = {}

    def has_them() -> bool:
        admin.get("/api/v1/status")  # (a look at it, which finds what its drive offers)
        reply = admin.get(media(device))
        shown.update(reply.json() if reply.status_code == 200 else {"images": []})
        return reply.status_code == 200 and set(names) <= {image["id"] for image in shown["images"]}

    wait_until(has_them, f"the machine's images were never listed with {names}", 20)
    return shown


def upload_refused_or_not(live: Wall, admin: httpx.Client, device: str, query: dict[str, str], size: int) -> tuple[int, dict[str, Any]]:
    """An upload whose headers alone are sent until the wall answers (refused, it answers before it reads a byte; sent
    with its bytes, a refused one closes the connection under a sender still sending, which may lose the answer), then its
    bytes where it waits for them."""
    cookie = "; ".join(f"{key}={value}" for key, value in admin.cookies.items())
    with socket.create_connection(("127.0.0.1", live.port), timeout=30) as sock:
        sock.sendall(f"POST {media(device)}/upload?{urlencode(query)} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {size}\r\nX-QKVM: 1\r\nCookie: {cookie}\r\n\r\n".encode())
        sock.settimeout(5.0)
        answer = b""
        try:
            answer = sock.recv(65536)
        except TimeoutError:
            for piece in pieces(size):  # (nothing came back: the wall reads the image)
                sock.sendall(piece)
        sock.settimeout(60)
        while True:
            head, gap, body = answer.partition(b"\r\n\r\n")
            said = re.search(rb"(?im)^content-length:\s*(\d+)", head) if gap else None
            if said is not None and len(body) >= int(said.group(1)):
                return int(head.split()[1]), json.loads(body[: int(said.group(1))])
            came = sock.recv(65536)
            assert came, answer
            answer += came


def change(live: Wall, admin: httpx.Client, device: str, what: str, listed: str | None) -> tuple[int, dict[str, Any]]:
    """One change of the machine's media, as a box sends it (`listed`: as it was shown; None: as a client before 0.3.2)."""
    said = {"machine": "glkvm", **({"listed": listed} if listed is not None else {})}
    if what == "upload":
        return upload_refused_or_not(live, admin, device, {"name": "new.iso", **said}, 1_000_000)
    path, image = {"mount": ("", DEBIAN), "unmount": ("/unmount", DEBIAN), "delete": ("/delete", ALPINE)}[what]
    reply = admin.post(media(device) + path, json={"image": image, **said}, timeout=60)
    return reply.status_code, reply.json()


def as_it_was(fake: FakeKvm) -> tuple[Any, ...]:
    """All of a KVM's drive and storage that a change could have touched."""
    return dict(fake.state.msd_drive), {name: dict(image) for name, image in fake.state.msd_images.items()}, list(fake.state.msd_calls), list(fake.state.msd_writes)


@pytest.mark.parametrize("what", CHANGES)
def test_a_change_listed_for_one_kvm_is_refused_once_its_tile_is_at_another(tmp_path: Path, two_kvms: tuple[FakeKvm, FakeKvm], what: str) -> None:
    first, second = two_kvms
    if what == "unmount":
        for fake in (first, second):
            fake.state.msd_drive = dict(MOUNTED)  # (the same image in both drives)
    with Wall(tmp_path) as live:
        admin = live.browser()
        device = live.add(admin, first.url, name="glkvm")
        shown = listing(admin, device, DEBIAN, ALPINE)
        assert re.fullmatch(r"[0-9a-f]{32}", shown["listed"]), shown.get("listed")
        # Its box still open, the tile is edited to the other KVM's address, by its name as it was.
        edited = admin.put(f"/api/v1/devices/{device}", json={"name": "glkvm", "url": second.url, "password": "secret"})
        assert edited.status_code == 200, edited.text
        now = listing(admin, device, ONLY_THERE)  # (it speaks to the second one from here on)
        assert now["listed"] != shown["listed"]
        before = as_it_was(first), as_it_was(second)
        status, said = change(live, admin, device, what, shown["listed"])
        assert (status, said.get("code")) == (409, "moved"), f"a {what} chosen from the first KVM's list: {status} {said}"
        assert said["message"].startswith("glkvm is not the machine its images were listed for any more") and "Nothing was" in said["message"]
        assert (as_it_was(first), as_it_was(second)) == before, f"a {what} chosen from the first KVM's list was done all the same"
        # A list made anew, of what the tile is now, is taken: the box that lists again does what it is asked, there.
        status, said = change(live, admin, device, what, now["listed"])
        assert status == 200, said
        assert as_it_was(second) != before[1] and as_it_was(first) == before[0]


@pytest.mark.parametrize("what", CHANGES)
def test_a_client_that_sends_no_list_is_served_as_before(tmp_path: Path, two_kvms: tuple[FakeKvm, FakeKvm], what: str) -> None:
    # (Within v1 nothing is taken away: the Desktop App 0.1.x, and any script written against 0.3.0 or 0.3.1, send no
    # `listed`. Their change is done on the machine the tile is at when it comes, as it was.)
    first, second = two_kvms
    if what == "unmount":
        second.state.msd_drive = dict(MOUNTED)
    with Wall(tmp_path) as live:
        admin = live.browser()
        device = live.add(admin, first.url, name="glkvm")
        listing(admin, device, DEBIAN)
        assert admin.put(f"/api/v1/devices/{device}", json={"name": "glkvm", "url": second.url, "password": "secret"}).status_code == 200
        listing(admin, device, ONLY_THERE)
        before = as_it_was(second)
        status, said = change(live, admin, device, what, None)
        assert status == 200, said
        assert as_it_was(second) != before


def test_a_list_stays_good_across_a_look_and_an_edit_that_leaves_the_machine_as_it_was(tmp_path: Path, two_kvms: tuple[FakeKvm, FakeKvm]) -> None:
    first, _ = two_kvms
    with Wall(tmp_path) as live:
        admin = live.browser()
        device = live.add(admin, first.url, name="glkvm")
        shown = listing(admin, device, DEBIAN)
        # The tile put in a group, and asked again since: the same machine at the same address.
        assert admin.put(f"/api/v1/devices/{device}", json={"name": "glkvm", "url": first.url, "group": "rack 4"}).status_code == 200
        assert listing(admin, device, DEBIAN)["listed"] == shown["listed"]
        assert change(live, admin, device, "mount", shown["listed"])[0] == 200
        assert change(live, admin, device, "unmount", shown["listed"])[0] == 200
        assert first.state.msd_drive["connected"] is False and len(first.state.msd_calls) >= 2


PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n"


def test_the_mark_of_a_list_is_of_the_address_and_the_machine_there_and_of_nothing_else() -> None:
    spec = DeviceSpec(id="ab12", name="glkvm", base_url="https://192.0.2.10", username="admin", password="a password", cert_pem=PEM)
    mark = server.media_listed("ab12", spec)
    assert re.fullmatch(r"[0-9a-f]{32}", mark)
    # Another address, kind, check or certificate, another number of the machine there, another identity, another tile.
    for other in (
        {"base_url": "https://192.0.2.11"}, {"base_url": "https://192.0.2.10:8443"}, {"kind": "jetkvm"}, {"tls": "insecure"},
        {"cert_pem": None}, {"cert_pem": PEM.replace("fake", "else")}, {"machine": "amt:" + "1" * 32}, {"ident": "own:ab12"},
    ):  # fmt: skip
        assert server.media_listed("ab12", dataclasses.replace(spec, **other)) != mark, other
    assert server.media_listed("cd34", spec) != mark
    # What does not make it another machine: its name, the account and password it is signed in with, how its tile is set.
    for same in ({"name": "renamed"}, {"username": "root"}, {"password": "another"}, {"fingerbot_strength": "light"}, {"amt_view": "live"}):
        assert server.media_listed("ab12", dataclasses.replace(spec, **same)) == mark, same
