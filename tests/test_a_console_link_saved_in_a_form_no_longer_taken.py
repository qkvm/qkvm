"""A console link 0.2.0 saved in a form 0.2.1 no longer takes (0.3.0, section 5).

0.2.0 saved a console link as typed. One whose host is numbers in a form a browser reads as another host than Python does
(127.1, 2130706433) is refused since 0.2.1 (I2 of its review: the page and the server are to read the same host from it).
The tile's edit sends the saved link back, and was refused for it until the link was written again: a new name, group or
password could not be saved, and what the refusal named was the link alone.
"""

from __future__ import annotations

from pathlib import Path

from tests.fake_kvm import FakeKvm, FakeState
from tests.test_wall import add, wall

OLD = "http://127.1:8443/"  # (as 0.2.0 saved it)


def test_the_rest_of_an_edit_is_saved_and_the_link_kept_as_it_was_saved(tmp_path: Path) -> None:
    # Sent back unchanged, the link is kept as it was saved, and the reply says so: no way into a console is made out to
    # such a host (security.shares_our_name takes a host that looks like numbers and cannot be read so for the wall's own),
    # and the page reads it as the browser does.
    fake = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            store = client.core.store  # type: ignore[attr-defined]
            store.device(device).open_url = OLD
            edited = client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Renamed", "open_url": OLD})
            assert edited.status_code == 200, edited.text
            assert (store.device(device).name, store.device(device).open_url) == ("Renamed", OLD)
            assert "console link" in edited.json()["note"], edited.json()
    finally:
        fake.stop()


def test_a_link_written_into_such_a_form_is_refused_by_its_name(tmp_path: Path) -> None:
    fake = FakeKvm(FakeState()).start()
    try:
        with wall(tmp_path) as client:
            device = add(client, fake.url)
            store = client.core.store  # type: ignore[attr-defined]
            store.device(device).open_url = OLD
            for changed in ("http://2130706433/", "https://0x7f.0.0.1/"):
                reply = client.put(f"/api/v1/devices/{device}", json={"url": fake.url, "name": "Renamed", "open_url": changed})
                assert (reply.status_code, reply.json()["code"]) == (422, "invalid"), reply.text
                assert reply.json()["message"].startswith("The console link"), reply.json()
            assert (store.device(device).name, store.device(device).open_url) != ("Renamed", changed)
    finally:
        fake.stop()
