"""A wall of 0.3.2 updated to 0.4.0: its one alert address is its first destination, sent to as before.

0.3.2 kept one address under "alerts" (sealed by the vault for "alerts:webhook") and how its service wanted to be spoken
to ("format"). 0.4.0 keeps a list of destinations; the address is carried over by the program itself, as it was sealed,
and GET/PUT /api/v1/alerts keep their fields and meaning, speaking of that first destination.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from qkvm import alerts, kvm, update, vault
from qkvm.store import FROM_0_3_2, Store, sealed_for
from tests.settings_file import settings_text
from tests.test_alerts import Inbox
from tests.test_wall import wall


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(alerts, "CHECK_EVERY", 0.05)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


def as_0_3_2(data: Path, alerts_part: dict[str, Any]) -> None:
    """Make the settings of a wall that ran in `data` what 0.3.2 wrote: no destinations, its alert settings as given."""
    store = Store(data / "qkvm.json")
    document = store.snapshot()
    document.pop("destinations", None)
    document["alerts"] = {**{k: v for k, v in document["alerts"].items()}, **alerts_part}
    store.write(document)


def written(data: Path) -> dict[str, Any]:
    return dict(json.loads(settings_text(data / "qkvm.json")))


def test_the_address_of_0_3_2_is_the_first_destination_and_is_sent_to_as_before(tmp_path: Path) -> None:
    inbox = Inbox()
    try:
        with wall(tmp_path) as admin:
            sealed = admin.core.vault.encrypt(inbox.url, "alerts:webhook")  # type: ignore[attr-defined]  # as 0.3.2 sealed it
        as_0_3_2(tmp_path, {"enabled": True, "webhook": sealed, "format": "ntfy", "offline": False, "recovered": True})
        with wall(tmp_path) as admin:
            shown = admin.get("/api/v1/alerts").json()
            assert (shown["enabled"], shown["has_webhook"], shown["format"], shown["offline"]) == (True, True, "ntfy", False)
            [first] = admin.core.store.destinations  # type: ignore[attr-defined]
            assert (first.id, first.kind, first.secret, first.private) == (FROM_0_3_2, "ntfy", sealed, True)
            assert sealed_for(first.id) == "alerts:webhook"
            # Sent to as 0.3.2 sent it: ntfy's way.
            assert admin.post("/api/v1/alerts/test").status_code == 200
            arrived = inbox.received[-1]
            assert arrived["headers"]["Title"] == "Test alert from qKVM" and arrived["body"] == b"If you can read this, alerts will reach you."
        # Written in the shape of 0.4.0 at the first save; and, for as long as it is the address of 0.3.2 unchanged, in the
        # place 0.3.2 reads it from as well (the review of 0.4.0's first wave, M2: a wall that went back to 0.3.2 found
        # none there, and went on with alerts on and nowhere to send them).
        saved = written(tmp_path)
        assert (saved["alerts"]["webhook"], saved["alerts"]["format"]) == (sealed, "ntfy")
        assert saved["destinations"][0]["id"] == FROM_0_3_2 and saved["destinations"][0]["secret"] == sealed
        assert inbox.url not in settings_text(tmp_path / "qkvm.json")
    finally:
        inbox.close()


@pytest.mark.parametrize(
    "said, kind, form",
    [
        ({"format": "json"}, "webhook", "json"),
        ({"format": "auto"}, "webhook", "auto"),
        ({"format": "slack"}, "slack", None),
        ({"format": "discord"}, "discord", None),
        ({"format": "carrier-pigeon"}, "webhook", "auto"),  # a hand's edit: what 0.3.2 took it for
        ({}, "webhook", "auto"),
    ],
)
def test_each_format_of_0_3_2_is_the_kind_it_spoke_as(tmp_path: Path, said: dict[str, Any], kind: str, form: str | None) -> None:
    store = Store(tmp_path / "qkvm.json")
    document = store.snapshot()
    document.pop("destinations")
    document["alerts"].update({"webhook": {"nonce": "AAAA", "data": "AAAA"}, **said})
    store.write(document)
    [first] = Store(tmp_path / "qkvm.json").destinations
    assert (first.kind, first.config.get("format")) == (kind, form)


def test_no_address_in_0_3_2_is_no_destination_and_one_removed_stays_removed(tmp_path: Path) -> None:
    store = Store(tmp_path / "qkvm.json")
    document = store.snapshot()
    document.pop("destinations")
    document["alerts"].update({"webhook": None, "format": "ntfy"})
    store.write(document)
    assert Store(tmp_path / "qkvm.json").destinations == []
    # A file of 0.4.0 whose destinations were all removed has none, whatever an old copy's place for an address holds.
    document = Store(tmp_path / "qkvm.json").snapshot()
    document["alerts"]["webhook"] = {"nonce": "AAAA", "data": "AAAA"}
    store.write(document)
    again = Store(tmp_path / "qkvm.json")
    assert again.destinations == [] and "webhook" not in again.snapshot()["alerts"]


def test_a_damaged_address_of_0_3_2_is_a_destination_that_says_so(tmp_path: Path) -> None:
    store = Store(tmp_path / "qkvm.json")
    document = store.snapshot()
    document.pop("destinations")
    document["alerts"].update({"enabled": True, "webhook": "https://written.by.hand.example/hook"})
    store.write(document)
    [first] = Store(tmp_path / "qkvm.json").destinations
    assert first.secret is not None and "damaged" in first.secret  # opens with no key: "does not open", said on the page


def test_a_wall_that_goes_back_to_0_3_2_finds_its_address_until_it_is_changed_in_0_4_0(tmp_path: Path) -> None:
    with wall(tmp_path) as admin:
        sealed = admin.core.vault.encrypt("https://ntfy.example.org/alerts", "alerts:webhook")  # type: ignore[attr-defined]
        key = admin.core.vault._require_key()  # type: ignore[attr-defined]  # (what 0.3.2 would open it with)
    as_0_3_2(tmp_path, {"enabled": True, "webhook": sealed, "format": "auto"})
    for _ in range(2):  # 0.4.0 started (and saved), and started again: one destination, and 0.3.2's place kept
        with wall(tmp_path) as admin:
            assert len(admin.core.store.destinations) == 1  # type: ignore[attr-defined]
            assert admin.put("/api/v1/alerts", json={"enabled": True, "recovered": False}).status_code == 200  # (a save)
        saved = written(tmp_path)
        assert (saved["alerts"]["webhook"], saved["alerts"]["format"]) == (sealed, "auto") and len(saved["destinations"]) == 1
    # What 0.3.2 reads there opens as its address, as 0.3.2 sealed it.
    opened = vault.Vault()
    opened.adopt(key)
    assert opened.decrypt(saved["alerts"]["webhook"], "alerts:webhook") == "https://ntfy.example.org/alerts"
    # Changed in 0.4.0, it is the first destination's alone: 0.3.2 would not read it as an address, and is not given it.
    with wall(tmp_path) as admin:
        assert admin.put("/api/v1/alerts", json={"enabled": True, "webhook": "https://ntfy.example.org/elsewhere", "format": "ntfy"}).status_code == 200
    saved = written(tmp_path)
    assert "webhook" not in saved["alerts"] and "format" not in saved["alerts"]
    # ...and so when it is removed.
    as_0_3_2(tmp_path, {"enabled": True, "webhook": sealed, "format": "json"})
    with wall(tmp_path) as admin:
        first = admin.core.store.destinations[0].id  # type: ignore[attr-defined]
        assert admin.delete(f"/api/v1/alerts/destinations/{first}").status_code == 200
    assert "webhook" not in written(tmp_path)["alerts"]


def test_the_guide_says_that_alerts_go_through_no_proxy_any_more_and_what_to_do_behind_one() -> None:
    # (The review of 0.4.0's first wave, M3.) 0.3.2 posted alerts through the proxy the environment named; 0.4.0 connects to
    # the address it has checked, and through no proxy. A wall that reaches the internet only through one stops alerting.
    guide = (Path(__file__).resolve().parent.parent / "GUIDE.md").read_text(encoding="utf-8")
    since = guide.split("### From 0.3.2", 1)[1].split("\n### ", 1)[0]
    assert "HTTPS_PROXY" in since and "proxy" in since and "firewall" in since
    # ...and that a saved secret is typed again where a destination is to be reached elsewhere (H1), and that a wall that
    # goes back to 0.3.2 finds its address (M2).
    assert "typed again" in guide.split("## Alerts", 1)[1].split("\n## ", 1)[0]
    assert "back to 0.3.2" in since


def test_a_0_3_2_address_on_this_computer_keeps_working_after_the_update(tmp_path: Path) -> None:
    # The owner's decision of 2026-11-17: loopback is what "May be a private address" lets through, and the address carried
    # over from 0.3.2 has that switch on: a relay or an ntfy on the wall's own computer goes on being sent to.
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    got: list[bytes] = []

    class Taking(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            got.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *said: Any) -> None:
            pass

    taking = ThreadingHTTPServer(("127.0.0.1", 0), Taking)
    threading.Thread(target=taking.serve_forever, daemon=True).start()
    try:
        with wall(tmp_path) as admin:
            sealed = admin.core.vault.encrypt(f"http://localhost:{taking.server_port}/hook", "alerts:webhook")  # type: ignore[attr-defined]
        as_0_3_2(tmp_path, {"enabled": True, "webhook": sealed, "format": "json"})
        with wall(tmp_path) as admin:
            assert admin.post("/api/v1/alerts/test").status_code == 200
            assert json.loads(got[0])["title"] == "Test alert from qKVM"
    finally:
        taking.shutdown()
        taking.server_close()
