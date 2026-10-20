"""Keys and the mouse over the live line, as a real Comet took them (2026-10-18), against a stand-in that answers the same.

The real one's mouse was set to relative ("usb_rel"; `mouse.absolute` false in its /api/hid): every place the line sent
was dropped (the pointer never moved), while steps moved it, faster the faster they came (the PC's own acceleration).
Stock kvmd drops the other kind while its mouse is absolute (W7). So the line says to its viewers how the machine's
pointer is moved, and says it again when that changes. Keys arrived each once, at any pace the line was sent them, and
nothing stayed down when the keyboard was given back or the line was cut: the stand-in already took them so.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qkvm import kvm, live, vault
from tests.fake_jetkvm import FakeJetKvm, JetState
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_live import Wall
from tests.test_wall import wait_until

# (A line is opened and held by a `Viewer` for as long as a test wants it, not in a `with`, as test_live.py does.)
pytestmark = pytest.mark.filterwarnings(r"ignore:connect\(\) must be used as a context manager:DeprecationWarning")


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(kvm, "STATUS_FIRST_WAIT", 10)
    monkeypatch.setattr(kvm, "FIRST_CONTACT_WAIT", 10)
    monkeypatch.setattr(kvm, "PICTURE_PATIENCE", 10)
    monkeypatch.setattr(live, "STATE_EVERY", 0.1)


def test_the_line_says_how_a_kvms_pointer_is_moved_and_says_it_again_when_that_changes(tmp_path: Path) -> None:
    comet = FakeKvm(FakeState(mouse_absolute=False)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, comet.url)
            viewer = wall.line(admin, device)
            said = viewer.word("state")
            while said.get("pointer") is None:  # (the first look may come before the KVM said how its mouse is)
                said = viewer.word("state")
            assert said == {"t": "state", "state": "online", "pointer": "relative"}, said
            # Whoever holds keyboard and mouse sends steps; a place would have been dropped by the KVM.
            viewer.say(t="control", on=True)
            assert viewer.word("control") == {"t": "control", "on": True}
            viewer.say(t="mr", dx=40, dy=-10)
            wait_until(lambda: [e["event_type"] for e in comet.state.hid] == ["mouse_relative"], f"the step did not arrive: {comet.state.hid}")
            assert comet.state.pointer_dropped == 0
            # Its mouse set to absolute on the KVM's own page: said.
            comet.state.mouse_absolute = True
            assert viewer.word("state", timeout=10) == {"t": "state", "state": "online", "pointer": "absolute"}
            viewer.say(t="control", on=False)
            viewer.close()
    finally:
        comet.stop()


def test_a_jetkvms_pointer_is_moved_both_ways(tmp_path: Path) -> None:
    # A JetKVM takes places and steps (its absolute and relative reports): both.
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    try:
        with Wall(tmp_path) as wall:
            admin = wall.browser()
            device = wall.add(admin, jet.url)
            viewer = wall.line(admin, device)
            said = viewer.word("state", timeout=10)
            while said.get("pointer") is None:
                said = viewer.word("state", timeout=10)
            assert said["pointer"] == "both", said
            viewer.close()
    finally:
        jet.stop()
