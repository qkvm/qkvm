"""Keep-awake (the jiggler) on a KVM whose firmware gives it settings of its own: GLKVM of late, seen on the owner's GL.iNet
Comet Pro on 2026-11-15.

There, GET /api/hid says the jiggler is `enabled`, and beside that what its own settings say (`config`) and why it does not
run (`state.blocked_reason`): "disabled" where those settings switch it off. Switched on through qKVM then, the KVM refused
it, and the wall said 502 `action_failed`, in the KVM's words of nothing. Where the KVM says so, the wall now says why and
sends nothing; switched on in the KVM's own settings, it is switched from qKVM as before. A KVM of the older shape (no
settings of its own) is switched as it always was.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from qkvm import kvm, update, vault
from tests.fake_kvm import FakeKvm, FakeState
from tests.test_wall import add, wait_until, wall

SWITCHED_OFF_THERE = "The jiggler is switched off in the KVM's own settings: switch it on there first"


@pytest.fixture(autouse=True)
def fast(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(vault, "SCRYPT_N", 2**12)
    monkeypatch.setattr(kvm, "ERROR_HOLD", 0)
    monkeypatch.setattr(kvm, "STATUS_TTL", 0)
    monkeypatch.setattr(update, "DEFAULT_REPO", "")


@pytest.fixture
def comet() -> Iterator[FakeKvm]:
    """A Comet on the firmware that gives its jiggler settings of its own, which switch it off."""
    fake = FakeKvm(FakeState(jiggler_settings=True, jiggler_settings_on=False)).start()
    yield fake
    fake.stop()


def act(admin: Any, device: str, action: str) -> Any:
    return admin.post(f"/api/v1/devices/{device}/actions", json={"action": action})


def looked_at(admin: Any, device: str) -> dict[str, Any]:
    status: dict[str, Any] = {}

    def came() -> bool:
        status.update(admin.get("/api/v1/status").json()[device])
        return status.get("state") == "online"

    wait_until(came, "the KVM was never seen online", 10)
    return status


def test_a_jiggler_its_own_settings_switch_off_is_refused_in_those_words_and_nothing_is_sent(tmp_path: Path, comet: FakeKvm) -> None:
    with wall(tmp_path) as admin:
        device = add(admin, comet.url)
        assert "jiggler" in looked_at(admin, device)["can"]  # (offered: pressed, it says why it cannot be)
        reply = act(admin, device, "jiggler_on")
        assert (reply.status_code, reply.json().get("code"), reply.json().get("message")) == (422, "invalid", SWITCHED_OFF_THERE), reply.text
        assert "jiggler 1" not in comet.state.actions and comet.state.jiggler is False
        # Switching it off is no harm, and goes as ever.
        assert act(admin, device, "jiggler_off").status_code == 200
        # Switched on in the KVM's own settings since: from the next look on, it is switched from qKVM as before.
        comet.state.jiggler_settings_on = True
        wait_until(lambda: looked_at(admin, device) and act(admin, device, "jiggler_on").status_code == 200, "the jiggler was never switched on")
        assert comet.state.jiggler is True and comet.state.actions.count("jiggler 1") == 1


@pytest.mark.parametrize("stock", [False, True])
def test_a_kvm_of_the_older_shape_switches_its_jiggler_as_before(tmp_path: Path, stock: bool) -> None:
    # (GLKVM before that firmware says nothing of a jiggler in /api/hid; stock kvmd says `enabled` alone, true here.)
    fake = FakeKvm(FakeState(stock=stock)).start()
    try:
        with wall(tmp_path) as admin:
            device = add(admin, fake.url)
            assert "jiggler" in looked_at(admin, device)["can"]
            assert act(admin, device, "jiggler_on").status_code == 200 and fake.state.jiggler is True
            assert act(admin, device, "jiggler_off").status_code == 200 and fake.state.jiggler is False
    finally:
        fake.stop()
