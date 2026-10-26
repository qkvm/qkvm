"""A takeover confirmation belongs to the observed control lease, not a display name."""
import asyncio

import pytest

from tests.test_live_letting_go import Scene, Way, played, told


def scene_with_ways() -> tuple[Scene, list[Way]]:
    scene = Scene()
    made: list[Way] = []

    def way() -> Way:
        item = Way(f"way {len(made)}", scene.said)
        item.owe = scene.lines.tasks.add
        made.append(item)
        return item

    scene.machine._hid = way
    scene.lines.admins.update({"B", "A"})
    return scene, made


@pytest.mark.parametrize("replacement", ["same_name_new_line", "same_prefix_account", "same_line_new_lease"])
@pytest.mark.parametrize("reference_mode", ["name", "opaque"])
def test_a_confirmed_holder_cannot_be_replaced_even_when_its_name_matches(replacement: str, reference_mode: str) -> None:
    async def check() -> None:
        s, ways = scene_with_ways()
        old = s.a if replacement != "same_prefix_account" else s.line("a" * 60 + "1111")
        await s.take(old)
        offer = await s.machine.control(s.b, True)
        reference = offer["by"] if reference_mode == "name" else offer.get("from", offer["by"])
        assert offer["code"] == "taken"
        assert offer["by"] == old.holder.name  # do not truncate valid 64-character account names
        await s.machine.control(old, False)
        if replacement == "same_name_new_line":
            new = s.line("A")
        elif replacement == "same_prefix_account":
            new = s.line("a" * 60 + "2222")
        else:
            new = old
        await s.take(new)
        opened = len(ways)
        denied = await s.machine.control(s.b, True, take=True, taking_from=reference)
        assert denied["on"] is False and denied["code"] == "taken", denied
        assert s.machine.holder is new and new.control
        assert len(ways) == opened, "a stale confirmation must not open an input connection"
        assert denied["from"] != offer["from"]
        await s.machine.control(new, False)
        await s.settled()
    played(check)()


def test_the_current_offer_accepts_opaque_or_legacy_name_but_not_an_unobserved_name() -> None:
    async def check() -> None:
        for mode in ("opaque", "name"):
            s, ways = scene_with_ways()
            await s.take(s.a)
            denied = await s.machine.control(s.b, True, take=True, taking_from="A")
            assert denied["on"] is False, "a guessed name is not confirmation of an observed lease"
            assert len(ways) == 1
            assert denied["from"] != denied["by"]
            reference = denied["from"] if mode == "opaque" else denied["by"]
            assert (await s.machine.control(s.b, True, take=True, taking_from=reference))["on"] is True
            revoked = told(s.a)[-1]
            assert revoked["code"] == "taken" and revoked["by"] == "B" and revoked["from"]
            assert (await s.machine.control(s.a, True, take=True, taking_from=revoked["from"]))["on"] is True
            await s.machine.control(s.a, False)
            await s.settled()
    played(check)()


def test_ownership_is_rechecked_by_lease_after_the_input_connection_opens() -> None:
    async def check() -> None:
        s, _ways = scene_with_ways()
        await s.take(s.a)
        offer = await s.machine.control(s.b, True)
        pending_way = Way("pending", s.said)
        pending_way.owe = s.lines.tasks.add
        pending_way.opening = asyncio.get_running_loop().create_future()
        ordinary = s.machine._hid
        s.machine._hid = lambda: pending_way
        pending = asyncio.create_task(s.machine.control(s.b, True, take=True, taking_from=offer.get("from", offer["by"])))
        await pending_way.opening_started.wait()
        await s.machine.control(s.a, False)
        s.machine._hid = ordinary
        replacement = s.line("A")
        await s.take(replacement)
        pending_way.opening.set_result(None)
        denied = await pending
        assert denied["on"] is False and denied["code"] == "taken", denied
        assert s.machine.holder is replacement
        await s.settled()
        assert pending_way.closed
        await s.machine.control(replacement, False)
        await s.settled()
    played(check)()


def test_another_viewer_cannot_reuse_a_control_offer_it_was_not_shown() -> None:
    async def check() -> None:
        s, ways = scene_with_ways()
        s.lines.admins.add("C")
        c = s.line("C")
        await s.take(s.a)
        offer = await s.machine.control(s.b, True)
        denied = await s.machine.control(c, True, take=True, taking_from=offer["from"])
        assert denied["on"] is False and denied["code"] == "taken"
        assert s.machine.holder is s.a and len(ways) == 1
        assert (await s.machine.control(c, True, take=True, taking_from=denied["from"]))["on"] is True
        await s.machine.control(c, False)
        await s.settled()
    played(check)()
