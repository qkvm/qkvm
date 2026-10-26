"""Typed text on a JetKVM, in the keyboard layout its computer uses (track W14d).

A JetKVM says which layout its computer uses (`getKeyboardLayout`, set at its own page). Text is typed with the keys of
that layout, from tables made of Unicode CLDR's description of the layouts Windows has under those names
(`qkvm/layouts.py`, made by tools/make_layouts.py); a character the layout cannot type is refused before anything is
typed. The keys of the live line are places on the keyboard and are not touched by this.
"""

from __future__ import annotations

import asyncio
import string
from pathlib import Path
from typing import Any

import pytest

from qkvm import jetkvm, kvm, layouts
from tests.fake_jetkvm import FakeJetKvm, JetState, no_long_handshake

SHIFT, ALTGR = 0x02, 0x40


def keys(text: str, layout: str) -> list[tuple[int, list[int]]]:
    return jetkvm.text_reports(text, layout)


def test_the_us_table_made_from_cldr_types_every_character_as_the_one_qkvm_had() -> None:
    # (A check of the tables' making: the US layout made from CLDR's data gives the keys of the table written by hand.)
    for char in string.printable.replace("\r", "").replace("\x0b", "").replace("\x0c", ""):
        made = [(step >> 8, [step & 0xFF]) for step in layouts.LAYOUTS["en-US"][char]]
        assert made == keys(char, "en-US"), (char, made, keys(char, "en-US"))


def test_german_keys() -> None:
    assert keys("zy", "de-DE") == [(0, [0x1C]), (0, [0x1D])]  # (QWERTZ)
    assert keys("@", "de-DE") == [(ALTGR, [0x14])]  # AltGr and Q
    assert keys(chr(0x00E4) + chr(0x00DF), "de-DE") == [(0, [0x34]), (0, [0x2D])]
    assert keys(chr(0x20AC), "de-DE") == [(ALTGR, [0x08])]  # the euro sign: AltGr and E
    assert keys("^", "de-DE") == [(0, [0x35]), (0, [0x2C])]  # a dead key, alone: it and a space
    assert keys(chr(0x00EA), "de-DE") == [(0, [0x35]), (0, [0x08])]  # the dead circumflex, then e
    assert keys("A!", "de-DE") == [(SHIFT, [0x04]), (SHIFT, [0x1E])]


def test_french_and_belgian_keys() -> None:
    assert keys("aqzw", "fr-FR") == [(0, [0x14]), (0, [0x04]), (0, [0x1A]), (0, [0x1D])]  # (AZERTY)
    assert keys("1", "fr-FR") == [(SHIFT, [0x1E])]  # (the digits take Shift)
    assert keys(chr(0x00E9), "fr-FR") == [(0, [0x1F])]
    assert keys("@", "fr-FR") == [(ALTGR, [0x27])]
    assert keys("a1", "nl-BE") == [(0, [0x14]), (SHIFT, [0x1E])]


def test_japanese_keys_are_those_of_a_jis_keyboard() -> None:
    # (CLDR's Windows "Japanese" is laid out as a US keyboard; a Japanese PC's is JIS, as CLDR's ChromeOS one has it, but
    # for the tilde, which Windows has on Shift and the caret key only.)
    assert keys("@:", "ja-JP") == [(0, [0x2F]), (0, [0x34])]
    assert keys('"*', "ja-JP") == [(SHIFT, [0x1F]), (SHIFT, [0x34])]
    assert keys("\\_~", "ja-JP") == [(0, [0x89]), (SHIFT, [0x87]), (SHIFT, [0x2E])]


def test_a_character_a_layout_cannot_type_is_refused_before_anything_is_typed() -> None:
    with pytest.raises(kvm.KvmError) as refused:
        keys("privet", "ru-RU")  # Latin letters on a Russian keyboard
    assert refused.value.status == 422 and "Russian" in refused.value.message and "Nothing was typed" in refused.value.message
    # (The character is said by its place, never shown: the words go to the activity log, where a saved text never goes.)
    assert "character 1 of the text" in refused.value.message and "'p'" not in refused.value.message, refused.value.message
    assert keys(chr(0x043F), "ru-RU") == [(0, [0x0A])]  # (the Cyrillic letter on the key of G)
    with pytest.raises(kvm.KvmError) as unknown:
        keys("a", "xx-XX")
    assert unknown.value.status == 422 and "no table" in unknown.value.message
    with pytest.raises(kvm.KvmError):
        keys("caf" + chr(0x00E9), "en-US")


def test_every_layout_types_what_its_keyboard_has_and_only_with_shift_and_altgr() -> None:
    usages = {0x28, 0x2B, 0x2C, *range(0x04, 0x39), 0x64, 0x87, 0x89}
    for name, table in layouts.LAYOUTS.items():
        assert name in layouts.NAMES
        assert {" ", "\n", "\t", "0", "9", ".", ","} <= set(table), name
        if name != "ru-RU":
            assert set(string.ascii_lowercase) <= set(table), name
        for char, steps in table.items():
            assert 1 <= len(steps) <= 2, (name, char)
            for step in steps:
                assert step >> 8 in (0, SHIFT, ALTGR, ALTGR | SHIFT) and step & 0xFF in usages, (name, char, step)
    source = Path(layouts.__file__).read_bytes()
    assert source.isascii()  # (the characters are written as escapes)


def run(jet: FakeJetKvm, test: Any) -> None:
    async def inside() -> None:
        wall = jetkvm.JetKvmDevice(kvm.DeviceSpec("w", "the wall", jet.url, "", "secret", kind="jetkvm"))
        try:
            await test(wall)
        finally:
            await wall.close()

    try:
        asyncio.run(inside())
    finally:
        jet.stop()


@pytest.mark.parametrize("hidrpc", [True, False], ids=["hidrpc", "json-rpc"])
def test_text_is_typed_in_the_layout_the_jetkvm_says_its_computer_uses(monkeypatch: pytest.MonkeyPatch, hidrpc: bool) -> None:
    # (On the program as it was, a JetKVM set to German got US keys: "z" typed as "y", "@" as nothing it asked for.)
    no_long_handshake(monkeypatch, hidrpc)  # (where the stand-in has no hidrpc: on the other road the wall waits its own two seconds)
    jet = FakeJetKvm(JetState(hidrpc=hidrpc, layout="de-DE", width=640, height=360)).start()

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.act("text", text="z@" + chr(0x00EA))
        assert jet.state.typed == [(0, [0x1C]), (ALTGR, [0x14]), (0, [0x35]), (0, [0x08])], jet.state.typed
        with pytest.raises(kvm.KvmError) as refused:
            await wall.act("text", text="ok " + chr(0x0436))  # (a Cyrillic letter, which German keys do not type)
        assert refused.value.status == 422 and "German" in refused.value.message
        assert len(jet.state.typed) == 4, "something was typed of a text that was refused"

    run(jet, test)


def test_a_jetkvm_that_has_no_layout_to_say_gets_us_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    jet = FakeJetKvm(JetState(width=640, height=360)).start()
    real = jetkvm.JetKvmDevice._call

    async def call(self: Any, session: Any, method: str, params: Any = None, within: Any = None) -> Any:
        if method == "getKeyboardLayout":
            raise kvm.KvmError("action_failed", "Method not found")  # (as one that has no such question answers)
        return await real(self, session, method, params, within)

    monkeypatch.setattr(jetkvm.JetKvmDevice, "_call", call)

    async def test(wall: jetkvm.JetKvmDevice) -> None:
        await wall.act("text", text="zy")
        assert jet.state.typed == [(0, [0x1D]), (0, [0x1C])], jet.state.typed

    run(jet, test)
