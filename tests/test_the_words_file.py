"""The words of the wall are one file, static/words.json, and the program and the page keep to it.

The page shows a state, a device's trouble and a kind of device by a word; a program of another kind that
talks to a wall shows the same things, and was given the words a second time, by hand, which is how two
programs come to call one thing by two names. So the file holds them once: the states and what the page
says for each, every code a device's trouble is reported under and the state a tile shows it in, every
code the wall refuses a request with and the statuses it comes with, the kinds of device, and the words of
`can`. The page reads it as it starts; the others are built from it. And this asks the program and the page
whether they use a word the file does not have, so that the file cannot fall behind either of them.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from qkvm import kvm
from qkvm.amt import AmtDevice
from qkvm.jetkvm import JetKvmDevice
from qkvm.proxmox import ProxmoxGuest
from qkvm.redfish import RedfishDevice
from qkvm.vncdevice import VncDevice

qKVM = Path(__file__).resolve().parent.parent / "qkvm"
WORDS = json.loads((qKVM / "static" / "words.json").read_text(encoding="utf-8"))
SCRIPT = (qKVM / "static" / "app.js").read_text(encoding="utf-8")
PROGRAM = {path.name: path.read_text(encoding="utf-8") for path in qKVM.glob("*.py")}
STATES = ("connecting", "online", "no_signal", "offline", "auth", "error", "busy")
# What the page says of its own where no server answered: not the wall's words, and so not in the file.
PAGES_OWN_CODES = {"network", "error"}
# The live line's own codes, which its `control` and `bye` messages carry (live.py; the README's chapter "Live view and
# control" names them) and the file does not hold: the page may name one only where the line can say it.
LINE_CODES = (
    set(re.findall(r'refused\("(\w+)"', PROGRAM["live.py"]))
    | set(re.findall(r'_let_go\([^,()]+, "(\w+)"', PROGRAM["live.py"]))
    | set(re.findall(r'\.end\("(\w+)"', PROGRAM["live.py"]))
)


def test_the_file_holds_what_it_is_for_and_nothing_else() -> None:
    assert list(WORDS) == ["states", "server_states", "codes", "refusals", "kinds", "can"]
    assert tuple(WORDS["states"]) == STATES
    assert set(WORDS["server_states"]) <= set(STATES)
    for part in ("states", "server_states", "kinds", "can"):
        assert all(isinstance(label, str) and label.strip() for label in WORDS[part].values()), part
    assert set(WORDS["codes"].values()) <= set(STATES)
    for code, statuses in WORDS["refusals"].items():
        assert statuses == sorted(set(statuses)) and all(400 <= status <= 599 for status in statuses), code
    assert all(re.fullmatch(r"[a-z][a-z_]*", word) for part in ("codes", "refusals", "can") for word in WORDS[part])


def test_the_words_of_can_are_the_drivers_vocabulary_in_its_order() -> None:
    assert tuple(WORDS["can"]) == kvm.ABILITIES
    # Every driver's own list is of these words, and a look that adds to it can only add these: a word that is
    # not one is refused where the list is made, so a driver cannot say one the file does not have.
    for driver in (kvm.KvmDevice, JetKvmDevice, RedfishDevice, AmtDevice, VncDevice, ProxmoxGuest):
        assert kvm.can_do(*driver.can) == list(driver.can), driver.kind
        assert driver.kind in WORDS["kinds"]
    assert set(WORDS["kinds"]) == {kvm.KvmDevice.kind, JetKvmDevice.kind, RedfishDevice.kind, AmtDevice.kind, VncDevice.kind, ProxmoxGuest.kind}
    for word in ("power", "reset", "ports", "screen", "console", "locator", "live"):  # what a look adds, as written in the drivers
        assert any(f'"{word}" if' in text for text in PROGRAM.values()), word
    try:
        kvm.can_do("keys", "something_else")
    except ValueError as refused:
        assert "something_else" in str(refused)
    else:
        raise AssertionError("a word that is no ability was taken")


def test_every_state_and_code_of_the_program_is_in_the_file() -> None:
    # A driver puts a state into a status in a few written ways; each is one of the seven.
    states = set()
    for name in ("kvm.py", "jetkvm.py", "redfish.py", "amt.py", "vncdevice.py", "proxmox.py"):
        states |= set(re.findall(r'"state": "(\w+)"', PROGRAM[name])) | set(re.findall(r'state = "(\w+)"', PROGRAM[name]))
        states |= set(re.findall(r'self\._told = "(\w+)"', PROGRAM[name])) | set(re.findall(r'return "(\w+)"(?: if| else|\n)', PROGRAM[name]))
    assert states - set(STATES) == set(), states - set(STATES)

    codes = set(WORDS["codes"]) | set(WORDS["refusals"])
    # Every code a device's trouble is raised under, with the status it is answered with where one is given, and 502 where none is.
    # (A call's arguments may hold parentheses two deep, and end in a comma on a line of their own.)
    raised = re.compile(r'KvmError\(\s*"([a-z_]+)",(?:[^()]|\((?:[^()]|\([^()]*\))*\))*?(?:,\s*(\d{3}))?\s*,?\s*\)')
    sites = 0
    for name, text in PROGRAM.items():
        for code, status in raised.findall(text):
            sites += 1
            assert code in codes, (name, code)
            if status:
                assert int(status) in WORDS["refusals"].get(code, []), (name, code, status)
            elif code not in WORDS["codes"]:
                assert 502 in WORDS["refusals"][code], (name, code)
        # Every site is matched: one written in a way the expression does not follow would go unchecked.
        assert len(re.findall(r'KvmError\(\s*"', text)) == len(raised.findall(text)), (name, "a KvmError written in a way this test does not read")
    assert sites > 100
    assert ("missing_driver", "501") in raised.findall(PROGRAM["jetkvm.py"])  # (the one with its status on a line of its own)
    for code in re.findall(r'"code": "([a-z_]+)"', "".join(PROGRAM[name] for name in ("kvm.py", "jetkvm.py", "redfish.py", "amt.py", "vncdevice.py", "proxmox.py"))):
        assert code in WORDS["codes"], code  # (what a status says of its own: a critical fault, an error inside the program)
    # Every refusal of the wall's own, with its status.
    for status, code in re.findall(r'fail\(\s*(\d{3}),\s*"([a-z_]+)"', PROGRAM["server.py"]):
        assert int(status) in WORDS["refusals"].get(code, []), (code, status)
    assert 409 in WORDS["refusals"]["same_device"]  # (the one refusal written out by hand, with more in it than a code)
    for code in re.findall(r'ExchangeError\(\s*"([a-z_]+)"', PROGRAM["exchange.py"]):
        assert 422 in WORDS["refusals"].get(code, []), code  # (a file that does not pass is answered 422)
    # And nothing in the file that the program never says.
    said = set()
    for text in PROGRAM.values():
        said |= set(re.findall(r'KvmError\(\s*"([a-z_]+)"', text)) | set(re.findall(r'fail\(\s*\d{3},\s*"([a-z_]+)"', text))
        said |= set(re.findall(r'"code": "([a-z_]+)"', text)) | set(re.findall(r'ExchangeError\(\s*"([a-z_]+)"', text))
    said.add("console_time_up")  # made from a word (redfish.py: the controller ended the console session, its time being up)
    assert codes - said == set(), codes - said


def test_the_page_uses_no_word_the_file_does_not_have() -> None:
    # The page shows a state by its label and a trouble by the state its code maps to; both come from the file,
    # at boot, and the page's own literals name only what the file has.
    assert "const LABELS = WORDS.states;" in SCRIPT and "const FEED_STATES = WORDS.codes;" in SCRIPT and "const KINDS = WORDS.kinds;" in SCRIPT
    assert "await Promise.all([api('GET', 'api/v1/session'), loadWords()])" in SCRIPT  # before the first tile
    for label in WORDS["states"].values():
        assert f"'{label}'" not in SCRIPT or label in ("Online", "No signal"), label  # (two are also the names of filters)
    assert "'Powered off'" not in SCRIPT

    # (The live view's video decoder has a state of its own, the browser's word for it, which is no tile's.)
    states = set(re.findall(r"(?<!decoder\.)\bstate\s*[!=]==\s*'(\w+)'", SCRIPT)) | set(re.findall(r"(?<!decoder)\.state\s*[!=]==\s*'(\w+)'", SCRIPT))
    states |= set(re.findall(r"return \['(\w+)', ", SCRIPT))
    for table in ("GROUPS", "VEIL_ICONS"):
        line = SCRIPT[SCRIPT.index(f"const {table} = {{") :].split("\n", 1)[0]
        states |= set(re.findall(r"(\w+): '", line))
    assert states - set(STATES) == set(), states - set(STATES)

    # KeyboardEvent.code is a physical key, not an application error code.
    codes = page_error_codes(SCRIPT)
    reached = SCRIPT[SCRIPT.index("const CANNOT_BE_REACHED = [") :].split("\n", 1)[0]
    codes |= set(re.findall(r"'(\w+)'", reached))
    known = set(WORDS["codes"]) | set(WORDS["refusals"]) | PAGES_OWN_CODES | LINE_CODES
    assert codes - known == set(), codes - known
    assert {"taken", "idle", "not_allowed", "gone"} <= LINE_CODES, LINE_CODES  # (the look at live.py finds what it is meant to)

    kinds = set(re.findall(r"device\.kind\s*[!=]==\s*'(\w+)'", SCRIPT))
    assert kinds - set(WORDS["kinds"]) == set(), kinds - set(WORDS["kinds"])

    asked = set(re.findall(r"canDo\([^,()]+, '(\w+)'\)", SCRIPT)) | set(re.findall(r"\bable\('(\w+)'\)", SCRIPT))
    assert len(asked) >= 8 and asked - set(WORDS["can"]) == set(), asked - set(WORDS["can"])
    # And the menu goes by the list, not by the kind: nothing in it is shown or hidden for a tile being a server.
    menu = SCRIPT[SCRIPT.index("function actionsDialog(") : SCRIPT.index("function recoveryKeyView(")]
    assert "!servers &&" not in menu and "picture !== false &&" not in menu and "tile.status?.atx?.enabled" not in menu


def test_every_entry_of_the_activity_log_has_a_name_on_the_page() -> None:
    # What the program writes into the activity log, by the event it is written under, the page shows by a name
    # (EVENTS); an event without one is shown as the word it is written with ("live_control", say).
    written: set[str] = set()
    for text in PROGRAM.values():
        written |= set(re.findall(r'\baudit(?:\.write)?\(\s*"([a-z_]+)"', text))
    assert len(written) > 40 and "live_control" in written
    named = SCRIPT[SCRIPT.index("const EVENTS = {") :].split("\n};", 1)[0]
    assert written - set(re.findall(r"\b([a-z_]+): '", named)) == set(), written - set(re.findall(r"\b([a-z_]+): '", named))


def page_error_codes(script: str) -> set[str]:
    return set(re.findall(r"(?<!event\.)\bcode\s*[!=]==\s*'(\w+)'", script))


def test_error_code_check_distinguishes_keyboard_events_without_hiding_unknown_errors() -> None:
    assert page_error_codes("event.code !== 'ControlRight'; keyCode === 'Space'; ex.code === 'unknown_refusal'; code === 'unknown_stream'") == {"unknown_refusal", "unknown_stream"}
