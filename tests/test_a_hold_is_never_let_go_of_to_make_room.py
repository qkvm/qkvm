"""What is kept of the passwords devices said no to never lets go of a hold that has not run out to make room.

Found by the desktop app's agent (its finding 11), as the outside review of the desktop had found it in the desktop's own
pacing (F3, fixed there in 818877ef): `kvm.Rejected` kept MOST marks and, past that, let go of the oldest whatever it held.
A password a device had said no to a moment ago came back as never offered (no count, no wait) once enough others were
noted after it: a big wall, passwords changed on many devices, somebody adding devices with one wrong password after
another. The device was offered it again at once, and one that locks an account after a few wrong ones was given fresh
tries.

Room is made now only of what protects nothing any more: a mark whose wait has run out, the oldest of those first. Where
every mark still stands, all of them are kept (more than the most, for as long as they stand), and a device new to it is
let in as ever: nothing stands against it.
"""

from __future__ import annotations

import dataclasses

from qkvm import kvm
from qkvm.kvm import DeviceSpec

SPEC = DeviceSpec(id="ab12", name="KVM", base_url="https://192.0.2.50", username="admin", password="the saved one")


def guess(number: int) -> DeviceSpec:
    return dataclasses.replace(SPEC, password=f"guess {number}")


def noted_against(known: kvm.Rejected, count: int, then: str = "guess") -> list[str]:
    """`count` other passwords, each said no to once, the newest last: every one of them a hold that stands."""
    marks = [known.what("login", dataclasses.replace(SPEC, password=f"{then} {number}")) for number in range(count)]
    for mark in marks:
        known.said_no(mark)
    return marks


def run_out(known: kvm.Rejected, *marks: str) -> None:
    """Their waits over (all of them where none are named), as if that much time had passed for them."""
    for what in marks or list(known._known):
        times, unanswered, _ = known._known[what]
        known._known[what] = (times, unanswered, 0.0)


def test_a_no_that_stands_is_kept_whatever_comes_after_it() -> None:
    known = kvm.Rejected()
    first = known.what("login", SPEC)
    assert known.said_no(first) == kvm.LOGIN_BACKOFF
    noted_against(known, known.MOST)
    # Its count, and its wait: the password is not offered to the device again before its minute is over.
    assert known.times(first) == 1, "a no that stands was let go of to make room for others"
    assert known.wait_left(first) > kvm.LOGIN_BACKOFF - 5
    # And the next no counts on it: the second in a row waits five minutes, not one.
    assert known.said_no(first) == kvm.LOGIN_BACKOFFS[1]
    assert len(known._known) == known.MOST + 1


def test_a_sign_in_that_is_out_is_kept_whatever_comes_after_it() -> None:
    known = kvm.Rejected()
    first = known.what("login", SPEC)
    known.said_no(first)
    run_out(known, first)  # (its minute over: the password goes out again)
    known.sent(first)
    noted_against(known, known.MOST)
    # What went out stands as one that nothing answered yet, and what was known before it is known still.
    assert (known.times(first), known.silent(first)) == (1, 1), "a sign-in that is out was let go of to make room for others"
    assert known.wait_left(first) > 0
    # Its answer, a no, is the second in a row.
    assert known.said_no(first) == kvm.LOGIN_BACKOFFS[1]


def test_room_is_made_of_what_has_run_out_and_the_oldest_of_that_first() -> None:
    known = kvm.Rejected()
    marks = noted_against(known, known.MOST)
    run_out(known, *marks[5:10])  # five in the middle whose wait is over; the rest stand
    later = noted_against(known, 3, then="later")
    assert len(known._known) == known.MOST
    # The three oldest of the five that had run out went; what stands, older or not, is all there.
    assert [known.times(mark) for mark in marks[:12]] == [1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1]
    assert all(known.wait_left(mark) > 0 for mark in marks[:5] + marks[10:] + later)


def test_where_all_that_is_kept_still_stands_a_device_new_to_it_is_let_in_as_ever() -> None:
    # The choice where every mark still protects something (the desktop made the same, 818877ef): none of them goes, and more
    # than the most are kept for as long as they stand. Refusing a sign-in for want of room would lock a device out that
    # earned nothing of it; letting one go would offer a rejected password again too soon. What can be kept so is bounded
    # by what went out: each mark stands for a sign-in that went to a device (or what it came to) within the longest wait,
    # an hour, and a new mark comes only of a new address, user or password.
    known = kvm.Rejected()
    first = known.what("login", SPEC)
    known.said_no(first)
    noted_against(known, known.MOST)
    well = known.what("login", dataclasses.replace(SPEC, base_url="https://192.0.2.51", password="right"))
    assert (known.times(well), known.wait_left(well)) == (0, 0)  # nothing stands against it: no "wrong password", no wait
    known.sent(well)
    assert known.silent(well) == 1 and len(known._known) == known.MOST + 2
    known.accepted(well)
    assert known.times(well) == 0 and len(known._known) == known.MOST + 1
    assert known.times(first) == 1 and known.wait_left(first) > 0
    # Once they have run out, room is made of them at the next mark kept: no more than the most again.
    run_out(known)
    known.said_no(known.what("login", guess(-1)))
    assert len(known._known) == known.MOST
    assert known.times(first) == 0  # (the oldest of what had run out went first)
