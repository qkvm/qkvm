"""Which versions get fixes, for how long, how a security fix is announced and how far back an update works: said in the
guide (Updates, "Which versions get fixes") and in SECURITY.md ("Supported versions"), and said alike, so that a change
of the policy made in one place and not the other is seen (0.4.0, the support policy)."""

from __future__ import annotations

from pathlib import Path

APP = Path(__file__).resolve().parent.parent


def part(path: Path, start: str) -> str:
    """The text under a heading, up to the next heading of its depth or higher, on one line."""
    text = path.read_text(encoding="utf-8")
    begin = text.index(start + "\n")
    depth = start.split(" ", 1)[0]
    ends = [text.find("\n" + "#" * level + " ", begin + len(start)) for level in range(1, len(depth) + 1)]
    end = min((at for at in ends if at > 0), default=len(text))
    return " ".join(text[begin + len(start) : end].split())


GUIDE = part(APP / "GUIDE.md", "### Which versions get fixes")
SECURITY = part(APP / "SECURITY.md", "## Supported versions")


def test_the_guide_puts_the_policy_under_updates() -> None:
    text = (APP / "GUIDE.md").read_text(encoding="utf-8")
    assert text.index("## Updates\n") < text.index("### Which versions get fixes\n") < text.index("### From 0.1.x to 0.2.0, and back\n")


def test_both_say_which_versions_get_fixes_and_for_how_long() -> None:
    for said in (GUIDE, SECURITY):
        # (The owner, 2026-11-17: before 1.0 nothing is carried back to an older line; long-term support comes with 1.0.)
        assert "Before 1.0, only the newest release gets fixes" in said.replace("**", "")
        assert "nothing is carried back to an older line" in said
        assert "Long-term support starts with 1.0" in said.replace("**", "")
        assert "90 days" not in said


def test_both_say_how_a_security_fix_is_announced() -> None:
    for said in (GUIDE, SECURITY):
        plain = said.replace("**", "").replace("*", "")
        assert "A security fix is announced by a GitHub security advisory" in plain
        assert "a Security part in its version's chapter of CHANGELOG.md" in plain
        assert "Update button" in plain


def test_both_say_how_far_back_an_update_works() -> None:
    for said in (GUIDE, SECURITY):
        plain = said.replace("**", "")
        assert "An update works from every release of the minor version before it and of its own" in plain
        assert "the newest release of each minor version between" in plain
    assert "a test opens a data folder made by the newest release of the minor version before" in GUIDE
    assert "qkvm --roll-back" in GUIDE


def test_neither_promises_a_response_time() -> None:
    for said in (GUIDE, SECURITY):
        assert "There is no promise of a response time" in said
