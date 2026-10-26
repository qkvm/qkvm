"""What the public repository says in words is written in plain punctuation: no long dashes, curly quotes, arrows or
ellipses, and no space that does not break or cannot be seen (the owner's rule for everything published). The page's own
key labels (an arrow on an arrow key) are signs, not words, and are not Markdown. The texts for Docker Hub and the
organization's page are held to it by tools/test_listings.py."""

from __future__ import annotations

from pathlib import Path

APP = Path(__file__).resolve().parent.parent
KEPT_OUT = {0x2010: "a hyphen sign", 0x2011: "a hyphen sign", 0x2012: "a dash", 0x2013: "an en dash", 0x2014: "an em dash", 0x2015: "a dash",
            0x2212: "a minus sign", 0x2018: "a curly quote", 0x2019: "a curly quote", 0x201C: "a curly quote", 0x201D: "a curly quote",
            0x2190: "an arrow", 0x2191: "an arrow", 0x2192: "an arrow", 0x2193: "an arrow", 0x2026: "an ellipsis",
            0x00A0: "a space that does not break", 0x202F: "a space that does not break", 0x2009: "a thin space", 0x200B: "a space that cannot be seen",
            0xFEFF: "a mark that cannot be seen"}
# Folders a checkout or a run may hold that are not the repository's: what is in them is not published.
NOT_OURS = {".git", ".venv", "venv", "env", ".tox", ".nox", "node_modules", "build", "dist", "public", "__pycache__", ".mypy_cache", ".ruff_cache"}


def _kind(sign: str) -> str | None:
    """What a sign is, where it is one the rule keeps out: by name where it is listed, else by its kind (a space other
    than the plain one, one that cannot be seen, a dash other than the hyphen, an opening or closing quote, an arrow)."""
    import unicodedata

    if ord(sign) in KEPT_OUT:
        return KEPT_OUT[ord(sign)]
    if sign.isascii():
        return None
    kind = unicodedata.category(sign)
    if kind == "Zs":
        return "a space that is not the plain one"
    if kind == "Cf":
        return "a sign that cannot be seen"
    if kind == "Pd":
        return "a dash"
    if kind in ("Pi", "Pf") or 0x2018 <= ord(sign) <= 0x201F:  # (a low quote is told as an opening bracket)
        return "a curly or angled quote"
    if 0x2190 <= ord(sign) <= 0x21FF or 0x27F0 <= ord(sign) <= 0x27FF or 0x2900 <= ord(sign) <= 0x297F:
        return "an arrow"
    return None


def kept_out(text: str) -> list[tuple[int, str]]:
    """Where `text` has one of those, as a character or as HTML writes it (`&nbsp;`, `&#8212;`, `&#x2014;`)."""
    import html
    import re

    found = []
    for number, line in enumerate(text.splitlines(), 1):
        written = html.unescape("".join(re.findall(r"&#?[0-9A-Za-z]+;", line)))  # (only the entities read: never the line's other text)
        found += sorted({(number, name) for sign in line + written if (name := _kind(sign)) is not None})
    return found


def test_every_markdown_file_is_in_plain_punctuation() -> None:
    found = []
    for path in sorted(APP.rglob("*.md")):
        parts = path.relative_to(APP).parts[:-1]
        if any(part in NOT_OURS or part.startswith(".pytest") or part.endswith(".egg-info") for part in parts):
            continue
        found += [f"{path.relative_to(APP).as_posix()}:{number}: {name}" for number, name in kept_out(path.read_text(encoding="utf-8"))]
    assert not found, "\n".join(found[:20]) + f"\n({len(found)} in all)"


def test_the_rule_knows_signs_by_their_kind() -> None:
    # (The last review, of f1660f2: a list of signs let others of the same kind through: a figure space, a word joiner,
    # a soft hyphen, a two-em dash, low and angled quotes, a double arrow.)
    for code in (0x2007, 0x2002, 0x200A, 0x2060, 0x00AD, 0x200D, 0x2E3A, 0x201E, 0x00AB, 0x21D2, 0x2194):
        assert kept_out("a" + chr(code) + "b"), hex(code)
    for allowed in ("a - b", "it's", '"a"', "1 " + chr(0x00D7) + " 2", chr(0x00A9) + " 2026", "a " + chr(0x00B7) + " b"):
        assert not kept_out(allowed), allowed
