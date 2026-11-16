"""What the public repository says in words is written in plain punctuation: no long dashes, curly quotes, arrows or
ellipses, and no space that does not break or cannot be seen (the owner's rule for everything published). The page's own
key labels (an arrow on an arrow key) are signs, not words, and are not Markdown. The texts for Docker Hub and the
organization's page are held to it by tools/test_listings.py.

What the page says and what the server sends in words (everything in qkvm/: the page's files, words.json, the
messages) is held to it for dashes as well: no dash but the hyphen, however it is written there."""

from __future__ import annotations

import html
import re
import unicodedata
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


# --- what the page says, and the words the server sends -------------------------------------------------------------

# A dash may be written in qkvm/ as itself, as HTML writes it (by name or by number), or made from its number where the
# page or the server runs: an escape of JavaScript (four digits, or in braces), of Python (four or eight digits, or by
# its name), of CSS, or a call that makes a character of a number (fromCharCode, fromCodePoint, chr). Desktop finding 18:
# the Add KVM sentence said its model and "over plain HTTP" after a dot, where the Desktop App says them in brackets.
BACKSLASH = re.escape(chr(92))  # (put so: this file writes no escape whole, which a tool that edits it might turn into its sign)
MADE = re.compile(
    BACKSLASH + r"u\{([0-9A-Fa-f]{1,6})\}"
    + "|" + BACKSLASH + r"u([0-9A-Fa-f]{4})"
    + "|" + BACKSLASH + r"U([0-9A-Fa-f]{8})"
    + "|" + BACKSLASH + r"([0-9A-Fa-f]{1,6})(?![0-9A-Fa-f])"
    + r"|&#([0-9]{1,8});?|&#[xX]([0-9A-Fa-f]{1,6});?"
    + r"|(?:fromCharCode|fromCodePoint|chr)\(\s*(0[xX][0-9A-Fa-f]+|[0-9]+)\s*[,)]"
)  # fmt: skip
BY_NAME = re.compile(BACKSLASH + r"N\{([^}]{1,80})\}")
ENTITY = re.compile(r"&[A-Za-z][A-Za-z0-9]{1,31};")


def is_dash(sign: str) -> bool:
    """A dash other than the hyphen: a sign of the kind dash, from U+2010 to U+2015 and the rest of that kind, or the minus sign."""
    return not sign.isascii() and (unicodedata.category(sign) == "Pd" or ord(sign) == 0x2212)


def dashes(text: str) -> list[tuple[int, str]]:
    """Each dash other than the hyphen in `text`, by its line: as a character, as HTML writes it, or made from its number."""
    found = []
    for number, line in enumerate(text.splitlines(), 1):
        signs = [f"U+{ord(sign):04X}" for sign in line if is_dash(sign)]
        for made in MADE.finditer(line):
            digits = made.group(made.lastindex or 0)
            code = int(digits, 16) if made.lastindex != 5 and (made.lastindex != 7 or digits[:2] in ("0x", "0X")) else int(digits)
            if code <= 0x10FFFF and is_dash(chr(code)):
                signs.append(made.group(0))
        for named in BY_NAME.finditer(line):
            try:
                sign = unicodedata.lookup(named.group(1))
            except KeyError:
                continue
            if is_dash(sign):
                signs.append(named.group(0))
        signs += [entity.group(0) for entity in ENTITY.finditer(line) if any(is_dash(sign) for sign in html.unescape(entity.group(0)))]
        found += [(number, sign) for sign in dict.fromkeys(signs)]
    return found


def test_what_the_page_and_the_server_say_has_no_dash() -> None:
    found = []
    for path in sorted((APP / "qkvm").rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # (no words: there is none such in qkvm/ today)
        found += [f"{path.relative_to(APP).as_posix()}:{number}: {sign}" for number, sign in dashes(text)]
    assert not found, "\n".join(found[:20]) + f"\n({len(found)} in all)"


def test_a_dash_is_known_however_it_is_written() -> None:
    slash = chr(92)
    for written in (
        chr(0x2014), chr(0x2013), chr(0x2010), chr(0x2011), chr(0x2012), chr(0x2015), chr(0x2212), chr(0x2E3A), chr(0xFE58),
        "&mdash;", "&ndash;", "&minus;", "&dash;", "&horbar;", "&#8212;", "&#8211", "&#x2014;", "&#X2013;", "&#x02212;",
        slash + "u2014", slash + "u{2014}", slash + "u{2013}", slash + "U00002014", slash + "N{EM DASH}", slash + "N{MINUS SIGN}", slash + "2014 ",
        "String.fromCharCode(8212)", "String.fromCharCode(0x2014)", "String.fromCodePoint(0x2212)", "String.fromCharCode(8211, 32)", "chr(8211)", "chr(0x2010)",
    ):  # fmt: skip
        assert dashes("said " + written + " here"), written
    for allowed in (
        "a - b", "well-known", "x -= 1", "a " + chr(0x00B7) + " b", "&middot;", "&#183;", "&amp;", slash + "u00b7", slash + "x2d", slash + "1",
        slash + "d{3}", "String.fromCharCode(45)", "String.fromCharCode(code)", "chr(0x41)", slash + "N{MIDDLE DOT}", slash + "N{NO SUCH SIGN}",
    ):  # fmt: skip
        assert not dashes(allowed), allowed
