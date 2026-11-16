"""No processor of a real make is named by its model in the public repository: the stand-ins' processors are made up.

The owner's rule for everything published: the makers of the machines qKVM was tried on may be named (Gigabyte, ASRock
Rack), their models, firmware, processors, memory and sensor names never. Two real processor models of those machines
were in the code (a stand-in's processor, and the shape of what one board says of its own), and they are made up now,
of the same shape. Here, any model of a processor family of a real make (Xeon, EPYC, Core i7 and the like, with its
number) is refused wherever it is written in app/, but where it is not of a machine of ours, and that is said below;
and in the demo the website shows (demo/ beside app/, where this is the monorepo: the public repository is app/ alone).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

APP = Path(__file__).resolve().parent.parent
# The demo's folder, where app/ is the monorepo's (its own name app, and the demo's script beside it); else None.
DEMO = APP.parent / "demo" if APP.name == "app" and (APP.parent / "demo" / "demo.js").is_file() else None
MODEL = re.compile(
    r"\b(?:xeon|epyc|opteron|ryzen|threadripper|athlon|celeron|pentium|core)(?:\s*\((?:r|tm)\))?"
    r"(?:\s+(?:silver|gold|platinum|bronze|max|ultra|[a-z]|i[3579]|\d))?"
    r"[\s-]+[a-z]{0,2}\d{3,5}[a-z+]{0,3}(?![\w+])",
    re.IGNORECASE,
)
# Named, and of no machine of ours: (the file, what is named there) -> why it may be. (Each written in two parts, so
# that this file is held to the rule as well.)
NOT_OURS_TO_NAME = {
    ("qkvm/amt.py", "Xeon" + " 3400"): "a processor family's name in SMBIOS's own table of families, which an engine answers by number",
    ("tests/test_controllers.py", "Xeon(R)" + " Gold 5415+"): "what Dell's own published capture of an iDRAC9 says of its processor",
}
# Folders a checkout or a run may hold that are not the repository's.
NOT_THE_REPOSITORYS = {".git", ".venv", "venv", "env", ".tox", ".nox", "node_modules", "build", "dist", "public", "__pycache__", ".mypy_cache", ".ruff_cache"}


def named_models(text: str) -> list[tuple[int, str]]:
    """Each processor model of a real make in `text`: (its line, the model as written)."""
    return [(number, found.group(0)) for number, line in enumerate(text.splitlines(), 1) for found in MODEL.finditer(line)]


def models_under(folder: Path) -> list[str]:
    """Each processor model of a real make in the files under `folder`, as "file:line: model", but those said above."""
    found = []
    for path in sorted(folder.rglob("*")):
        where = path.relative_to(folder)
        if not path.is_file() or any(part in NOT_THE_REPOSITORYS or part.startswith(".pytest") or part.endswith(".egg-info") for part in where.parts[:-1]):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue  # (a picture, a font: no words)
        found += [f"{where.as_posix()}:{number}: {model}" for number, model in named_models(text) if (where.as_posix(), model) not in NOT_OURS_TO_NAME]
    return found


def test_no_processor_of_a_real_make_is_named_by_its_model() -> None:
    found = models_under(APP)
    assert not found, "\n".join(found)


@pytest.mark.skipif(DEMO is None, reason="the demo is not beside app/ here: the public repository is app/ alone")
def test_nor_in_the_demo_the_website_shows() -> None:
    assert DEMO is not None
    found = models_under(DEMO)
    assert not found, "\n".join(found)


def test_the_rule_knows_a_model_by_its_shape() -> None:
    # Made from parts here, so that this file names none of them whole.
    for family, model in (("Xeon", "Silver 1234Y"), ("Xeon", "E-1234"), ("Xeon(R)", "Gold 1234+"), ("EPYC", "1234X"), ("Core", "i7-12345K"), ("Ryzen", "9 1234X"), ("Celeron", "N1234")):
        assert named_models(f'"Intel {family} {model} CPU, 3000 Mhz"'), (family, model)
    for allowed in ("Intel Core i5, 3.4 GHz", "6 Core(s), 12 Logical Processor(s)", "Example Silver 9100Y", "Pentium 4", "Dual-Core Intel Xeon 3xxx", "the core 2 of 8"):
        assert not named_models(allowed), allowed
