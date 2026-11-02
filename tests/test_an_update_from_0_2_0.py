"""An update installed from inside the app of 0.2.0 starts this code, under 0.2.0's own starter.

An in-app update never replaces the starter: `python -m qkvm` of the copy pip installed loads `qkvm`, `qkvm.__main__` and
`qkvm._where` from that copy, puts the update's folder in front of the package, and only then imports the update's
`cli`. What the starter loaded stays loaded under those names for the whole process. 7d6ebf7 had cli take four new names
from `_where`; 0.2.0's has one: every in-app update from 0.2.0 ended in "ImportError: cannot import name 'READ' from
'qkvm._where'", the starter went back to 0.2.0, and the update was offered again (the review of 2026-11-01, M1,
review-core\\probes\\inapp_update_from_020.py).

The starter of 0.2.0 is kept here as it shipped, those of its files that it loads (tests/fixtures/starter-0.2.0, from
b1f37b2), and the package of this tree is the update.
"""

from __future__ import annotations

import ast
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import httpx
import pytest

import qkvm
from tests.test_wall import closed_port

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "starter-0.2.0"
PACKAGE = Path(qkvm.__file__).resolve().parent  # this tree's package: the update
APP = PACKAGE.parent
# What the starter loads under the package's names before an update's code: kept for the whole process, as installed.
STARTER = ("__init__", "__main__", "_where")


def defined(source: Path) -> set[str]:
    """The names a module defines at its top (and in the blocks of an `if` or a `try` there)."""
    names: set[str] = set()

    def walk(body: list[ast.stmt]) -> None:
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(node.name)
            elif isinstance(node, ast.Assign):
                names.update(target.id for target in node.targets if isinstance(target, ast.Name))
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
                names.add(node.target.id)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                names.update((alias.asname or alias.name).split(".")[0] for alias in node.names)
            elif isinstance(node, (ast.If, ast.Try)):
                walk(node.body)
                walk(node.orelse)
                for handler in getattr(node, "handlers", []):
                    walk(handler.body)
    walk(ast.parse(source.read_text(encoding="utf-8")).body)
    return names


def taken_from_the_starter(source: Path) -> list[tuple[str, str]]:
    """(module, name) for every name a module of the package takes from one of the starter's, by any way of importing it."""
    tree = ast.parse(source.read_text(encoding="utf-8"))
    taken: list[tuple[str, str]] = []
    aliases: dict[str, str] = {}  # a starter module imported as a module: its name here -> which
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level == 1 and module in STARTER:
                taken += [(module, alias.name) for alias in node.names]
            elif node.level == 0 and module.startswith("qkvm.") and module[5:] in STARTER:
                taken += [(module[5:], alias.name) for alias in node.names]
            elif (node.level == 1 and not module) or (node.level == 0 and module == "qkvm"):
                aliases.update({alias.asname or alias.name: alias.name for alias in node.names if alias.name in STARTER})
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("qkvm.") and alias.name[5:] in STARTER:
                    taken.append((alias.name[5:], "*" if alias.asname is None else "(module)"))
                    if alias.asname:
                        aliases[alias.asname] = alias.name[5:]
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            taken.append((aliases[node.value.id], node.attr))
    return [(module, name) for module, name in taken if name != "(module)"]


def test_what_this_code_takes_from_the_starter_the_starter_of_0_2_0_has() -> None:
    have = {name: defined(FIXTURE / "qkvm" / f"{name}.py") for name in STARTER}
    lacking = [
        f"{source.name}: {module}.{name}"
        for source in sorted(PACKAGE.glob("*.py"))
        if source.stem not in STARTER
        for module, name in taken_from_the_starter(source)
        if name not in have[module]
    ]
    assert lacking == [], f"an in-app update from 0.2.0 would not start: 0.2.0's starter has none of {lacking}"


def test_the_starter_loads_nothing_of_the_package_under_its_names_but_the_starter() -> None:
    # Whatever the starter imports by the package's names is kept, as installed, for the whole process: a module that this
    # tree's starter took up under such a name would be frozen for every update after it.
    for name in ("__main__", "_where"):
        tree = ast.parse((PACKAGE / f"{name}.py").read_text(encoding="utf-8"))
        loaded = {
            node.module or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.level >= 1
            for alias in node.names
        }
        loaded |= {alias.name[5:] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names if alias.name.startswith("qkvm.")}
        assert loaded <= {"_where"} - {name}, (name, loaded)
    # ...and what it loads from beside itself under a name of its own (__main__.own_folders) needs nothing of the package.
    tree = ast.parse((PACKAGE / "_folders.py").read_text(encoding="utf-8"))
    assert not [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level >= 1]
    assert not [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names if alias.name.startswith("qkvm")]


def test_an_update_from_0_2_0_to_this_code_starts_and_is_proven(tmp_path: Path) -> None:
    # As Updater._activate leaves it: the version unpacked into updates/, and current.json naming it, not proven yet.
    data = tmp_path / "data"
    update = data / "updates" / "9.9.9" / "qkvm"
    shutil.copytree(PACKAGE, update, ignore=shutil.ignore_patterns("__pycache__"))
    (update / "_version.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    if os.name == "posix":  # (as update.unpack writes it: its owner's alone, whatever the modes of the tree it was copied from)
        for path in [update.parent, update, *update.rglob("*")]:
            path.chmod(0o700 if path.is_dir() else 0o600)
    (data / "updates" / "current.json").write_text(json.dumps({"version": "9.9.9", "previous": None, "previous_proven": False}), encoding="utf-8")
    port = closed_port()
    environment = {**os.environ, "PYTHONPATH": str(FIXTURE), "PYTHONDONTWRITEBYTECODE": "1"}  # (the copy pip installed: 0.2.0's starter)
    environment.pop("QKVM_CHILD", None)
    said = tmp_path / "starter.txt"
    with said.open("w", encoding="utf-8") as out:
        starter = subprocess.Popen(
            [sys.executable, "-P", "-m", "qkvm", "--data-dir", str(data), "--port", str(port), "--bind", "local"],
            env=environment, cwd=tmp_path, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
        )  # fmt: skip
    try:
        deadline = time.monotonic() + 120  # (0.2.0's starter calls an update proven after it stayed up for thirty seconds)
        while True:
            pointer = data / "updates" / "current.json"
            noted = json.loads(pointer.read_text(encoding="utf-8")) if pointer.exists() else {}
            if noted.get("proven") is True:
                break
            if starter.poll() is not None or time.monotonic() > deadline or not pointer.exists():
                pytest.fail(f"the update did not start under 0.2.0's starter; current.json: {noted or '(gone)'}; it said:\n{said.read_text(encoding='utf-8')[-3000:]}")
            time.sleep(0.5)
        assert noted["version"] == "9.9.9"
        assert httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=10).json()["version"] == "9.9.9"  # this tree's code, serving
    finally:
        asked = {**environment, "PYTHONPATH": str(APP)}
        subprocess.run([sys.executable, "-P", "-m", "qkvm", "stop", "--data-dir", str(data)], env=asked, cwd=tmp_path, capture_output=True, timeout=90)
        try:
            starter.wait(60)
        except subprocess.TimeoutExpired:
            starter.kill()
            starter.wait(10)
