"""The release workflows read as text, as the tests of the image read its Dockerfile: by the lines that matter.

There is no YAML reader among what the tests are installed with, and none is needed: the workflows are written with
two spaces for a job, and a step starts with "- " at one depth throughout a job. What is looked for here is what a run
does (commands, `uses:`, `needs:`), so lines that are only comments are left out.
"""
from __future__ import annotations

import re
from pathlib import Path

APP = Path(__file__).resolve().parent.parent
WORKFLOWS = APP / ".github" / "workflows"
SECURITY = APP / ".github" / "security"


def uncommented(text: str) -> str:
    """The text without the lines that are only a comment (a comment is not what a run does)."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def jobs(path: Path) -> dict[str, str]:
    """Each job of a workflow by its name, with its own text (up to the next job), comments left out."""
    text = uncommented(path.read_text(encoding="utf-8")) + "\n"
    body = text[text.index("\njobs:\n") + len("\njobs:\n") :]
    parts = re.split(r"^  ([A-Za-z_][A-Za-z0-9_-]*):\n", body, flags=re.M)
    return {parts[index]: parts[index + 1] for index in range(1, len(parts), 2)}


def steps(text: str) -> list[str]:
    """The steps of a job (or of a composite action), each with its own text, in their order."""
    start = re.search(r"^ *steps:\n", text, flags=re.M)
    assert start, "no steps"
    body = uncommented(text[start.end() :])
    first = re.match(r"( *)- ", body)
    assert first, "no first step"
    return re.split(rf"^{first.group(1)}- ", body, flags=re.M)[1:]


def needs(job: str) -> set[str]:
    """The jobs a job waits for."""
    found = re.search(r"^    needs: *(.+)$", job, flags=re.M)
    if not found:
        return set()
    return {name.strip() for name in found.group(1).strip().strip("[]").split(",") if name.strip()}


def waits_for(all_jobs: dict[str, str], name: str) -> set[str]:
    """Every job that has to finish before this one starts, however far back."""
    seen: set[str] = set()
    todo = list(needs(all_jobs[name]))
    while todo:
        other = todo.pop()
        if other not in seen:
            seen.add(other)
            todo.extend(needs(all_jobs[other]))
    return seen
