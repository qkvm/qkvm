"""Every release carries an SBOM: a CycloneDX 1.5 JSON of exactly what installing the version brings in, made from the
metadata of the environments it is installed in, with Python's own library alone (.github/security/make-sbom.py), and
signed with the rest (0.4.0, the support policy's item Q2).

The release workflow's job `libraries` installs each target's lock and the built wheel into an environment of its own,
as pip installs them there, from the wheels it downloaded and held to PyPI's hashes (make-libraries.py --environments),
reads the SBOM from them, and lists it in LIBRARIES.sums, whose hash it hands on; `sign` puts it in SHA256SUMS before it
signs; the draft and the publication hold the list to exactly this version's five files.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import importlib.util
import json
import re
import shutil
import sys
import tomllib
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from tests.workflow_text import APP, SECURITY, WORKFLOWS, jobs, steps

RELEASE = WORKFLOWS / "release.yml"
LINUX, WINDOWS = "cp313-linux-x86_64", "cp313-win-amd64"


def script(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), SECURITY / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SBOM = script("make-sbom")


def metadata(name: str, version: str, requires: tuple[str, ...] = (), **fields: Any) -> str:
    lines = ["Metadata-Version: 2.4", f"Name: {name}", f"Version: {version}"]
    for field, value in fields.items():
        for each in value if isinstance(value, list) else [value]:
            lines.append(f"{field.replace('_', '-')}: {each}")
    lines += [f"Requires-Dist: {each}" for each in requires]
    return "\n".join(lines) + "\n\n"


def installed(folder: Path, name: str, version: str, requires: tuple[str, ...] = (), **fields: Any) -> None:
    """A library as pip leaves it installed in a folder: its dist-info, with its metadata."""
    info = folder / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir(parents=True)
    (info / "METADATA").write_text(metadata(name, version, requires, **fields), encoding="utf-8")


def wheel_entry(file: str) -> dict[str, Any]:
    digest = hashlib.sha256(file.encode()).hexdigest()
    return {"file": file, "url": f"https://files.pythonhosted.org/packages/{digest[:2]}/{digest[2:4]}/{digest[4:]}/{file}", "sha256": digest, "size": 10, "unpacked": 20}


QKVM = ("alpha>=1", "beta[fast]>=2", 'winonly; sys_platform == "win32"', 'old; python_version < "3.11"')
PURE = {"alpha": "alpha-1.0-py3-none-any.whl", "beta": "Beta-2.0-py3-none-any.whl"}
GAMMA = {
    LINUX: ["gamma-3.0-cp313-cp313-manylinux_2_17_x86_64.manylinux2014_x86_64.whl", "gamma-3.0-cp313-cp313-manylinux_2_28_x86_64.whl"],
    WINDOWS: ["gamma-3.0-cp313-cp313-win_amd64.whl"],
}


def two_targets(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Environments of two targets as make-libraries.py leaves them, their lock, and the built wheel."""
    environments = tmp_path / "environments"
    lock: dict[str, Any] = {"format": 1, "version": "9.9.9", "targets": {}}
    for target in (LINUX, WINDOWS):
        here = environments / target
        installed(here, "qkvm", "9.9.9", QKVM, License_Expression="AGPL-3.0-only", Project_URL=["Homepage, https://qkvm.com", "Source, https://github.com/qkvm/qkvm", "Funding, https://example.org"])
        installed(here, "alpha", "1.0", License_Expression="MIT")
        installed(here, "Beta", "2.0", ('gamma>=3; extra == "fast"', 'delta; extra == "slow"'), License="BSD-3-Clause")
        installed(here, "gamma", "3.0", Classifier=["License :: OSI Approved :: Apache Software License", "Programming Language :: Python"])
        libraries = [
            {"name": "alpha", "version": "1.0", "wheels": [wheel_entry(PURE["alpha"])]},
            {"name": "beta", "version": "2.0", "wheels": [wheel_entry(PURE["beta"])]},
            {"name": "gamma", "version": "3.0", "wheels": [wheel_entry(file) for file in GAMMA[target]]},
        ]
        if target == WINDOWS:
            installed(here, "winonly", "1.0", License="Permission is hereby granted, free of charge,\n to any person")
            libraries.append({"name": "winonly", "version": "1.0", "wheels": [wheel_entry("winonly-1.0-py3-none-any.whl")]})
        lock["targets"][target] = {"libraries": libraries}
    path = tmp_path / "qkvm-9.9.9-libraries.json"
    path.write_text(json.dumps(lock), encoding="utf-8")
    wheel = tmp_path / "qkvm-9.9.9-py3-none-any.whl"
    wheel.write_bytes(b"the built wheel")
    return environments, path, wheel


def made(tmp_path: Path, environments: Path, lock: Path | None, wheel: Path, version: str = "9.9.9") -> dict[str, Any]:
    out = tmp_path / "out.cdx.json"
    SBOM.main(["--version", version, "--wheel", str(wheel), "--environments", str(environments), "--output", str(out), *(["--lock", str(lock)] if lock else [])])
    raw = out.read_bytes()
    assert raw.isascii() and raw.endswith(b"\n")
    return dict(json.loads(raw))


def test_the_sbom_names_each_library_with_its_licence_purl_wheels_and_targets(tmp_path: Path) -> None:
    environments, lock, wheel = two_targets(tmp_path)
    sbom = made(tmp_path, environments, lock, wheel)
    assert (sbom["bomFormat"], sbom["specVersion"], sbom["version"]) == ("CycloneDX", "1.5", 1)
    assert re.fullmatch(r"urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", sbom["serialNumber"])
    subject = sbom["metadata"]["component"]
    assert subject == {
        "type": "application", "bom-ref": "pkg:pypi/qkvm@9.9.9", "name": "qkvm", "version": "9.9.9", "licenses": [{"expression": "AGPL-3.0-only"}],
        "purl": "pkg:pypi/qkvm@9.9.9", "hashes": [{"alg": "SHA-256", "content": hashlib.sha256(b"the built wheel").hexdigest()}],
        "externalReferences": [{"type": "website", "url": "https://qkvm.com"}, {"type": "vcs", "url": "https://github.com/qkvm/qkvm"}],
    }  # fmt: skip
    assert sbom["metadata"]["properties"] == [{"name": "qkvm:targets", "value": f"{LINUX} {WINDOWS}"}]
    by = {each["name"]: each for each in sbom["components"]}
    assert [(each["name"], each["version"], each["purl"]) for each in sbom["components"]] == [
        ("alpha", "1.0", "pkg:pypi/alpha@1.0"), ("Beta", "2.0", "pkg:pypi/beta@2.0"), ("gamma", "3.0", "pkg:pypi/gamma@3.0"), ("winonly", "1.0", "pkg:pypi/winonly@1.0"),
    ]  # fmt: skip
    assert all(each["type"] == "library" and each["bom-ref"] == each["purl"] for each in sbom["components"])
    # The licence as the metadata says it: an expression, a short License field, the classifiers; a licence's text is none.
    assert by["alpha"]["licenses"] == [{"expression": "MIT"}]
    assert by["Beta"]["licenses"] == [{"license": {"name": "BSD-3-Clause"}}]
    assert by["gamma"]["licenses"] == [{"license": {"name": "Apache Software License"}}]
    assert "licenses" not in by["winonly"]
    # One wheel for every target: the component's own hash. Several: each a distribution reference, with its targets.
    alpha = wheel_entry(PURE["alpha"])
    assert by["alpha"]["hashes"] == [{"alg": "SHA-256", "content": alpha["sha256"]}]
    assert by["alpha"]["externalReferences"] == [{"type": "distribution", "url": alpha["url"], "hashes": [{"alg": "SHA-256", "content": alpha["sha256"]}], "comment": "the wheel for every target"}]
    assert "hashes" not in by["gamma"]
    gamma = {reference["url"].rsplit("/", 1)[1]: reference for reference in by["gamma"]["externalReferences"]}
    assert set(gamma) == {*GAMMA[LINUX], *GAMMA[WINDOWS]}
    assert gamma[GAMMA[LINUX][1]]["comment"] == f"the wheel for {LINUX}" and gamma[GAMMA[WINDOWS][0]]["comment"] == f"the wheel for {WINDOWS}"
    assert gamma[GAMMA[WINDOWS][0]]["hashes"] == [{"alg": "SHA-256", "content": wheel_entry(GAMMA[WINDOWS][0])["sha256"]}]
    assert by["winonly"]["properties"] == [{"name": "qkvm:targets", "value": WINDOWS}] and "properties" not in by["alpha"]
    # What each requires that is installed beside it: an extra only where it was asked for, a marker by what is installed.
    assert sbom["dependencies"] == [
        {"ref": "pkg:pypi/qkvm@9.9.9", "dependsOn": ["pkg:pypi/alpha@1.0", "pkg:pypi/beta@2.0", "pkg:pypi/winonly@1.0"]},
        {"ref": "pkg:pypi/alpha@1.0", "dependsOn": []},
        {"ref": "pkg:pypi/beta@2.0", "dependsOn": ["pkg:pypi/gamma@3.0"]},
        {"ref": "pkg:pypi/gamma@3.0", "dependsOn": []},
        {"ref": "pkg:pypi/winonly@1.0", "dependsOn": []},
    ]
    # The same input, the same bytes.
    again = made(tmp_path, environments, lock, wheel)
    assert again == sbom


def test_without_a_lock_it_names_what_is_installed_and_no_wheel(tmp_path: Path) -> None:
    environments, _, wheel = two_targets(tmp_path)
    sbom = made(tmp_path, environments, None, wheel)
    assert [each["name"] for each in sbom["components"]] == ["alpha", "Beta", "gamma", "winonly"]
    assert all("hashes" not in each and "externalReferences" not in each for each in sbom["components"])


@pytest.mark.parametrize(
    "spoil, said",
    [
        (lambda env, lock: installed(env / LINUX, "pip", "26.0", License_Expression="MIT"), "not brought in by qkvm: pip"),
        (lambda env, lock: shutil.rmtree(env / WINDOWS / "alpha-1.0.dist-info"), "qkvm requires alpha, which is not installed there"),
        (lambda env, lock: shutil.rmtree(env / LINUX / "gamma-3.0.dist-info"), f"{LINUX}: what is installed is not what the lock names (gamma 3.0)"),
        (lambda env, lock: (env / LINUX / "gamma-3.0.dist-info" / "METADATA").write_text("", encoding="utf-8"), "a library installed twice, or with no metadata"),
        (lambda env, lock: (env / LINUX / "alpha-1.0.dist-info" / "METADATA").write_text(metadata("alpha", "1.1"), encoding="utf-8"), "not what the lock names (alpha 1.0, alpha 1.1)"),
        (lambda env, lock: (env / "cp314-linux-x86_64").mkdir(), "are not the lock's targets"),
        (lambda env, lock: (env / WINDOWS / "qkvm-9.9.9.dist-info" / "METADATA").write_text(metadata("qkvm", "9.9.8", QKVM), encoding="utf-8"), "qkvm 9.9.9 is not installed there"),
        (lambda env, lock: lock.write_text(lock.read_text(encoding="utf-8").replace('"sha256": "', '"sha256": "x', 1), encoding="utf-8"), "has a wheel with no checksum or address"),
    ],
)
def test_what_is_not_exactly_what_the_version_brings_in_makes_no_sbom(tmp_path: Path, spoil: Any, said: str) -> None:
    environments, lock, wheel = two_targets(tmp_path)
    spoil(environments, lock)
    with pytest.raises(SystemExit, match=re.escape(said)):
        made(tmp_path, environments, lock, wheel)
    assert not (tmp_path / "out.cdx.json").exists()


def test_from_real_metadata_it_finds_what_packaging_finds(tmp_path: Path) -> None:
    # The metadata of the libraries qkvm runs here, as they are installed in this Python, read by the script's own reading
    # of the requirements (Python's library alone) and by packaging's (markers judged for this Python and system): both
    # come to the same libraries at the same versions. Every requirement packaging takes is among the SBOM's dependencies,
    # and every dependency of the SBOM is a requirement in the metadata (one whose marker is false here, of a library that
    # is installed all the same, is one: true on another target).
    from packaging.requirements import Requirement
    from packaging.utils import canonicalize_name

    project = tomllib.loads((APP / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = "9.9.9"
    here = tmp_path / "environments" / "this-python"
    installed(here, "qkvm", version, tuple(project["dependencies"]), License_Expression=project["license"])
    expected: dict[str, set[str]] = {}
    todo: list[tuple[str, tuple[str, ...], frozenset[str]]] = [("qkvm", tuple(project["dependencies"]), frozenset())]
    versions = {"qkvm": version}
    while todo:
        name, requires, extras = todo.pop()
        edges = expected.setdefault(name, set())
        for text in requires:
            requirement = Requirement(text)
            if requirement.marker is not None and not any(requirement.marker.evaluate({"extra": extra}) for extra in (sorted(extras) or [""])):
                continue
            dependency = canonicalize_name(requirement.name)
            edges.add(dependency)
            if dependency not in versions:
                distribution = importlib.metadata.distribution(requirement.name)
                versions[dependency] = distribution.version
                folder = here / f"{dependency.replace('-', '_')}-{distribution.version}.dist-info"
                folder.mkdir(parents=True)
                (folder / "METADATA").write_text(distribution.read_text("METADATA") or "", encoding="utf-8")
                todo.append((dependency, tuple(distribution.requires or ()), frozenset(requirement.extras)))
    wheel = tmp_path / f"qkvm-{version}-py3-none-any.whl"
    wheel.write_bytes(b"built")
    sbom = made(tmp_path, tmp_path / "environments", None, wheel, version)
    named = {SBOM.canonical(each["name"]): each for each in sbom["components"]}
    assert set(named) == set(versions) - {"qkvm"} and {"fastapi", "cryptography", "aiortc", "av"} <= set(named)
    assert all(named[name]["version"] == versions[name] for name in named)
    found = {each["ref"].split("/", 1)[1].split("@")[0]: {ref.split("/", 1)[1].split("@")[0] for ref in each["dependsOn"]} for each in sbom["dependencies"]}
    assert set(found) == set(versions)
    assert all(expected[name] <= found[name] for name in expected), {name: expected[name] - found[name] for name in expected}
    for name, edges in found.items():
        requires = tuple(project["dependencies"]) if name == "qkvm" else tuple(importlib.metadata.distribution(name).requires or ())
        assert edges <= {canonicalize_name(Requirement(text).name) for text in requires}, name
    assert sbom["metadata"]["component"]["licenses"] == [{"expression": "AGPL-3.0-only"}]
    assert named["fastapi"]["licenses"] == [{"expression": "MIT"}]
    assert sum("licenses" in each for each in named.values()) >= len(named) - 3, [name for name, each in named.items() if "licenses" not in each]


def a_wheel(folder: Path, file: str, requires: tuple[str, ...] = ()) -> Path:
    """A wheel as small as one can be, of the name, version and tags its file name gives."""
    name, version = file.split("-")[:2]
    tags = file[: -len(".whl")].split("-")[2:]
    info = f"{name}-{version}.dist-info"
    path = folder / file
    with zipfile.ZipFile(path, "w") as archive:
        files = {
            f"{name}/__init__.py": "",
            f"{info}/METADATA": metadata(name, version, requires, License_Expression="MIT"),
            f"{info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: test\nRoot-Is-Purelib: {'true' if tags[2] == 'any' else 'false'}\nTag: {'-'.join(tags)}\n",
        }
        record = "".join(f"{each},,\n" for each in [*files, f"{info}/RECORD"])
        for each, text in {**files, f"{info}/RECORD": record}.items():
            archive.writestr(each, text)
    return path


def test_the_lock_maker_installs_each_target_from_what_it_downloaded_and_the_sbom_reads_them(tmp_path: Path) -> None:
    # Real pip, as the release runs it (--target, another system's platform, nothing fetched): the environments the SBOM
    # is read from are what pip installs for each target from the wheels the lock maker downloaded.
    if importlib.util.find_spec("pip") is None:
        pytest.skip("this Python has no pip (the container image)")
    make = script("make-libraries")
    work, release = tmp_path / "work", tmp_path / "release"
    work.mkdir()
    release.mkdir()
    files = {LINUX: ["alpha-1.0-py3-none-any.whl", "gamma-3.0-cp313-cp313-manylinux_2_28_x86_64.whl"], WINDOWS: ["alpha-1.0-py3-none-any.whl", "gamma-3.0-cp313-cp313-win_amd64.whl"]}
    for file in {each for target in files.values() for each in target}:
        a_wheel(work, file, ("alpha>=1",) if file.startswith("gamma") else ())
    wheel = a_wheel(release, "qkvm-9.9.9-py3-none-any.whl", ("gamma",))
    lock: dict[str, Any] = {"format": 1, "version": "9.9.9", "targets": {}}
    for target, names in files.items():
        listed = []
        for file in names:
            digest = hashlib.sha256((work / file).read_bytes()).hexdigest()
            listed.append({"name": file.split("-")[0], "version": file.split("-")[1], "wheels": [{**wheel_entry(file), "sha256": digest}]})
        lock["targets"][target] = {"libraries": listed}
        locked = tmp_path / f"{target}.txt"
        locked.write_text("".join(f"{each['name']}=={each['version']} --hash=sha256:{each['wheels'][0]['sha256']}\n" for each in listed), encoding="utf-8")
        make.installed(target, wheel, work, locked, tmp_path / "environments" / target)
    lock_path = tmp_path / "qkvm-9.9.9-libraries.json"
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    sbom = made(tmp_path, tmp_path / "environments", lock_path, wheel)
    by = {each["name"]: each for each in sbom["components"]}
    assert sorted(by) == ["alpha", "gamma"]
    assert {reference["url"].rsplit("/", 1)[1] for reference in by["gamma"]["externalReferences"]} == {files[LINUX][1], files[WINDOWS][1]}
    assert sbom["metadata"]["component"]["hashes"][0]["content"] == hashlib.sha256(wheel.read_bytes()).hexdigest()
    # (And a wheel whose bytes are not the lock's is refused by pip, by its hash: nothing is installed of it.)
    (work / files[LINUX][0]).write_bytes(b"not the wheel")
    with pytest.raises(Exception, match="returned non-zero exit status"):
        make.installed(LINUX, wheel, work, tmp_path / f"{LINUX}.txt", tmp_path / "again")


def test_the_sbom_is_made_with_the_lock_held_to_its_jobs_hash_and_signed_with_the_rest() -> None:
    every = jobs(RELEASE)
    lock = next(step for step in steps(every["libraries"]) if "make-libraries.py" in step)
    assert '--out libraries --environments "$RUNNER_TEMP/environments"' in lock
    made_at = lock.index("python -I -S .github/security/make-sbom.py")
    assert lock.index("-m qkvm.release libraries") < made_at
    command = lock[made_at : lock.index("\n", made_at)]
    for part in ('--version "${TAG#v}"', '--wheel "release/qkvm-${TAG#v}-py3-none-any.whl"', '--lock "libraries/qkvm-${TAG#v}-libraries.json"',
                 '--environments "$RUNNER_TEMP/environments"', '--output "libraries/qkvm-${TAG#v}-sbom.cdx.json"'):  # fmt: skip
        assert part in command, part
    listed = lock.index('(cd libraries && sha256sum -- "qkvm-${TAG#v}-sbom.cdx.json" >> LIBRARIES.sums)')
    assert made_at < listed < lock.index("(cd libraries && sha256sum --check --strict LIBRARIES.sums)") < lock.index('echo "sums=$sums"')
    signing = steps(every["sign"])
    held = next(index for index, step in enumerate(signing) if "needs.libraries.outputs.sums" in step)
    signed = next(index for index, step in enumerate(signing) if "-m qkvm.release publish" in step)
    assert held < signed
    assert 'cp "libraries/qkvm-${TAG#v}-sbom.cdx.json" release/' in signing[held]
    assert '(cd release && sha256sum -- "qkvm-${TAG#v}-sbom.cdx.json" >> SHA256SUMS)' in signing[held]
    assert signing[held].index("(cd libraries && sha256sum --check --strict LIBRARIES.sums)") < signing[held].index('cp "libraries/qkvm-${TAG#v}-sbom.cdx.json"')


FIVE = "qkvm-${TAG#v}-image.json qkvm-${TAG#v}-libraries.json qkvm-${TAG#v}-py3-none-any.whl qkvm-${TAG#v}-sbom.cdx.json qkvm-${TAG#v}.tar.gz "


def test_the_draft_and_the_publication_hold_the_list_to_the_five_files_and_say_what_the_sbom_is() -> None:
    every = jobs(RELEASE)
    draft = "\n".join(steps(every["draft"]))
    assert draft.count(f'test "$listed" = "{FIVE}"') == 2
    assert f'test "$held" = "SHA256SUMS SHA256SUMS.sig {FIVE}"' in draft
    notes = re.search(r'--notes "([^"\n]*)"', draft)
    assert notes, draft
    assert "qkvm-${TAG#v}-sbom.cdx.json" in notes.group(1) and "CycloneDX 1.5" in notes.group(1)
    assert "SHA256SUMS lists it and SHA256SUMS.sig signs that list" in notes.group(1) and "under Updates in the guide" in notes.group(1)
    assert f'test "$listed" = "{FIVE}"' in "\n".join(steps(every["published"]))
    # (PyPI gets the two packages and nothing else: test_pypi_gets_only_the_signed_packages.)


def test_the_guide_and_the_security_policy_say_what_the_sbom_is_and_how_to_check_it() -> None:
    for name in ("GUIDE.md", "SECURITY.md"):
        text = " ".join((APP / name).read_text(encoding="utf-8").split())
        assert "qkvm-<version>-sbom.cdx.json" in text and "CycloneDX 1.5" in text, name
        assert "python -m qkvm.release verify --signed SHA256SUMS qkvm-<version>-sbom.cdx.json" in text, name


def test_the_script_uses_pythons_own_library_alone() -> None:
    text = (SECURITY / "make-sbom.py").read_text(encoding="utf-8")
    imported = {match.split(".")[0] for match in re.findall(r"^(?:from|import) ([A-Za-z_][\w.]*)", text, flags=re.M)}
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}, imported
