#!/usr/bin/env python3
"""Regression tests for the making of a release's lock (make-libraries.py), with PyPI's listings stood in for: nothing is
resolved or downloaded here. Needs packaging, as the script does."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location("make_libraries", Path(__file__).with_name("make-libraries.py"))
MAKE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MAKE)
from qkvm import _libraries  # noqa: E402  (the checkout, put on the path by make-libraries.py)


def listed(file):
    digest = hashlib.blake2b(file.encode(), digest_size=32).hexdigest()
    return {
        "filename": file, "packagetype": "bdist_wheel", "yanked": False, "size": 1000,
        "url": f"https://files.pythonhosted.org/packages/{digest[:2]}/{digest[2:4]}/{digest[4:]}/{file}",
        "digests": {"sha256": hashlib.sha256(file.encode()).hexdigest()},
    }


AV = [
    "av-17.2.0-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl",
    "av-17.2.0-cp311-abi3-manylinux_2_28_x86_64.whl",
    "av-17.2.0-cp311-abi3-musllinux_1_2_x86_64.whl",
    "av-17.2.0-cp311-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl",
    "av-17.2.0-cp311-abi3-win_amd64.whl",
    "av-17.2.0-cp311-abi3-macosx_11_0_arm64.whl",
]
PURE = ["h11-0.16.0-py3-none-any.whl"]
LISTINGS = {("av", "17.2.0"): [listed(file) for file in AV] + [{"filename": "av-17.2.0.tar.gz", "packagetype": "sdist"}], ("h11", "0.16.0"): [listed(file) for file in PURE]}
SIZES = {file: 5000 for file in AV + PURE}


def chosen(target, av_file):
    return [
        {"name": "av", "version": "17.2.0", "file": av_file, "sha256": hashlib.sha256(av_file.encode()).hexdigest()},
        {"name": "h11", "version": "0.16.0", "file": PURE[0], "sha256": hashlib.sha256(PURE[0].encode()).hexdigest()},
    ]


class TheLock(unittest.TestCase):
    def test_the_tags_of_a_target_are_what_pip_takes_there(self):
        linux = {str(tag) for tag in MAKE.tags("cp311-linux-x86_64")}
        self.assertIn("cp311-abi3-manylinux_2_17_x86_64", linux)
        self.assertIn("cp311-abi3-manylinux_2_39_x86_64", linux)
        self.assertIn("py3-none-any", linux)
        self.assertNotIn("cp311-abi3-manylinux_2_40_x86_64", linux)
        self.assertNotIn("cp311-abi3-musllinux_1_2_x86_64", linux)
        self.assertIn("cp314-cp314-win_amd64", {str(tag) for tag in MAKE.tags("cp314-win-amd64")})

    def test_every_build_that_fits_a_target_is_listed_and_the_lock_is_one_the_program_reads(self):
        made = MAKE.lock("9.9.9", {
            "cp311-linux-x86_64": chosen("cp311-linux-x86_64", AV[1]),
            "cp311-linux-aarch64": chosen("cp311-linux-aarch64", AV[3]),
            "cp311-win-amd64": chosen("cp311-win-amd64", AV[4]),
        }, LISTINGS, SIZES)  # fmt: skip
        read = _libraries.read(made, "9.9.9")
        files = {target: {library.name: [wheel.file for wheel in library.wheels] for library in libraries} for target, libraries in read.targets.items()}
        self.assertEqual(files["cp311-linux-x86_64"]["av"], [AV[0], AV[1]])  # both glibc builds, so a wall takes what pip would
        self.assertEqual(files["cp311-linux-aarch64"]["av"], [AV[3]])
        self.assertEqual(files["cp311-win-amd64"], {"av": [AV[4]], "h11": PURE})
        self.assertEqual(json.loads(made)["targets"]["cp311-win-amd64"]["libraries"][0]["wheels"][0]["unpacked"], 5000)
        requirements = MAKE.requirements(read, "cp311-linux-x86_64").splitlines()
        self.assertEqual(requirements[0], "av==17.2.0 " + " ".join(f"--hash=sha256:{hashlib.sha256(file.encode()).hexdigest()}" for file in AV[:2]))

    def test_a_file_pip_chose_that_pypi_does_not_list_with_its_hash_stops_it(self):
        wrong = chosen("cp311-win-amd64", AV[4])
        wrong[0]["sha256"] = "0" * 64
        with self.assertRaises(SystemExit):
            MAKE.lock("9.9.9", {"cp311-win-amd64": wrong}, LISTINGS, SIZES)

    def test_a_dependency_is_judged_by_the_markers_of_each_target_and_not_by_the_python_that_runs_pip(self):
        # (The final review of 0.3.0, core L1.) pip judges the markers of what it resolves by the Python that runs it,
        # whatever target it is told: run on Linux 3.13, a dependency for Windows alone, or for Pythons before 3.12, was
        # left out of those targets' locks. Here as a locker on Windows 3.14 would have it (winonly in, the others out).
        top = ['winonly; sys_platform == "win32"', 'linuxonly; sys_platform == "linux"', 'old>=1; python_version < "3.12"', 'extraonly; extra == "more"']
        items = [item("qkvm", ["top"]), item("top", top), item("winonly")]
        self.assertEqual(MAKE.needed(items, "cp311-linux-x86_64"), ({"top"}, ["linuxonly", "old>=1"]))
        self.assertEqual(MAKE.needed(items, "cp314-linux-aarch64"), ({"top"}, ["linuxonly"]))
        self.assertEqual(MAKE.needed(items, "cp313-win-amd64"), ({"top", "winonly"}, []))
        self.assertEqual(MAKE.needed(items, "cp311-win-amd64"), ({"top", "winonly"}, ["old>=1"]))
        environment = MAKE.environments("cp312-win-amd64")[0]
        self.assertEqual((environment["sys_platform"], environment["platform_machine"], environment["python_version"]), ("win32", "AMD64", "3.12"))

    def test_what_a_target_needs_that_pip_left_out_is_asked_for_and_what_it_does_not_need_is_not_locked(self):
        asked = []

        def pip(command, check):
            report = Path(command[command.index("--report") + 1])
            wanted = command[command.index(str(WHEEL)) + 1 :]
            asked.append(wanted)
            items = [item("qkvm", ["top"]), item("top", ['winonly; sys_platform == "win32"', 'linuxonly; sys_platform == "linux"', 'old; python_version < "3.12"']), item("winonly")]
            items += [item(name.split(">")[0]) for name in wanted]
            report.write_text(json.dumps({"install": items}), encoding="utf-8")

        real, MAKE.subprocess.run = MAKE.subprocess.run, pip
        try:
            with tempfile.TemporaryDirectory() as work:
                chosen = MAKE.resolved(WHEEL, "cp311-linux-x86_64", Path(work))
        finally:
            MAKE.subprocess.run = real
        self.assertEqual(sorted(each["name"] for each in chosen), ["linuxonly", "old", "top"])
        self.assertEqual(asked, [[], ["linuxonly", "old"]])


WHEEL = Path("qkvm-9.9.9-py3-none-any.whl")


def item(name, requires=()):
    """An entry of pip's report (--report) of what it would install: its metadata and where it is downloaded from."""
    file = f"{name}-1.0-py3-none-any.whl"
    return {
        "metadata": {"name": name, "version": "1.0", "requires_dist": list(requires)},
        "download_info": {"url": listed(file)["url"], "archive_info": {"hashes": {"sha256": hashlib.sha256(file.encode()).hexdigest()}}},
    }


if __name__ == "__main__":
    sys.exit(unittest.main())
