#!/usr/bin/env python3
"""Regression tests for holding the source archive to the tested wheel; stdlib only."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
import zipfile
import zlib

SPEC = importlib.util.spec_from_file_location("check_sdist", Path(__file__).with_name("check-sdist.py"))
SDIST = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SDIST)

METADATA = """Metadata-Version: 2.4
Name: qkvm
Version: 9.9.9
Requires-Python: >=3.11
Requires-Dist: cryptography>=50
Requires-Dist: fastapi>=0.142

The description.
"""
CODE = {"qkvm/__init__.py": b"", "qkvm/_version.py": b'__version__ = "9.9.9"\n', "qkvm/static/app.js": b"js"}


def raw_zip_entry(name):
    """A zip entry under exactly this name (ZipInfo would turn a backslash into a slash on Windows)."""
    info = zipfile.ZipInfo("placeholder")
    info.filename = name
    return info


def make(folder, *, wheel_files=None, sdist_files=None, wheel_metadata=METADATA, sdist_metadata=METADATA, root="qkvm-9.9.9", extra_root=False,
         wheel_extra=None, sdist_raw=None):
    wheel = folder / "qkvm-9.9.9-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        for name, data in (CODE if wheel_files is None else wheel_files).items():
            archive.writestr(name, data)
        archive.writestr("qkvm-9.9.9.dist-info/METADATA", wheel_metadata)
        archive.writestr("qkvm-9.9.9.dist-info/RECORD", "")
        archive.writestr("qkvm-9.9.9.dist-info/licenses/LICENSE", "AGPL")
        for name, data in (wheel_extra or {}).items():
            archive.writestr(raw_zip_entry(name), data)
    sdist = folder / "qkvm-9.9.9.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        contents = {**(CODE if sdist_files is None else sdist_files), "PKG-INFO": sdist_metadata.encode(),
                    "pyproject.toml": b"[project]\n", "tests/test_x.py": b""}
        for name, data in contents.items():
            info = tarfile.TarInfo(f"{root}/{name}")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        for name, data in (sdist_raw or {}).items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        if extra_root:
            info = tarfile.TarInfo("elsewhere/qkvm/__init__.py")
            archive.addfile(info, io.BytesIO(b""))
    return wheel, sdist


class SourceArchive(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.folder = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def test_the_same_code_and_metadata_pass(self):
        SDIST.check(*make(self.folder))

    def test_different_code_is_refused(self):
        cases = {
            "changed": dict(sdist_files={**CODE, "qkvm/static/app.js": b"other js"}),
            "only in the source": dict(sdist_files={**CODE, "qkvm/extra.py": b""}),
            "only in the wheel": dict(wheel_files={**CODE, "qkvm/extra.py": b""}),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(SDIST.Refused):
                    SDIST.check(*make(self.folder, **change))

    def test_different_metadata_is_refused(self):
        for old, new in (("Version: 9.9.9", "Version: 9.9.8"), ("Requires-Dist: fastapi>=0.142\n", ""),
                         ("cryptography>=50", "cryptography>=1"), ("Requires-Python: >=3.11", "Requires-Python: >=3.9"),
                         ("Name: qkvm", "Name: qkvm-other")):
            with self.subTest(change=old):
                with self.assertRaises(SDIST.Refused):
                    SDIST.check(*make(self.folder, sdist_metadata=METADATA.replace(old, new)))

    def test_an_archive_that_is_not_one_package_is_refused(self):
        with self.assertRaises(SDIST.Refused):
            SDIST.check(*make(self.folder, extra_root=True))
        with self.assertRaises(SDIST.Refused):
            SDIST.check(*make(self.folder, root="qkvm-9.9.8"))
        with self.assertRaises(SDIST.Refused):
            SDIST.check(*make(self.folder, wheel_files={}, sdist_files={}))

    def test_a_wheel_with_anything_beside_its_package_and_its_dist_info_is_refused(self):
        # A top-level .pth runs at every start of the Python it is installed into; nothing of the kind belongs here.
        for extra in ({"evil.pth": "import os"}, {"qkvm.libs/native.so": b"\x7fELF"}, {"qkvm-9.9.8.dist-info/METADATA": METADATA},
                      {"qkvm-9.9.9.data/scripts/run": "#!/bin/sh"}, {"other/__init__.py": ""}):
            with self.subTest(extra=sorted(extra)):
                with self.assertRaises(SDIST.Refused):
                    SDIST.check(*make(self.folder, wheel_extra=extra))

    def test_a_name_that_is_not_plain_is_refused_in_either(self):
        # pip makes qkvm/../evil.pth into site-packages/evil.pth; nothing but plain names belongs in either archive.
        names = ("qkvm-9.9.9.dist-info/../evil.pth", "qkvm/../evil.pth", "qkvm/./x.py", "qkvm//x.py", "qkvm/x\\y.py",
                 "/qkvm/x.py", "qkvm/sub/..", "qkvm/.")
        for name in names:
            with self.subTest(wheel=name):
                with self.assertRaisesRegex(SDIST.Refused, "not plain"):
                    SDIST.check(*make(self.folder, wheel_extra={name: b"x"}))
            with self.subTest(sdist=name):
                with self.assertRaisesRegex(SDIST.Refused, "not plain"):
                    SDIST.check(*make(self.folder, sdist_raw={f"qkvm-9.9.9/{name.lstrip('/')}" if not name.startswith("/") else name: b"x"}))

    def test_a_unicode_path_field_that_names_another_file_is_refused(self):
        # Since Python 3.12 zipfile takes an entry's name from its Unicode Path extra field (0x7075) where that field's
        # checksum of the stored name matches, and pip installs by that name; the check must see it on any Python.
        def unicode_path(stored, said):
            data = struct.pack("<B", 1) + struct.pack("<I", zlib.crc32(stored.encode())) + said.encode()
            return struct.pack("<HH", 0x7075, len(data)) + data

        stored = "qkvm-9.9.9.dist-info/x.txt"
        for said in ("qkvm-9.9.9.dist-info/../evil.pth", "qkvm-9.9.9.dist-info/y.txt"):
            with self.subTest(said=said):
                wheel, sdist = make(self.folder)
                with zipfile.ZipFile(wheel, "a") as archive:
                    info = zipfile.ZipInfo(stored)
                    info.extra = unicode_path(stored, said)
                    archive.writestr(info, b"x")
                with self.assertRaisesRegex(SDIST.Refused, "Unicode Path"):
                    SDIST.check(wheel, sdist)
        wheel, sdist = make(self.folder)
        with zipfile.ZipFile(wheel, "a") as archive:  # (a field that says the stored name again is harmless)
            info = zipfile.ZipInfo(stored)
            info.extra = unicode_path(stored, stored)
            archive.writestr(info, b"x")
        SDIST.check(wheel, sdist)

    def test_the_command_says_no_with_its_exit_status(self):
        for change, expected in (({}, 0), ({"sdist_files": {**CODE, "qkvm/extra.py": b""}}, 1)):
            with self.subTest(expected=expected):
                wheel, sdist = make(self.folder, **change)
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(SDIST.main([str(wheel), str(sdist)]), expected)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(SDIST.main([str(wheel)]), 2)


if __name__ == "__main__":
    unittest.main()
