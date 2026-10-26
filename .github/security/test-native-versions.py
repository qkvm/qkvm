#!/usr/bin/env python3
"""Regression tests for the gate on native libraries the scanner cannot see; stdlib only."""

from contextlib import redirect_stderr, redirect_stdout
from copy import deepcopy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).parent


def load(name, module):
    spec = importlib.util.spec_from_file_location(module, HERE / name)
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    return loaded


GATE = load("check-native-versions.py", "native_gate")
COLLECTOR = load("native-versions.py", "native_collector")
MINIMUMS = json.loads((HERE / "native-minimums.json").read_text(encoding="utf-8"))

# What the image of 0.2.0 said of itself on both architectures (python -P - < native-versions.py, 2026-10-26).
SHIPPED = {
    "cpython": "3.13.16",
    "ffmpeg": "8.1.1",
    "libvpx": "v1.16.0",
    "libopus": "libopus 1.6.1",
    "libdav1d": "1.5.3",
    "cryptography-openssl": "OpenSSL 4.0.3 29 Sep 2026",
    "pylibsrtp-libsrtp": "libsrtp2 2.7.0",
    "pylibsrtp-openssl": "OpenSSL 3.5.4 30 Sep 2025",
}


def recorded(arch="amd64", **raw):
    return {"schema": 1, "arch": arch, "raw": {**SHIPPED, **raw}, "context": {}}


class NativeVersions(unittest.TestCase):
    def evaluate(self, record, minimums=None, arch="amd64"):
        return GATE.evaluate(record, deepcopy(MINIMUMS) if minimums is None else minimums, arch)

    def test_what_the_image_ships_today_passes_on_both_architectures(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                versions, blocked = self.evaluate(recorded(arch), arch=arch)
                self.assertEqual(blocked, [])
                self.assertEqual(set(versions), set(SHIPPED))

    def test_the_kept_minimums_are_what_the_image_ships_today(self):
        # Raised on purpose only, with its reason; never lowered to let an older library through.
        for name, text in SHIPPED.items():
            with self.subTest(component=name):
                self.assertEqual(GATE.version_of(name, text), GATE.parse_version(MINIMUMS["components"][name]["minimum"]))

    def test_a_library_below_its_minimum_blocks(self):
        older = {
            "cpython": "3.13.15", "ffmpeg": "8.0.2", "libvpx": "v1.15.2", "libopus": "libopus 1.5.2",
            "libdav1d": "1.5.2", "cryptography-openssl": "OpenSSL 3.5.4 30 Sep 2025",
            "pylibsrtp-libsrtp": "libsrtp2 2.6.0", "pylibsrtp-openssl": "OpenSSL 3.0.15 3 Sep 2024",
        }
        for name, text in older.items():
            with self.subTest(component=name):
                _, blocked = self.evaluate(recorded(**{name: text}))
                self.assertTrue(any(name in row and "below" in row for row in blocked), blocked)

    def test_a_newer_library_passes(self):
        _, blocked = self.evaluate(recorded(ffmpeg="8.2", libvpx="v1.17.0", **{"pylibsrtp-openssl": "OpenSSL 3.6.1 1 Jan 2027"}))
        self.assertEqual(blocked, [])

    def test_a_version_that_cannot_be_read_blocks(self):
        for name, text in (("ffmpeg", "N-123456-gabcdef"), ("cpython", "3.14.0rc1"), ("libopus", "1.6.1"),
                           ("cryptography-openssl", "LibreSSL 4.0.0"), ("libvpx", ""), ("pylibsrtp-libsrtp", "libsrtp 2.7")):
            with self.subTest(component=name, text=text):
                _, blocked = self.evaluate(recorded(**{name: text}))
                self.assertTrue(any(name in row and "cannot" in row for row in blocked), blocked)

    def test_a_component_missing_or_unknown_is_refused(self):
        record = recorded()
        record["raw"].pop("libdav1d")
        with self.assertRaises(GATE.InvalidInput):
            self.evaluate(record)
        record = recorded(libwebp="1.6.0")
        with self.assertRaises(GATE.InvalidInput):
            self.evaluate(record)
        minimums = deepcopy(MINIMUMS)
        minimums["components"].pop("libdav1d")
        with self.assertRaises(GATE.InvalidInput):
            self.evaluate(recorded(), minimums)

    def test_the_minimums_must_say_why(self):
        mutations = [
            lambda doc: doc["components"]["ffmpeg"].update(reason=""),
            lambda doc: doc["components"]["ffmpeg"].pop("reason"),
            lambda doc: doc["components"]["ffmpeg"].update(minimum="8.1.x"),
            lambda doc: doc["components"]["ffmpeg"].update(extra="x"),
            lambda doc: doc["components"]["ffmpeg"].update(source=" "),
            lambda doc: doc.update(schema=2),
            lambda doc: doc["components"].update(libwebp={"minimum": "1.6.0", "source": "x", "reason": "y"}),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                minimums = deepcopy(MINIMUMS)
                mutate(minimums)
                with self.assertRaises(GATE.InvalidInput):
                    self.evaluate(recorded(), minimums)

    def test_the_record_must_be_of_this_architecture(self):
        with self.assertRaises(GATE.InvalidInput):
            self.evaluate(recorded("arm64"), arch="amd64")

    def test_the_collector_asks_for_exactly_what_is_gated(self):
        self.assertEqual(set(COLLECTOR.COMPONENTS), set(GATE.PATTERNS))
        self.assertEqual(set(MINIMUMS["components"]), set(GATE.PATTERNS))

    def test_the_command_line_says_no_with_its_exit_status(self):
        with tempfile.TemporaryDirectory() as directory:
            record_file = Path(directory) / "native-versions.json"
            minimums_file = HERE / "native-minimums.json"
            for record, expected, said in ((recorded(), 0, "PASS:"), (recorded(ffmpeg="7.1.2"), 1, "BLOCKED:"),
                                           ({"schema": 1}, 2, "INVALID INPUT:")):
                with self.subTest(expected=expected):
                    record_file.write_text(json.dumps(record), encoding="utf-8")
                    output = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(output):
                        self.assertEqual(GATE.main([str(record_file), "--minimums", str(minimums_file), "--arch", "amd64"]), expected)
                    self.assertIn(said, output.getvalue())


if __name__ == "__main__":
    unittest.main()
