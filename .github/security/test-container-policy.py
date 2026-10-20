#!/usr/bin/env python3
"""Regression tests for fail-closed container release decisions; stdlib only."""

from copy import deepcopy
from datetime import date, timedelta
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr


SPEC = importlib.util.spec_from_file_location(
    "container_policy", Path(__file__).with_name("check-container-scan.py")
)
POLICY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(POLICY)
TODAY = date(2026, 10, 20)


def clean_report():
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "debian", "Name": "13.7"},
            "ImageConfig": {
                "architecture": "amd64", "os": "linux", "config": {"User": "qkvm"},
            },
        },
        "Results": [
            {
                "Class": "os-pkgs", "Type": "debian",
                "Packages": [{"Name": "libc6", "Version": "2.41", "Release": "12+deb13u4"}],
            },
            {
                "Class": "lang-pkgs", "Type": "python-pkg",
                "Packages": [{"Name": "qkvm", "Version": "0.2.0"}],
            },
        ],
    }


def exceptions():
    return {
        "schema": 1, "os": {"family": "debian", "version": "13.7"},
        "exceptions": [{
            "id": "CVE-2026-12345", "severity": "HIGH",
            "architectures": ["amd64", "arm64"],
            "packages": {"libc6": "2.41-12+deb13u4"},
            "reviewed": "2026-10-20", "expires": "2026-11-19",
            "reason": "Unfixed Debian issue reviewed for this exact runtime package.",
            "references": ["https://security-tracker.debian.org/tracker/CVE-2026-12345"],
        }],
    }


def add_finding(report, *, severity="HIGH", result_index=0, **changes):
    finding = {
        "VulnerabilityID": "CVE-2026-12345",
        "PkgName": "libc6", "InstalledVersion": "2.41-12+deb13u4",
        "Severity": severity,
    }
    if result_index == 1:
        finding.update(PkgName="qkvm", InstalledVersion="0.2.0")
    finding.update(changes)
    report["Results"][result_index].setdefault("Vulnerabilities", []).append(finding)
    return finding


class ContainerPolicyTests(unittest.TestCase):
    def setUp(self):
        self.report = clean_report()
        self.exceptions = exceptions()

    def evaluate(self, *, arch="amd64", today=TODAY):
        return POLICY.evaluate(self.report, self.exceptions, arch, today)

    def assertBlocked(self, text, **kwargs):
        violations, _, _, _ = self.evaluate(**kwargs)
        self.assertTrue(any(text in item for item in violations), violations)

    def test_clean_inventory_without_vulnerabilities_field_passes(self):
        violations, accepted, residual, inventory = self.evaluate()
        self.assertEqual((violations, accepted, residual), ([], [], {}))
        self.assertEqual(inventory, {"debian": 1, "python-pkg": 1})

    def test_exact_reviewed_exception_is_visible(self):
        add_finding(self.report)
        violations, accepted, _, _ = self.evaluate()
        self.assertEqual(violations, [])
        self.assertEqual(len(accepted), 1)
        self.assertIn("libc6@2.41-12+deb13u4", accepted[0])
        self.assertIn("2026-11-19", accepted[0])
        self.assertIn("https://security-tracker.debian.org/", accepted[0])

    def test_lower_unfixed_findings_are_disclosed(self):
        for severity in ["UNKNOWN", "LOW", "MEDIUM"]:
            add_finding(self.report, severity=severity)
        violations, accepted, residual, _ = self.evaluate()
        self.assertEqual(violations, [])
        self.assertEqual(accepted, [])
        self.assertEqual(residual, {"UNKNOWN": 1, "LOW": 1, "MEDIUM": 1})

    def test_every_python_finding_blocks_even_if_unfixed_and_low(self):
        for severity in POLICY.SEVERITIES:
            with self.subTest(severity=severity):
                self.report = clean_report()
                add_finding(self.report, result_index=1, severity=severity)
                self.assertBlocked("all Python vulnerabilities")

    def test_fixed_os_findings_block_at_every_severity(self):
        for severity in POLICY.SEVERITIES:
            with self.subTest(severity=severity):
                self.report = clean_report()
                add_finding(self.report, severity=severity, FixedVersion="2.42-1")
                self.assertBlocked("fixed version available")

    def test_critical_overrides_matching_exception(self):
        add_finding(self.report, severity="CRITICAL")
        self.assertBlocked("CRITICAL always")

    def test_whitespace_fixed_version_cannot_bypass_gate(self):
        add_finding(self.report, FixedVersion=" ")
        self.assertBlocked("fixed version available")

    def test_new_id_cannot_use_another_exception(self):
        add_finding(self.report, VulnerabilityID="CVE-2026-99999")
        self.assertBlocked("no current exact exception")

    def test_changed_package_version_cannot_use_exception(self):
        self.report["Results"][0]["Packages"][0]["Release"] = "12+deb13u5"
        add_finding(self.report, InstalledVersion="2.41-12+deb13u5")
        self.assertBlocked("no current exact exception")

    def test_changed_package_name_cannot_use_exception(self):
        self.report["Results"][0]["Packages"][0]["Name"] = "libc-bin"
        add_finding(self.report, PkgName="libc-bin")
        self.assertBlocked("no current exact exception")

    def test_changed_os_version_cannot_use_exception(self):
        self.report["Metadata"]["OS"]["Name"] = "13.8"
        add_finding(self.report)
        self.assertBlocked("no current exact exception")

    def test_changed_os_family_cannot_use_exception(self):
        self.report["Metadata"]["OS"]["Family"] = "ubuntu"
        add_finding(self.report)
        self.assertBlocked("no current exact exception")
        self.assertBlocked("unsupported OS family")

    def test_architecture_must_match_image_and_exception(self):
        add_finding(self.report)
        self.assertBlocked("does not match requested", arch="arm64")
        self.report["Metadata"]["ImageConfig"]["architecture"] = "arm64"
        self.exceptions["exceptions"][0]["architectures"] = ["amd64"]
        self.assertBlocked("no current exact exception", arch="arm64")

    def test_unknown_architectures_fail_closed(self):
        with self.assertRaises(POLICY.InvalidInput):
            self.evaluate(arch="riscv64")
        self.report["Metadata"]["ImageConfig"]["architecture"] = "riscv64"
        self.assertBlocked("does not match requested")

    def test_expiry_boundary_is_first_invalid_utc_date(self):
        add_finding(self.report)
        self.assertEqual(self.evaluate(today=date(2026, 11, 18))[0], [])
        self.assertBlocked("exception expired", today=date(2026, 11, 19))
        self.assertBlocked("no current exact exception", today=date(2026, 11, 19))

    def test_unused_expired_exceptions_still_require_cleanup(self):
        self.assertBlocked("exception expired", today=date(2026, 11, 20))

    def test_future_review_cannot_authorize_finding(self):
        add_finding(self.report)
        self.assertBlocked("is in the future", today=TODAY - timedelta(days=1))
        self.assertBlocked("no current exact exception", today=TODAY - timedelta(days=1))

    def test_overlong_and_invalid_exception_dates_are_rejected(self):
        for reviewed, expires in [
            ("2026-10-20", "2026-11-21"), ("2026-10-20", "2026-10-20"),
            ("2026-10-20", "2026-10-19"), ("2026-2-01", "2026-02-28"),
            ("2026-02-30", "2026-03-01"),
        ]:
            with self.subTest(reviewed=reviewed, expires=expires):
                self.exceptions = exceptions()
                self.exceptions["exceptions"][0].update(reviewed=reviewed, expires=expires)
                with self.assertRaises(POLICY.InvalidInput):
                    self.evaluate()

    def test_exception_schema_cannot_broaden_matching(self):
        mutations = [
            lambda doc: doc.update(schema=True),
            lambda doc: doc.update(ignored="unexpected"),
            lambda doc: doc["os"].update(family="ubuntu"),
            lambda doc: doc["exceptions"][0].update(severity="CRITICAL"),
            lambda doc: doc["exceptions"][0].update(packages={"*": "*"}),
            lambda doc: doc["exceptions"][0].update(architectures=["*"]),
            lambda doc: doc["exceptions"][0].update(architectures=["amd64", "amd64"]),
            lambda doc: doc["exceptions"][0].update(reason=""),
            lambda doc: doc["exceptions"][0].update(references=["http://example.com/"]),
            lambda doc: doc["exceptions"][0].update(references=["https://[/"]),
            lambda doc: doc["exceptions"][0].update(packages={}),
            lambda doc: doc["exceptions"].append(deepcopy(doc["exceptions"][0])),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.exceptions = exceptions()
                mutate(self.exceptions)
                with self.assertRaises(POLICY.InvalidInput):
                    self.evaluate()

    def test_missing_or_invalid_report_metadata_fails_closed(self):
        mutations = [
            lambda doc: doc.update(SchemaVersion=True),
            lambda doc: doc.update(SchemaVersion=3),
            lambda doc: doc.update(ArtifactType="filesystem"),
            lambda doc: doc.pop("Metadata"),
            lambda doc: doc["Metadata"].pop("OS"),
            lambda doc: doc["Metadata"]["OS"].pop("Name"),
            lambda doc: doc["Metadata"]["OS"].update(EOSL="false"),
            lambda doc: doc["Metadata"].pop("ImageConfig"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.report = clean_report()
                mutate(self.report)
                with self.assertRaises(POLICY.InvalidInput):
                    self.evaluate()

    def test_eol_os_blocks_without_any_findings(self):
        self.report["Metadata"]["OS"]["EOSL"] = True
        self.assertBlocked("past end of support")

    def test_root_ambiguous_and_missing_image_users_block(self):
        for user in [None, "", "root", "root:root", "0", "00", "0:10001", ":10001", "qkvm:", "unknown", " qkvm"]:
            with self.subTest(user=user):
                self.report["Metadata"]["ImageConfig"]["config"]["User"] = user
                self.assertBlocked("must declare USER")

    def test_nonroot_declared_users_pass(self):
        for user in ["qkvm", "qkvm:qkvm", "10001", "10001:10001"]:
            with self.subTest(user=user):
                self.report["Metadata"]["ImageConfig"]["config"]["User"] = user
                self.assertEqual(self.evaluate()[0], [])

    def test_missing_results_and_empty_inventories_fail_closed(self):
        mutations = [
            lambda doc: doc.pop("Results"),
            lambda doc: doc.update(Results=[]),
            lambda doc: doc.update(Results=None),
            lambda doc: doc["Results"].pop(0),
            lambda doc: doc["Results"].pop(1),
            lambda doc: doc["Results"][0].pop("Packages"),
            lambda doc: doc["Results"][1].update(Packages=[]),
            lambda doc: doc["Results"][1]["Packages"][0].update(Name="pip"),
            lambda doc: doc["Results"][0].update(Type="alpine"),
            lambda doc: doc["Results"][0].update(Type=[]),
            lambda doc: doc["Results"][0].update(Class={}),
            lambda doc: doc["Results"][0].update(Vulnerabilities=None),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.report = clean_report()
                mutate(self.report)
                with self.assertRaises(POLICY.InvalidInput):
                    self.evaluate()

    def test_malformed_finding_cannot_disappear(self):
        mutations = [
            lambda finding: finding.update(Severity="high"),
            lambda finding: finding.pop("Severity"),
            lambda finding: finding.pop("VulnerabilityID"),
            lambda finding: finding.update(PkgName="not-in-inventory"),
            lambda finding: finding.update(FixedVersion=None),
            lambda finding: finding.update(InstalledVersion=""),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.report = clean_report()
                finding = add_finding(self.report)
                mutate(finding)
                with self.assertRaises(POLICY.InvalidInput):
                    self.evaluate()

    def test_debian_epoch_and_release_are_exact(self):
        self.report["Results"][0]["Packages"][0]["Epoch"] = 1
        self.exceptions["exceptions"][0]["packages"]["libc6"] = "1:2.41-12+deb13u4"
        add_finding(self.report, InstalledVersion="1:2.41-12+deb13u4")
        self.assertEqual(self.evaluate()[0], [])
        self.exceptions["exceptions"][0]["packages"]["libc6"] = "2.41-12+deb13u4"
        self.assertBlocked("no current exact exception")

    def test_json_duplicate_keys_and_nonstandard_numbers_rejected(self):
        for value in ['{"schema":1,"schema":2}', '{"schema":NaN}']:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "input.json"
                path.write_text(value, encoding="utf-8")
                with self.assertRaises(POLICY.InvalidInput):
                    POLICY.load_json(path)

    def test_cli_exit_status_distinguishes_blocked_and_invalid(self):
        # Empty policy is independent of the calendar date when the tests are run.
        self.exceptions["exceptions"] = []
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / "report.json"
            policy = Path(directory) / "policy.json"
            policy.write_text(json.dumps(self.exceptions), encoding="utf-8")
            arguments = [str(report), "--exceptions", str(policy), "--arch", "amd64"]
            for expected in [0, 1, 2]:
                with self.subTest(expected=expected):
                    self.report = clean_report()
                    if expected == 1:
                        add_finding(self.report)
                    elif expected == 2:
                        self.report.pop("Results")
                    report.write_text(json.dumps(self.report), encoding="utf-8")
                    output = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(output):
                        self.assertEqual(POLICY.main(arguments), expected)
                    self.assertIn({0: "PASS:", 1: "BLOCKED:", 2: "INVALID INPUT:"}[expected], output.getvalue())


if __name__ == "__main__":
    unittest.main()
