#!/usr/bin/env python3
"""Apply the release policy to a complete Trivy container vulnerability report.

Run Trivy with --scanners vuln --list-all-pkgs and without severity/ignore filters.
The caller must independently enforce scanner database freshness. Exit status:
0 = policy passed (possibly with disclosed residual risk), 1 = policy violation,
2 = malformed or incomplete input. This is not a signature verifier for reports.
"""

import argparse
from collections import Counter
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlsplit


ARCHITECTURES = {"amd64", "arm64"}
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


class InvalidInput(ValueError):
    """The report or exception document cannot safely be interpreted."""


def object_value(value, label):
    if not isinstance(value, dict):
        raise InvalidInput(f"{label} must be an object")
    return value


def text_value(value, label):
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise InvalidInput(f"{label} must be a nonempty string without outer whitespace")
    return value


def list_value(value, label, *, nonempty=False):
    if not isinstance(value, list) or (nonempty and not value):
        raise InvalidInput(f"{label} must be {'a nonempty' if nonempty else 'an'} array")
    return value


def exact_keys(value, keys, label):
    if set(value) != set(keys):
        raise InvalidInput(f"{label} must contain exactly: {', '.join(sorted(keys))}")


def date_value(value, label):
    text_value(value, label)
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise InvalidInput(f"{label} must use YYYY-MM-DD")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise InvalidInput(f"{label} is not a valid date") from exc


def exception_policy(document, today):
    """Validate every exception, including unused ones, so stale policy fails."""
    document = object_value(document, "exceptions")
    exact_keys(document, {"schema", "os", "exceptions"}, "exceptions")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise InvalidInput("exceptions.schema must be 1")
    os_info = object_value(document["os"], "exceptions.os")
    exact_keys(os_info, {"family", "version"}, "exceptions.os")
    if os_info["family"] != "debian":
        raise InvalidInput("exceptions.os.family must be debian")
    text_value(os_info["version"], "exceptions.os.version")
    entries = {}
    violations = []
    fields = {
        "id", "severity", "architectures", "packages", "reviewed", "expires",
        "reason", "references",
    }
    for index, item in enumerate(list_value(document["exceptions"], "exceptions.exceptions")):
        label = f"exceptions.exceptions[{index}]"
        item = object_value(item, label)
        exact_keys(item, fields, label)
        identifier = text_value(item["id"], f"{label}.id")
        if identifier in entries:
            raise InvalidInput(f"duplicate exception ID: {identifier}")
        if item["severity"] != "HIGH":
            raise InvalidInput(f"{identifier}: only HIGH exceptions are permitted")
        arches = list_value(item["architectures"], f"{label}.architectures", nonempty=True)
        if any(not isinstance(arch, str) or arch not in ARCHITECTURES for arch in arches):
            raise InvalidInput(f"{identifier}: unsupported exception architecture")
        if len(arches) != len(set(arches)):
            raise InvalidInput(f"{identifier}: duplicate exception architecture")
        packages = object_value(item["packages"], f"{label}.packages")
        if not packages:
            raise InvalidInput(f"{identifier}: packages must not be empty")
        for name, version in packages.items():
            text_value(name, f"{identifier} package name")
            text_value(version, f"{identifier} package version")
            if any(char in name + version for char in "*?[]"):
                raise InvalidInput(f"{identifier}: package wildcards are forbidden")
        reviewed = date_value(item["reviewed"], f"{label}.reviewed")
        expires = date_value(item["expires"], f"{label}.expires")
        if not 0 < (expires - reviewed).days <= 31:
            raise InvalidInput(f"{identifier}: exception lifetime must be 1 through 31 days")
        if reviewed > today:
            violations.append(f"{identifier}: review date {reviewed} is in the future")
        # expires is the first UTC calendar date on which the exception is invalid.
        if today >= expires:
            violations.append(f"{identifier}: exception expired at {expires} 00:00 UTC")
        text_value(item["reason"], f"{label}.reason")
        for reference in list_value(item["references"], f"{label}.references", nonempty=True):
            text_value(reference, f"{identifier} reference")
            try:
                parsed = urlsplit(reference)
                valid_reference = parsed.scheme == "https" and bool(parsed.hostname)
            except ValueError as exc:
                raise InvalidInput(f"{identifier}: malformed reference URL") from exc
            if not valid_reference:
                raise InvalidInput(f"{identifier}: references must be absolute HTTPS URLs")
        entries[identifier] = item
    return os_info, entries, violations


def package_inventory(result, result_type, label):
    inventory = set()
    packages = list_value(result.get("Packages"), f"{label}.Packages", nonempty=True)
    for index, package in enumerate(packages):
        item_label = f"{label}.Packages[{index}]"
        package = object_value(package, item_label)
        name = text_value(package.get("Name"), f"{item_label}.Name")
        version = text_value(package.get("Version"), f"{item_label}.Version")
        if result_type == "debian":
            epoch = package.get("Epoch", 0)
            if type(epoch) is not int or epoch < 0:
                raise InvalidInput(f"{item_label}.Epoch must be a nonnegative integer")
            release = package.get("Release", "")
            if not isinstance(release, str):
                raise InvalidInput(f"{item_label}.Release must be a string")
            version = (f"{epoch}:" if epoch else "") + version
            if release:
                version += f"-{release}"
        inventory.add((name, version))
    return inventory


def nonroot_user(value):
    """The Dockerfile defines qkvm; all other named users require manual review."""
    if not isinstance(value, str) or value != value.strip():
        return False
    parts = value.split(":")
    if len(parts) > 2 or any(not part for part in parts):
        return False
    user = parts[0]
    return user == "qkvm" or (
        re.fullmatch(r"[0-9]+", user) is not None and bool(user.lstrip("0"))
    )


def evaluate(report, document, arch, today=None):
    """Return policy violations, accepted HIGH rows, residual counts and inventory."""
    if arch not in ARCHITECTURES:
        raise InvalidInput(f"unsupported requested architecture: {arch}")
    today = today or datetime.now(timezone.utc).date()
    policy_os, exceptions, violations = exception_policy(document, today)
    report = object_value(report, "report")
    if type(report.get("SchemaVersion")) is not int or report["SchemaVersion"] != 2:
        raise InvalidInput("report.SchemaVersion must be 2")
    if report.get("ArtifactType") != "container_image":
        raise InvalidInput("report.ArtifactType must be container_image")
    metadata = object_value(report.get("Metadata"), "report.Metadata")
    os_info = object_value(metadata.get("OS"), "report.Metadata.OS")
    family = text_value(os_info.get("Family"), "report.Metadata.OS.Family")
    version = text_value(os_info.get("Name"), "report.Metadata.OS.Name")
    if family != "debian":
        violations.append(f"unsupported OS family: {family}")
    eosl = os_info.get("EOSL", False)
    if not isinstance(eosl, bool):
        raise InvalidInput("report.Metadata.OS.EOSL must be a boolean")
    if eosl:
        violations.append(f"{family} {version} is past end of support")
    image = object_value(metadata.get("ImageConfig"), "report.Metadata.ImageConfig")
    image_arch = text_value(image.get("architecture"), "ImageConfig.architecture")
    if image_arch != arch:
        violations.append(f"image architecture {image_arch} does not match requested {arch}")
    if image.get("os") != "linux":
        violations.append("image operating system must be linux")
    config = object_value(image.get("config"), "ImageConfig.config")
    if not nonroot_user(config.get("User")):
        violations.append("image must declare USER qkvm or a positive numeric UID")

    accepted = []
    residual = Counter()
    inventory_counts = Counter()
    python_names = set()
    os_matches = family == policy_os["family"] and version == policy_os["version"]
    results = list_value(report.get("Results"), "report.Results", nonempty=True)
    for index, result in enumerate(results):
        label = f"report.Results[{index}]"
        result = object_value(result, label)
        result_type = text_value(result.get("Type"), f"{label}.Type")
        result_class = text_value(result.get("Class"), f"{label}.Class")
        if (result_class, result_type) not in {
            ("os-pkgs", "debian"), ("lang-pkgs", "python-pkg"),
        }:
            raise InvalidInput(f"{label}: unsupported result class/type {result_class!r}/{result_type!r}")
        inventory = package_inventory(result, result_type, label)
        inventory_counts[result_type] += len(inventory)
        if result_type == "python-pkg":
            python_names.update(name.lower().replace("_", "-") for name, _ in inventory)
        # Trivy legitimately omits this field when there are no findings.
        findings = list_value(result.get("Vulnerabilities", []), f"{label}.Vulnerabilities")
        for finding_index, finding in enumerate(findings):
            item_label = f"{label}.Vulnerabilities[{finding_index}]"
            finding = object_value(finding, item_label)
            identifier = text_value(finding.get("VulnerabilityID"), f"{item_label}.VulnerabilityID")
            package = text_value(finding.get("PkgName"), f"{item_label}.PkgName")
            installed = text_value(finding.get("InstalledVersion"), f"{item_label}.InstalledVersion")
            severity = text_value(finding.get("Severity"), f"{item_label}.Severity")
            if severity not in SEVERITIES:
                raise InvalidInput(f"{identifier}: unrecognized severity {severity!r}")
            if (package, installed) not in inventory:
                raise InvalidInput(f"{identifier}: {package}@{installed} is absent from the package inventory")
            fixed = finding.get("FixedVersion", "")
            if not isinstance(fixed, str):
                raise InvalidInput(f"{identifier}: FixedVersion must be a string")
            row = f"{identifier} {severity} {result_type} {package}@{installed}"
            if result_type == "python-pkg":
                violations.append(f"{row}: all Python vulnerabilities block release")
            elif fixed:
                violations.append(f"{row}: fixed version available: {fixed}")
            elif severity == "CRITICAL":
                violations.append(f"{row}: CRITICAL always blocks release")
            elif severity == "HIGH":
                exception = exceptions.get(identifier)
                if (
                    exception is not None
                    and os_matches
                    and arch in exception["architectures"]
                    and exception["packages"].get(package) == installed
                    and date.fromisoformat(exception["reviewed"]) <= today
                    and today < date.fromisoformat(exception["expires"])
                ):
                    accepted.append(
                        f"{row}: accepted until {exception['expires']} 00:00 UTC; "
                        f"{exception['reason']} References: {', '.join(exception['references'])}"
                    )
                else:
                    violations.append(f"{row}: no current exact exception for OS, architecture and package version")
            else:
                residual[severity] += 1
    if not inventory_counts["debian"]:
        raise InvalidInput("report must include nonempty Debian package inventory")
    if not inventory_counts["python-pkg"] or "qkvm" not in python_names:
        raise InvalidInput("report must include nonempty Python runtime inventory containing qkvm")
    return violations, accepted, residual, inventory_counts


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise InvalidInput(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def reject_constant(value):
    raise InvalidInput(f"nonstandard JSON constant: {value}")


def load_json(path):
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream, object_pairs_hook=unique_object, parse_constant=reject_constant)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", help="complete Trivy JSON report")
    parser.add_argument("--exceptions", required=True, help="reviewed exception policy JSON")
    parser.add_argument("--arch", required=True, choices=sorted(ARCHITECTURES))
    arguments = parser.parse_args(argv)
    try:
        violations, accepted, residual, inventory = evaluate(
            load_json(arguments.report), load_json(arguments.exceptions), arguments.arch
        )
    except (OSError, UnicodeError, json.JSONDecodeError, InvalidInput) as exc:
        print(f"INVALID INPUT: {exc}", file=sys.stderr)
        return 2
    for row in accepted:
        print(f"ACCEPTED TEMPORARILY: {row}")
    if residual:
        counts = ", ".join(f"{severity}={residual[severity]}" for severity in sorted(residual))
        print(f"RESIDUAL RISK: {sum(residual.values())} unfixed lower/unknown severity OS findings ({counts}).")
    else:
        print("RESIDUAL RISK: no unfixed lower/unknown severity OS findings.")
    for row in violations:
        print(f"BLOCKED: {row}")
    print(
        f"{'FAIL' if violations else 'PASS'}: {arguments.arch}; "
        f"{inventory['debian']} OS packages; {inventory['python-pkg']} Python packages; "
        f"{len(accepted)} temporary HIGH exceptions; {len(violations)} policy violations."
    )
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
