#!/usr/bin/env python3
"""Regression tests for tying the published image to the one the scan saw; stdlib only."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("image_digests", Path(__file__).with_name("image-digests.py"))
DIGESTS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIGESTS)


def blob(layout, data):
    if not isinstance(data, bytes):
        data = json.dumps(data, sort_keys=True).encode()
    digest = hashlib.sha256(data).hexdigest()
    path = layout / "blobs" / "sha256" / digest
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return {"digest": f"sha256:{digest}", "size": len(data)}


def build(layout, arch="amd64", *, plain=False, extra=None, config_arch=None, attestation_of=None):
    """An OCI layout as BuildKit's exporter writes one: index.json, then an index of an image and its attestation."""
    layout.mkdir(parents=True, exist_ok=True)
    (layout / "oci-layout").write_text('{"imageLayoutVersion":"1.0.0"}', encoding="utf-8")
    layer = blob(layout, b"layer of " + arch.encode())
    diff_id = "sha256:" + hashlib.sha256(b"uncompressed " + arch.encode()).hexdigest()
    config = blob(layout, {"architecture": config_arch or arch, "os": "linux", "rootfs": {"type": "layers", "diff_ids": [diff_id]}})
    image = {"schemaVersion": 2, "mediaType": DIGESTS.OCI_MANIFEST,
             "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **config},
             "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", **layer}]}
    image_descriptor = {"mediaType": DIGESTS.OCI_MANIFEST, **blob(layout, image),
                        "platform": {"architecture": arch, "os": "linux"}}
    statement = blob(layout, {"_type": "https://in-toto.io/Statement/v0.1", "subject": [{"digest": image_descriptor["digest"]}]})
    attestation = {"schemaVersion": 2, "mediaType": DIGESTS.OCI_MANIFEST,
                   "config": {"mediaType": "application/vnd.oci.image.config.v1+json", **blob(layout, b"{}")},
                   "layers": [{"mediaType": "application/vnd.in-toto+json", **statement}]}
    attestation_descriptor = {
        "mediaType": DIGESTS.OCI_MANIFEST, **blob(layout, attestation),
        "platform": {"architecture": "unknown", "os": "unknown"},
        "annotations": {"vnd.docker.reference.digest": attestation_of or image_descriptor["digest"],
                        "vnd.docker.reference.type": "attestation-manifest"},
    }
    if plain:
        top = {"mediaType": DIGESTS.OCI_MANIFEST, "digest": image_descriptor["digest"], "size": image_descriptor["size"]}
    else:
        children = [image_descriptor, attestation_descriptor] + (extra or [])
        index = {"schemaVersion": 2, "mediaType": DIGESTS.OCI_INDEX, "manifests": children}
        top = {"mediaType": DIGESTS.OCI_INDEX, **blob(layout, index)}
    (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "mediaType": DIGESTS.OCI_INDEX, "manifests": [top]}), encoding="utf-8")
    report = {"SchemaVersion": 2, "ArtifactType": "container_image",
              "Metadata": {"ImageID": config["digest"], "DiffIDs": [diff_id]}}
    return report, image_descriptor, attestation_descriptor


def archive_of(layout, path):
    with tarfile.open(path, "w") as archive:
        for item in sorted(layout.rglob("*")):
            archive.add(item, arcname=str(item.relative_to(layout)), recursive=False)
    return path


class Scanned(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.layout = self.root / "oci"

    def tearDown(self):
        self.directory.cleanup()

    def record(self, report, arch="amd64"):
        archive = archive_of(self.layout, self.root / f"image-{arch}.tar")
        return DIGESTS.record(self.layout, report, archive, arch), archive

    def test_the_record_names_what_is_pushed_and_what_the_scanner_saw(self):
        report, image, attestation = build(self.layout)
        record, archive = self.record(report)
        top = json.loads((self.layout / "index.json").read_text())["manifests"][0]
        self.assertEqual(record["index"], {key: top[key] for key in ("mediaType", "digest", "size")})
        self.assertEqual(record["archive"]["sha256"], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual([m["digest"] for m in record["manifests"]], [image["digest"], attestation["digest"]])
        self.assertEqual(record["image"]["manifest"], image["digest"])
        self.assertEqual(record["image"]["config"], report["Metadata"]["ImageID"])

    def test_a_single_image_without_an_index_is_its_own_manifest(self):
        report, image, _ = build(self.layout, plain=True)
        record, _ = self.record(report)
        self.assertEqual([m["digest"] for m in record["manifests"]], [image["digest"]])
        self.assertEqual(record["index"]["digest"], image["digest"])

    def test_a_report_of_another_image_is_refused(self):
        for change in ("ImageID", "DiffIDs", "ArtifactType"):
            with self.subTest(change=change):
                report, _, _ = build(self.layout)
                if change == "ImageID":
                    report["Metadata"]["ImageID"] = "sha256:" + "0" * 64
                elif change == "DiffIDs":
                    report["Metadata"]["DiffIDs"] = []
                else:
                    report["ArtifactType"] = "filesystem"
                with self.assertRaises(DIGESTS.Refused):
                    self.record(report)

    def test_a_blob_that_is_not_what_its_name_says_is_refused(self):
        report, image, _ = build(self.layout)
        path = self.layout / "blobs" / "sha256" / image["digest"].split(":")[1]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaises(DIGESTS.Refused):
            self.record(report)

    def test_a_missing_layer_is_refused(self):
        report, image, _ = build(self.layout)
        manifest = json.loads((self.layout / "blobs" / "sha256" / image["digest"].split(":")[1]).read_text())
        (self.layout / "blobs" / "sha256" / manifest["layers"][0]["digest"].split(":")[1]).unlink()
        with self.assertRaises(DIGESTS.Refused):
            self.record(report)

    def test_only_one_image_of_the_asked_architecture_and_its_attestations(self):
        cases = {
            "another architecture": lambda: build(self.layout, "arm64"),
            "config of another architecture": lambda: build(self.layout, config_arch="arm64"),
            "an attestation of something else": lambda: build(self.layout, attestation_of="sha256:" + "1" * 64),
            "an unexplained manifest": lambda: build(self.layout, extra=[{
                "mediaType": DIGESTS.OCI_MANIFEST, **blob(self.layout, {"schemaVersion": 2}),
                "platform": {"architecture": "amd64", "os": "windows"}}]),
        }
        for name, make in cases.items():
            with self.subTest(case=name):
                if self.layout.exists():
                    for item in sorted(self.layout.rglob("*"), reverse=True):
                        item.rmdir() if item.is_dir() else item.unlink()
                report, _, _ = make()
                with self.assertRaises(DIGESTS.Refused):
                    self.record(report, "amd64")

    def test_two_images_for_one_architecture_are_refused(self):
        report, image, _ = build(self.layout)
        index_path = self.layout / "index.json"
        top = json.loads(index_path.read_text())
        nested = json.loads((self.layout / "blobs" / "sha256" / top["manifests"][0]["digest"].split(":")[1]).read_text())
        nested["manifests"].append(dict(image))
        top["manifests"][0] = {"mediaType": DIGESTS.OCI_INDEX, **blob(self.layout, nested)}
        index_path.write_text(json.dumps(top))
        with self.assertRaises(DIGESTS.Refused):
            self.record(report)

    def test_a_layout_that_points_at_two_things_is_refused(self):
        report, _, _ = build(self.layout)
        index_path = self.layout / "index.json"
        top = json.loads(index_path.read_text())
        top["manifests"].append(dict(top["manifests"][0]))
        index_path.write_text(json.dumps(top))
        with self.assertRaises(DIGESTS.Refused):
            self.record(report)


class Published(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.records = {}
        self.archives = {}
        for arch in ("amd64", "arm64"):
            layout = self.root / arch
            report, _, _ = build(layout, arch)
            self.archives[arch] = archive_of(layout, self.root / f"image-{arch}.tar")
            self.records[arch] = DIGESTS.record(layout, report, self.archives[arch], arch)

    def tearDown(self):
        self.directory.cleanup()

    def published_index(self):
        manifests = [dict(m) for arch in ("amd64", "arm64") for m in self.records[arch]["manifests"]]
        return {"schemaVersion": 2, "mediaType": DIGESTS.OCI_INDEX, "manifests": manifests}

    def test_the_archive_is_the_one_scanned(self):
        DIGESTS.check_archive(self.records["amd64"], self.archives["amd64"], "amd64")
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.check_archive(self.records["amd64"], self.archives["arm64"], "amd64")
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.check_archive(self.records["amd64"], self.archives["amd64"], "arm64")
        changed = self.root / "changed.tar"
        changed.write_bytes(self.archives["amd64"].read_bytes() + b"\0" * 512)
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.check_archive(self.records["amd64"], changed, "amd64")

    def test_a_record_that_disagrees_with_the_archives_layout_is_refused(self):
        record = json.loads(json.dumps(self.records["amd64"]))
        record["index"]["digest"] = "sha256:" + "2" * 64
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.check_archive(record, self.archives["amd64"], "amd64")

    def test_the_index_the_tags_point_at_lists_exactly_the_scanned_manifests(self):
        index = self.published_index()
        index["manifests"].reverse()  # (the order is the registry's)
        DIGESTS.check_index(json.dumps(index).encode(), list(self.records.values()))

    def test_anything_else_behind_the_tags_is_refused(self):
        mutations = [
            lambda index: index["manifests"].pop(),
            lambda index: index["manifests"].append(dict(index["manifests"][0])),
            lambda index: index["manifests"].append({"mediaType": DIGESTS.OCI_MANIFEST, "digest": "sha256:" + "3" * 64, "size": 9,
                                                     "platform": {"architecture": "amd64", "os": "linux"}}),
            lambda index: index["manifests"][0].update(size=index["manifests"][0]["size"] + 1),
            lambda index: index["manifests"][0].update(mediaType=DIGESTS.DOCKER_MANIFEST),
            lambda index: index["manifests"][0].update(platform={"architecture": "arm64", "os": "linux"}),
            lambda index: index.update(mediaType=DIGESTS.OCI_MANIFEST),
            lambda index: index.update(manifests=None),
        ]
        for number, mutate in enumerate(mutations):
            with self.subTest(number=number):
                index = self.published_index()
                mutate(index)
                with self.assertRaises(DIGESTS.Refused):
                    DIGESTS.check_index(json.dumps(index).encode(), list(self.records.values()))

    @property
    def NATIVES(self):  # (what native-versions.py prints, for both architectures; made anew for each use)
        return [{"schema": 1, "arch": arch, "raw": {"ffmpeg": "8.1.1"}, "context": {}} for arch in ("amd64", "arm64")]

    def release_record(self, **changes):
        made = DIGESTS.release_record("9.9.9", "a" * 40, 4242, list(self.records.values()), self.NATIVES)
        made.update(changes)
        return made

    def test_the_release_record_carries_both_scans_and_where_their_archives_are(self):
        made = self.release_record()
        self.assertEqual(made["run"], {"id": 4242})
        self.assertEqual(made["images"], self.records)
        # What each image said of the native code the scanner cannot see, kept with the release it went out in.
        self.assertEqual(made["native"], {item["arch"]: item for item in self.NATIVES})
        split = DIGESTS.from_release(made, "9.9.9", "a" * 40)
        self.assertEqual(split, (4242, self.records))

    def test_the_native_versions_of_both_images_are_required(self):
        for natives in ([self.NATIVES[0]], [self.NATIVES[0], self.NATIVES[0]], [{**self.NATIVES[0], "schema": 2}, self.NATIVES[1]],
                        [{**self.NATIVES[0], "raw": None}, self.NATIVES[1]]):
            with self.subTest(natives=natives):
                with self.assertRaises(DIGESTS.Refused):
                    DIGESTS.release_record("9.9.9", "a" * 40, 4242, list(self.records.values()), natives)
        made = self.release_record()
        made.pop("native")
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.from_release(made, "9.9.9", "a" * 40)
        swapped = self.release_record()
        swapped["native"] = {"amd64": self.NATIVES[1], "arm64": self.NATIVES[0]}
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.from_release(swapped, "9.9.9", "a" * 40)

    def test_a_release_record_of_another_version_commit_or_shape_is_refused(self):
        cases = [
            ({}, "9.9.8", "a" * 40),
            ({}, "9.9.9", "b" * 40),
            ({"run": {"id": 0}}, "9.9.9", "a" * 40),
            ({"run": {"id": "4242"}}, "9.9.9", "a" * 40),
            ({"images": {"amd64": None}}, "9.9.9", "a" * 40),
            ({"schema": 2}, "9.9.9", "a" * 40),
        ]
        for changes, version, commit in cases:
            with self.subTest(changes=changes, version=version, commit=commit[:1]):
                with self.assertRaises(DIGESTS.Refused):
                    DIGESTS.from_release(self.release_record(**changes), version, commit)
        swapped = self.release_record()
        swapped["images"] = {"amd64": self.records["arm64"], "arm64": self.records["amd64"]}
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.from_release(swapped, "9.9.9", "a" * 40)
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.release_record("9.9.9", "a" * 40, 4242, [self.records["amd64"]], self.NATIVES)
        with self.assertRaises(DIGESTS.Refused):
            DIGESTS.release_record("9.9.9", "a" * 40, 4242, [self.records["amd64"], self.records["amd64"]], self.NATIVES)

    def test_the_release_record_round_trip_on_the_command_line(self):
        records = []
        natives = []
        for (arch, made), native in zip(self.records.items(), self.NATIVES, strict=True):
            path = self.root / f"scanned-{arch}.json"
            path.write_text(json.dumps(made), encoding="utf-8")
            records.append(str(path))
            path = self.root / f"native-{arch}.json"
            path.write_text(json.dumps(native), encoding="utf-8")
            natives += ["--native", str(path)]
        combined = self.root / "qkvm-9.9.9-image.json"
        out = self.root / "signed"
        out.mkdir()
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(DIGESTS.main(["release-record", "--version", "9.9.9", "--commit", "a" * 40, "--run-id", "4242",
                                           "--output", str(combined), *natives, *records]), 0)
        self.assertEqual(json.loads(combined.read_text(encoding="utf-8"))["native"]["arm64"], self.NATIVES[1])
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(DIGESTS.main(["from-release", "--version", "9.9.9", "--commit", "a" * 40, str(combined), str(out)]), 0)
        self.assertEqual(output.getvalue().strip(), "4242")
        for arch in ("amd64", "arm64"):
            self.assertEqual(json.loads((out / f"scanned-image-{arch}.json").read_text(encoding="utf-8")), self.records[arch])
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(DIGESTS.main(["from-release", "--version", "9.9.8", "--commit", "a" * 40, str(combined), str(out)]), 1)

    def test_the_command_line_says_no_with_its_exit_status(self):
        record = self.root / "record.json"
        record.write_text(json.dumps(self.records["amd64"]), encoding="utf-8")
        published = self.root / "published.json"
        for arguments, expected in (
            (["check-archive", "--arch", "amd64", str(record), str(self.archives["amd64"])], 0),
            (["check-archive", "--arch", "amd64", str(record), str(self.archives["arm64"])], 1),
            (["digest", str(record)], 0),
            (["check-index", str(published), str(record)], 1),
        ):
            with self.subTest(arguments=arguments[0], expected=expected):
                published.write_text(json.dumps(self.published_index()), encoding="utf-8")
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(output):
                    self.assertEqual(DIGESTS.main(arguments), expected)
                if arguments[0] == "digest":
                    self.assertEqual(output.getvalue().strip(), self.records["amd64"]["index"]["digest"])


IDS = {"amd64": 4101, "arm64": 4102}


def artifact(name, expires, expired=False, id=None):
    arch = name.removeprefix("release-image-")
    return {"id": IDS.get(arch, 99) if id is None else id, "name": name, "expires_at": expires, "expired": expired}


class PublishBefore(unittest.TestCase):
    NOW = "2026-10-26T12:00:00Z"

    def test_the_date_is_the_first_archive_to_expire_less_the_margin(self):
        listing = [{"total_count": 3, "artifacts": [
            artifact("release-image-amd64", "2027-01-24T10:00:00Z"), artifact("release-image-arm64", "2027-01-23T23:00:00Z"),
            artifact("signed", "2026-11-01T00:00:00Z")]}]
        self.assertEqual(DIGESTS.publish_before(listing, 2, self.NOW, artifact_ids=IDS), "2027-01-21")

    def test_one_page_or_pages_alike(self):
        page = {"artifacts": [artifact("release-image-amd64", "2027-01-24T10:00:00Z"), artifact("release-image-arm64", "2027-01-24T10:00:00Z")]}
        self.assertEqual(DIGESTS.publish_before(page, 2, self.NOW, artifact_ids=IDS), DIGESTS.publish_before([page], 2, self.NOW, artifact_ids=IDS))

    def test_the_archives_are_the_very_ones_the_image_jobs_uploaded(self):
        # (fresh review of web-020-pipe, 3) Each image job hands on the ID its upload got; an archive of that name
        # with any other ID (uploaded again, or beside it, by whatever else got at the run's artifacts) is refused
        # before the draft is made, and so is an ID that is not a number.
        kept = artifact("release-image-arm64", "2027-01-24T10:00:00Z")
        cases = {
            "another id": [artifact("release-image-amd64", "2027-01-24T10:00:00Z", id=4999), kept],
            "one more beside it": [artifact("release-image-amd64", "2027-01-24T10:00:00Z"),
                                   artifact("release-image-amd64", "2027-01-25T10:00:00Z", id=5000), kept],
            "no id": [{"name": "release-image-amd64", "expires_at": "2027-01-24T10:00:00Z", "expired": False}, kept],
            "an id that is text": [artifact("release-image-amd64", "2027-01-24T10:00:00Z", id="4101"), kept],
            "an id that is true": [artifact("release-image-amd64", "2027-01-24T10:00:00Z", id=True), kept],
        }
        for name, artifacts in cases.items():
            with self.subTest(case=name):
                with self.assertRaisesRegex(DIGESTS.Refused, "release-image-amd64"):
                    DIGESTS.publish_before({"artifacts": artifacts}, 2, self.NOW, artifact_ids=IDS)
        for ids in ({"amd64": 4101}, {**IDS, "riscv64": 1}, {"amd64": 4101, "arm64": True}, {"amd64": 4101, "arm64": "4102"}):
            with self.subTest(ids=ids):
                with self.assertRaises(DIGESTS.Refused):
                    DIGESTS.publish_before({"artifacts": [artifact("release-image-amd64", "2027-01-24T10:00:00Z"), kept]}, 2, self.NOW, artifact_ids=ids)

    def test_a_run_again_leaves_an_earlier_attempts_archive_beside_it(self):
        # (delta-g review of web-020-pipe, 1) Where GitHub keeps an earlier attempt's archive of the same name beside
        # the one a run again uploaded, the earlier one has the lower ID (GitHub numbers artifacts in the order they
        # are made): it is let be, whatever its expiry, and the date is the handed-on archives'. One with a higher ID
        # than the handed-on one was uploaded after it and is refused; so is a listing without the handed-on one.
        # Each in either order of the listing.
        earlier = [artifact("release-image-amd64", "2027-01-20T10:00:00Z", id=3101),
                   artifact("release-image-arm64", "2026-10-20T10:00:00Z", expired=True, id=3102)]
        handed = [artifact("release-image-amd64", "2027-01-25T10:00:00Z"), artifact("release-image-arm64", "2027-01-25T10:00:00Z")]
        for listing in (earlier + handed, handed + earlier, [earlier[0], handed[1], earlier[1], handed[0]]):
            with self.subTest(order=[item["id"] for item in listing]):
                self.assertEqual(DIGESTS.publish_before({"artifacts": listing}, 2, self.NOW, artifact_ids=IDS), "2027-01-23")
        later = artifact("release-image-arm64", "2027-01-26T10:00:00Z", id=4103)
        for listing in (handed + [later], [later, *handed], earlier + [later, *handed]):
            with self.subTest(later=[item["id"] for item in listing]):
                with self.assertRaisesRegex(DIGESTS.Refused, "release-image-arm64"):
                    DIGESTS.publish_before({"artifacts": listing}, 2, self.NOW, artifact_ids=IDS)
        for listing in ([earlier[0], handed[1]], [handed[1], earlier[0]]):
            with self.subTest(only_earlier=[item["id"] for item in listing]):
                with self.assertRaisesRegex(DIGESTS.Refused, "release-image-amd64"):
                    DIGESTS.publish_before({"artifacts": listing}, 2, self.NOW, artifact_ids=IDS)
        twice = [*handed, artifact("release-image-amd64", "2027-01-25T10:00:00Z")]
        with self.assertRaisesRegex(DIGESTS.Refused, "release-image-amd64"):
            DIGESTS.publish_before({"artifacts": twice}, 2, self.NOW, artifact_ids=IDS)
        gone = [artifact("release-image-amd64", "2027-01-25T10:00:00Z", expired=True), handed[1], earlier[0]]
        with self.assertRaisesRegex(DIGESTS.Refused, "release-image-amd64"):
            DIGESTS.publish_before({"artifacts": gone}, 2, self.NOW, artifact_ids=IDS)

    def test_the_rule_does_not_rest_on_the_order_of_ids(self):
        # (delta-i review, a nit) Whatever order GitHub gives IDs in, an accepted listing has the handed-on ID as the
        # highest of its name (the one a download by name takes); where a later upload got a lower ID than an earlier
        # one, the earlier, listed beside it with the higher ID, is refused. The docstring claims no order as fact.
        later_but_lower = [artifact("release-image-amd64", "2027-01-25T10:00:00Z", id=5000),
                           artifact("release-image-amd64", "2027-01-26T10:00:00Z", id=4101),
                           artifact("release-image-arm64", "2027-01-26T10:00:00Z")]
        with self.assertRaisesRegex(DIGESTS.Refused, "release-image-amd64"):
            DIGESTS.publish_before({"artifacts": later_but_lower}, 2, self.NOW, artifact_ids=IDS)
        doc = " ".join(DIGESTS.publish_before.__doc__.split())
        self.assertNotIn("(GitHub numbers artifacts in the order they are made)", doc)
        self.assertIn("The rule does not rest on the order GitHub gives IDs in", doc)

    def test_the_listing_of_a_run_run_again_in_full(self):
        # A run whose every job ran again (attempt 2, ids 2xx) beside what attempt 1 made (1xx), as GitHub might list it.
        def item(ident, name, expires):
            return {"id": ident, "name": name, "expires_at": expires, "expired": False}
        listing = [{"total_count": 12, "artifacts": [
            item(101, "release", "2027-01-20T10:00:00Z"), item(102, "container-security-amd64", "2027-01-20T10:00:00Z"),
            item(103, "release-image-amd64", "2027-01-20T10:00:00Z"), item(104, "release-image-arm64", "2027-01-20T10:00:00Z"),
            item(105, "dependency-security", "2027-01-20T10:00:00Z"), item(106, "signed", "2026-10-28T10:00:00Z"),
            item(201, "release", "2027-01-25T10:00:00Z"), item(202, "container-security-amd64", "2027-01-25T10:00:00Z"),
            item(203, "release-image-amd64", "2027-01-25T10:00:00Z"), item(204, "release-image-arm64", "2027-01-25T10:00:00Z"),
            item(205, "dependency-security", "2027-01-25T10:00:00Z"), item(206, "signed", "2026-11-02T10:00:00Z")]}]
        self.assertEqual(DIGESTS.publish_before(listing, 2, "2026-11-01T00:00:00Z", artifact_ids={"amd64": 203, "arm64": 204}), "2027-01-23")
        with self.assertRaises(DIGESTS.Refused):  # (the first attempt's IDs, handed on by mistake: newer ones are listed)
            DIGESTS.publish_before(listing, 2, "2026-11-01T00:00:00Z", artifact_ids={"amd64": 103, "arm64": 104})

    def test_missing_expired_or_nearly_gone_archives_are_refused(self):
        cases = [
            {"artifacts": [artifact("release-image-amd64", "2027-01-24T10:00:00Z")]},
            {"artifacts": [artifact("release-image-amd64", "2027-01-24T10:00:00Z"), artifact("release-image-arm64", "2027-01-24T10:00:00Z", expired=True)]},
            {"artifacts": [artifact("release-image-amd64", "2026-10-28T10:00:00Z"), artifact("release-image-arm64", "2027-01-24T10:00:00Z")]},
            {"artifacts": [artifact("release-image-amd64", "soon"), artifact("release-image-arm64", "2027-01-24T10:00:00Z")]},
            {"artifacts": None},
        ]
        for listing in cases:
            with self.subTest(listing=listing):
                with self.assertRaises(DIGESTS.Refused):
                    DIGESTS.publish_before(listing, 2, self.NOW, artifact_ids=IDS)

    def test_the_command_prints_the_date(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifacts.json"
            path.write_text(json.dumps([{"artifacts": [artifact("release-image-amd64", "2027-01-24T10:00:00Z"),
                                                       artifact("release-image-arm64", "2027-01-24T10:00:00Z")]}]), encoding="utf-8")
            ids = ["--artifact-id", "amd64=4101", "--artifact-id", "arm64=4102"]
            output = io.StringIO()
            with redirect_stdout(output), redirect_stderr(output):
                self.assertEqual(DIGESTS.main(["publish-before", str(path), "--margin-days", "2", "--now", self.NOW, *ids]), 0)
            self.assertEqual(output.getvalue().strip(), "2027-01-22")
            # The IDs are required, one for each architecture, each a number.
            for wrong in ([], ["--artifact-id", "amd64=4101"], ["--artifact-id", "amd64=4101", "--artifact-id", "arm64=4999"],
                          [*ids, "--artifact-id", "amd64=4101"], ["--artifact-id", "amd64=4101", "--artifact-id", "arm64="],
                          ["--artifact-id", "amd64=4101", "--artifact-id", "arm64=04102"], ["--artifact-id", "amd64=4101", "--artifact-id", "arm64"]):
                with self.subTest(wrong=wrong):
                    output = io.StringIO()
                    with redirect_stdout(output), redirect_stderr(output):
                        try:
                            status = DIGESTS.main(["publish-before", str(path), "--margin-days", "2", "--now", self.NOW, *wrong])
                        except SystemExit as stop:
                            status = stop.code
                    self.assertNotEqual(status, 0)


if __name__ == "__main__":
    unittest.main()
