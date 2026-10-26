#!/usr/bin/env python3
"""Tie the image that reaches the registries to the image the scan saw; stdlib only.

    image-digests.py record --layout DIR --report trivy.json --archive image.tar --arch ARCH --output scanned-image.json
        Run by scan-image.sh on the OCI layout it unpacked from the archive and handed to the scanner. Checks every blob
        against its digest, finds the one image of ARCH (and its attestations) under what the layout points at, holds
        it to the scanner's own report (its image ID is the image's config, its layers the config's), and writes down
        the archive's checksum, the digest that a copy of the archive pushes, and every manifest under it.
    image-digests.py check-archive --arch ARCH scanned-image.json image.tar
        The archive is, byte for byte, the one that was scanned, and points at what the record says.
    image-digests.py digest scanned-image.json
        Prints the digest the scan saw, the one a copy with its digests kept pushes.
    image-digests.py check-index INDEX.json scanned-image.json...
        INDEX.json (a registry's raw answer for a tag, or what `imagetools create --dry-run` would push) lists exactly
        the manifests the records name, each as it was scanned, and nothing else.
    image-digests.py release-record --version V --commit SHA --run-id N --output qkvm-V-image.json
                                    --native native-versions.json... scanned-image.json...
        What a release signs of its images (listed in its SHA256SUMS): both architectures' records, what each image
        said of the native code the scanner cannot see, the commit, and the run that keeps the archives.
    image-digests.py publish-before ARTIFACTS.json --margin-days N --artifact-id amd64=ID --artifact-id arm64=ID
        The last day a draft can be published on: the first of the run's release-image-* artifacts to expire (GitHub's
        listing of the run's artifacts), less N days, of the archives the image jobs uploaded (the IDs their upload
        steps got). Refused where one of those is not listed or not kept, where one of the name was uploaded after it
        (a higher ID; a lower one, an earlier attempt's, is let be), or where no day is left.
    image-digests.py from-release --version V --commit SHA qkvm-V-image.json FOLDER
        From a release's image record (its signature checked before), made for this version and commit only: writes
        FOLDER/scanned-image-<arch>.json and prints the run that keeps the archives.

Exit status: 0 = as scanned, 1 = refused (with the reason), 2 = usage.
"""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sys
import tarfile

OCI_INDEX = "application/vnd.oci.image.index.v1+json"
DOCKER_LIST = "application/vnd.docker.distribution.manifest.list.v2+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
INDEXES = {OCI_INDEX, DOCKER_LIST}
MANIFESTS = {OCI_MANIFEST, DOCKER_MANIFEST}
ARCHITECTURES = {"amd64", "arm64"}
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ATTESTATION = "attestation-manifest"


class Refused(ValueError):
    """What was given is not the image that was scanned, or cannot be read as one."""


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refused(f"duplicate JSON object key: {key}")
        value[key] = item
    return value


def parse(data, label):
    try:
        value = json.loads(data, object_pairs_hook=unique_object)
    except (UnicodeError, ValueError) as error:
        raise Refused(f"{label} is not JSON: {error}") from None
    if not isinstance(value, dict):
        raise Refused(f"{label} is not a JSON object")
    return value


def descriptor(value, label):
    """A content descriptor: its media type, digest and size, and nothing taken on trust."""
    if not isinstance(value, dict):
        raise Refused(f"{label} is not a descriptor")
    digest, size, media = value.get("digest"), value.get("size"), value.get("mediaType")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise Refused(f"{label} has no sha256 digest")
    if type(size) is not int or size < 0:
        raise Refused(f"{label} has no size")
    if not isinstance(media, str) or not media:
        raise Refused(f"{label} has no media type")
    return value


def read_blob(layout, item, label):
    """The blob a descriptor names, checked against its digest and size."""
    path = layout / "blobs" / "sha256" / item["digest"].split(":", 1)[1]
    try:
        data = path.read_bytes()
    except OSError:
        raise Refused(f"{label} {item['digest']} is not in the layout") from None
    if len(data) != item["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != item["digest"]:
        raise Refused(f"{label} {item['digest']} is not what its digest says")
    return data


def platform_of(item):
    platform = item.get("platform")
    if not isinstance(platform, dict):
        return None, None
    return platform.get("os"), platform.get("architecture")


def file_sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def layout_top(index_json, label):
    """The one thing an OCI layout's index.json points at: what a copy of the archive pushes."""
    index = parse(index_json, label)
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or len(manifests) != 1:
        raise Refused(f"{label} must point at exactly one image or index")
    top = descriptor(manifests[0], f"{label} manifest")
    if top["mediaType"] not in INDEXES | MANIFESTS:
        raise Refused(f"{label} points at {top['mediaType']}, not an image or an index")
    return top


def record(layout, report, archive, arch):
    """What the scan saw, from the layout it scanned and the scanner's own report."""
    if arch not in ARCHITECTURES:
        raise Refused(f"unsupported architecture: {arch}")
    layout = Path(layout)
    try:
        version = parse((layout / "oci-layout").read_bytes(), "oci-layout").get("imageLayoutVersion")
        top = layout_top((layout / "index.json").read_bytes(), "index.json")
    except OSError:
        raise Refused("not an OCI layout") from None
    if version != "1.0.0":
        raise Refused("not an OCI layout of version 1.0.0")
    top_data = read_blob(layout, top, "the layout's image")
    if top["mediaType"] in INDEXES:
        nested = parse(top_data, "the image index")
        children = nested.get("manifests")
        if not isinstance(children, list) or not children:
            raise Refused("the image index lists no manifests")
        children = [descriptor(child, "an indexed manifest") for child in children]
    else:
        config = parse(read_blob(layout, descriptor(parse(top_data, "the image").get("config"), "the image's config"), "the image's config"), "the image's config")
        children = [{**top, "platform": {"os": config.get("os"), "architecture": config.get("architecture")}}]
    images = [child for child in children if platform_of(child) == ("linux", arch)]
    if len(images) != 1:
        raise Refused(f"there must be exactly one linux/{arch} image, found {len(images)}")
    image = images[0]
    digests = [child["digest"] for child in children]
    if len(set(digests)) != len(digests):
        raise Refused("a manifest is listed twice")
    for child in children:
        if child["mediaType"] not in MANIFESTS:
            raise Refused(f"{child['digest']} is a {child['mediaType']}, not an image manifest")
        if child is not image:
            annotations = child.get("annotations") if isinstance(child.get("annotations"), dict) else {}
            if annotations.get("vnd.docker.reference.type") != ATTESTATION or annotations.get("vnd.docker.reference.digest") != image["digest"]:
                raise Refused(f"{child['digest']} is neither the linux/{arch} image nor an attestation of it")
        # Every blob that is published with it is read and checked, as the copy would send it.
        manifest = parse(read_blob(layout, child, "a manifest"), "a manifest")
        for part in [manifest.get("config")] + list(manifest.get("layers") or []):
            read_blob(layout, descriptor(part, "a manifest's part"), "a manifest's part")
    manifest = parse(read_blob(layout, image, "the image"), "the image")
    config_descriptor = descriptor(manifest.get("config"), "the image's config")
    config = parse(read_blob(layout, config_descriptor, "the image's config"), "the image's config")
    if (config.get("os"), config.get("architecture")) != ("linux", arch):
        raise Refused(f"the image's config is not linux/{arch}")
    rootfs = config.get("rootfs") if isinstance(config.get("rootfs"), dict) else {}
    diff_ids = rootfs.get("diff_ids")
    if not isinstance(diff_ids, list) or not diff_ids:
        raise Refused("the image's config names no layers")
    # The scanner's own report says which image it read: its ID is the config's digest, its layers the config's.
    if not isinstance(report, dict) or report.get("ArtifactType") != "container_image":
        raise Refused("the report is not of a container image")
    metadata = report.get("Metadata") if isinstance(report.get("Metadata"), dict) else {}
    if metadata.get("ImageID") != config_descriptor["digest"] or metadata.get("DiffIDs") != diff_ids:
        raise Refused("the scanner's report is of another image than the layout's linux/" + arch)
    keep = ("mediaType", "digest", "size", "platform", "annotations")
    return {
        "schema": 1,
        "arch": arch,
        "archive": {"sha256": file_sha256(archive)},
        "index": {key: top[key] for key in ("mediaType", "digest", "size")},
        "manifests": [{key: child[key] for key in keep if key in child} for child in children],
        "image": {"manifest": image["digest"], "config": config_descriptor["digest"], "layers": diff_ids},
    }


def checked_record(value, label="the scan's record"):
    if not isinstance(value, dict) or value.get("schema") != 1 or value.get("arch") not in ARCHITECTURES:
        raise Refused(f"{label} is not a record of a scanned image")
    archive = value.get("archive")
    if not isinstance(archive, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(archive.get("sha256"))):
        raise Refused(f"{label} names no archive checksum")
    descriptor(value.get("index"), f"{label}'s index")
    manifests = value.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise Refused(f"{label} names no manifests")
    for item in manifests:
        descriptor(item, f"{label}'s manifest")
    return value


def check_archive(scanned, archive, arch):
    """The archive is byte for byte the scanned one, and its layout points at the digest the record names."""
    scanned = checked_record(scanned)
    if scanned["arch"] != arch:
        raise Refused(f"the record is of {scanned['arch']}, not {arch}")
    if file_sha256(archive) != scanned["archive"]["sha256"]:
        raise Refused(f"{archive} is not the archive that was scanned")
    try:
        with tarfile.open(archive) as tar:
            members = [item for item in tar.getmembers() if item.name.removeprefix("./") == "index.json"]
            stream = tar.extractfile(members[0]) if len(members) == 1 and members[0].isfile() else None
            if stream is None:
                raise Refused(f"{archive} holds no single index.json")
            top = layout_top(stream.read(), "the archive's index.json")
    except (OSError, tarfile.TarError):
        raise Refused(f"{archive} is not an OCI archive") from None
    if {key: top[key] for key in ("mediaType", "digest", "size")} != scanned["index"]:
        raise Refused(f"{archive} does not point at the digest the scan saw")


def check_index(raw, records):
    """The index behind a tag lists exactly the scanned manifests, each as scanned, and nothing else."""
    records = [checked_record(item) for item in records]
    if not records or len({item["arch"] for item in records}) != len(records):
        raise Refused("one record for each architecture is needed")
    index = parse(raw, "the index")
    if index.get("mediaType") not in INDEXES:
        raise Refused("what the tag names is not a multiarchitecture index")
    listed = index.get("manifests")
    if not isinstance(listed, list):
        raise Refused("the index lists no manifests")
    expected = {}
    for item in records:
        for manifest in item["manifests"]:
            expected[manifest["digest"]] = manifest
    found = {}
    for item in listed:
        item = descriptor(item, "an indexed manifest")
        if item["digest"] in found:
            raise Refused(f"{item['digest']} is listed twice")
        found[item["digest"]] = item
    if set(found) != set(expected):
        missing = sorted(set(expected) - set(found))
        extra = sorted(set(found) - set(expected))
        raise Refused(f"the index is not the scanned images: missing {missing}, not scanned {extra}")
    for digest, item in found.items():
        scanned = expected[digest]
        if item["mediaType"] != scanned["mediaType"] or item["size"] != scanned["size"]:
            raise Refused(f"{digest} is not described as it was scanned")
        if platform_of(item) != platform_of(scanned):
            raise Refused(f"{digest} is listed for another platform than it was scanned for")


COMMIT = re.compile(r"[0-9a-f]{40}")
VERSION = re.compile(r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)")  # (no leading zeros: the files of 0.2.01 are 0.2.1)


def checked_natives(natives):
    """What each image said of the native code the scanner cannot see (native-versions.py), one for each architecture."""
    if isinstance(natives, dict):
        if any(not isinstance(item, dict) or item.get("arch") != arch for arch, item in natives.items()):
            raise Refused("a native record is filed under another architecture")
        natives = list(natives.values())
    if not isinstance(natives, list):
        raise Refused("the native versions are not a list")
    by_arch = {}
    for item in natives:
        if not isinstance(item, dict) or item.get("schema") != 1 or not isinstance(item.get("raw"), dict) or item.get("arch") not in ARCHITECTURES:
            raise Refused("not what native-versions.py prints")
        if item["arch"] in by_arch:
            raise Refused(f"two native records of {item['arch']}")
        by_arch[item["arch"]] = item
    if set(by_arch) != ARCHITECTURES:
        raise Refused(f"one native record for each of {', '.join(sorted(ARCHITECTURES))} is needed")
    return by_arch


def release_record(version, commit, run_id, records, natives):
    """What the release signs of its images: both scans' records, what each image said of its native code, the commit
    and the run that made the archives."""
    # A version is three numbers, as the tag's run and the publication require (vX.Y.Z): 0.3 or 0.3.0.1 is refused
    # here, before anything is signed, not after a release of it is published.
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise Refused(f"a release record needs a version of three numbers, not {version!r}")
    if not COMMIT.fullmatch(str(commit)):
        raise Refused("a release record needs the full commit")
    records = [checked_record(item) for item in records]
    images = {item["arch"]: item for item in records}
    if len(records) != len(ARCHITECTURES) or set(images) != ARCHITECTURES:
        raise Refused(f"one record for each of {', '.join(sorted(ARCHITECTURES))} is needed")
    if type(run_id) is not int or run_id < 1:
        raise Refused("a release record needs the run that kept the archives")
    return {"schema": 1, "version": version, "commit": commit, "run": {"id": run_id}, "images": images, "native": checked_natives(natives)}


def from_release(made, version, commit):
    """The run that kept the archives, and each architecture's record, from a release's signed image record: only one
    made for this version and this commit."""
    if not isinstance(made, dict) or made.get("schema") != 1 or set(made) != {"schema", "version", "commit", "run", "images", "native"}:
        raise Refused("not a release's image record")
    checked_natives(made["native"])
    if made["version"] != version or made["commit"] != commit:
        raise Refused(f"the image record is of {made['version']} at {made['commit']}, not of {version} at {commit}")
    run = made["run"]
    if not isinstance(run, dict) or set(run) != {"id"} or type(run["id"]) is not int or run["id"] < 1:
        raise Refused("the image record names no run")
    images = made["images"]
    if not isinstance(images, dict) or set(images) != ARCHITECTURES:
        raise Refused("the image record does not hold one record for each architecture")
    for arch, item in images.items():
        if checked_record(item, f"the {arch} record")["arch"] != arch:
            raise Refused(f"the {arch} record is of another architecture")
    return run["id"], images


def expiry(text):
    if not isinstance(text, str):
        raise Refused("an archive has no expiry")
    try:
        when = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise Refused(f"an archive's expiry cannot be read: {text!r}") from None
    if when.tzinfo is None:
        raise Refused(f"an archive's expiry has no time zone: {text!r}")
    return when


def publish_before(listing, margin_days, now=None, *, artifact_ids):
    """The last day to publish a draft on: the first of the run's two image archives to expire (GitHub's listing of the
    run's artifacts, one page or pages), less `margin_days`; refused where that leaves no day.

    The two are the ones the image jobs uploaded: `artifact_ids` gives, by architecture, the ID that job's upload step
    got, handed on as a job output. For each release-image-<arch> the listing holds:
      the handed-on ID: the archive, which must be listed once and kept (not expired), and whose expiry counts;
      a lower ID: let be, expired or not (where GitHub gives IDs in the order artifacts are made, as it appears to, an
        earlier attempt's that a run again keeps beside the new one; the publication holds whatever archive it takes
        to the signed record);
      a higher ID: refused (where IDs come in that order, one uploaded after the image job's, by something else);
      no number for an ID, or an architecture that is not built: refused.
    And refused where the handed-on ID of an architecture is not listed. The rule does not rest on the order GitHub
    gives IDs in: whatever it is, a listing is accepted only where the handed-on ID is the highest of its name (the one
    a download by name takes, the newest), and where IDs came out of that order it is refused, not passed."""
    if set(artifact_ids) != ARCHITECTURES or any(type(value) is not int or value <= 0 for value in artifact_ids.values()):
        raise Refused(f"not one artifact ID (a number) for each of {', '.join(sorted(ARCHITECTURES))}: {artifact_ids!r}")
    pages = listing if isinstance(listing, list) else [listing]
    found = {}
    for page in pages:
        artifacts = page.get("artifacts") if isinstance(page, dict) else None
        if not isinstance(artifacts, list):
            raise Refused("not GitHub's listing of a run's artifacts")
        for item in artifacts:
            name = item.get("name") if isinstance(item, dict) else None
            arch = name.removeprefix("release-image-") if isinstance(name, str) and name.startswith("release-image-") else None
            if arch is None:
                continue
            if arch not in ARCHITECTURES:
                raise Refused(f"{name} is not an image archive of this release")
            ident, handed = item.get("id"), artifact_ids[arch]
            if type(ident) is not int:
                raise Refused(f"{name} is listed without a numeric ID: {ident!r}")
            if ident > handed:
                raise Refused(f"{name} (artifact {ident}) has a higher ID than the one its image job uploaded ({handed}), "
                              "which is then not the newest of its name")
            if ident < handed:
                continue  # an earlier one of the name, an earlier attempt's: let be
            if arch in found:
                raise Refused(f"{name} (artifact {ident}) is listed twice")
            if item.get("expired") is not False:
                raise Refused(f"{name} (artifact {ident}) is not kept any more")
            found[arch] = expiry(item.get("expires_at"))
    missing = sorted(ARCHITECTURES - set(found))
    if missing:
        raise Refused("the run lists no " + ", ".join(f"release-image-{arch} with the ID its image job handed on ({artifact_ids[arch]})" for arch in missing))
    first = min(found.values())
    last_day = (first - timedelta(days=margin_days)).date()
    today = (expiry(now) if now else datetime.now(timezone.utc)).date()
    if last_day <= today:
        raise Refused(f"the image archives expire {first.isoformat()}: no day is left to publish a draft in")
    return last_day.isoformat()


def load(path):
    return parse(Path(path).read_bytes(), str(path))


def artifact_id(text):
    """ARCH=ID, as --artifact-id takes it: an architecture and a number (no leading zero)."""
    arch, _, value = text.partition("=")
    if arch not in ARCHITECTURES or not re.fullmatch(r"[1-9][0-9]*", value):
        raise argparse.ArgumentTypeError(f"not ARCH=ID: {text!r}")
    return arch, int(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    making = commands.add_parser("record")
    making.add_argument("--layout", required=True)
    making.add_argument("--report", required=True)
    making.add_argument("--archive", required=True)
    making.add_argument("--arch", required=True, choices=sorted(ARCHITECTURES))
    making.add_argument("--output", required=True)
    archive = commands.add_parser("check-archive")
    archive.add_argument("--arch", required=True, choices=sorted(ARCHITECTURES))
    archive.add_argument("record")
    archive.add_argument("archive")
    digest = commands.add_parser("digest")
    digest.add_argument("record")
    index = commands.add_parser("check-index")
    index.add_argument("index")
    index.add_argument("records", nargs="+")
    combined = commands.add_parser("release-record")
    combined.add_argument("--version", required=True)
    combined.add_argument("--commit", required=True)
    combined.add_argument("--run-id", required=True, type=int)
    combined.add_argument("--output", required=True)
    combined.add_argument("--native", action="append", default=[], help="native-versions.json of an image (once for each)")
    combined.add_argument("records", nargs="+")
    split = commands.add_parser("from-release")
    split.add_argument("--version", required=True)
    split.add_argument("--commit", required=True)
    split.add_argument("record")
    split.add_argument("folder")
    before = commands.add_parser("publish-before")
    before.add_argument("listing")
    before.add_argument("--margin-days", required=True, type=int)
    before.add_argument("--now", default=None)
    before.add_argument("--artifact-id", dest="artifact_ids", action="append", required=True, type=artifact_id,
                        help="ARCH=ID: the artifact its image job uploaded (once for each architecture)")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "record":
            made = record(arguments.layout, load(arguments.report), arguments.archive, arguments.arch)
            Path(arguments.output).write_text(json.dumps(made, indent=2) + "\n", encoding="utf-8")
            print(f"Scanned {arguments.arch}: {made['index']['digest']} (image {made['image']['manifest']}, config {made['image']['config']})")
        elif arguments.command == "check-archive":
            check_archive(load(arguments.record), arguments.archive, arguments.arch)
            print(f"{arguments.archive} is the archive that was scanned")
        elif arguments.command == "digest":
            print(checked_record(load(arguments.record))["index"]["digest"])
        elif arguments.command == "release-record":
            made = release_record(arguments.version, arguments.commit, arguments.run_id, [load(path) for path in arguments.records],
                                  [load(path) for path in arguments.native])
            Path(arguments.output).write_text(json.dumps(made, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"Wrote {arguments.output}")
        elif arguments.command == "publish-before":
            listing = json.loads(Path(arguments.listing).read_text(encoding="utf-8"))
            ids = dict(arguments.artifact_ids)
            if len(ids) != len(arguments.artifact_ids):
                raise Refused("an architecture's artifact ID is given twice")
            print(publish_before(listing, arguments.margin_days, arguments.now, artifact_ids=ids))
        elif arguments.command == "from-release":
            run_id, images = from_release(load(arguments.record), arguments.version, arguments.commit)
            for arch, item in sorted(images.items()):
                (Path(arguments.folder) / f"scanned-image-{arch}.json").write_text(json.dumps(item, indent=2) + "\n", encoding="utf-8")
            print(run_id)
        else:
            check_index(Path(arguments.index).read_bytes(), [load(path) for path in arguments.records])
            print(f"{arguments.index} lists exactly the scanned manifests")
    except (OSError, ValueError) as error:  # (Refused is a ValueError, as is JSON that cannot be read)
        print(f"REFUSED: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
