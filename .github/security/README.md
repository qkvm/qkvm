# Release security gate

The release first requires its tagged commit to be in the history of the protected branch `main` (asked of GitHub by the branch's full name, so that a tag called `main` cannot stand in for it): a `v*` tag can be made on any commit, and a commit that never went through `main` is not released. It then requires the latest eligible `Tests` push/manual run for its exact commit and every one of the 18 required jobs to succeed, including integrations otherwise allowed to fail in Tests. A running match is awaited for up to 95 minutes; missing, failed or incomplete evidence blocks release.

Releases are made draft first. Pushing a `v*` tag runs the checks, the build, the tests, the scans and the signature. `sign` waits for the wheel's dependency audit and for **both** `amd64` and `arm64` image jobs, and signs `SHA256SUMS` (the wheel, the source archive and the record of the scanned images); `signature` checks that signature with the cryptography library; `draft`, which has no key, makes the draft with every file attached, and reads every file back from the draft and checks it against the signature. A failing scanner, unavailable advisory database, malformed report, failed runtime check, or policy failure means no draft and no signature. A person reviews the draft and publishes it; only that publication runs the publishing jobs. A first job, with no secret, checks every file of the published release against the signature (refusing any the signed list does not name) and the archives its signed image record names against the scan; the image job waits for it, and the PyPI job for both, since an upload to PyPI cannot be undone. The publishing jobs, which hold the registries' credentials and PyPI's token, install nothing: they are handed the SHA-256 of the `SHA256SUMS` whose signature the first job checked, require that very list, and hold what they upload to it with `sha256sum`. Nothing changes a release's files after it is published (GitHub's immutable releases refuse it).

The build jobs have read-only repository permissions and no signing or registry secrets. Each secret is in an environment of its own, named by the one job that uses it: the signing key in `release` (job `sign`), the Docker Hub credentials in `registries` (job `image`), and `pypi` holds none. The signing key stays in the separate `release` environment job (`sign`), which signs and does nothing else, and installs nothing: it signs with the runner's own openssl (`qkvm.release publish --openssl`, checked first against RFC 8032's test key and signature, and refused where openssl does not give them). A job with no secret (`signature`) then checks that signature with the cryptography library, what every installed copy checks with, before the job that makes the draft (`draft`, no key) runs; the draft's files are held byte for byte to what was checked, and read back with openssl. Images are built once into OCI archives with SBOM/provenance, tested and scanned in that form, and uploaded as job artifacts only after success. BuildKit and its SBOM generator are named by digest (`action.yml`), as the actions are by commit.

`image-digests.py` ties what is published to what was scanned. The scan writes `scanned-image.json` from the layout it handed the scanner: the archive's checksum, the digest a copy of the archive pushes, and every manifest under it (the one image of the architecture and its attestations, nothing else), every blob checked against its digest and the image held to the scanner's own report (its image ID and layers). The archive is held to that record before its checksum is written and again in the publisher, before anything is pushed. The publisher pushes with `skopeo copy --all --preserve-digests`, requires the digest the scan saw, and reads each architecture's tag back from the registry; the multiarchitecture index that the version tags name is checked to list exactly the scanned manifests before any tag is moved to it, and read back from each registry after. No image rebuild runs in a publishing job.

## Policy

`audit-wheel.sh` installs the built wheel in an environment without pip, inventories every installed runtime dependency, and checks those exact versions with pip-audit using a separate tool environment and fresh advisory lookup. Lookup errors fail the job. qKVM itself is the unpublished artifact under review and is excluded from the third-party advisory lookup.

The build job installs only the build tools, each pinned by hash (`build-requirements.txt`), builds without fetching a build environment, and checksums the packages and hands them on at once (the checksum list's hash as a job output); everything else that tries them (twine, the test suite, `check-sdist.py`, the dependency audit, all with code from PyPI) runs in the job `packages`, on a copy first held to that hash. That code could change an artifact at most, never have it signed: each image job (one per architecture) hands on the SHA-256 of its image.tar, scanned-image.json and native-versions.json as job outputs, written only by the job that made the artifact (another job's code cannot set them) and taken in the shared action right after the scan and the native step, before the suite's test tools (pinned wheels, `image-test-requirements.txt`) are installed on that runner, and `sign` holds the packages to the build's hash and the image evidence to the image jobs' (each scan's archive checksum to its image.tar's) and refuses anything else; `signature` and `draft` hold their copies of what was signed to the hashes `sign` hands on in turn. The release's test run uses the built wheel installed by itself, from outside the source tree. `check-sdist.py` holds the source archive to that wheel (the same files of `qkvm/`, byte for byte, and the same declared dependencies), refuses a wheel that holds anything but `qkvm/` and its own dist-info (a top-level `.pth` would run at every start of the Python it is installed into), and the archive is installed by itself. Both are listed in the signed `SHA256SUMS`. On publication, `published` runs `python -m qkvm.release verify --all --signed` on every file of the published release (the signature, every file listed with its checksum, every file listed held, and nothing else), and checks that the list names exactly this version's wheel, source archive and image record; the PyPI job holds both packages to that list, by its hash, with `sha256sum`, before it uploads anything, and installs nothing. (`--signed` refuses where the checking copy has no key built in, instead of checking the checksums only, as it does for a fork's unsigned release.)

`scan-image.sh` verifies the SHA-256 of Trivy 0.76.0, creates an empty private cache, downloads the current vulnerability database and rejects data more than 48 hours old. It saves the database timestamp, scanner version, complete JSON report, CycloneDX SBOM, archive checksum, the record of the scanned digests and policy output. No `.trivyignore`, `--ignore-unfixed`, VEX or severity suppression is used. The image policy blocks:

- Every reported Python vulnerability, at any severity.
- Every OS vulnerability with an available fixed version, at any severity.
- Every CRITICAL finding, including unfixed ones.
- Every HIGH finding without an exact, current, reviewed exception.
- Incomplete/unknown scan data, missing Debian or Python inventories, missing qKVM, wrong architecture, root execution, and an unsupported OS.

The scanner cannot see native libraries bundled inside wheels or the CPython built from source. `native-versions.py` asks each image what they are (CPython, FFmpeg, libvpx, libopus, dav1d, cryptography's OpenSSL, pylibsrtp's libsrtp and OpenSSL), the answers are kept with the evidence, and `check-native-versions.py` blocks an image with any of them below its minimum in `native-minimums.json` (each kept with its reason) or unreadable.

Unfixed LOW, MEDIUM and UNKNOWN OS findings remain disclosed in the report as residual risk; they are not represented as a clean scan. The scanner cannot establish absence of unknown native decoder vulnerabilities or prove application reachability.

## Current application-only runtime

`container-exceptions.json` contains **no exceptions**. The application-only image excludes the packages responsible for the previous nine HIGH rows, including `libacl1`, `libsystemd0`, `libuuid1`, ncurses and shell/administration tools. With this empty exception list, every reported HIGH finding blocks the build. The former November 19 expiry applied to the superseded image; it is not an active acceptance window for this candidate.

The Dockerfile installs and updates dependencies in a build stage. `assemble-runtime.py` copies the application, its required native libraries, TLS trust and timezone data into the final `scratch` stage. It preserves original records and license files for the shipped Debian packages and verifies native-library provenance. Shells, package managers and optional CPython curses/readline/Tk/native UUID extensions are absent. qKVM's UUID4 generation, controller support, discovery, accounts, video and keyboard/mouse features remain. Native/PyPI installations are unchanged.

`check-image-runtime.py` runs natively on both architectures. It verifies UID 10001, no setuid/setgid files, absent maintenance tools and removed packages, agreement between the runtime manifest and package inventory, required native imports, TLS trust, UUID/timezone support and isolated JPEG roundtrips. CI also requires certificate-verified HTTPS startup and the complete application suite against the installed package inside each final image. Test tooling is mounted separately and is not installed in the runtime. Updates replace the image; no shell or package-manager maintenance inside it is supported.

Fresh scan artifacts remain the authority for current package versions and finding counts. Removing the former HIGH-associated packages does not patch retained libraries or prove that native decoding has no exploitable defects. See [the current container assessment and historical HIGH register](CONTAINER-ADVISORIES.md) and [the residual-risk assessment](CONTAINER-RESIDUALS.md). Preserve decoder isolation and the supplied nonroot, read-only, capability-free deployment; privileged execution and modified entrypoints are outside these assessments.

The exception mechanism remains available for an explicitly reviewed future change, but no exception is currently granted. Any proposed exception must identify the exact advisory and package versions, document its trigger and runtime conditions, cite sources, and expire within 31 days. A fix becoming available or a changed version/severity must fail the gate. Never renew dates automatically. `test-container-policy.py` covers malformed reports and attempted policy bypasses, including expiry, fix availability and severity escalation.

## Local reproduction

From the repository root, after building `image.tar` with the OCI exporter:

```sh
python .github/security/test-container-policy.py
python .github/security/test-image-digests.py
python .github/security/test-native-versions.py
python .github/security/test-newest-release.py
bash .github/security/scan-image.sh image.tar amd64 image-evidence
bash .github/security/audit-wheel.sh dist/qkvm-0.2.0-py3-none-any.whl dependency-evidence
```

The composite action in this directory also tests the archived image's health under the Compose security settings. It is shared by scheduled/push/pull-request CI and release builds so newly disclosed vulnerabilities surface before the next release attempt.


## Required release CI

`check-required-ci.py` requires the exact set of 18 Tests jobs to succeed for the
release commit, including integrations that the Tests workflow otherwise allows
to fail. Missing jobs, failed steps, mismatched commits and run identifiers are
rejected. The release workflow also rejects evidence collected across different
run attempts and waits up to 95 minutes within a 100-minute job timeout.

`check-required-ci.py --on-main` decides whether the release commit is on
`main` from GitHub's answers for the branch and for the comparison of the two;
a tag, another branch, a commit ahead of `main` or beside it is refused.

Run `python .github/security/test-required-ci.py` to check these decisions.
When intentionally changing the Tests matrix or job names, update the required
set and its tests in the same change. Do not remove a required job to pass a release.
