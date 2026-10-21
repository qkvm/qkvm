# Release security gate

The release requires the latest eligible `Tests` push/manual run for its exact commit and every one of the 18 required jobs to succeed, including integrations otherwise allowed to fail in Tests. A running match is awaited for up to 95 minutes; missing, failed or incomplete evidence blocks release.

Every publication job in `release.yml` waits for the wheel's dependency audit and for **both** `amd64` and `arm64` image jobs. A failing scanner, unavailable advisory database, malformed report, failed runtime check, or policy failure stops GitHub asset attachment, PyPI upload and image publication. The GitHub release event itself already exists when this workflow starts; the gate controls its downloadable assets and the other publication channels.

The build jobs have read-only repository permissions and no signing or registry secrets. The signing key stays in the separate `release` environment job. Images are built once into OCI archives with SBOM/provenance, tested and scanned in that form, and uploaded as job artifacts only after success. The publisher verifies archive checksums and uses `skopeo copy --all --preserve-digests`; it refuses any changed manifest digest. Multiarchitecture tags combine those copied manifests with their attestations. No image rebuild runs in a publishing job.

## Policy

`audit-wheel.sh` installs the built wheel in an environment without pip, inventories every installed runtime dependency, and checks those exact versions with pip-audit using a separate tool environment and fresh advisory lookup. Lookup errors fail the job. qKVM itself is the unpublished artifact under review and is excluded from the third-party advisory lookup.

`scan-image.sh` verifies the SHA-256 of Trivy 0.76.0, creates an empty private cache, downloads the current vulnerability database and rejects data more than 48 hours old. It saves the database timestamp, scanner version, complete JSON report, CycloneDX SBOM, archive checksum and policy output. No `.trivyignore`, `--ignore-unfixed`, VEX or severity suppression is used. The image policy blocks:

- Every reported Python vulnerability, at any severity.
- Every OS vulnerability with an available fixed version, at any severity.
- Every CRITICAL finding, including unfixed ones.
- Every HIGH finding without an exact, current, reviewed exception.
- Incomplete/unknown scan data, missing Debian or Python inventories, missing qKVM, wrong architecture, root execution, and an unsupported OS.

Unfixed LOW, MEDIUM and UNKNOWN OS findings remain disclosed in the report as residual risk; they are not represented as a clean scan. The scanner cannot establish absence of unknown native decoder vulnerabilities or prove application reachability.

## Reviewed exceptions, October 21, 2026

`container-exceptions.json` records seven HIGH advisories as individual entries, with the precise Debian 13.7 binary package versions reported for this candidate. Each entry cites upstream and Debian sources, identifies the trigger and the reason no application path was established, and expires at **00:00 UTC on November 19, 2026**. The 30-day review window does not imply those packages were patched. A changed package version, distribution release, vulnerability severity, new finding or available fix fails the gate until reviewed. Expired entries fail even if not used.

- Four util-linux advisories remain attributed to `libuuid1`, retained for Python `_uuid`. The affected mount/nsenter executables and `libmount1` are removed. The UUID library does not implement those vulnerable paths.
- The ACL advisory requires privileged pathname ACL operations that qKVM does not perform; `setfacl` is absent.
- The ncurses advisory affects the removed `infocmp` executable. Libraries/data remain for Python curses and the base shell; retaining their source-version findings does not mean the CLI code remains.
- The systemd advisory affects `systemd-homed`/`systemd-homework`, which are absent. Only `libsystemd0` remains; `libudev1` has been removed.
- The Perl advisory is removed from the exception list: `perl-base` is now removed entirely. `Archive::Tar` was already absent before trimming.

The Dockerfile purges 21 unused OS packages after upgrades, Python installation and account creation. Several are Debian general-purpose OS essentials; this removal is intentionally limited to the immutable application image, never a host installation. Run OS updates by rebuilding/replacing the image, not by administering it as a general-purpose Debian system. Package metadata remains intact and `dpkg --audit` must be empty.

`check-image-runtime.py` runs against each architecture and verifies UID 10001, absence of setuid/setgid files, empty fstab, absence of removed utilities/libraries and installer tooling, and successful imports of Python native extensions plus the video/TLS stack. The scan policy rejects all 21 removed packages even if a future scanner reports no CVE for them. Source reachability remains a review obligation. See [the lower-severity assessment](CONTAINER-RESIDUALS.md) for the remaining library and deployment risks, and [the advisory assessment](CONTAINER-ADVISORIES.md) for the eight original CVEs and remaining exposure. Privileged containers, arbitrary shell/tool execution inside the image, and modified entrypoints are outside these dispositions.

Do not renew dates automatically. Recheck upstream fixes, the final image package versions, each exception's trigger and runtime conditions. Remove exceptions when the package is fixed or absent. Keep any new exception equally specific and time-limited. `test-container-policy.py` tests malformed reports and attempted policy bypasses, including changed versions, fix availability, expiry and severity escalation.

## Local reproduction

From the repository root, after building `image.tar` with the OCI exporter:

```sh
python .github/security/test-container-policy.py
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

Run `python .github/security/test-required-ci.py` to check these decisions.
When intentionally changing the Tests matrix or job names, update the required
set and its tests in the same change. Do not remove a required job to pass a release.
