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
