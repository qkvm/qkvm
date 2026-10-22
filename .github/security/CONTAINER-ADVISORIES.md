# Application-only container remediation — 22 October 2026

The application-only candidate replaces the earlier trimmed general-purpose image. All nine HIGH-associated packages are excluded from the final runtime, and `container-exceptions.json` now contains no exceptions. The release scan must therefore report zero HIGH and CRITICAL findings. Both architectures must pass fresh scans and the full application suite inside the final image before release.

The build stage installs the unchanged qKVM package on the same pinned Debian-based Python image and applies stable updates. The final stage copies Python/application files, the vendor-owned libraries required by their native objects, certificate and timezone data, and original package records/license files. It excludes shell/package-management tools and their ACL/systemd dependencies. Original package names, versions and source attribution are retained for shipped packages; no scanner ignore filter or VEX suppression is used.

Optional CPython curses/readline/Tk/native UUID extensions are excluded. These are terminal/desktop interfaces and native UUID1 support, not qKVM web features. qKVM's UUID4 generation retains Python's OS-randomness implementation. No controller, discovery, account, storage, browser, video, or keyboard/mouse feature is removed. The container is an application appliance, not a general-purpose Python development environment; use Docker logs and the Python health check instead of an interactive shell. Native/PyPI installations are unchanged.

The build verifies native dependency provenance. Runtime checks verify nonroot execution, privilege bits, absence of the removed components, TLS trust, UUIDs, timezones and isolated JPEG roundtrips. CI additionally runs the complete application test suite against the installed package inside each final image, with test tooling mounted separately. The ordinary Windows/Linux, browser and controller CI jobs remain required.

Remaining MEDIUM/LOW library findings stay visible and require evaluation and upstream updates. A clean HIGH count does not resolve codec risk or prove absence of unknown vulnerabilities. Keep the existing decoder isolation and deployment restrictions.

## Historical assessment of the previous image

The following records why the earlier image had nine HIGH rows. Its exceptions are superseded by package removal above and must not be renewed for the new image.

### Container HIGH advisory assessment — 21 October 2026

The original 44 HIGH package/advisory rows per architecture represented eight distinct CVEs, not 44 independent defects. Four util-linux CVEs were each attributed to nine binary packages from the same source. This assessment concerns the supplied qKVM container, not the Docker host or an independently managed Python installation.

The container now removes `bsdutils`, `login`, `mount`, `util-linux`, `ncurses-bin`, `perl-base`, `libblkid1`, `liblastlog2-2`, `libmount1` and `libsmartcols1`. Removing packages also removes their executables/libraries through the package manager; package records are not hidden or rewritten. Python-linked libraries remain. This is an immutable application image: Debian's general-purpose essential-package assumption is deliberately narrowed, after installation and user creation. Upgrade by rebuilding/replacing the image.

## Disposition of each original HIGH advisory

| Advisory | Original rows | Retained scope | qKVM exposure and action |
|---|---:|---|---|
| [CVE-2026-76642](https://security-tracker.debian.org/tracker/CVE-2026-76642) | 9 | `libuuid1` | Failed mount helpers could still trigger privileged post-mount operations. Removed `mount` and `libmount1`; qKVM does not perform OS mount operations. The retained UUID library does not contain that implementation. |
| [CVE-2026-78408](https://security-tracker.debian.org/tracker/CVE-2026-78408) | 9 | `libuuid1` | A privileged operator using `nsenter --join-cgroup` could pass a privileged descriptor to an untrusted target. Removed `nsenter` with util-linux. The retained UUID library does not implement namespace entry. |
| [CVE-2026-78409](https://security-tracker.debian.org/tracker/CVE-2026-78409) | 9 | `libuuid1` | Privileged `X-mount.subdir` resolution could escape through intermediate symlinks. Removed mount/libmount. The default fstab is unconfigured; the UUID library has no mount-path resolution code. |
| [CVE-2026-78410](https://security-tracker.debian.org/tracker/CVE-2026-78410) | 9 | `libuuid1` | Restricted privileged bind mounts could redirect ownership/mode changes. Removed mount/libmount. qKVM does not invoke this functionality. |
| [CVE-2026-54369](https://security-tracker.debian.org/tracker/CVE-2026-54369) | 1 | `libacl1` | Pathname ACL operations can follow attacker-controlled symlinks. The library remains because core base utilities depend on it. No qKVM use of its ACL APIs was identified; `setfacl` is absent. This is conditional residual risk, not a patched-library claim. Root execution of ACL-aware tools on attacker-controlled paths would invalidate the deployment assumptions. |
| [CVE-2025-69720](https://security-tracker.debian.org/tracker/CVE-2025-69720) | 4 | ncurses libraries/data | The overflow is in `infocmp`'s `analyze_string`, not the retained shared-library implementation. Removed `infocmp` with ncurses-bin; qKVM does not accept terminfo input. Libraries remain to preserve Python curses and shell compatibility. |
| [CVE-2026-16742](https://github.com/systemd/systemd/security/advisories/GHSA-jm29-p7hh-vjhv) | 2 | `libsystemd0` | The affected homed/homework authentication components are absent. Their shared source package also produces these libraries; library presence does not install the vulnerable service. The runtime check rejects both executables. |
| [CVE-2026-9538](https://security-tracker.debian.org/tracker/CVE-2026-9538) | 1 | None | Perl Archive::Tar can allocate excessive memory from a crafted header. That module was absent already; perl-base is now also removed and its exception deleted. qKVM does not use Perl to unpack archives. |

## Remaining risks and how to reduce them

No remotely reachable qKVM exploit for these eight CVEs was established. Component absence provides stronger evidence than an unused-feature assumption, but this review does not prove absence of every exploit chain or unknown vulnerability. The ACL library remains a conditional exposure; runtime nonroot identity, no setuid/setgid executables, dropped capabilities, no-new-privileges and a read-only root constrain its privileged trigger. Do not run the container privileged, as root, with host namespaces, or with the Docker socket mounted.

The Debian stable tracker still lists the relevant source versions as vulnerable/deferred. Upstream fixes and newer Debian unstable/testing packages exist, but mixing unstable system libraries into the stable image would add ABI and maintenance risk. Continue rebuilding for stable security updates. When stable fixes arrive, the policy blocks old exceptions from accepting a finding that has an available fix. If a retained library becomes necessary on an untrusted or privileged path, address that path immediately rather than renewing an exception.

The follow-up runtime reduction also removes apt, libapt-pkg7.0, adduser, passwd, login.defs, libpam-modules, libpam-modules-bin, libpam-runtime, libpam0g, sysvinit-utils and libudev1. The expected remaining scanner attribution is nine HIGH rows: four for libuuid1, three for ncurses libraries/data, one for libsystemd0 and one for libacl1. These are retained in raw scan evidence and are not filtered with ignore files or VEX. Confirm counts against each build's fresh scan. Exceptions retain their original expiry: **November 19, 2026, 00:00 UTC**, with no automatic renewal.

The scan gate rejects all 21 removed package names even without a vulnerability finding. Runtime checks reject the affected executable/module paths and libmount, preserve package inventory, check nonroot identity and filesystem privilege bits, and import Python native extensions plus video/TLS dependencies. Both architectures must pass these checks and certificate-verified HTTPS startup before publication.

A future smaller runtime base could eliminate more source-package attributions, but it must preserve Python native extensions, codec dependencies, CA certificates, timezone data and a verifiable SBOM. Removing package metadata or suppressing advisories is not remediation. Native decoder hardening, host patching, restricted controller networks and secure storage remain separate security obligations.
