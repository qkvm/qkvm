#!/usr/bin/env bash
# Usage: bash .github/security/scan-image.sh image.tar amd64 evidence-directory
set -euo pipefail
archive=$(realpath "$1")
arch=$2
out=$(realpath -m "$3")
policy_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
case "$arch" in amd64|arm64) ;; *) echo 'Unsupported architecture' >&2; exit 2;; esac
mkdir -p "$out"
scan_tmp=$(mktemp -d)
trap 'rm -rf "$scan_tmp"' EXIT

# The scanner executable is pinned; the vulnerability data is deliberately downloaded afresh.
# An empty private cache also prevents accidental reuse of an old database or scan result.
version=0.76.0
case "$(uname -m)" in
  x86_64) scanner_arch=64bit; checksum=e24b1c51293c1b15e4ba8d45bbc7891ba053f90278ec2698f3562c993e145fe7 ;;
  aarch64) scanner_arch=ARM64; checksum=aab21e677a7b7071fc79f1711480840754c18a1b9d9cefa7ccd06af63a0e8f4c ;;
  *) echo 'Unsupported scanner host architecture' >&2; exit 2 ;;
esac
curl --fail --silent --show-error --location --retry 3 \
  "https://github.com/aquasecurity/trivy/releases/download/v${version}/trivy_${version}_Linux-${scanner_arch}.tar.gz" \
  -o "$scan_tmp/trivy.tar.gz"
printf '%s  %s\n' "$checksum" "$scan_tmp/trivy.tar.gz" | sha256sum --check --strict
tar -xzf "$scan_tmp/trivy.tar.gz" -C "$scan_tmp" trivy
# Ignore local Trivy config/ignore files: only the reviewed policy below may grant an exception.
printf '{}\n' > "$scan_tmp/empty.yaml"
"$scan_tmp/trivy" image --config "$scan_tmp/empty.yaml" --cache-dir "$scan_tmp/cache" \
  --download-db-only --no-progress
cp "$scan_tmp/cache/db/metadata.json" "$out/database.json"
python3 - "$out/database.json" <<'PY'
import datetime
import json
import sys
metadata = json.load(open(sys.argv[1], encoding="utf-8"))
updated = datetime.datetime.fromisoformat(metadata["UpdatedAt"].replace("Z", "+00:00"))
now = datetime.datetime.now(datetime.timezone.utc)
age = now - updated
if metadata["Version"] != 2 or not datetime.timedelta(0) <= age <= datetime.timedelta(hours=48):
    raise SystemExit(f"Refusing missing, future-dated, or stale vulnerability database: {metadata}")
print(f"Vulnerability database updated {updated.isoformat()}")
PY
"$scan_tmp/trivy" --cache-dir "$scan_tmp/cache" --version > "$out/scanner-version.txt"
# Trivy reads OCI layouts as directories (its tar input is Docker-format only).
# Unpack the same archive that the publisher copies, without rebuilding or rewriting any blob.
python3 - "$archive" "$scan_tmp/oci" <<'PYOCI'
import sys
import tarfile
with tarfile.open(sys.argv[1]) as archive:
    archive.extractall(sys.argv[2], filter="data")
PYOCI
"$scan_tmp/trivy" image --config "$scan_tmp/empty.yaml" --cache-dir "$scan_tmp/cache" \
  --skip-db-update --scanners vuln --ignorefile '' --ignore-unfixed=false \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL --list-all-pkgs --exit-code 0 \
  --platform "linux/$arch" --input "$scan_tmp/oci" --format json --output "$out/trivy.json" --no-progress
"$scan_tmp/trivy" convert --ignorefile '' --format cyclonedx \
  --output "$out/sbom.cdx.json" "$out/trivy.json"
sha256sum "$archive" > "$out/archive.sha256"
# What the scanner saw, held to its own report: the archive's checksum, the digest a copy of it pushes, every
# manifest under that digest. The publisher pushes nothing else (image-digests.py).
python3 "$policy_dir/image-digests.py" record --layout "$scan_tmp/oci" --report "$out/trivy.json" --archive "$archive" --arch "$arch" --output "$out/scanned-image.json"
python3 "$policy_dir/check-container-scan.py" "$out/trivy.json" \
  --exceptions "$policy_dir/container-exceptions.json" --arch "$arch" | tee "$out/policy.txt"
