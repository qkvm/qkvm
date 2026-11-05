#!/usr/bin/env bash
# Audit every library a release's lock names, for every Python and system an update is installed in place on (each
# name and version once), against today's advisory data, as audit-wheel.sh audits what the wheel installs here.
#     bash .github/security/audit-lock.sh LIBRARIES-FOLDER OUT
set -euo pipefail
libraries=$(realpath "$1")
out=$(realpath -m "$2")
mkdir -p "$out"
audit_tmp=$(mktemp -d)
trap 'rm -rf "$audit_tmp"' EXIT
cat "$libraries"/requirements/*.txt | cut -d ' ' -f 1 | LC_ALL=C sort -u > "$out/lock-requirements.txt"
test -s "$out/lock-requirements.txt"
python -m venv "$audit_tmp/auditor"
"$audit_tmp/auditor/bin/python" -m pip install pip-audit==2.10.1
# No cache reuse: a release always checks today's advisory service, and lookup errors fail closed.
"$audit_tmp/auditor/bin/python" -m pip_audit --strict --disable-pip --no-deps \
  --cache-dir "$audit_tmp/cache" -r "$out/lock-requirements.txt" --format json --output "$out/pip-audit-lock.json"
