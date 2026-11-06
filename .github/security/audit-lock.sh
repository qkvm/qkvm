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
# pip-audit takes a package once in a list. The lock may name one at two versions (pyee 13 for Python 3.11, 16 from
# 3.12): each list holds every name once, the first version of each in the first, a second one in the second, and so on.
awk -v out="$out" '{ key = tolower($0); sub(/==.*/, "", key); gsub(/[-_.]+/, "-", key); print > (out "/lock-requirements-" (++seen[key]) ".txt") }' "$out/lock-requirements.txt"
"$audit_tmp/auditor/bin/python" -m pip install pip-audit==2.10.1
# No cache reuse: a release always checks today's advisory service, and lookup errors fail closed.
for list in "$out"/lock-requirements-*.txt; do
  round=$(basename "$list" .txt)
  "$audit_tmp/auditor/bin/python" -m pip_audit --strict --disable-pip --no-deps \
    --cache-dir "$audit_tmp/cache" -r "$list" --format json --output "$out/pip-audit-${round#lock-requirements-}.json"
done
