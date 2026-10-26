#!/usr/bin/env bash
# Audit the dependencies actually installed by this wheel, without audit-tool dependencies mixed in.
set -euo pipefail
wheel=$(realpath "$1")
out=$(realpath -m "$2")
mkdir -p "$out"
audit_tmp=$(mktemp -d)
trap 'rm -rf "$audit_tmp"' EXIT
python -m venv --without-pip "$audit_tmp/runtime"
python -m pip --python "$audit_tmp/runtime" install "$wheel"
"$audit_tmp/runtime/bin/python" - "$out/requirements.txt" <<'PY'
import importlib.metadata
import sys
packages = sorted((d.metadata["Name"], d.version) for d in importlib.metadata.distributions())
if not any(name.lower() == "qkvm" for name, _ in packages):
    raise SystemExit("qkvm wheel was not installed")
with open(sys.argv[1], "w", encoding="utf-8") as requirements:
    for name, version in packages:
        # qKVM is our unpublished artifact, covered by its own security review. All dependencies count.
        if name.lower() != "qkvm":
            requirements.write(f"{name}=={version}\n")
PY
python -m venv "$audit_tmp/auditor"
"$audit_tmp/auditor/bin/python" -m pip install pip-audit==2.10.0
# No cache reuse: a release always checks today's advisory service, and lookup errors fail closed.
"$audit_tmp/auditor/bin/python" -m pip_audit --strict --disable-pip --no-deps \
  --cache-dir "$audit_tmp/cache" -r "$out/requirements.txt" --format json --output "$out/pip-audit.json"
