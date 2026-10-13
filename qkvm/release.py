"""For whoever publishes releases: make a signing key, and sign a release's checksums.

    python -m qkvm.release keygen release-signing.key
        Writes a new private key to that file and prints the public key to put in
        RELEASE_KEYS in qkvm/update.py. Keep the file out of the repository.

    python -m qkvm.release sums dist/qkvm-1.2.3-py3-none-any.whl > SHA256SUMS
        Prints the checksum line(s) for the files of a release.

    python -m qkvm.release sign release-signing.key SHA256SUMS
        Writes SHA256SUMS.sig next to SHA256SUMS. The key may also come from the
        RELEASE_SIGNING_KEY environment variable (pass "-" as the key file), for CI.

    python -m qkvm.release publish SHA256SUMS
        What the release workflow runs. Signs with the key in RELEASE_SIGNING_KEY, and
        checks the result against the keys built into this copy (RELEASE_KEYS). Refuses
        where what would go out is a release that no copy installs: one that is not
        signed although this version takes only signed ones, or signed with another key.
        With no key here and none built in, it says so and leaves the release unsigned.

Attach the wheel, SHA256SUMS and SHA256SUMS.sig to a GitHub release tagged v1.2.3.

This file needs the cryptography library and nothing else of what the program needs: where
the key is used, as little as possible is installed.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def keygen(path: Path) -> str:
    """Create a private key file; returns the matching public key (base64)."""
    if path.exists():
        raise SystemExit(f"{path} already exists - refusing to overwrite a signing key")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    # Created private from the start (POSIX; on Windows the folder's permissions apply).
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(handle, "w", encoding="ascii") as fh:
        fh.write(base64.b64encode(raw).decode() + "\n")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(public).decode()


def sums(files: list[Path]) -> str:
    return "".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in files)


def sign(key_text: str, data: bytes) -> str:
    """Base64 Ed25519 signature of `data` with the private key (base64, as keygen writes it)."""
    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_text.strip()))
    return base64.b64encode(key.sign(data)).decode()


def built_in_keys(source: Path | None = None) -> tuple[str, ...]:
    """The public keys this copy takes releases from: RELEASE_KEYS in update.py, read without loading that file and all it needs."""
    tree = ast.parse((source or Path(__file__).with_name("update.py")).read_text(encoding="utf-8"))
    for node in tree.body:
        target: ast.expr
        value: ast.expr | None
        if isinstance(node, ast.AnnAssign):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign):
            target, value = node.targets[0], node.value
        else:
            continue
        if isinstance(target, ast.Name) and target.id == "RELEASE_KEYS" and value is not None:
            return tuple(str(key) for key in ast.literal_eval(value))
    raise SystemExit("RELEASE_KEYS was not found in update.py")


def publish(target: Path, key_text: str, keys: tuple[str, ...]) -> str:
    """Sign `target` for a release of a copy that has `keys` built in. Returns what was done, in a sentence; SystemExit where it must not go out."""
    signature = target.with_name(target.name + ".sig")
    if not key_text.strip():
        if keys:
            raise SystemExit(
                "This version installs only releases signed with a key that is built into it, and there is no signing key here "
                "(RELEASE_SIGNING_KEY). Published unsigned, it would be a release that no copy installs."
            )
        return "No signing key here and none built into this version: the release goes out unsigned, and copies say so."
    private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_text.strip()))
    public = private.public_key()
    said = base64.b64encode(public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
    if keys and said not in keys:
        raise SystemExit("The signing key here is not one of the keys built into this version (RELEASE_KEYS): no copy would take its signature.")
    made = sign(key_text, target.read_bytes())
    try:
        public.verify(base64.b64decode(made), target.read_bytes())
    except InvalidSignature:
        raise SystemExit("The signature that was just made does not check out. Nothing was written.") from None
    signature.write_text(made + "\n", encoding="ascii")
    return f"Wrote {signature}, signed with the key {said[:8]}..." + ("" if keys else " (No key is built into this version yet: its copies do not ask for one.)")


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "publish":
        print(publish(Path(argv[1]), os.environ.get("RELEASE_SIGNING_KEY", ""), built_in_keys()))
        return 0
    if len(argv) == 2 and argv[0] == "keygen":
        public = keygen(Path(argv[1]))
        print(f"Private key written to {argv[1]}. Keep it secret and backed up; anyone who has it can sign releases.")
        print("Public key, for RELEASE_KEYS in qkvm/update.py:")
        print(f'    "{public}",')
        return 0
    if len(argv) >= 2 and argv[0] == "sums":
        sys.stdout.write(sums([Path(name) for name in argv[1:]]))
        return 0
    if len(argv) == 3 and argv[0] == "sign":
        key_text = os.environ.get("RELEASE_SIGNING_KEY", "") if argv[1] == "-" else Path(argv[1]).read_text(encoding="ascii")
        if not key_text.strip():
            raise SystemExit("no signing key given")
        target = Path(argv[2])
        signature = target.with_name(target.name + ".sig")
        signature.write_text(sign(key_text, target.read_bytes()) + "\n", encoding="ascii")
        print(f"Wrote {signature}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
