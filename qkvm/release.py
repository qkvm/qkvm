"""For whoever publishes releases: make a signing key, and sign a release's checksums.

    python -m qkvm.release keygen release-signing.key
        Writes a new private key to that file and prints the public key to put in
        RELEASE_KEYS in qkvm/update.py. Keep the file out of the repository.

    python -m qkvm.release sums dist/qkvm-1.2.3-py3-none-any.whl > SHA256SUMS
        Prints the checksum line(s) for the files of a release.

    python -m qkvm.release sign release-signing.key SHA256SUMS
        Writes SHA256SUMS.sig next to SHA256SUMS. The key may also come from the
        RELEASE_SIGNING_KEY environment variable (pass "-" as the key file), for CI.

    python -m qkvm.release publish [--openssl] SHA256SUMS
        What the release workflow runs. Signs with the key in RELEASE_SIGNING_KEY, and
        checks the result against the keys built into this copy (RELEASE_KEYS). Refuses
        where what would go out is a release that no copy installs: one that is not
        signed although this version takes only signed ones, or signed with another key.
        With no key here and none built in, it says so and leaves the release unsigned.
        With --openssl, the signing is done by the openssl command (3.0 or later) instead
        of the cryptography library: the same signature, byte for byte (Ed25519 is
        deterministic), where nothing may be installed beside the key. On Linux that is
        /usr/bin/openssl, not whatever PATH finds first. An openssl that does not give
        RFC 8032's own signature for RFC 8032's own key is refused.

    python -m qkvm.release verify [--signed] [--all | --all-packages] [--openssl] SHA256SUMS FILE...
        What the release workflow runs before files go out elsewhere (to PyPI). Refuses unless
        SHA256SUMS is signed (SHA256SUMS.sig beside it) with a key built into this copy, and
        every FILE is listed in it with its checksum; with --all-packages, also unless every
        wheel and source archive it lists is among the FILEs; with --all, every file it lists.
        A copy with no key built in checks the checksums only, unless --signed is given:
        then it refuses, as there is no key to check a signature with. With --openssl, the
        signature is checked by the openssl command.

Attach the wheel, the source archive, SHA256SUMS and SHA256SUMS.sig to a GitHub release tagged v1.2.3 (the release
workflow makes it a draft with these files and the record of the scanned images, and a person publishes it).

This file needs the cryptography library, or with --openssl the openssl command instead, and nothing else of what the
program needs: where the key is used, as little as possible is installed. The library is loaded only where it is used.
"""

from __future__ import annotations

import ast
import base64
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

# Ed25519 keys as DER, around the 32 raw bytes keygen writes (PKCS #8 for the private key, SubjectPublicKeyInfo for
# the public one): how openssl is handed and gives them.
PRIVATE_DER = bytes.fromhex("302e020100300506032b657004220420")
PUBLIC_DER = bytes.fromhex("302a300506032b6570032100")
# RFC 8032, 7.1, TEST 2: a key, a message of one byte, and the signature every Ed25519 gives for them. (TEST 1 signs
# the empty message, which openssl's pkeyutl does not take from a file.)
RFC8032_SECRET = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
RFC8032_PUBLIC = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
RFC8032_MESSAGE = bytes.fromhex("72")
RFC8032_SIGNATURE = bytes.fromhex(
    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
)


def default_openssl(system: str = os.name) -> str | None:
    """The openssl to use where none is named: on Linux and the like the system's own, /usr/bin/openssl (what lies first
    on PATH can be anything put there); elsewhere (Windows) the one PATH finds."""
    return "/usr/bin/openssl" if system == "posix" else shutil.which("openssl")


class OpenSSL:
    """Ed25519 by the openssl command (3.0 or later) instead of the cryptography library, for where nothing may be
    installed beside the signing key. Checked when made: an openssl that does not give RFC 8032's own public key and
    signature for RFC 8032's own key, or that takes a wrong signature, is refused, and says so."""

    def __init__(self, program: str | None = None) -> None:
        wanted = program or default_openssl()
        found = shutil.which(wanted) if wanted else None
        if not found:
            raise SystemExit(f"No openssl command here ({wanted or 'openssl'} was not found): nothing was signed or checked.")
        self.program = found
        with tempfile.TemporaryDirectory() as folder:
            message = Path(folder) / "message"
            message.write_bytes(RFC8032_MESSAGE)
            right = (
                self.public(RFC8032_SECRET) == RFC8032_PUBLIC
                and self.sign(RFC8032_SECRET, message) == RFC8032_SIGNATURE
                and self.check(RFC8032_PUBLIC, RFC8032_MESSAGE, RFC8032_SIGNATURE)
                and not self.check(RFC8032_PUBLIC, b"another message", RFC8032_SIGNATURE)
            )
        if not right:
            raise SystemExit(f"This openssl ({found}) does not sign with Ed25519 as RFC 8032 says: nothing was signed or checked with it.")

    def _run(self, arguments: list[str], given: bytes = b"") -> bytes:
        try:
            done = subprocess.run([self.program, *arguments], input=given, capture_output=True, timeout=60, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise SystemExit(f"openssl ({self.program}) could not be run: {error}") from None
        if done.returncode:
            said = done.stderr.decode("utf-8", "replace").strip().splitlines()
            raise SystemExit(f"openssl ({self.program}) could not do it ({' '.join(arguments[:2])}): {said[0] if said else done.returncode}")
        return done.stdout

    def public(self, private: bytes) -> bytes:
        """The raw public key of a raw private key (the key goes over a pipe)."""
        made = self._run(["pkey", "-inform", "DER", "-pubout", "-outform", "DER"], PRIVATE_DER + private)
        if len(made) != len(PUBLIC_DER) + 32 or not made.startswith(PUBLIC_DER):
            raise SystemExit(f"openssl ({self.program}) did not give an Ed25519 public key")
        return made[len(PUBLIC_DER) :]

    def sign(self, private: bytes, path: Path) -> bytes:
        """The Ed25519 signature of the file's bytes, raw (64 bytes)."""
        key = PRIVATE_DER + private
        if os.name == "posix":
            # Over a pipe: the key is in no file.
            made = self._run(["pkeyutl", "-sign", "-rawin", "-inkey", "/dev/stdin", "-keyform", "DER", "-in", str(path)], key)
        else:
            # (openssl on Windows has no /dev/stdin: the key is in a file of this user's own while it signs, then gone.)
            with tempfile.TemporaryDirectory() as folder:
                key_file = Path(folder) / "key.der"
                handle = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(handle, "wb") as stream:
                    stream.write(key)
                try:
                    made = self._run(["pkeyutl", "-sign", "-rawin", "-inkey", str(key_file), "-keyform", "DER", "-in", str(path)])
                finally:
                    key_file.unlink(missing_ok=True)
        if len(made) != 64:
            raise SystemExit(f"openssl ({self.program}) did not give an Ed25519 signature")
        return made

    def check(self, public: bytes, data: bytes, signature: bytes) -> bool:
        """Whether `public` (raw) signed `data` with `signature` (raw)."""
        with tempfile.TemporaryDirectory() as folder:
            files = {name: Path(folder) / name for name in ("public.der", "message", "signature")}
            files["public.der"].write_bytes(PUBLIC_DER + public)
            files["message"].write_bytes(data)
            files["signature"].write_bytes(signature)
            arguments = ["pkeyutl", "-verify", "-rawin", "-pubin", "-inkey", str(files["public.der"]), "-keyform", "DER",
                         "-in", str(files["message"]), "-sigfile", str(files["signature"])]
            try:
                done = subprocess.run([self.program, *arguments], capture_output=True, timeout=60, check=False)
            except (OSError, subprocess.SubprocessError) as error:
                raise SystemExit(f"openssl ({self.program}) could not be run: {error}") from None
        return done.returncode == 0 and b"Signature Verified Successfully" in done.stdout


def keygen(path: Path) -> str:
    """Create a private key file; returns the matching public key (base64)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_text.strip()))
    return base64.b64encode(key.sign(data)).decode()


def private_key(key_text: str) -> bytes:
    """The raw private key from its text (base64, as keygen writes it); never repeated in a message."""
    try:
        raw = base64.b64decode(key_text.strip(), validate=True)
    except ValueError:
        raise SystemExit("The signing key is not base64, as keygen writes it.") from None
    if len(raw) != 32:
        raise SystemExit("The signing key is not an Ed25519 key (32 bytes, as keygen writes it).")
    return raw


def library_public(private: bytes) -> bytes:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def library_sign(private: bytes, data: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    return Ed25519PrivateKey.from_private_bytes(private).sign(data)


def library_check(public: bytes, data: bytes, signature: bytes) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


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


def publish(target: Path, key_text: str, keys: tuple[str, ...], openssl: OpenSSL | None = None) -> str:
    """Sign `target` for a release of a copy that has `keys` built in, with the cryptography library or, given one, with
    openssl. Returns what was done, in a sentence; SystemExit where it must not go out."""
    signature = target.with_name(target.name + ".sig")
    if not key_text.strip():
        if keys:
            raise SystemExit(
                "This version installs only releases signed with a key that is built into it, and there is no signing key here "
                "(RELEASE_SIGNING_KEY). Published unsigned, it would be a release that no copy installs."
            )
        return "No signing key here and none built into this version: the release goes out unsigned, and copies say so."
    private = private_key(key_text)
    public = openssl.public(private) if openssl else library_public(private)
    said = base64.b64encode(public).decode()
    if keys and said not in keys:
        raise SystemExit("The signing key here is not one of the keys built into this version (RELEASE_KEYS): no copy would take its signature.")
    data = target.read_bytes()
    made = openssl.sign(private, target) if openssl else library_sign(private, data)
    if not (openssl.check(public, data, made) if openssl else library_check(public, data, made)):
        raise SystemExit("The signature that was just made does not check out. Nothing was written.")
    # (A line feed on every system: the very bytes, wherever it is signed.)
    signature.write_text(base64.b64encode(made).decode() + "\n", encoding="ascii", newline="\n")
    return (
        f"Wrote {signature}, signed with the key {said[:8]}..." + (" (by openssl)" if openssl else "")
        + ("" if keys else " (No key is built into this version yet: its copies do not ask for one.)")
    )


SUMS_LINE = re.compile(r"([0-9a-f]{64}) [ *]([^/\\\s][^/\\]*)")
PACKAGES = (".whl", ".tar.gz")  # what goes to PyPI of what a release lists


def listed(sums: bytes) -> dict[str, str]:
    """A release's checksum list, read exactly: one "<sha256>  <name>" a line, as sha256sum writes it, each name once."""
    try:
        text = sums.decode("ascii")
    except UnicodeDecodeError:
        raise SystemExit("The release's SHA256SUMS is not plain text") from None
    names: dict[str, str] = {}
    for line in text.splitlines():
        match = SUMS_LINE.fullmatch(line)
        if not match or match.group(2) in names:
            raise SystemExit(f"The release's SHA256SUMS has a line that is not the checksum of one file named once: {line!r}")
        names[match.group(2)] = match.group(1)
    if not names:
        raise SystemExit("The release's SHA256SUMS lists no file")
    return names


def signed_by(data: bytes, signature: bytes, keys: tuple[str, ...], openssl: OpenSSL | None = None) -> bool:
    """Whether one of `keys` signed `data` (the signature as the release carries it: base64, then a line feed), checked
    with the cryptography library or, given one, with openssl."""
    try:
        raw = base64.b64decode(signature.strip(), validate=True)
    except ValueError:
        return False
    if len(raw) != 64:
        return False
    for key in keys:
        try:
            public = base64.b64decode(key, validate=True)
        except ValueError:
            continue
        if len(public) == 32 and (openssl.check(public, data, raw) if openssl else library_check(public, data, raw)):
            return True
    return False


def verify(
    sums: Path, files: list[Path], keys: tuple[str, ...], complete: str | None = None, signed: bool = False, openssl: OpenSSL | None = None
) -> str:
    """Hold files that go out elsewhere (to PyPI) to the release's signed checksum list. Returns what was checked, in a
    sentence; SystemExit where they are not the files the release lists, or the list is not signed with one of `keys`.

    complete: None, every file given is listed; "packages", and every wheel and source archive listed is given; "all",
    and every file listed is given. signed: a signature is required even where `keys` is empty (where a release is
    published, a copy built without a key is a mistake, not a fork's unsigned release). openssl: the signature is
    checked with it, not with the cryptography library.
    """
    if not files:
        raise SystemExit("No file to check")
    if signed and not keys:
        raise SystemExit("A signature is required here, and this copy has no key built in to check one with (RELEASE_KEYS).")
    data = sums.read_bytes()
    if keys:
        signature = sums.with_name(sums.name + ".sig")
        if not signature.is_file():
            raise SystemExit("The release's SHA256SUMS has no signature, and this version takes only signed releases.")
        if not signed_by(data, signature.read_bytes(), keys, openssl):
            raise SystemExit("The release's SHA256SUMS is not signed with a key built into this version (RELEASE_KEYS).")
    names = listed(data)
    given: set[str] = set()
    for path in files:
        if path.name in given:
            raise SystemExit(f"{path.name} is given twice")
        given.add(path.name)
        if path.name not in names:
            raise SystemExit(f"{path.name} is not in the release's checksums")
        if hashlib.sha256(path.read_bytes()).hexdigest() != names[path.name]:
            raise SystemExit(f"{path} is not the one the release lists: its checksum differs")
    if complete is not None:
        wanted = {name for name in names if complete == "all" or name.endswith(PACKAGES)}
        missing = sorted(wanted - given)
        if missing:
            raise SystemExit(f"The release lists {', '.join(missing)}, which is not here")
    if keys:
        return f"{len(files)} file(s) are the ones the release lists in its SHA256SUMS, signed with a key built into this version."
    return f"{len(files)} file(s) are the ones the release lists. No key is built into this version: checked against the checksums only."


def main(argv: list[str]) -> int:
    if argv[:1] == ["verify"]:
        rest = argv[1:]
        options: list[str] = []
        while rest and rest[0].startswith("--"):
            options.append(rest.pop(0))
        completes = {"--all": "all", "--all-packages": "packages"}
        chosen = [completes[option] for option in options if option in completes]
        known = (*completes, "--signed", "--openssl")
        if len(rest) < 2 or len(chosen) > 1 or any(option not in known for option in options) or len(set(options)) != len(options):
            print(__doc__)
            return 2
        complete = chosen[0] if chosen else None
        openssl = OpenSSL() if "--openssl" in options else None
        print(verify(Path(rest[0]), [Path(name) for name in rest[1:]], built_in_keys(), complete, signed="--signed" in options, openssl=openssl))
        return 0
    if argv[:1] == ["publish"] and (len(argv) == 2 or (len(argv) == 3 and argv[1] == "--openssl")):
        openssl = OpenSSL() if argv[1] == "--openssl" else None
        print(publish(Path(argv[-1]), os.environ.get("RELEASE_SIGNING_KEY", ""), built_in_keys(), openssl))
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
        signature.write_text(sign(key_text, target.read_bytes()) + "\n", encoding="ascii", newline="\n")
        print(f"Wrote {signature}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
