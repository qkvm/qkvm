"""Self-signed certificate for serving the wall over HTTPS."""

from __future__ import annotations

import datetime
import ipaddress
import os
import socket
import sys
from collections.abc import Iterable
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ._folders import not_ours, private, private_folder

VALID_DAYS = 825  # the longest lifetime Apple platforms accept for a server certificate
RENEW_DAYS = 30


def _fingerprint(cert: x509.Certificate) -> str:
    digest = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))


def _names(addresses: Iterable[str]) -> tuple[set[str], set[str]]:
    host = socket.gethostname().lower()
    # A computer's name with letters outside ASCII in it ("büro-pc") cannot be written into a certificate as it
    # is, and one that tried was a qKVM that did not start: it is reached by its addresses and as localhost.
    dns = {"localhost", *([host] if host and host.isascii() and " " not in host else [])}
    # An address as it stands in a certificate: without the "%3" that says which network card (a certificate
    # has no place for that, and one that was compared with it never matched and was made anew at every look).
    ips = {str(ipaddress.ip_address(address.split("%", 1)[0])) for address in {"127.0.0.1", *addresses} - {"0.0.0.0", "::"}}
    return dns, ips


def _covers(cert: x509.Certificate, dns: set[str], ips: set[str]) -> bool:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return False
    have_dns = set(san.get_values_for_type(x509.DNSName))
    have_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    return dns <= have_dns and ips <= have_ips


def certificate_fingerprint(cert_path: Path) -> str:
    """The SHA-256 fingerprint of the (first) certificate in a PEM file, as browsers show it."""
    return _fingerprint(x509.load_pem_x509_certificate(cert_path.read_bytes()))


class NotOurs(ValueError):
    """The folder the certificate is kept in is a link, or another account's: nothing is written into it."""


def ensure_certificate(directory: Path, addresses: Iterable[str]) -> tuple[Path, Path, str]:
    """Create the wall's certificate, or renew it when it is expiring or misses an address.

    Returns (certificate file, key file, SHA-256 fingerprint). NotOurs where the folder is a link or another account's:
    what another account put in the data folder while it was open stays that account's (whoever owns a file may change its
    permissions), and a junction planted as `tls` took the wall's HTTPS key into a folder of theirs (the round 3 review).
    A certificate or key in it that is a link or another account's is not used: a pair of the wall's own replaces it.
    """
    if os.path.lexists(directory):
        if (why := not_ours(directory)) is not None:
            raise NotOurs(
                f"{directory} {why}: it may have been put there by another account while the data folder was open, and nothing "
                "is written into it. Delete it, and qKVM makes its own."
            )
    elif sys.platform == "win32":
        private_folder(directory)  # (its own, from its first instant)
    else:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    cert_path, key_path = directory / "cert.pem", directory / "key.pem"
    dns, ips = _names(addresses)
    now = datetime.datetime.now(datetime.timezone.utc)

    if cert_path.exists() and key_path.exists() and not_ours(cert_path) is None and not_ours(key_path) is None:
        try:
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            fresh = cert.not_valid_after_utc - now > datetime.timedelta(days=RENEW_DAYS)
            # The two are two files: one written and the other not (the power went) is a pair the web server
            # cannot start with, however often it tries.
            held = serialization.load_pem_private_key(key_path.read_bytes(), None).public_key()
            spelt = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            pair = held.public_bytes(*spelt) == cert.public_key().public_bytes(*spelt)
            if fresh and pair and _covers(cert, dns, ips):
                return cert_path, key_path, _fingerprint(cert)
        except (OSError, ValueError, TypeError):
            pass  # unreadable: replace it

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "qKVM")])
    san = [x509.DNSName(d) for d in sorted(dns)] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sorted(ips)]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    # Each is written in full under another name and then put in place, the key first: a file is the old
    # one or the new one, never half of one. The key is private from the start (POSIX by its mode; Windows by
    # its own ACL, given as it is made, whatever the folder's: _vault_windows.create_private).
    new_key, new_cert = key_path.with_suffix(".new"), cert_path.with_suffix(".new")
    if sys.platform == "win32":
        from ._vault_windows import create_private

        new_key.unlink(missing_ok=True)  # (left by a write that was cut off: made anew, its own)
        fd = create_private(new_key)
    else:
        fd = os.open(new_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key_pem)
    new_cert.unlink(missing_ok=True)
    with private(new_cert, "xb") as fh:  # (nothing secret in it: but every file the wall makes is its own)
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    os.replace(new_key, key_path)
    os.replace(new_cert, cert_path)
    return cert_path, key_path, _fingerprint(cert)
