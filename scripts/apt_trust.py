#!/usr/bin/env python3
"""APT signing-key bootstrap and signed-index verification primitives."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from release_contract import (
    COMMIT_RE,
    ContractError,
    REPOSITORY_RE,
    validate_apt_values,
)


FINGERPRINT_RE = re.compile(r"^(?:[0-9A-F]{40}|[0-9A-F]{64})$")
KEY_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._+-]+$")
RELEASE_PATH_RE = re.compile(r"^[A-Za-z0-9+._~/-]+$")
MAX_KEY_BYTES = 1024 * 1024
MAX_INRELEASE_BYTES = 4 * 1024 * 1024
MAX_PACKAGES_BYTES = 128 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        raise ContractError(f"redirect refused: HTTP {code}")


@dataclass(frozen=True)
class SignedFile:
    sha256: str
    size: int


def validate_signing_key_values(url: str, fingerprint: str) -> None:
    if not isinstance(fingerprint, str) or not FINGERPRINT_RE.fullmatch(fingerprint):
        raise ContractError(
            "apt_signing_key_fingerprint must be a full uppercase fingerprint"
        )
    if (
        not isinstance(url, str)
        or not url
        or "\\" in url
        or any(ord(character) < 0x21 or character.isspace() for character in url)
    ):
        raise ContractError("apt_signing_key_url contains an invalid character")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ContractError("apt_signing_key_url is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "raw.githubusercontent.com"
        or port is not None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in url
        or "#" in url
        or urllib.parse.unquote(parsed.path) != parsed.path
    ):
        raise ContractError(
            "apt_signing_key_url must be an uncredentialed GitHub HTTPS raw URL"
        )
    parts = parsed.path.removeprefix("/").split("/")
    if (
        len(parts) < 4
        or not REPOSITORY_RE.fullmatch("/".join(parts[:2]))
        or not COMMIT_RE.fullmatch(parts[2])
        or any(
            part in {"", ".", ".."} or not KEY_COMPONENT_RE.fullmatch(part)
            for part in parts[3:]
        )
    ):
        raise ContractError(
            "apt_signing_key_url must pin a file at a full immutable commit SHA"
        )


def download_no_redirect(url: str, timeout: int, maximum_bytes: int) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Cache-Control": "no-cache", "User-Agent": "xr-release-workflows/1"},
    )
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.status != 200:
            raise ContractError(f"download returned HTTP {response.status}")
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None:
            try:
                if int(declared_length) > maximum_bytes:
                    raise ContractError("download exceeds the permitted size")
            except ValueError as exc:
                raise ContractError("download has an invalid Content-Length") from exc
        payload = response.read(maximum_bytes + 1)
    if len(payload) > maximum_bytes:
        raise ContractError("download exceeds the permitted size")
    return payload


def parse_primary_fingerprints(colon_listing: str) -> list[str]:
    fingerprints: list[str] = []
    awaiting_primary = False
    for raw in colon_listing.splitlines():
        fields = raw.split(":")
        record_type = fields[0] if fields else ""
        if record_type in {"sec", "ssb"}:
            raise ContractError("APT signing key file must not contain private key material")
        if record_type == "pub":
            if awaiting_primary:
                raise ContractError("APT signing key is missing a primary fingerprint")
            awaiting_primary = True
            continue
        if record_type == "fpr" and awaiting_primary:
            if len(fields) <= 9 or not FINGERPRINT_RE.fullmatch(fields[9]):
                raise ContractError("GPG returned an invalid primary-key fingerprint")
            fingerprints.append(fields[9])
            awaiting_primary = False
    if awaiting_primary:
        raise ContractError("APT signing key is missing its primary fingerprint")
    return fingerprints


def require_gpg_tools() -> tuple[str, str]:
    gpg = shutil.which("gpg")
    gpgv = shutil.which("gpgv")
    if not gpg or not gpgv:
        raise ContractError("gpg and gpgv are required for APT signature verification")
    return gpg, gpgv


def inspect_key_fingerprint(key_path: Path, expected: str, gpg: str) -> None:
    with tempfile.TemporaryDirectory(prefix="xr-apt-key-inspect-") as temporary:
        home = Path(temporary)
        home.chmod(0o700)
        result = subprocess.run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--homedir",
                str(home),
                "--with-colons",
                "--import-options",
                "show-only",
                "--import",
                str(key_path),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise ContractError("cannot inspect the APT signing key")
    fingerprints = parse_primary_fingerprints(result.stdout)
    if fingerprints != [expected]:
        raise ContractError("APT signing key fingerprint does not match the pinned value")


def prepare_trusted_keyring(
    key_payload: bytes,
    expected_fingerprint: str,
    directory: Path,
    gpg: str,
) -> Path:
    key_path = directory / "apt-signing-key"
    keyring_path = directory / "trustedkeys.gpg"
    key_path.write_bytes(key_payload)
    inspect_key_fingerprint(key_path, expected_fingerprint, gpg)
    home = directory / "gnupg"
    home.mkdir(mode=0o700)
    with keyring_path.open("wb") as output:
        result = subprocess.run(
            [
                gpg,
                "--batch",
                "--no-options",
                "--homedir",
                str(home),
                "--import-options",
                "import-export,import-minimal",
                "--import",
                str(key_path),
            ],
            check=False,
            stdout=output,
            stderr=subprocess.PIPE,
        )
    if result.returncode != 0 or not keyring_path.is_file() or keyring_path.stat().st_size == 0:
        raise ContractError("cannot construct the pinned APT verification keyring")
    return keyring_path


def bootstrap_signing_key(url: str, fingerprint: str, timeout: int) -> bytes:
    validate_signing_key_values(url, fingerprint)
    if not 1 <= timeout <= 120:
        raise ContractError("key download timeout is outside the permitted range")
    gpg, _ = require_gpg_tools()
    payload = download_no_redirect(url, timeout, MAX_KEY_BYTES)
    if not payload:
        raise ContractError("APT signing key download is empty")
    with tempfile.TemporaryDirectory(prefix="xr-apt-bootstrap-") as temporary:
        key_path = Path(temporary) / "apt-signing-key"
        key_path.write_bytes(payload)
        inspect_key_fingerprint(key_path, fingerprint, gpg)
    return payload


def verify_inrelease(
    key_payload: bytes,
    expected_fingerprint: str,
    inrelease_payload: bytes,
) -> bytes:
    if not inrelease_payload:
        raise ContractError("APT InRelease download is empty")
    gpg, gpgv = require_gpg_tools()
    with tempfile.TemporaryDirectory(prefix="xr-apt-inrelease-") as temporary:
        directory = Path(temporary)
        keyring = prepare_trusted_keyring(
            key_payload,
            expected_fingerprint,
            directory,
            gpg,
        )
        inrelease_path = directory / "InRelease"
        release_path = directory / "Release"
        inrelease_path.write_bytes(inrelease_payload)
        result = subprocess.run(
            [
                gpgv,
                "--quiet",
                "--homedir",
                str(directory / "gnupg"),
                "--keyring",
                str(keyring),
                "--output",
                str(release_path),
                str(inrelease_path),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if result.returncode != 0 or not release_path.is_file():
            raise ContractError("APT InRelease signature verification failed")
        release_payload = release_path.read_bytes()
    if not release_payload or len(release_payload) > MAX_INRELEASE_BYTES:
        raise ContractError("verified APT Release payload has an invalid size")
    return release_payload


def safe_release_path(value: str) -> str:
    path = PurePosixPath(value)
    raw_parts = value.split("/")
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "//" in value
        or not RELEASE_PATH_RE.fullmatch(value)
        or any(part in {"", ".", ".."} for part in raw_parts)
        or len(path.parts) != len(raw_parts)
    ):
        raise ContractError("signed Release contains an unsafe index path")
    return value


def parse_release_sha256(release_payload: bytes) -> dict[str, SignedFile]:
    try:
        text = release_payload.decode("utf-8")
    except UnicodeError as exc:
        raise ContractError("verified APT Release payload is not UTF-8") from exc
    lines = text.splitlines()
    section_indexes = [index for index, line in enumerate(lines) if line == "SHA256:"]
    if len(section_indexes) != 1:
        raise ContractError("verified APT Release must contain exactly one SHA256 section")
    records: dict[str, SignedFile] = {}
    for raw in lines[section_indexes[0] + 1 :]:
        if not raw.startswith(" "):
            break
        fields = raw.split()
        if len(fields) != 3:
            raise ContractError("verified APT Release has a malformed SHA256 entry")
        digest, size_text, filename = fields
        if not re.fullmatch(r"[0-9a-f]{64}", digest) or not size_text.isdecimal():
            raise ContractError("verified APT Release has an invalid SHA256 entry")
        size = int(size_text)
        safe_release_path(filename)
        if filename in records:
            raise ContractError("verified APT Release has duplicate SHA256 entries")
        records[filename] = SignedFile(digest, size)
    if not records:
        raise ContractError("verified APT Release SHA256 section is empty")
    return records


def verify_signed_file(
    signed_files: dict[str, SignedFile],
    filename: str,
    payload: bytes,
) -> None:
    expected = signed_files.get(filename)
    if expected is None:
        raise ContractError(f"APT index is not covered by signed Release: {filename}")
    if len(payload) != expected.size:
        raise ContractError(f"APT signed index length mismatch: {filename}")
    if hashlib.sha256(payload).hexdigest() != expected.sha256:
        raise ContractError(f"APT signed index SHA-256 mismatch: {filename}")


def apt_index_path(component: str, architecture: str) -> str:
    return f"{component}/binary-{architecture}/Packages"


def apt_index_url(
    base: str,
    distribution: str,
    component: str,
    architecture: str,
) -> str:
    quoted = [
        urllib.parse.quote(value, safe="")
        for value in (distribution, component, architecture)
    ]
    return (
        f"{base.rstrip('/')}/dists/{quoted[0]}/{quoted[1]}/"
        f"binary-{quoted[2]}/Packages"
    )


def fetch_verified_index_payloads(
    base: str,
    distribution: str,
    component: str,
    architectures: list[str],
    timeout: int,
    key_payload: bytes,
    signing_key_fingerprint: str,
) -> dict[str, bytes]:
    if sorted(architectures) != ["amd64", "arm64"]:
        raise ContractError("signed APT verification requires amd64 and arm64")
    quoted_distribution = urllib.parse.quote(distribution, safe="")
    inrelease = download_no_redirect(
        f"{base.rstrip('/')}/dists/{quoted_distribution}/InRelease",
        timeout,
        MAX_INRELEASE_BYTES,
    )
    release_payload = verify_inrelease(
        key_payload,
        signing_key_fingerprint,
        inrelease,
    )
    signed_files = parse_release_sha256(release_payload)
    payloads: dict[str, bytes] = {}
    for architecture in architectures:
        payload = download_no_redirect(
            apt_index_url(base, distribution, component, architecture),
            timeout,
            MAX_PACKAGES_BYTES,
        )
        verify_signed_file(
            signed_files,
            apt_index_path(component, architecture),
            payload,
        )
        payloads[architecture] = payload
    return payloads


def verify_repository_bootstrap(
    base: str,
    distribution: str,
    component: str,
    allow_plain_http: bool,
    key_url: str,
    fingerprint: str,
    timeout: int,
) -> None:
    validate_apt_values(base, distribution, component, allow_plain_http)
    validate_signing_key_values(key_url, fingerprint)
    key_payload = bootstrap_signing_key(key_url, fingerprint, timeout)
    fetch_verified_index_payloads(
        base,
        distribution,
        component,
        ["amd64", "arm64"],
        timeout,
        key_payload,
        fingerprint,
    )
