#!/usr/bin/env python3
"""Strict APT upload and repository-index verification adapter."""

from __future__ import annotations

import argparse
import base64
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from apt_trust import (
    NoRedirect,
    bootstrap_signing_key,
    fetch_verified_index_payloads,
    validate_signing_key_values,
)
from deb_artifacts import DebArtifact, inspect_directory
from release_contract import ContractError, validate_apt_values


@dataclass(frozen=True)
class AptRecord:
    package: str
    version: str
    architecture: str
    sha256: str
    filename: str


def parse_packages(text: str) -> list[AptRecord]:
    paragraphs: list[dict[str, str]] = []
    current: dict[str, str] = {}
    last_key: str | None = None
    for raw in text.splitlines() + [""]:
        if not raw:
            if current:
                paragraphs.append(current)
                current = {}
                last_key = None
            continue
        if raw[0].isspace():
            if last_key is None:
                raise ContractError("malformed continuation in APT Packages index")
            current[last_key] += "\n" + raw[1:]
            continue
        if ":" not in raw:
            raise ContractError("malformed field in APT Packages index")
        key, value = raw.split(":", 1)
        last_key = key
        current[key] = value.lstrip()
    records: list[AptRecord] = []
    for fields in paragraphs:
        required = ("Package", "Version", "Architecture", "SHA256", "Filename")
        if not all(fields.get(field) for field in required):
            continue
        records.append(
            AptRecord(
                package=fields["Package"],
                version=fields["Version"],
                architecture=fields["Architecture"],
                sha256=fields["SHA256"],
                filename=fields["Filename"],
            )
        )
    return records


def fetch_verified_records(
    base: str,
    distribution: str,
    component: str,
    architectures: list[str],
    timeout: int,
    key_payload: bytes,
    signing_key_fingerprint: str,
) -> dict[str, list[AptRecord]]:
    payloads = fetch_verified_index_payloads(
        base,
        distribution,
        component,
        architectures,
        timeout,
        key_payload,
        signing_key_fingerprint,
    )
    records: dict[str, list[AptRecord]] = {}
    for architecture in architectures:
        try:
            records[architecture] = parse_packages(
                payloads[architecture].decode("utf-8")
            )
        except UnicodeError as exc:
            raise ContractError("APT Packages index is not UTF-8") from exc
    return records


def matching_record(
    records: list[AptRecord], artifact: DebArtifact
) -> AptRecord | None:
    matches = [
        record
        for record in records
        if record.package == artifact.package
        and record.version == artifact.version
        and record.architecture == artifact.architecture
    ]
    if len(matches) > 1:
        raise ContractError(
            f"APT index has duplicate {artifact.package} {artifact.version} "
            f"{artifact.architecture} records"
        )
    return matches[0] if matches else None


def preflight(
    artifacts: list[DebArtifact],
    records_by_architecture: dict[str, list[AptRecord]],
) -> list[DebArtifact]:
    uploads: list[DebArtifact] = []
    for artifact in artifacts:
        existing = matching_record(
            records_by_architecture[artifact.architecture], artifact
        )
        if existing is None:
            uploads.append(artifact)
        elif existing.sha256 != artifact.sha256:
            raise ContractError(
                f"refusing same-version replacement for {artifact.package} "
                f"{artifact.version} {artifact.architecture}"
            )
        else:
            print(f"APT already has byte-identical {artifact.path.name}")
    return uploads


def upload(
    artifact: DebArtifact, base: str, username: str, password: str, timeout: int
) -> None:
    target = f"{base.rstrip('/')}/upload/{urllib.parse.quote(artifact.path.name, safe='')}"
    credential = base64.b64encode(f"{username}:{password}".encode()).decode("ascii")
    body = artifact.path.read_bytes()
    request = urllib.request.Request(
        target,
        data=body,
        method="PUT",
        headers={
            "Authorization": f"Basic {credential}",
            "Content-Type": "application/vnd.debian.binary-package",
            "Content-Length": str(len(body)),
            "User-Agent": "xr-release-workflows/1",
        },
    )
    opener = urllib.request.build_opener(NoRedirect())
    with opener.open(request, timeout=timeout) as response:
        if response.status not in (200, 201, 204):
            raise ContractError(f"upload of {artifact.path.name} returned HTTP {response.status}")
    print(f"uploaded {artifact.path.name}")


def indexes_match(
    artifacts: list[DebArtifact],
    base: str,
    distribution: str,
    component: str,
    timeout: int,
    key_payload: bytes,
    signing_key_fingerprint: str,
) -> bool:
    architectures = sorted({item.architecture for item in artifacts})
    records_by_architecture = fetch_verified_records(
        base,
        distribution,
        component,
        architectures,
        timeout,
        key_payload,
        signing_key_fingerprint,
    )
    for artifact in artifacts:
        record = matching_record(records_by_architecture[artifact.architecture], artifact)
        if record is None or record.sha256 != artifact.sha256:
            return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--signing-key-url", required=True)
    parser.add_argument("--signing-key-fingerprint", required=True)
    parser.add_argument("--allow-plain-http", action="store_true")
    parser.add_argument("--poll-timeout", type=int, default=180)
    parser.add_argument("--request-timeout", type=int, default=30)
    args = parser.parse_args()
    try:
        username = os.environ.get("XR_APT_REPO_USER", "")
        password = os.environ.get("XR_APT_REPO_PASS", "")
        if not username or not password:
            raise ContractError("both APT upload credentials are required")
        validate_apt_values(
            args.repository_url,
            args.distribution,
            args.component,
            args.allow_plain_http,
        )
        validate_signing_key_values(
            args.signing_key_url,
            args.signing_key_fingerprint,
        )
        if not 1 <= args.poll_timeout <= 900 or not 1 <= args.request_timeout <= 120:
            raise ContractError("timeout is outside the permitted range")
        key_payload = bootstrap_signing_key(
            args.signing_key_url,
            args.signing_key_fingerprint,
            args.request_timeout,
        )
        artifacts = inspect_directory(args.directory)
        if not artifacts:
            raise ContractError("no DEBs available for APT publication")
        architectures = sorted({item.architecture for item in artifacts})
        if architectures != ["amd64", "arm64"]:
            raise ContractError("APT publication requires amd64 and arm64 artifacts")
        records = fetch_verified_records(
            args.repository_url,
            args.distribution,
            args.component,
            architectures,
            args.request_timeout,
            key_payload,
            args.signing_key_fingerprint,
        )
        uploads = preflight(artifacts, records)
        for artifact in uploads:
            upload(
                artifact,
                args.repository_url,
                username,
                password,
                args.request_timeout,
            )

        deadline = time.monotonic() + args.poll_timeout
        while True:
            if indexes_match(
                artifacts,
                args.repository_url,
                args.distribution,
                args.component,
                args.request_timeout,
                key_payload,
                args.signing_key_fingerprint,
            ):
                print("APT signature, signed indexes, and DEB SHA-256 values match")
                return 0
            if time.monotonic() >= deadline:
                raise ContractError("APT index did not converge before timeout")
            time.sleep(5)
    except (ContractError, OSError, UnicodeError, urllib.error.URLError) as exc:
        print(f"APT publication failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
