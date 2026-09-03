#!/usr/bin/env python3
"""Dependency-free validation helpers for the XR Linux release contract."""

from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit


SCHEMA_ID = "xr-linux-deb-release-manifest/1"
ARCHITECTURES = {
    "amd64": "ubuntu-24.04",
    "arm64": "ubuntu-24.04-arm",
}
PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{1,127}$")
REPOSITORY_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})$"
)
TAG_RE = re.compile(r"^v[0-9][0-9A-Za-z.+:~_-]{0,127}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
APT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
CONTAINER_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._/:@-]*@sha256:[0-9a-f]{64}$"
)
ALLOWED_MANIFEST_KEYS = {
    "schema",
    "packages",
    "build_script",
    "release_notes_path",
    "architectures",
}


class ContractError(ValueError):
    """Raised when caller-controlled release data violates the contract."""


def safe_repository_path(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 240:
        raise ContractError(f"{field} must be a non-empty repository-relative path")
    if "\\" in value or "\x00" in value:
        raise ContractError(f"{field} contains an invalid character")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ContractError(f"{field} must not be absolute or traverse directories")
    if any(not re.fullmatch(r"[A-Za-z0-9._+-]+", part) for part in path.parts):
        raise ContractError(f"{field} contains an unsupported path component")
    return value


def validate_source_values(
    source_repository: str,
    source_tag: str,
    source_commit: str,
    manifest_path: str,
) -> None:
    if not REPOSITORY_RE.fullmatch(source_repository):
        raise ContractError("source_repository must be OWNER/REPOSITORY")
    if not TAG_RE.fullmatch(source_tag):
        raise ContractError("source_tag must be an exact v-prefixed release tag")
    if not COMMIT_RE.fullmatch(source_commit):
        raise ContractError("source_commit must be a lowercase 40-character SHA")
    safe_repository_path(manifest_path, "manifest_path")


def validate_source_auth_selection(
    token_configured: bool,
    ssh_key_configured: bool,
) -> str:
    if not isinstance(token_configured, bool) or not isinstance(
        ssh_key_configured, bool
    ):
        raise ContractError("private source credential flags must be boolean")
    if token_configured == ssh_key_configured:
        raise ContractError(
            "configure exactly one of XR_PRIVATE_SOURCE_TOKEN or "
            "XR_PRIVATE_SOURCE_SSH_KEY"
        )
    return "token" if token_configured else "ssh"


def validate_apt_values(
    apt_repository_url: str,
    apt_distribution: str,
    apt_component: str,
    apt_allow_plain_http: bool = False,
) -> None:
    if not isinstance(apt_allow_plain_http, bool):
        raise ContractError("apt_allow_plain_http must be a boolean")
    if (
        not isinstance(apt_repository_url, str)
        or not apt_repository_url
        or "\\" in apt_repository_url
        or any(
            ord(character) < 0x21 or character.isspace()
            for character in apt_repository_url
        )
    ):
        raise ContractError("apt_repository_url contains an invalid character")
    try:
        parsed = urlsplit(apt_repository_url)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise ContractError("apt_repository_url is invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ContractError("apt_repository_url must use HTTP or HTTPS")
    if parsed.scheme == "http" and not apt_allow_plain_http:
        raise ContractError(
            "plaintext HTTP APT requires explicit apt_allow_plain_http opt-in"
        )
    if (
        not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "?" in apt_repository_url
        or "#" in apt_repository_url
    ):
        raise ContractError(
            "apt_repository_url must not contain credentials, query, or fragment"
        )
    if ":" in hostname:
        try:
            ipaddress.IPv6Address(hostname)
        except ipaddress.AddressValueError as exc:
            raise ContractError("apt_repository_url hostname is invalid") from exc
        expected_netloc = f"[{hostname}]"
    else:
        labels = hostname.split(".")
        if any(
            not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels
        ):
            raise ContractError("apt_repository_url hostname is invalid")
        expected_netloc = hostname
    if port == 0:
        raise ContractError("apt_repository_url port is invalid")
    if port is not None:
        expected_netloc += f":{port}"
    if parsed.netloc.lower() != expected_netloc.lower():
        raise ContractError("apt_repository_url authority is invalid")
    path = parsed.path
    if (
        unquote(path) != path
        or "\\" in path
        or "//" in path
        or any(ord(character) < 0x20 or character.isspace() for character in path)
    ):
        raise ContractError("apt_repository_url contains a suspicious path")
    path_parts = [part for part in path.split("/") if part]
    if any(
        part in {".", ".."}
        or not re.fullmatch(r"[A-Za-z0-9._~-]+", part)
        or part.lower() in {"dists", "pool", "upload"}
        for part in path_parts
    ):
        raise ContractError("apt_repository_url must name an APT repository base path")
    if not APT_NAME_RE.fullmatch(apt_distribution):
        raise ContractError("apt_distribution is invalid")
    if not APT_NAME_RE.fullmatch(apt_component):
        raise ContractError("apt_component is invalid")


def validate_dispatch_values(
    source_repository: str,
    source_tag: str,
    source_commit: str,
    manifest_path: str,
    apt_repository_url: str,
    apt_distribution: str,
    apt_component: str,
    apt_allow_plain_http: bool = False,
) -> None:
    validate_source_values(
        source_repository,
        source_tag,
        source_commit,
        manifest_path,
    )
    validate_apt_values(
        apt_repository_url,
        apt_distribution,
        apt_component,
        apt_allow_plain_http,
    )


def validate_manifest_data(data: object) -> dict:
    if not isinstance(data, dict):
        raise ContractError("manifest root must be an object")
    unknown = set(data) - ALLOWED_MANIFEST_KEYS
    missing = ALLOWED_MANIFEST_KEYS - set(data)
    if unknown:
        raise ContractError(f"manifest has unknown fields: {sorted(unknown)}")
    if missing:
        raise ContractError(f"manifest is missing fields: {sorted(missing)}")
    if data["schema"] != SCHEMA_ID:
        raise ContractError(f"manifest schema must be {SCHEMA_ID}")

    packages = data["packages"]
    if not isinstance(packages, list) or not 1 <= len(packages) <= 20:
        raise ContractError("packages must contain between 1 and 20 names")
    if any(not isinstance(name, str) or not PACKAGE_RE.fullmatch(name) for name in packages):
        raise ContractError("packages contains an invalid Debian package name")
    if len(packages) != len(set(packages)):
        raise ContractError("packages must be unique")

    safe_repository_path(data["build_script"], "build_script")
    safe_repository_path(data["release_notes_path"], "release_notes_path")

    architectures = data["architectures"]
    if not isinstance(architectures, dict) or set(architectures) != set(ARCHITECTURES):
        raise ContractError("architectures must contain exactly amd64 and arm64")
    for architecture, expected_runner in ARCHITECTURES.items():
        entry = architectures[architecture]
        if not isinstance(entry, dict) or set(entry) != {"runner", "container"}:
            raise ContractError(f"{architecture} must contain runner and container only")
        if entry["runner"] != expected_runner:
            raise ContractError(
                f"{architecture} runner must be {expected_runner}, got {entry['runner']}"
            )
        container = entry["container"]
        if not isinstance(container, str) or not CONTAINER_RE.fullmatch(container):
            raise ContractError(f"{architecture} container must use an immutable digest")
    return data


def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read manifest {path}: {exc}") from exc
    return validate_manifest_data(data)


def compact_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
