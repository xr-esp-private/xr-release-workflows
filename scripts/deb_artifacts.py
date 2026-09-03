#!/usr/bin/env python3
"""Inspect Debian binary packages without trusting their filenames."""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path

from release_contract import ContractError


@dataclass(frozen=True)
class DebArtifact:
    path: Path
    package: str
    version: str
    architecture: str
    sha256: str


def dpkg_field(path: Path, field: str) -> str:
    try:
        result = subprocess.run(
            ["dpkg-deb", "--field", str(path), field],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise ContractError("dpkg-deb is required by the build container") from exc
    except subprocess.CalledProcessError as exc:
        raise ContractError(f"cannot read {field} from {path.name}") from exc
    value = result.stdout.strip()
    if not value or "\n" in value or "\r" in value:
        raise ContractError(f"invalid {field} in {path.name}")
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inspect_deb(path: Path) -> DebArtifact:
    if not path.is_file() or path.is_symlink():
        raise ContractError(f"artifact is not a regular, non-symlink file: {path}")
    if path.name != Path(path.name).name or any(char.isspace() for char in path.name):
        raise ContractError(f"unsafe artifact filename: {path.name}")
    return DebArtifact(
        path=path,
        package=dpkg_field(path, "Package"),
        version=dpkg_field(path, "Version"),
        architecture=dpkg_field(path, "Architecture"),
        sha256=sha256_file(path),
    )


def inspect_directory(directory: Path) -> list[DebArtifact]:
    if not directory.is_dir() or directory.is_symlink():
        raise ContractError(f"artifact directory does not exist: {directory}")
    return [inspect_deb(path) for path in sorted(directory.glob("*.deb"))]


def write_checksums(artifacts: list[DebArtifact], path: Path) -> None:
    lines = [f"{item.sha256}  {item.path.name}" for item in sorted(artifacts, key=lambda x: x.path.name)]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_checksum_file(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        parts = raw.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise ContractError(f"invalid checksum line {number} in {path.name}")
        digest, filename = parts
        if any(char not in "0123456789abcdef" for char in digest):
            raise ContractError(f"invalid SHA-256 on line {number} in {path.name}")
        if filename in result or filename != Path(filename).name:
            raise ContractError(f"invalid or duplicate filename in {path.name}")
        result[filename] = digest
    return result
