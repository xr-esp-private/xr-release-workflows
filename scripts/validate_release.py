#!/usr/bin/env python3
"""Validate the merged two-architecture release and create SHA256SUMS."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deb_artifacts import (
    inspect_directory,
    parse_checksum_file,
    write_checksums,
)
from release_contract import ARCHITECTURES, ContractError, PACKAGE_RE


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--packages-json", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--checksums-out", type=Path, required=True)
    args = parser.parse_args()
    try:
        packages = json.loads(args.packages_json)
        if (
            not isinstance(packages, list)
            or not packages
            or any(not isinstance(item, str) or not PACKAGE_RE.fullmatch(item) for item in packages)
            or len(packages) != len(set(packages))
        ):
            raise ContractError("packages-json is invalid")
        artifacts = inspect_directory(args.directory)
        expected_count = len(packages) * len(ARCHITECTURES)
        if len(artifacts) != expected_count:
            raise ContractError(f"expected {expected_count} DEBs, found {len(artifacts)}")

        observed: dict[tuple[str, str], object] = {}
        for item in artifacts:
            key = (item.package, item.architecture)
            if item.package not in packages or item.architecture not in ARCHITECTURES:
                raise ContractError(f"unexpected package/architecture: {key}")
            if item.version != args.version:
                raise ContractError(f"{item.path.name} has version {item.version}")
            if key in observed:
                raise ContractError(f"duplicate package/architecture: {key}")
            observed[key] = item
        expected = {
            (package, architecture)
            for package in packages
            for architecture in ARCHITECTURES
        }
        if set(observed) != expected:
            raise ContractError("merged release is missing a package/architecture pair")

        for architecture in ARCHITECTURES:
            checksum_path = args.directory / f"SHA256SUMS.{architecture}"
            if not checksum_path.is_file() or checksum_path.is_symlink():
                raise ContractError(f"missing {checksum_path.name}")
            recorded = parse_checksum_file(checksum_path)
            actual = {
                item.path.name: item.sha256
                for item in artifacts
                if item.architecture == architecture
            }
            if recorded != actual:
                raise ContractError(f"{checksum_path.name} does not match DEB bytes")

        write_checksums(artifacts, args.checksums_out)
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"release set rejected: {exc}", file=sys.stderr)
        return 2
    print(f"validated complete release with {len(artifacts)} DEBs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
