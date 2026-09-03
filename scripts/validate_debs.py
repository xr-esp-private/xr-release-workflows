#!/usr/bin/env python3
"""Validate one architecture's complete DEB output, then write its checksums."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from deb_artifacts import inspect_directory, write_checksums
from release_contract import ARCHITECTURES, ContractError, PACKAGE_RE


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--packages-json", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--architecture", choices=sorted(ARCHITECTURES), required=True)
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
        if len(artifacts) != len(packages):
            raise ContractError(
                f"expected {len(packages)} DEBs, found {len(artifacts)}"
            )
        observed: set[str] = set()
        for item in artifacts:
            if item.package not in packages or item.package in observed:
                raise ContractError(f"unexpected or duplicate package: {item.package}")
            if item.version != args.version:
                raise ContractError(
                    f"{item.package} version {item.version} != {args.version}"
                )
            if item.architecture != args.architecture:
                raise ContractError(
                    f"{item.package} architecture {item.architecture} != "
                    f"{args.architecture}"
                )
            observed.add(item.package)
        if observed != set(packages):
            raise ContractError("one or more declared packages are missing")
        write_checksums(artifacts, args.checksums_out)
    except (ContractError, OSError, json.JSONDecodeError) as exc:
        print(f"DEB set rejected: {exc}", file=sys.stderr)
        return 2
    print(f"validated {len(artifacts)} {args.architecture} DEB package(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
