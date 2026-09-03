#!/usr/bin/env python3
"""Validate source caller inputs without accepting publication configuration."""

from __future__ import annotations

import argparse
import sys

from release_contract import ContractError, validate_source_values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--manifest-path", required=True)
    args = parser.parse_args()
    try:
        validate_source_values(
            args.source_repository,
            args.source_tag,
            args.source_commit,
            args.manifest_path,
        )
    except ContractError as exc:
        print(f"source input rejected: {exc}", file=sys.stderr)
        return 2
    print("source inputs accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
