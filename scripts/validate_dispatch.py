#!/usr/bin/env python3
"""Validate all public caller inputs before the private checkout occurs."""

from __future__ import annotations

import argparse
import sys

from apt_trust import validate_signing_key_values
from release_contract import ContractError, validate_dispatch_values


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--apt-repository-url", required=True)
    parser.add_argument("--apt-distribution", required=True)
    parser.add_argument("--apt-component", required=True)
    parser.add_argument("--apt-signing-key-url", required=True)
    parser.add_argument("--apt-signing-key-fingerprint", required=True)
    parser.add_argument("--apt-allow-plain-http", action="store_true")
    args = parser.parse_args()
    try:
        validate_dispatch_values(
            args.source_repository,
            args.source_tag,
            args.source_commit,
            args.manifest_path,
            args.apt_repository_url,
            args.apt_distribution,
            args.apt_component,
            args.apt_allow_plain_http,
        )
        validate_signing_key_values(
            args.apt_signing_key_url,
            args.apt_signing_key_fingerprint,
        )
    except ContractError as exc:
        print(f"release input rejected: {exc}", file=sys.stderr)
        return 2
    print("release inputs accepted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
