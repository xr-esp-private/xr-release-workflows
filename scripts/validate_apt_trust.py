#!/usr/bin/env python3
"""Bootstrap and validate the public APT signing key before private checkout."""

from __future__ import annotations

import argparse
import sys
import urllib.error

from apt_trust import verify_repository_bootstrap
from release_contract import ContractError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-url", required=True)
    parser.add_argument("--fingerprint", required=True)
    parser.add_argument("--repository-url", required=True)
    parser.add_argument("--distribution", required=True)
    parser.add_argument("--component", required=True)
    parser.add_argument("--allow-plain-http", action="store_true")
    parser.add_argument("--request-timeout", type=int, default=30)
    args = parser.parse_args()
    try:
        verify_repository_bootstrap(
            args.repository_url,
            args.distribution,
            args.component,
            args.allow_plain_http,
            args.key_url,
            args.fingerprint,
            args.request_timeout,
        )
    except (ContractError, OSError, UnicodeError, urllib.error.URLError) as exc:
        print(f"APT signing-key bootstrap failed closed: {exc}", file=sys.stderr)
        return 2
    print("APT signing key, InRelease, and signed Packages indexes verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
