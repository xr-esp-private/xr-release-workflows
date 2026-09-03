#!/usr/bin/env python3
"""Select exactly one private source credential without receiving its value."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from release_contract import ContractError, validate_source_auth_selection


def strict_bool(value: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise argparse.ArgumentTypeError("credential presence flag must be true or false")


def append_output(path: Path, key: str, value: str) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--token-configured", type=strict_bool, required=True)
    parser.add_argument("--ssh-key-configured", type=strict_bool, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        mode = validate_source_auth_selection(
            args.token_configured,
            args.ssh_key_configured,
        )
        append_output(args.github_output, "mode", mode)
    except (ContractError, OSError) as exc:
        print(f"private source credential rejected: {exc}", file=sys.stderr)
        return 2
    print(f"private source credential mode accepted: {mode}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
