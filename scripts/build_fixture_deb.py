#!/usr/bin/env python3
"""Build a tiny architecture-specific DEB used only by credential-free CI."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="xr-release-fixture-") as temporary:
        root = Path(temporary) / "xr-release-fixture"
        control = root / "DEBIAN"
        payload = root / "usr/share/doc/xr-release-fixture"
        control.mkdir(parents=True)
        payload.mkdir(parents=True)
        (control / "control").write_text(
            "Package: xr-release-fixture\n"
            "Version: 1.2.3\n"
            f"Architecture: {args.architecture}\n"
            "Maintainer: XR Release CI <devnull@example.invalid>\n"
            "Description: Credential-free XR release workflow fixture\n",
            encoding="utf-8",
        )
        (payload / "README").write_text(
            f"fixture architecture={args.architecture}\n", encoding="utf-8"
        )
        output = args.output / f"xr-release-fixture_1.2.3_{args.architecture}.deb"
        environment = os.environ.copy()
        environment["SOURCE_DATE_EPOCH"] = "1788408000"
        subprocess.run(
            ["dpkg-deb", "--root-owner-group", "--build", str(root), str(output)],
            check=True,
            env=environment,
        )
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
