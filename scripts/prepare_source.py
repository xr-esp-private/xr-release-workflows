#!/usr/bin/env python3
"""Bind an exact source tag to a commit and emit validated build metadata."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

from release_contract import ContractError, compact_json, load_manifest, safe_repository_path


def git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *args],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def regular_file(root: Path, relative: str, field: str) -> Path:
    safe_repository_path(relative, field)
    path = root / relative
    if not path.is_file() or path.is_symlink():
        raise ContractError(f"{field} must name a regular, non-symlink file")
    return path


def append_output(path: Path, key: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ContractError(f"output {key} contains a newline")
    with path.open("a", encoding="utf-8") as stream:
        stream.write(f"{key}={value}\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--manifest-path", required=True)
    parser.add_argument("--metadata-dir", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args()
    try:
        head = git(args.source_dir, "rev-parse", "HEAD^{commit}")
        tag_commit = git(
            args.source_dir,
            "rev-parse",
            f"refs/tags/{args.source_tag}^{{commit}}",
        )
        if head != args.source_commit or tag_commit != args.source_commit:
            raise ContractError(
                "checked-out HEAD, exact tag, and declared source_commit must match"
            )

        manifest_file = regular_file(args.source_dir, args.manifest_path, "manifest_path")
        manifest = load_manifest(manifest_file)
        build_script = regular_file(
            args.source_dir, manifest["build_script"], "build_script"
        )
        if build_script.stat().st_size > 256 * 1024:
            raise ContractError("build_script exceeds 256 KiB")
        notes = regular_file(
            args.source_dir, manifest["release_notes_path"], "release_notes_path"
        )
        if notes.stat().st_size > 128 * 1024:
            raise ContractError("release notes exceed 128 KiB")

        matrix = {
            "include": [
                {
                    "architecture": architecture,
                    "runner": entry["runner"],
                    "container": entry["container"],
                }
                for architecture, entry in manifest["architectures"].items()
            ]
        }
        version = args.source_tag[1:]
        args.metadata_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(manifest_file, args.metadata_dir / "release-manifest.json")
        shutil.copyfile(notes, args.metadata_dir / "release-notes.md")
        metadata = {
            "schema": "xr-linux-deb-release-metadata/1",
            "source_repository": args.source_repository,
            "source_tag": args.source_tag,
            "source_commit": args.source_commit,
            "version": version,
        }
        (args.metadata_dir / "release-metadata.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        append_output(args.github_output, "matrix", compact_json(matrix))
        append_output(
            args.github_output, "packages", compact_json(manifest["packages"])
        )
        append_output(args.github_output, "build_script", manifest["build_script"])
        append_output(args.github_output, "version", version)
    except (ContractError, subprocess.CalledProcessError, OSError) as exc:
        print(f"source release contract rejected: {exc}", file=sys.stderr)
        return 2
    print(f"bound {args.source_tag} to {args.source_commit}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
