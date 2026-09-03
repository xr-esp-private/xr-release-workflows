#!/usr/bin/env python3
"""Create/reuse a draft release without overwriting different bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from release_contract import COMMIT_RE, ContractError, REPOSITORY_RE, TAG_RE


API = "https://api.github.com"
UPLOADS = "https://uploads.github.com"


def request(
    token: str,
    url: str,
    method: str = "GET",
    data: bytes | None = None,
    content_type: str = "application/vnd.github+json",
) -> tuple[int, bytes]:
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "xr-release-workflows/1",
    }
    if data is not None:
        headers["Content-Type"] = content_type
        headers["Content-Length"] = str(len(data))
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        payload = exc.read()
        if exc.code == 404 and method == "GET":
            return 404, payload
        raise ContractError(f"GitHub API returned HTTP {exc.code}") from exc


def json_request(
    token: str, url: str, method: str = "GET", value: object | None = None
) -> tuple[int, object]:
    data = None if value is None else json.dumps(value).encode("utf-8")
    status, payload = request(token, url, method, data)
    if status == 404:
        return status, {}
    try:
        return status, json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError("GitHub API returned invalid JSON") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def expected_assets(dist: Path, metadata: Path) -> dict[str, Path]:
    paths = list(sorted(dist.glob("*.deb"))) + [dist / "SHA256SUMS"] + [
        metadata / "release-manifest.json",
        metadata / "release-metadata.json",
    ]
    assets: dict[str, Path] = {}
    for path in paths:
        if not path.is_file() or path.is_symlink() or path.name in assets:
            raise ContractError(f"missing, unsafe, or duplicate release asset: {path}")
        assets[path.name] = path
    if not any(name.endswith(".deb") for name in assets):
        raise ContractError("release has no DEB assets")
    return assets


def release_by_tag(token: str, repository: str, tag: str) -> dict | None:
    quoted = urllib.parse.quote(tag, safe="")
    status, value = json_request(token, f"{API}/repos/{repository}/releases/tags/{quoted}")
    if status == 404:
        return None
    if not isinstance(value, dict):
        raise ContractError("GitHub release response is not an object")
    return value


def create_release(
    token: str,
    repository: str,
    tag: str,
    target_commit: str,
    prerelease: bool,
    body: str,
) -> dict:
    _, value = json_request(
        token,
        f"{API}/repos/{repository}/releases",
        "POST",
        {
            "tag_name": tag,
            "target_commitish": target_commit,
            "name": tag,
            "body": body,
            "draft": True,
            "prerelease": prerelease,
        },
    )
    if not isinstance(value, dict) or not isinstance(value.get("id"), int):
        raise ContractError("GitHub did not return a release id")
    print(f"created draft release {tag}")
    return value


def check_existing_assets(release: dict, assets: dict[str, Path]) -> set[str]:
    remote_assets = release.get("assets")
    if not isinstance(remote_assets, list):
        raise ContractError("release assets response is invalid")
    existing: set[str] = set()
    for remote in remote_assets:
        if not isinstance(remote, dict) or not isinstance(remote.get("name"), str):
            raise ContractError("release contains malformed asset metadata")
        name = remote["name"]
        if name not in assets:
            raise ContractError(f"draft release contains unexpected asset {name}")
        digest = remote.get("digest")
        expected = f"sha256:{sha256_file(assets[name])}"
        if digest != expected:
            raise ContractError(f"refusing to overwrite different bytes for {name}")
        existing.add(name)
    return existing


def upload_asset(
    token: str, repository: str, release_id: int, name: str, path: Path
) -> None:
    quoted = urllib.parse.urlencode({"name": name})
    body = path.read_bytes()
    status, payload = request(
        token,
        f"{UPLOADS}/repos/{repository}/releases/{release_id}/assets?{quoted}",
        "POST",
        body,
        "application/octet-stream",
    )
    if status != 201:
        raise ContractError(f"asset upload returned HTTP {status} for {name}")
    try:
        uploaded = json.loads(payload.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"asset upload returned invalid metadata for {name}") from exc
    expected_digest = f"sha256:{sha256_file(path)}"
    if uploaded.get("name") != name or uploaded.get("digest") != expected_digest:
        raise ContractError(f"GitHub digest verification failed for uploaded asset {name}")
    print(f"uploaded draft asset {name}")


def prepare(args: argparse.Namespace, token: str, repository: str) -> int:
    notes = args.notes.read_text(encoding="utf-8")
    metadata = json.loads((args.metadata / "release-metadata.json").read_text(encoding="utf-8"))
    if metadata.get("source_tag") != args.tag:
        raise ContractError("release metadata tag does not match requested tag")
    provenance = (
        "\n\n---\n"
        f"Source: `{metadata.get('source_repository')}@{metadata.get('source_commit')}`\n"
        f"Manifest: `xr-linux-deb-release-manifest/1`\n"
    )
    assets = expected_assets(args.dist, args.metadata)
    release = release_by_tag(token, repository, args.tag)
    if release is None:
        release = create_release(
            token,
            repository,
            args.tag,
            args.target_commit,
            args.prerelease,
            notes + provenance,
        )
    elif release.get("draft") is not True:
        raise ContractError("existing release is published; refusing mutation")
    elif bool(release.get("prerelease")) != args.prerelease:
        raise ContractError("existing draft prerelease flag differs")
    existing = check_existing_assets(release, assets)
    release_id = release.get("id")
    if not isinstance(release_id, int):
        raise ContractError("release id is invalid")
    for name, path in assets.items():
        if name not in existing:
            upload_asset(token, repository, release_id, name, path)
    print(f"draft release {args.tag} contains byte-identical assets")
    return 0


def finalize(args: argparse.Namespace, token: str, repository: str) -> int:
    release = release_by_tag(token, repository, args.tag)
    if release is None or release.get("draft") is not True:
        raise ContractError("finalization requires an existing draft release")
    release_id = release.get("id")
    if not isinstance(release_id, int):
        raise ContractError("release id is invalid")
    _, updated = json_request(
        token,
        f"{API}/repos/{repository}/releases/{release_id}",
        "PATCH",
        {"draft": False},
    )
    if not isinstance(updated, dict) or updated.get("draft") is not False:
        raise ContractError("GitHub did not publish the release")
    print(f"published GitHub Release {args.tag}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="mode", required=True)
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--dist", type=Path, required=True)
    prepare_parser.add_argument("--metadata", type=Path, required=True)
    prepare_parser.add_argument("--notes", type=Path, required=True)
    prepare_parser.add_argument("--tag", required=True)
    prepare_parser.add_argument("--target-commit", required=True)
    prepare_parser.add_argument("--prerelease", action="store_true")
    finalize_parser = subparsers.add_parser("finalize")
    finalize_parser.add_argument("--tag", required=True)
    args = parser.parse_args()
    try:
        token = os.environ.get("GITHUB_TOKEN", "")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        if not token:
            raise ContractError("GITHUB_TOKEN is required")
        if not REPOSITORY_RE.fullmatch(repository):
            raise ContractError("GITHUB_REPOSITORY is invalid")
        if not TAG_RE.fullmatch(args.tag):
            raise ContractError("release tag is invalid")
        if args.mode == "prepare":
            if not COMMIT_RE.fullmatch(args.target_commit):
                raise ContractError("target commit is invalid")
            return prepare(args, token, repository)
        return finalize(args, token, repository)
    except (ContractError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"GitHub Release operation failed closed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
