from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from apt_publish import AptRecord, preflight  # noqa: E402
from release_contract import (  # noqa: E402
    ContractError,
    load_manifest,
    validate_dispatch_values,
    validate_manifest_data,
)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.valid_path = ROOT / "fixtures/manifests/valid.json"
        self.valid = json.loads(self.valid_path.read_text(encoding="utf-8"))

    def test_valid_manifest(self) -> None:
        self.assertEqual(load_manifest(self.valid_path)["packages"], ["xr-release-fixture"])

    def test_mutable_container_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            load_manifest(ROOT / "fixtures/manifests/invalid-mutable-container.json")

    def test_wrong_runner_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            load_manifest(ROOT / "fixtures/manifests/invalid-runner.json")

    def test_unknown_field_is_rejected(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["extra"] = True
        with self.assertRaises(ContractError):
            validate_manifest_data(changed)

    def test_duplicate_package_is_rejected(self) -> None:
        changed = copy.deepcopy(self.valid)
        changed["packages"] = ["xr-release-fixture", "xr-release-fixture"]
        with self.assertRaises(ContractError):
            validate_manifest_data(changed)


class DispatchTests(unittest.TestCase):
    def valid(self, **overrides: str) -> None:
        values = {
            "source_repository": "xr-esp-private/example",
            "source_tag": "v1.2.3",
            "source_commit": "a" * 40,
            "manifest_path": "packaging/release-manifest.json",
            "apt_repository_url": "https://packages.example.invalid",
            "apt_distribution": "stable",
            "apt_component": "main",
        }
        values.update(overrides)
        validate_dispatch_values(**values)

    def test_valid_dispatch(self) -> None:
        self.valid()

    def test_http_apt_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(apt_repository_url="http://packages.example.invalid")

    def test_non_sha_commit_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(source_commit="main")

    def test_traversal_manifest_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(manifest_path="../release.json")


class SourceBindingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xr-source-binding-")
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.source, check=True)
        subprocess.run(
            ["git", "config", "user.email", "fixture@example.invalid"],
            cwd=self.source,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "XR Fixture"], cwd=self.source, check=True
        )
        (self.source / "packaging").mkdir()
        manifest = json.loads(
            (ROOT / "fixtures/manifests/valid.json").read_text(encoding="utf-8")
        )
        (self.source / "packaging/release-manifest.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )
        (self.source / "packaging/release-build.sh").write_text(
            "#!/bin/sh\nset -eu\n", encoding="utf-8"
        )
        (self.source / "CHANGELOG.md").write_text("# Fixture 1.2.3\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.source, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "fixture"], cwd=self.source, check=True)
        subprocess.run(["git", "tag", "v1.2.3"], cwd=self.source, check=True)
        self.commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=self.source,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def prepare(self, tag: str, commit: str, suffix: str) -> subprocess.CompletedProcess[str]:
        output = self.root / f"github-output-{suffix}"
        output.touch()
        return subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts/prepare_source.py"),
                "--source-dir",
                str(self.source),
                "--source-repository",
                "xr-esp-private/fixture",
                "--source-tag",
                tag,
                "--source-commit",
                commit,
                "--manifest-path",
                "packaging/release-manifest.json",
                "--metadata-dir",
                str(self.root / f"metadata-{suffix}"),
                "--github-output",
                str(output),
            ],
            capture_output=True,
            text=True,
        )

    def test_exact_tag_and_commit_are_accepted(self) -> None:
        result = self.prepare("v1.2.3", self.commit, "valid")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_tag_with_different_commit_is_rejected(self) -> None:
        result = self.prepare("v1.2.3", "b" * 40, "wrong-commit")
        self.assertEqual(result.returncode, 2)

    def test_missing_exact_tag_is_rejected(self) -> None:
        result = self.prepare("v9.9.9", self.commit, "wrong-tag")
        self.assertEqual(result.returncode, 2)


class AptCollisionTests(unittest.TestCase):
    def artifact(self, sha256: str):
        from deb_artifacts import DebArtifact

        return DebArtifact(
            path=Path("fixture_1.2.3_amd64.deb"),
            package="fixture",
            version="1.2.3",
            architecture="amd64",
            sha256=sha256,
        )

    def record(self, sha256: str) -> AptRecord:
        return AptRecord("fixture", "1.2.3", "amd64", sha256, "pool/fixture.deb")

    def test_identical_existing_package_is_idempotent(self) -> None:
        digest = "1" * 64
        self.assertEqual(preflight([self.artifact(digest)], {"amd64": [self.record(digest)]}), [])

    def test_same_version_different_bytes_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            preflight([self.artifact("1" * 64)], {"amd64": [self.record("2" * 64)]})


if __name__ == "__main__":
    unittest.main()
