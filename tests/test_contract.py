from __future__ import annotations

import copy
import hashlib
import http.server
import json
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from apt_publish import AptRecord, preflight, upload  # noqa: E402
from apt_trust import (  # noqa: E402
    download_no_redirect,
    inspect_key_fingerprint,
    parse_primary_fingerprints,
    parse_release_sha256,
    validate_signing_key_values,
    verify_inrelease,
    verify_signed_file,
)
from deb_artifacts import DebArtifact  # noqa: E402
from release_contract import (  # noqa: E402
    ContractError,
    load_manifest,
    validate_source_auth_selection,
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
    def valid(self, **overrides: object) -> None:
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

    def test_explicit_plain_http_origin_is_accepted(self) -> None:
        self.valid(
            apt_repository_url="http://packages.example.invalid:8080/apt",
            apt_allow_plain_http=True,
        )

    def test_url_userinfo_is_rejected_even_with_http_opt_in(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(
                apt_repository_url="http://user:pass@packages.example.invalid",
                apt_allow_plain_http=True,
            )

    def test_non_http_scheme_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(apt_repository_url="file:///tmp/repository")

    def test_suspicious_apt_base_paths_are_rejected(self) -> None:
        for url in (
            "https://packages.example.invalid/../repository",
            "https://packages.example.invalid/%2e%2e/repository",
            "https://packages.example.invalid/apt//repository",
            "https://packages.example.invalid/upload",
        ):
            with self.subTest(url=url), self.assertRaises(ContractError):
                self.valid(apt_repository_url=url)

    def test_plain_http_opt_in_must_be_boolean(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(apt_allow_plain_http="true")

    def test_non_sha_commit_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(source_commit="main")

    def test_traversal_manifest_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(manifest_path="../release.json")


class AptSigningKeyInputTests(unittest.TestCase):
    def valid(self, **overrides: str) -> None:
        values = {
            "url": (
                "https://raw.githubusercontent.com/xr-esp-private/"
                "example-release/" + "a" * 40 + "/keys/apt-signing-key.asc"
            ),
            "fingerprint": "A" * 40,
        }
        values.update(overrides)
        validate_signing_key_values(**values)

    def test_immutable_github_raw_key_url_is_accepted(self) -> None:
        self.valid()

    def test_mutable_key_ref_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            self.valid(
                url=(
                    "https://raw.githubusercontent.com/xr-esp-private/"
                    "example-release/main/keys/apt-signing-key.asc"
                )
            )

    def test_non_github_or_non_https_key_url_is_rejected(self) -> None:
        for url in (
            "http://raw.githubusercontent.com/o/r/" + "a" * 40 + "/key.asc",
            "https://example.invalid/o/r/" + "a" * 40 + "/key.asc",
            "https://raw.githubusercontent.com@evil.invalid/o/r/"
            + "a" * 40
            + "/key.asc",
        ):
            with self.subTest(url=url), self.assertRaises(ContractError):
                self.valid(url=url)

    def test_key_url_userinfo_query_and_fragment_are_rejected(self) -> None:
        base = (
            "https://raw.githubusercontent.com/xr-esp-private/example-release/"
            + "a" * 40
            + "/key.asc"
        )
        for url in (
            base.replace("https://", "https://user@"),
            base + "?raw=1",
            base + "#key",
        ):
            with self.subTest(url=url), self.assertRaises(ContractError):
                self.valid(url=url)

    def test_fingerprint_must_be_full_uppercase_hex(self) -> None:
        for fingerprint in ("A" * 39, "a" * 40, "G" * 40, "A" * 41):
            with self.subTest(fingerprint=fingerprint), self.assertRaises(ContractError):
                self.valid(fingerprint=fingerprint)


class AptSignedIndexTests(unittest.TestCase):
    def setUp(self) -> None:
        self.amd64 = b"Package: fixture\nArchitecture: amd64\n"
        self.arm64 = b"Package: fixture\nArchitecture: arm64\n"
        self.release = (
            "Suite: stable\n"
            "SHA256:\n"
            f" {hashlib.sha256(self.amd64).hexdigest()} {len(self.amd64)} main/binary-amd64/Packages\n"
            f" {hashlib.sha256(self.arm64).hexdigest()} {len(self.arm64)} main/binary-arm64/Packages\n"
            "SHA512:\n"
        ).encode("utf-8")

    def test_primary_fingerprint_ignores_subkey_fingerprint(self) -> None:
        listing = (
            "pub:-:2048:1:KEY:0:0::::::sc:\n"
            f"fpr:::::::::{'A' * 40}:\n"
            "sub:-:2048:1:SUB:0:0::::::s:\n"
            f"fpr:::::::::{'B' * 40}:\n"
        )
        self.assertEqual(parse_primary_fingerprints(listing), ["A" * 40])

    def test_multiple_primary_keys_are_visible_for_rejection(self) -> None:
        listing = (
            "pub:-:2048:1:ONE:0:0::::::sc:\n"
            f"fpr:::::::::{'A' * 40}:\n"
            "pub:-:2048:1:TWO:0:0::::::sc:\n"
            f"fpr:::::::::{'B' * 40}:\n"
        )
        self.assertEqual(parse_primary_fingerprints(listing), ["A" * 40, "B" * 40])

    def test_actual_key_fingerprint_mismatch_is_rejected(self) -> None:
        listing = (
            "pub:-:2048:1:KEY:0:0::::::sc:\n"
            f"fpr:::::::::{'A' * 40}:\n"
        )
        completed = subprocess.CompletedProcess(
            args=["gpg"],
            returncode=0,
            stdout=listing,
            stderr="",
        )
        with tempfile.TemporaryDirectory(prefix="xr-key-mismatch-") as temporary:
            key_path = Path(temporary) / "key.asc"
            key_path.write_bytes(b"public key fixture")
            with mock.patch("apt_trust.subprocess.run", return_value=completed):
                with self.assertRaises(ContractError):
                    inspect_key_fingerprint(key_path, "B" * 40, "gpg")

    def test_private_key_material_listing_is_rejected(self) -> None:
        with self.assertRaises(ContractError):
            parse_primary_fingerprints("sec:-:2048:1:KEY:0:0::::::sc:\n")

    def test_packages_bytes_match_signed_hash_and_length(self) -> None:
        signed = parse_release_sha256(self.release)
        verify_signed_file(signed, "main/binary-amd64/Packages", self.amd64)
        verify_signed_file(signed, "main/binary-arm64/Packages", self.arm64)

    def test_unsigned_packages_path_is_rejected(self) -> None:
        signed = parse_release_sha256(self.release)
        with self.assertRaises(ContractError):
            verify_signed_file(signed, "other/binary-amd64/Packages", self.amd64)

    def test_signed_packages_hash_mismatch_is_rejected(self) -> None:
        signed = parse_release_sha256(self.release)
        changed = self.amd64[:-1] + b"X"
        with self.assertRaises(ContractError):
            verify_signed_file(signed, "main/binary-amd64/Packages", changed)

    def test_signed_packages_length_mismatch_is_rejected(self) -> None:
        signed = parse_release_sha256(self.release)
        with self.assertRaises(ContractError):
            verify_signed_file(
                signed,
                "main/binary-amd64/Packages",
                self.amd64 + b"x",
            )

    def test_duplicate_or_unsafe_release_paths_are_rejected(self) -> None:
        duplicate = self.release.replace(
            b"SHA512:\n",
            (
                f" {hashlib.sha256(self.amd64).hexdigest()} {len(self.amd64)} "
                "main/binary-amd64/Packages\nSHA512:\n"
            ).encode("utf-8"),
        )
        with self.assertRaises(ContractError):
            parse_release_sha256(duplicate)
        unsafe = self.release.replace(
            b"main/binary-amd64/Packages",
            b"../binary-amd64/Packages",
        )
        with self.assertRaises(ContractError):
            parse_release_sha256(unsafe)

    def test_clearsigned_header_without_valid_signature_is_rejected(self) -> None:
        failed = subprocess.CompletedProcess(
            args=["gpgv"],
            returncode=1,
            stdout=b"",
            stderr=b"bad signature",
        )
        with (
            mock.patch("apt_trust.require_gpg_tools", return_value=("gpg", "gpgv")),
            mock.patch(
                "apt_trust.prepare_trusted_keyring",
                return_value=Path("trustedkeys.gpg"),
            ),
            mock.patch("apt_trust.subprocess.run", return_value=failed),
        ):
            with self.assertRaises(ContractError):
                verify_inrelease(
                    b"public-key",
                    "A" * 40,
                    b"-----BEGIN PGP SIGNED MESSAGE-----\nnot authenticated\n",
                )


@unittest.skipUnless(shutil.which("gpg") and shutil.which("gpgv"), "GnuPG unavailable")
class AptRealGpgvTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xr-gpgv-fixture-")
        self.root = Path(self.temporary.name)
        self.home = self.root / "gnupg"
        self.home.mkdir(mode=0o700)
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(self.home),
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                "XR APT Test <apt-test@example.invalid>",
                "rsa2048",
                "sign",
                "0",
            ],
            check=True,
            capture_output=True,
        )
        listing = subprocess.run(
            ["gpg", "--batch", "--homedir", str(self.home), "--with-colons", "--list-keys"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.fingerprint = parse_primary_fingerprints(listing)[0]
        self.key_payload = subprocess.run(
            ["gpg", "--batch", "--homedir", str(self.home), "--armor", "--export", self.fingerprint],
            check=True,
            capture_output=True,
        ).stdout
        self.release_payload = b"Suite: stable\nSHA256:\n " + b"0" * 64 + b" 0 main/binary-amd64/Packages\n"
        release_path = self.root / "Release"
        inrelease_path = self.root / "InRelease"
        release_path.write_bytes(self.release_payload)
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--homedir",
                str(self.home),
                "--local-user",
                self.fingerprint,
                "--digest-algo",
                "SHA256",
                "--clearsign",
                "--output",
                str(inrelease_path),
                str(release_path),
            ],
            check=True,
            capture_output=True,
        )
        self.inrelease_payload = inrelease_path.read_bytes()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_real_gpgv_extracts_authenticated_release(self) -> None:
        self.assertEqual(
            verify_inrelease(
                self.key_payload,
                self.fingerprint,
                self.inrelease_payload,
            ),
            self.release_payload,
        )

    def test_real_gpgv_rejects_tampered_inrelease(self) -> None:
        tampered = self.inrelease_payload.replace(b"Suite: stable", b"Suite: testing")
        with self.assertRaises(ContractError):
            verify_inrelease(self.key_payload, self.fingerprint, tampered)

    def test_real_gpgv_rejects_wrong_fingerprint(self) -> None:
        wrong = ("0" if self.fingerprint[0] != "0" else "1") + self.fingerprint[1:]
        with self.assertRaises(ContractError):
            verify_inrelease(self.key_payload, wrong, self.inrelease_payload)


class SourceCredentialTests(unittest.TestCase):
    def run_cli(self, token: bool, ssh_key: bool) -> tuple[subprocess.CompletedProcess[str], str]:
        with tempfile.TemporaryDirectory(prefix="xr-source-auth-") as temporary:
            output = Path(temporary) / "github-output"
            output.touch()
            result = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts/validate_source_auth.py"),
                    "--token-configured",
                    str(token).lower(),
                    "--ssh-key-configured",
                    str(ssh_key).lower(),
                    "--github-output",
                    str(output),
                ],
                capture_output=True,
                text=True,
            )
            return result, output.read_text(encoding="utf-8")

    def test_token_only_is_accepted(self) -> None:
        self.assertEqual(validate_source_auth_selection(True, False), "token")

    def test_ssh_key_only_is_accepted(self) -> None:
        self.assertEqual(validate_source_auth_selection(False, True), "ssh")

    def test_missing_credentials_are_rejected(self) -> None:
        with self.assertRaises(ContractError):
            validate_source_auth_selection(False, False)

    def test_multiple_credentials_are_rejected(self) -> None:
        with self.assertRaises(ContractError):
            validate_source_auth_selection(True, True)

    def test_cli_outputs_only_token_mode(self) -> None:
        result, output = self.run_cli(True, False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "mode=token\n")

    def test_cli_outputs_only_ssh_mode(self) -> None:
        result, output = self.run_cli(False, True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, "mode=ssh\n")

    def test_cli_missing_credentials_has_no_output(self) -> None:
        result, output = self.run_cli(False, False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output, "")

    def test_cli_multiple_credentials_has_no_output(self) -> None:
        result, output = self.run_cli(True, True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(output, "")


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


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class AptRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="xr-apt-redirect-")
        self.artifact_path = Path(self.temporary.name) / "fixture_1.2.3_amd64.deb"
        self.artifact_path.write_bytes(b"fixture")
        self.artifact = DebArtifact(
            path=self.artifact_path,
            package="fixture",
            version="1.2.3",
            architecture="amd64",
            sha256=hashlib.sha256(b"fixture").hexdigest(),
        )
        self.servers: list[ThreadingHTTPServer] = []
        self.threads: list[threading.Thread] = []

    def tearDown(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join(timeout=2)
        self.temporary.cleanup()

    def serve(self, handler: type[http.server.BaseHTTPRequestHandler]) -> str:
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.servers.append(server)
        self.threads.append(thread)
        return f"http://127.0.0.1:{server.server_port}"

    def test_same_origin_authenticated_redirect_is_rejected(self) -> None:
        state: dict[str, object] = {"redirect_target_reached": False}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self) -> None:  # noqa: N802
                if self.path.startswith("/upload/"):
                    state["authorization"] = self.headers.get("Authorization")
                    self.send_response(302)
                    self.send_header("Location", "/redirect-target")
                    self.end_headers()
                    return
                state["redirect_target_reached"] = True
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(Handler)
        username = "redirect-user-secret"
        password = "redirect-password-secret"
        with self.assertRaises(ContractError) as raised:
            upload(self.artifact, base, username, password, 5)
        self.assertFalse(state["redirect_target_reached"])
        self.assertTrue(str(state.get("authorization", "")).startswith("Basic "))
        self.assertNotIn(username, str(raised.exception))
        self.assertNotIn(password, str(raised.exception))

    def test_cross_origin_redirect_is_rejected_without_forwarding_credentials(self) -> None:
        target_state: dict[str, object] = {"reached": False, "authorization": None}

        class TargetHandler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self) -> None:  # noqa: N802
                target_state["reached"] = True
                target_state["authorization"] = self.headers.get("Authorization")
                self.send_response(204)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        target = self.serve(TargetHandler)

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_PUT(self) -> None:  # noqa: N802
                self.send_response(307)
                self.send_header("Location", f"{target}/redirect-target")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(RedirectHandler)
        username = "cross-origin-user-secret"
        password = "cross-origin-password-secret"
        with self.assertRaises(ContractError) as raised:
            upload(self.artifact, base, username, password, 5)
        self.assertFalse(target_state["reached"])
        self.assertIsNone(target_state["authorization"])
        self.assertNotIn(username, str(raised.exception))
        self.assertNotIn(password, str(raised.exception))

    def test_public_key_download_redirect_is_rejected(self) -> None:
        target_state = {"reached": False}

        class TargetHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                target_state["reached"] = True
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"unexpected")

            def log_message(self, format: str, *args: object) -> None:
                return

        target = self.serve(TargetHandler)

        class RedirectHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(302)
                self.send_header("Location", f"{target}/key.asc")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(RedirectHandler)
        with self.assertRaises(ContractError):
            download_no_redirect(f"{base}/key.asc", 5, 1024)
        self.assertFalse(target_state["reached"])

    def test_missing_public_key_download_fails(self) -> None:
        class MissingHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                self.send_response(404)
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        base = self.serve(MissingHandler)
        with self.assertRaises(urllib.error.HTTPError):
            download_no_redirect(f"{base}/missing.asc", 5, 1024)


if __name__ == "__main__":
    unittest.main()
