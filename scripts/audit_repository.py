#!/usr/bin/env python3
"""Fail closed on floating actions, release bypasses, secrets, and private paths."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github/workflows"
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA_RE = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
SOURCE_SECRET_IN_ENV_RE = re.compile(
    r"^\s+[A-Z][A-Z0-9_]*:\s*\$\{\{\s*secrets\."
    r"XR_PRIVATE_SOURCE_(?:TOKEN|SSH_KEY)\s*\}\}\s*$",
    re.MULTILINE,
)
DIRECT_CALLER_INPUT_ARGUMENT_RE = re.compile(
    r"^\s+--[^\n]*\$\{\{\s*inputs\.", re.MULTILINE
)


def fail(message: str) -> None:
    print(f"repository audit failed: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> int:
    tracked = [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts
    ]
    forbidden_bytes = [
        ("GitHub classic token", b"gh" + b"p_"),
        ("GitHub fine-grained token", b"github" + b"_pat_"),
        ("private key", b"BEGIN " + b"PRIVATE KEY"),
        ("developer absolute path", b"/Users" + b"/"),
        ("known production APT host", b"47.106." + b"100.173"),
    ]
    for path in tracked:
        content = path.read_bytes()
        for label, needle in forbidden_bytes:
            if needle in content:
                fail(f"{label} found in {path.relative_to(ROOT)}")

    workflows = sorted(WORKFLOW_ROOT.glob("*.yml"))
    if not workflows:
        fail("no workflows found")
    forbidden_workflow_text = [
        "secrets:" + " inherit",
        "continue-on-" + "error: true",
        "||" + " true",
    ]
    for path in workflows:
        text = path.read_text(encoding="utf-8")
        for forbidden in forbidden_workflow_text:
            if forbidden in text:
                fail(f"forbidden release bypass in {path.relative_to(ROOT)}")
        for reference in USES_RE.findall(text):
            if reference.startswith("./"):
                continue
            if not FULL_SHA_RE.fullmatch(reference):
                fail(f"floating action/workflow reference: {reference}")
        if SOURCE_SECRET_IN_ENV_RE.search(text):
            fail(
                f"private source credential exposed as an environment value in "
                f"{path.relative_to(ROOT)}"
            )
        if DIRECT_CALLER_INPUT_ARGUMENT_RE.search(text):
            fail(
                f"caller input interpolated directly into a shell argument in "
                f"{path.relative_to(ROOT)}"
            )

    reusable = (WORKFLOW_ROOT / "linux-deb-release.yml").read_text(encoding="utf-8")
    required = [
        "workflow_call:",
        "workflow_implementation_commit:",
        "apt_allow_plain_http:",
        "apt_signing_key_url:",
        "apt_signing_key_fingerprint:",
        "default: false",
        "type: boolean",
        "XR_PRIVATE_SOURCE_TOKEN:",
        "XR_PRIVATE_SOURCE_SSH_KEY:",
        "scripts/validate_source_auth.py",
        "ssh-key: ${{ secrets.XR_PRIVATE_SOURCE_SSH_KEY }}",
        "ssh-strict: true",
        "XR_APT_REPO_USER:",
        "XR_APT_REPO_PASS:",
        "XR_APT_REPO_URL:",
        "APT_REPOSITORY_URL: ${{ secrets.XR_APT_REPO_URL || inputs.apt_repository_url }}",
        "scripts/validate_apt_trust.py",
        "--signing-key-url",
        "--signing-key-fingerprint",
        "persist-credentials: false",
        "permissions:\n      contents: read",
        "permissions:\n      contents: write",
    ]
    for snippet in required:
        if snippet not in reusable:
            fail(f"reusable workflow is missing required contract: {snippet!r}")
    if reusable.count(
        "APT_REPOSITORY_URL: ${{ secrets.XR_APT_REPO_URL || inputs.apt_repository_url }}"
    ) != 3:
        fail("each APT URL consumer must resolve the optional Secret before the input")
    if reusable.index("scripts/validate_apt_trust.py") > reusable.index(
        "Check out the exact private source tag with the read-only token"
    ):
        fail("APT signing key must be bootstrapped before private source checkout")

    apt_publish = (ROOT / "scripts/apt_publish.py").read_text(encoding="utf-8")
    apt_trust = (ROOT / "scripts/apt_trust.py").read_text(encoding="utf-8")
    for snippet in (
        "fetch_verified_records(",
        "fetch_verified_index_payloads(",
        "bootstrap_signing_key(",
    ):
        if snippet not in apt_publish:
            fail(f"APT publisher is missing signed-index verification: {snippet!r}")
    for snippet in (
        'shutil.which("gpgv")',
        '"raw.githubusercontent.com"',
        "class NoRedirect",
        '"--keyring"',
        '"--output"',
        "verify_inrelease(",
        "parse_release_sha256(",
        "verify_signed_file(",
        "fetch_verified_index_payloads(",
        "verify_repository_bootstrap(",
    ):
        if snippet not in apt_trust:
            fail(f"APT trust bootstrap is missing required contract: {snippet!r}")
    if "BEGIN PGP SIGNED MESSAGE" in apt_publish:
        fail("APT publisher must not substitute a clearsigned header check for gpgv")

    validation = (WORKFLOW_ROOT / "linux-deb-validate.yml").read_text(
        encoding="utf-8"
    )
    validation_required = [
        "workflow_call:",
        "workflow_implementation_commit:",
        "XR_PRIVATE_SOURCE_TOKEN:",
        "XR_PRIVATE_SOURCE_SSH_KEY:",
        "scripts/validate_source_auth.py",
        "ssh-key: ${{ secrets.XR_PRIVATE_SOURCE_SSH_KEY }}",
        "ssh-strict: true",
        "scripts/validate_source.py",
        "scripts/validate_release.py",
        "permissions:\n      contents: read",
    ]
    for snippet in validation_required:
        if snippet not in validation:
            fail(f"validation workflow is missing required contract: {snippet!r}")
    for forbidden in (
        "XR_APT_",
        "apt_repository",
        "github_release.py",
        "contents: write",
    ):
        if forbidden in validation:
            fail(f"validation workflow contains publication capability: {forbidden!r}")
    for path, text in (
        (WORKFLOW_ROOT / "linux-deb-release.yml", reusable),
        (WORKFLOW_ROOT / "linux-deb-validate.yml", validation),
    ):
        for dependency in ("ca-certificates", "git", "openssh-client", "python3"):
            if dependency not in text:
                fail(
                    f"product-container bootstrap is missing {dependency!r} in "
                    f"{path.relative_to(ROOT)}"
                )
        auth_steps = [
            match.start()
            for match in re.finditer(
                "Require exactly one private source credential", text
            )
        ]
        if len(auth_steps) != 2 or text.index(
            "Bootstrap workflow dependencies in the product container"
        ) > auth_steps[1]:
            fail(
                f"product-container bootstrap must precede private source auth in "
                f"{path.relative_to(ROOT)}"
            )
        if "github.workflow_sha" in text:
            fail(
                f"reusable workflow must not use the caller workflow SHA in "
                f"{path.relative_to(ROOT)}"
            )
        if text.count("ref: ${{ inputs.workflow_implementation_commit }}") != 3:
            fail(
                f"every implementation checkout must use the explicit immutable "
                f"commit in {path.relative_to(ROOT)}"
            )
        if text.count("scripts/validate_source_auth.py") != 2:
            fail(
                f"each source-checkout job must validate credential selection in "
                f"{path.relative_to(ROOT)}"
            )
        ssh_checkout_sections = text.split(
            "- name: Check out the exact private source tag with the read-only Deploy Key"
        )[1:]
        token_checkout_sections = text.split(
            "- name: Check out the exact private source tag with the read-only token"
        )[1:]
        if len(ssh_checkout_sections) != 2 or len(token_checkout_sections) != 2:
            fail(f"source credential checkout branches are incomplete in {path.relative_to(ROOT)}")
        for section in ssh_checkout_sections:
            block = section.split("\n\n", 1)[0]
            if "token:" in block or "ssh-key:" not in block or "ssh-strict: true" not in block:
                fail(f"Deploy Key checkout branch is unsafe in {path.relative_to(ROOT)}")
        for section in token_checkout_sections:
            block = section.split("\n\n", 1)[0]
            if "ssh-key:" in block or "token:" not in block:
                fail(f"token checkout branch is unsafe in {path.relative_to(ROOT)}")

    ci = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    required_checks = [
        "name: Static contract checks",
        "name: Fixture DEB (${{ matrix.architecture }})",
        "name: Aggregate release contract",
        "command -v gpg >/dev/null",
        "command -v gpgv >/dev/null",
    ]
    for snippet in required_checks:
        if snippet not in ci:
            fail(f"CI is missing a branch-protection check contract: {snippet!r}")
    print(f"repository audit passed for {len(tracked)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
