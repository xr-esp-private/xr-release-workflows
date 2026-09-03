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

    reusable = (WORKFLOW_ROOT / "linux-deb-release.yml").read_text(encoding="utf-8")
    required = [
        "workflow_call:",
        "XR_PRIVATE_SOURCE_TOKEN:",
        "XR_APT_REPO_USER:",
        "XR_APT_REPO_PASS:",
        "persist-credentials: false",
        "permissions:\n      contents: read",
        "permissions:\n      contents: write",
    ]
    for snippet in required:
        if snippet not in reusable:
            fail(f"reusable workflow is missing required contract: {snippet!r}")
    print(f"repository audit passed for {len(tracked)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
