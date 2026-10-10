from __future__ import annotations

import argparse
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from github_release import API, finalize, prepare, release_by_tag  # noqa: E402
from release_contract import ContractError  # noqa: E402


class ReleaseLookupTests(unittest.TestCase):
    def release(self, tag: str = "v1.2.3", release_id: int = 123, draft: bool = True) -> dict:
        return {
            "id": release_id, "tag_name": tag, "draft": draft,
            "prerelease": False, "assets": [],
        }

    def lookup(self) -> dict | None:
        return release_by_tag("fixture", "owner/repo", "v1.2.3")

    def test_published_tag_endpoint_remains_authoritative(self) -> None:
        published = self.release(draft=False)
        with mock.patch("github_release.json_request", return_value=(200, published)) as api:
            self.assertEqual(self.lookup(), published)
            api.assert_called_once_with(
                "fixture", f"{API}/repos/owner/repo/releases/tags/v1.2.3"
            )

    def test_missing_tag_endpoint_finds_exact_draft_in_authenticated_list(self) -> None:
        draft = self.release()
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), (200, [self.release("v1.2.30", 124), draft]),
        ]) as api:
            self.assertEqual(self.lookup(), draft)
            self.assertEqual(api.call_args_list[1], mock.call(
                "fixture", f"{API}/repos/owner/repo/releases?per_page=100&page=1"
            ))

    def test_paginated_lookup_finds_draft_on_later_page(self) -> None:
        page_one = [self.release(f"v0.0.{index}", index + 1) for index in range(100)]
        draft = self.release(release_id=101)
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), (200, page_one), (200, [draft]),
        ]) as api:
            self.assertEqual(self.lookup(), draft)
            self.assertTrue(api.call_args_list[-1].args[1].endswith("page=2"))

    def test_missing_release_returns_none_after_listing(self) -> None:
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), (200, [self.release("v1.2.30")]),
        ]):
            self.assertIsNone(self.lookup())

    def test_duplicate_exact_tags_across_pages_fail_closed(self) -> None:
        page_one = [self.release()] + [
            self.release(f"v0.0.{index}", index + 1) for index in range(99)
        ]
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), (200, page_one), (200, [self.release(release_id=456)]),
        ]):
            with self.assertRaisesRegex(ContractError, "duplicate"):
                self.lookup()

    def test_invalid_list_responses_fail_closed(self) -> None:
        for response in ((404, {}), (200, {}), (200, [None]), (200, [self.release()] * 101)):
            with self.subTest(response=response), mock.patch(
                "github_release.json_request", side_effect=[(404, {}), response]
            ):
                with self.assertRaises(ContractError):
                    self.lookup()

    def test_malformed_metadata_fails_even_for_non_matching_tag(self) -> None:
        for field, value in (
            ("id", True), ("id", 0), ("id", "123"),
            ("tag_name", ""), ("tag_name", None), ("draft", "true"),
        ):
            malformed = self.release("v9.9.9")
            malformed[field] = value
            with self.subTest(field=field, value=value), mock.patch(
                "github_release.json_request",
                side_effect=[(404, {}), (200, [self.release(), malformed])],
            ):
                with self.assertRaises(ContractError):
                    self.lookup()

    def test_direct_lookup_wrong_tag_or_malformed_metadata_fails(self) -> None:
        for response in (None, self.release("v1.2.30"), {"id": 123, "tag_name": "v1.2.3"}):
            with self.subTest(response=response), mock.patch(
                "github_release.json_request", return_value=(200, response)
            ):
                with self.assertRaises(ContractError):
                    self.lookup()

    def test_pagination_limit_does_not_return_partial_match(self) -> None:
        full_page = [self.release(f"v0.0.{index}", index + 1) for index in range(100)]
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), *[(200, full_page)] * 100,
        ]):
            with self.assertRaisesRegex(ContractError, "pagination"):
                self.lookup()

    def test_finalize_patches_found_draft_id(self) -> None:
        draft = self.release()
        with mock.patch("github_release.json_request", side_effect=[
            (404, {}), (200, [draft]), (200, self.release(draft=False)),
        ]) as api:
            self.assertEqual(finalize(argparse.Namespace(tag="v1.2.3"), "fixture", "owner/repo"), 0)
            self.assertEqual(api.call_args_list[-1], mock.call(
                "fixture", f"{API}/repos/owner/repo/releases/123", "PATCH", {"draft": False}
            ))

    def test_prepare_reuses_unpublished_draft_without_recreating_or_retargeting(self) -> None:
        notes = mock.Mock()
        notes.read_text.return_value = "Fixture release"
        metadata = mock.MagicMock()
        metadata.__truediv__.return_value.read_text.return_value = '{"source_tag":"v1.2.3"}'
        args = argparse.Namespace(
            tag="v1.2.3", target_commit="a" * 40, prerelease=False,
            notes=notes, metadata=metadata, dist=Path("dist"),
        )
        draft = self.release()
        draft["target_commitish"] = "b" * 40
        with (
            mock.patch("github_release.json_request", side_effect=[(404, {}), (200, [draft])]) as api,
            mock.patch("github_release.expected_assets", return_value={"fixture.deb": Path("fixture.deb")}),
            mock.patch("github_release.check_existing_assets", return_value={"fixture.deb"}) as assets,
            mock.patch("github_release.create_release") as create,
            mock.patch("github_release.upload_asset") as upload,
        ):
            self.assertEqual(prepare(args, "fixture", "owner/repo"), 0)
            assets.assert_called_once()
            create.assert_not_called()
            upload.assert_not_called()
            self.assertEqual(api.call_count, 2)
            self.assertEqual(draft["target_commitish"], "b" * 40)

    def test_finalize_rejects_published_release_without_mutation(self) -> None:
        with mock.patch("github_release.json_request", return_value=(200, self.release(draft=False))) as api:
            with self.assertRaises(ContractError):
                finalize(argparse.Namespace(tag="v1.2.3"), "fixture", "owner/repo")
            self.assertEqual(api.call_count, 1)


if __name__ == "__main__":
    unittest.main()
