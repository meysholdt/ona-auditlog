from __future__ import annotations

import argparse
import unittest
from types import SimpleNamespace

from ona_auditlog.cli import audit_log_filter, audit_log_list_kwargs, build_base_url, to_payload


class CliTests(unittest.TestCase):
    def test_build_base_url_defaults_to_app_api(self) -> None:
        self.assertEqual(build_base_url("app.gitpod.io"), "https://app.gitpod.io/api")

    def test_build_base_url_accepts_scheme_and_appends_api(self) -> None:
        self.assertEqual(build_base_url("https://ona.example"), "https://ona.example/api")

    def test_build_base_url_preserves_custom_path_before_api(self) -> None:
        self.assertEqual(build_base_url("https://ona.example/custom"), "https://ona.example/custom/api")

    def test_to_payload_serializes_sdk_style_objects(self) -> None:
        payload = to_payload(SimpleNamespace(resource_type="RESOURCE_TYPE_ENVIRONMENT", resource_id="env-1"))
        self.assertEqual(payload, {"resource_type": "RESOURCE_TYPE_ENVIRONMENT", "resource_id": "env-1"})

    def test_audit_log_filter_omits_empty_filters(self) -> None:
        args = argparse.Namespace(
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        self.assertEqual(audit_log_filter(args), {})

    def test_audit_log_filter_supports_sdk_filter_fields(self) -> None:
        args = argparse.Namespace(
            from_time="2026-01-01T00:00:00Z",
            to_time=None,
            actor_id=["user-1"],
            actor_principal=["PRINCIPAL_USER"],
            subject_id=["env-1"],
            subject_type=["RESOURCE_TYPE_ENVIRONMENT"],
        )
        self.assertEqual(
            audit_log_filter(args),
            {
                "from": "2026-01-01T00:00:00Z",
                "actor_ids": ["user-1"],
                "actor_principals": ["PRINCIPAL_USER"],
                "subject_ids": ["env-1"],
                "subject_types": ["RESOURCE_TYPE_ENVIRONMENT"],
            },
        )

    def test_audit_log_list_kwargs_sets_page_size_and_descending_sort(self) -> None:
        args = argparse.Namespace(
            page_size=50,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        self.assertEqual(
            audit_log_list_kwargs(args),
            {
                "page_size": 50,
                "sort": {"field": "createdAt", "order": "SORT_ORDER_DESC"},
            },
        )

    def test_audit_log_list_kwargs_rejects_invalid_page_size(self) -> None:
        args = argparse.Namespace(
            page_size=0,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        with self.assertRaisesRegex(ValueError, "--page-size"):
            audit_log_list_kwargs(args)


if __name__ == "__main__":
    unittest.main()
