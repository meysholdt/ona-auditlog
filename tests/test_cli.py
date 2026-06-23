from __future__ import annotations

import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from ona_auditlog.cli import (
    audit_log_filter,
    audit_log_list_kwargs,
    build_base_url,
    enrichment_projection,
    enrich_entry,
    conversation_s3_url,
    poll_audit_logs,
    relevant_event_kind,
    recent_from_time,
    stdout_record,
    to_payload,
)


def audit_entry(
    *,
    id: str = "audit-1",
    subject_type: str = "RESOURCE_TYPE_ENVIRONMENT",
    subject_id: str = "env-1",
    action: str = "Environment created",
    actor_id: str = "user-1",
    actor_principal: str = "PRINCIPAL_USER",
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        actor_id=actor_id,
        actor_principal=actor_principal,
        subject_id=subject_id,
        subject_type=subject_type,
        action=action,
        created_at="2026-01-01T00:00:00Z",
    )


class FakeEvents:
    def __init__(self, entries: list[SimpleNamespace], pages: list[list[SimpleNamespace]] | None = None) -> None:
        self._entries = entries
        self._pages = pages
        self.calls = []

    def list(self, **kwargs):
        self.calls.append(kwargs)
        if self._pages is None:
            return SimpleNamespace(entries=self._entries, pagination=SimpleNamespace(next_token=None))

        if "token" in kwargs:
            index = int(kwargs["token"])
        else:
            index = 0
        next_token = str(index + 1) if index + 1 < len(self._pages) else None
        return SimpleNamespace(entries=self._pages[index], pagination=SimpleNamespace(next_token=next_token))


class FakeUsers:
    def get_user(self, *, user_id: str):
        return SimpleNamespace(user=SimpleNamespace(id=user_id, email="user@example.com", name="User One"))


class FakeEnvironments:
    def retrieve(self, *, environment_id: str):
        return SimpleNamespace(
            environment=SimpleNamespace(
                id=environment_id,
                metadata=SimpleNamespace(
                    name="Demo Env",
                    runner_id="runner-1",
                    creator=SimpleNamespace(id="user-1", principal="PRINCIPAL_USER"),
                ),
                status=SimpleNamespace(
                    phase="ENVIRONMENT_PHASE_RUNNING",
                    content=SimpleNamespace(
                        git=SimpleNamespace(clone_url="https://github.com/acme/example.git"),
                    ),
                ),
            )
        )


class FakeAgents:
    def retrieve_execution(self, *, agent_execution_id: str):
        return SimpleNamespace(
            agent_execution=SimpleNamespace(
                id=agent_execution_id,
                metadata=SimpleNamespace(
                    name="Demo Agent Execution",
                    creator=SimpleNamespace(id="user-1", principal="PRINCIPAL_USER"),
                ),
                spec=SimpleNamespace(code_context=SimpleNamespace(environment_id="env-1")),
                status=SimpleNamespace(
                    phase="PHASE_RUNNING",
                    used_environments=[SimpleNamespace(environment_id="env-2")],
                    conversation_url="https://runner.example/agent-exec-1/conversation",
                ),
            )
        )


class FakeRunners:
    def retrieve(self, *, runner_id: str):
        return SimpleNamespace(
            runner=SimpleNamespace(
                runner_id=runner_id,
                status=SimpleNamespace(
                    additional_info=[
                        SimpleNamespace(key="agentBucket", value="s3://agent-bucket"),
                    ]
                ),
            )
        )


class FakeClient:
    def __init__(
        self,
        entries: list[SimpleNamespace] | None = None,
        *,
        pages: list[list[SimpleNamespace]] | None = None,
        **_kwargs,
    ) -> None:
        self.events = FakeEvents(entries or [], pages=pages)
        self.users = FakeUsers()
        self.environments = FakeEnvironments()
        self.agents = FakeAgents()
        self.runners = FakeRunners()


class FailingEnvironments:
    def retrieve(self, *, environment_id: str):
        raise RuntimeError(f"environment {environment_id} is gone")


class FakeClientWithDeletedEnvironment(FakeClient):
    def __init__(self, entries: list[SimpleNamespace] | None = None, **kwargs) -> None:
        super().__init__(entries, **kwargs)
        self.environments = FailingEnvironments()


def parse_json_stream(content: str) -> list[dict]:
    decoder = json.JSONDecoder()
    index = 0
    records = []
    while index < len(content):
        while index < len(content) and content[index].isspace():
            index += 1
        if index >= len(content):
            break
        record, index = decoder.raw_decode(content, index)
        records.append(record)
    return records


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

    def test_relevant_event_kind_filters_requested_stdout_events(self) -> None:
        self.assertEqual(
            relevant_event_kind(audit_entry(action="Environment created (identity from cookie:account/user-1)")),
            "environment.created",
        )
        self.assertEqual(relevant_event_kind(audit_entry(action="Environment deleted")), "environment.deleted")
        self.assertEqual(relevant_event_kind(audit_entry(action="started environment")), "environment.started")
        self.assertEqual(relevant_event_kind(audit_entry(action="stopped environment")), "environment.stopped")
        self.assertEqual(
            relevant_event_kind(
                audit_entry(
                    subject_type="RESOURCE_TYPE_AGENT_EXECUTION",
                    subject_id="agent-exec-1",
                    action="AgentExecution created",
                )
            ),
            "agent_execution.started",
        )
        self.assertIsNone(relevant_event_kind(audit_entry(action="created environment logs token")))

    def test_enrich_entry_adds_user_and_environment_for_environment_event(self) -> None:
        record = enrich_entry(FakeClient(), audit_entry(), "environment.created")

        self.assertEqual(record["event"], "environment.created")
        self.assertEqual(record["user"]["email"], "user@example.com")
        self.assertEqual(record["environment"]["id"], "env-1")
        self.assertIsNone(record["agentExecution"])
        self.assertEqual(record["runner"]["runner_id"], "runner-1")

    def test_enrich_entry_uses_environment_creator_when_actor_is_not_user(self) -> None:
        record = enrich_entry(
            FakeClient(),
            audit_entry(
                action="stopped environment",
                actor_id="env-1",
                actor_principal="PRINCIPAL_ENVIRONMENT",
            ),
            "environment.stopped",
        )

        self.assertEqual(record["event"], "environment.stopped")
        self.assertEqual(record["user"]["id"], "user-1")

    def test_enrich_entry_adds_user_agent_execution_and_environments(self) -> None:
        record = enrich_entry(
            FakeClient(),
            audit_entry(
                subject_type="RESOURCE_TYPE_AGENT_EXECUTION",
                subject_id="agent-exec-1",
                action="AgentExecution created",
            ),
            "agent_execution.started",
        )

        self.assertEqual(record["event"], "agent_execution.started")
        self.assertEqual(record["user"]["id"], "user-1")
        self.assertEqual(record["agentExecution"]["id"], "agent-exec-1")
        self.assertEqual([item["id"] for item in record["environments"]], ["env-2", "env-1"])
        self.assertEqual(record["runner"]["runner_id"], "runner-1")

    def test_enrichment_projection_only_includes_requested_enriched_fields(self) -> None:
        enriched = enrich_entry(FakeClient(), audit_entry(), "environment.created")

        self.assertEqual(
            enrichment_projection(enriched),
            {
                "creatorEmail": "user@example.com",
                "gitRepoUrl": "https://github.com/acme/example.git",
            },
        )

    def test_stdout_record_includes_audit_log_and_clear_enrichment_section(self) -> None:
        enriched = enrich_entry(FakeClient(), audit_entry(id="audit-9"), "environment.created")

        record = stdout_record(enriched)

        self.assertEqual(record["auditLog"]["id"], "audit-9")
        self.assertEqual(record["auditLog"]["action"], "Environment created")
        self.assertEqual(record["enrichment"]["creatorEmail"], "user@example.com")
        self.assertEqual(record["enrichment"]["gitRepoUrl"], "https://github.com/acme/example.git")
        self.assertNotIn("agentConversationS3Url", record["enrichment"])

    def test_conversation_s3_url_computes_streamstore_prefix_from_runner_bucket(self) -> None:
        self.assertEqual(
            conversation_s3_url(
                {"id": "agent-exec-1", "status": {"conversationUrl": "https://runner.example/conversation"}},
                {"status": {"additionalInfo": [{"key": "agentBucket", "value": "s3://agent-bucket"}]}},
            ),
            "s3://agent-bucket/conversations/agent-exec-1/chunks/",
        )

    def test_poll_audit_logs_writes_all_new_entries_to_file_and_only_relevant_to_stdout(self) -> None:
        entries = [
            audit_entry(id="audit-1", action="created environment logs token"),
            audit_entry(id="audit-2", action="Environment created"),
        ]
        args = argparse.Namespace(
            host="app.gitpod.io",
            base_url=None,
            api_key=None,
            page_size=100,
            once=True,
            history_minutes=60,
            history_pages=1,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
            log_file="",
            enrichment_detail_file="",
        )

        with tempfile.TemporaryDirectory() as tmp:
            args.log_file = f"{tmp}/auditlog.log"
            args.enrichment_detail_file = f"{tmp}/enrichment-detail.log"
            stdout = io.StringIO()
            with patch("ona_auditlog.cli.Gitpod", lambda **kwargs: FakeClient(entries, **kwargs)):
                with redirect_stdout(stdout):
                    poll_audit_logs(args)

            with open(args.log_file, encoding="utf-8") as raw_log:
                raw_lines = [json.loads(line) for line in raw_log]
            with open(args.enrichment_detail_file, encoding="utf-8") as detail_log:
                detail_content = detail_log.read()
                detail_lines = parse_json_stream(detail_content)
            stdout_lines = parse_json_stream(stdout.getvalue())

        self.assertEqual(len(raw_lines), 2)
        self.assertEqual(raw_lines[0]["id"], "audit-2")
        self.assertEqual(raw_lines[1]["id"], "audit-1")
        self.assertEqual(len(stdout_lines), 1)
        self.assertEqual(stdout_lines[0]["auditLog"]["id"], "audit-2")
        self.assertEqual(stdout_lines[0]["auditLog"]["action"], "Environment created")
        self.assertEqual(stdout_lines[0]["enrichment"]["creatorEmail"], "user@example.com")
        self.assertEqual(stdout_lines[0]["enrichment"]["gitRepoUrl"], "https://github.com/acme/example.git")
        self.assertNotIn("agentConversationS3Url", stdout_lines[0]["enrichment"])
        self.assertNotIn("event", stdout_lines[0])
        self.assertEqual([line["kind"] for line in detail_lines], ["environment", "user", "runner"])
        self.assertIn("\n  ", stdout.getvalue())
        self.assertIn("\n  ", detail_content)

    def test_poll_audit_logs_scans_startup_history_pages(self) -> None:
        page_one = [audit_entry(id="audit-2", action="created environment logs token")]
        page_two = [
            audit_entry(
                id="audit-1",
                action="Environment created (identity from cookie:account/user-1)",
            )
        ]
        args = argparse.Namespace(
            host="app.gitpod.io",
            base_url=None,
            api_key=None,
            page_size=100,
            once=True,
            history_minutes=60,
            history_pages=2,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
            log_file="",
            enrichment_detail_file="",
        )

        with tempfile.TemporaryDirectory() as tmp:
            args.log_file = f"{tmp}/auditlog.log"
            args.enrichment_detail_file = f"{tmp}/enrichment-detail.log"
            stdout = io.StringIO()
            with patch("ona_auditlog.cli.Gitpod", lambda **kwargs: FakeClient(pages=[page_one, page_two], **kwargs)):
                with redirect_stdout(stdout):
                    poll_audit_logs(args)

            stdout_lines = parse_json_stream(stdout.getvalue())

        self.assertEqual(len(stdout_lines), 1)
        self.assertEqual(stdout_lines[0]["auditLog"]["id"], "audit-1")

    def test_enrich_entry_can_use_cached_environment_for_deleted_event(self) -> None:
        cached_environment = {
            "id": "env-1",
            "metadata": {
                "runnerId": "runner-1",
                "creator": {"id": "user-1", "principal": "PRINCIPAL_USER"},
            },
            "status": {"content": {"git": {"cloneUrl": "https://github.com/acme/cached.git"}}},
        }
        enriched = enrich_entry(
            FakeClientWithDeletedEnvironment(),
            audit_entry(action="Environment deleted"),
            "environment.deleted",
            environment_cache={"env-1": cached_environment},
        )

        record = stdout_record(enriched)

        self.assertEqual(record["enrichment"]["creatorEmail"], "user@example.com")
        self.assertEqual(record["enrichment"]["gitRepoUrl"], "https://github.com/acme/cached.git")
        self.assertNotIn("agentConversationS3Url", record["enrichment"])

    def test_recent_from_time_formats_utc_timestamp(self) -> None:
        self.assertEqual(
            recent_from_time(15, now=datetime(2026, 1, 1, 12, 30, 45, tzinfo=timezone.utc)),
            "2026-01-01T12:15:45Z",
        )

    def test_recent_from_time_rejects_negative_history(self) -> None:
        with self.assertRaisesRegex(ValueError, "--history-minutes"):
            recent_from_time(-1)

    def test_audit_log_filter_defaults_to_recent_history(self) -> None:
        args = argparse.Namespace(
            history_minutes=60,
            history_pages=3,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        self.assertEqual(
            audit_log_filter(args, now=datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)),
            {"from": "2026-01-01T11:00:00Z"},
        )

    def test_audit_log_filter_can_disable_default_history(self) -> None:
        args = argparse.Namespace(
            history_minutes=0,
            history_pages=3,
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
            history_minutes=60,
            history_pages=3,
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
            history_minutes=0,
            history_pages=3,
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
            history_minutes=0,
            history_pages=3,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        with self.assertRaisesRegex(ValueError, "--page-size"):
            audit_log_list_kwargs(args)

    def test_audit_log_list_kwargs_rejects_invalid_history_pages(self) -> None:
        args = argparse.Namespace(
            page_size=100,
            history_minutes=0,
            history_pages=0,
            from_time=None,
            to_time=None,
            actor_id=[],
            actor_principal=[],
            subject_id=[],
            subject_type=[],
        )
        with self.assertRaisesRegex(ValueError, "--history-pages"):
            audit_log_list_kwargs(args)


if __name__ == "__main__":
    unittest.main()
