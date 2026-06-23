from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gitpod import Gitpod

DEFAULT_HOST = "app.gitpod.io"
DEFAULT_LOG_FILE = "auditlog.log"
DEFAULT_ENRICHMENT_DETAIL_FILE = "enrichment-detail.log"

ENVIRONMENT_EVENTS = {
    ("RESOURCE_TYPE_ENVIRONMENT", "Environment created"): "environment.created",
    ("RESOURCE_TYPE_ENVIRONMENT", "Environment deleted"): "environment.deleted",
    ("RESOURCE_TYPE_ENVIRONMENT", "marked for deletion"): "environment.deleted",
    ("RESOURCE_TYPE_ENVIRONMENT", "force deleted environment"): "environment.deleted",
    ("RESOURCE_TYPE_ENVIRONMENT", "started environment"): "environment.started",
    ("RESOURCE_TYPE_ENVIRONMENT", "stopped environment"): "environment.stopped",
}
AGENT_EXECUTION_EVENTS = {
    ("RESOURCE_TYPE_AGENT_EXECUTION", "AgentExecution created"): "agent_execution.started",
}


def build_base_url(host: str) -> str:
    host = host.strip().rstrip("/")
    if not host:
        raise ValueError("host must not be empty")

    if "://" not in host:
        host = f"https://{host}"

    parsed = urlsplit(host)
    path = parsed.path.rstrip("/")
    if not path:
        path = "/api"
    elif not path.endswith("/api"):
        path = f"{path}/api"

    return urlunsplit((parsed.scheme, parsed.netloc, path, "", ""))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Poll Ona audit logs, append all entries to auditlog.log, "
            "append enrichment fetches to enrichment-detail.log, and print relevant audit entries with enrichment."
        ),
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Ona host to connect to. Defaults to {DEFAULT_HOST}.",
    )
    parser.add_argument(
        "--base-url",
        help="Full Ona API base URL. Overrides --host when set.",
    )
    parser.add_argument(
        "--api-key",
        help="Ona API key. Defaults to the GITPOD_API_KEY environment variable.",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5.0,
        help="Seconds to wait between polls. Defaults to 5.",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
        help="Maximum audit log entries to fetch per poll. Defaults to 100.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Fetch one page of audit log entries and exit.",
    )
    parser.add_argument(
        "--log-file",
        default=DEFAULT_LOG_FILE,
        help=f"File to append the full raw audit log stream to. Defaults to {DEFAULT_LOG_FILE}.",
    )
    parser.add_argument(
        "--enrichment-detail-file",
        default=DEFAULT_ENRICHMENT_DETAIL_FILE,
        help=(
            "File to append full JSON objects fetched for stdout enrichment to. "
            f"Defaults to {DEFAULT_ENRICHMENT_DETAIL_FILE}."
        ),
    )
    parser.add_argument(
        "--from",
        dest="from_time",
        help="Only fetch entries created at or after this RFC3339 timestamp.",
    )
    parser.add_argument(
        "--to",
        dest="to_time",
        help="Only fetch entries created at or before this RFC3339 timestamp.",
    )
    parser.add_argument(
        "--actor-id",
        action="append",
        default=[],
        help="Filter by actor ID. May be provided multiple times.",
    )
    parser.add_argument(
        "--actor-principal",
        action="append",
        default=[],
        help="Filter by actor principal. May be provided multiple times.",
    )
    parser.add_argument(
        "--subject-id",
        action="append",
        default=[],
        help="Filter by subject ID. May be provided multiple times.",
    )
    parser.add_argument(
        "--subject-type",
        action="append",
        default=[],
        help="Filter by subject resource type. May be provided multiple times.",
    )
    return parser.parse_args(argv)


def to_payload(value: Any) -> Any:
    if value is None:
        return None

    if isinstance(value, dict):
        return {key: to_payload(item) for key, item in value.items()}

    if isinstance(value, list):
        return [to_payload(item) for item in value]

    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)

    if hasattr(value, "dict"):
        return value.dict(by_alias=True)

    if hasattr(value, "__dict__"):
        return {key: to_payload(item) for key, item in vars(value).items()}

    return value


def compact_json(value: Any) -> str:
    return json.dumps(to_payload(value), sort_keys=True, separators=(",", ":"))


def formatted_json(value: Any) -> str:
    return json.dumps(to_payload(value), indent=2, sort_keys=True)


def append_formatted_json(file, value: Any) -> None:
    file.write(formatted_json(value))
    file.write("\n")


def attr(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


def relevant_event_kind(entry: Any) -> str | None:
    key = (attr(entry, "subject_type"), attr(entry, "action"))
    if key in ENVIRONMENT_EVENTS:
        return ENVIRONMENT_EVENTS[key]
    if key in AGENT_EXECUTION_EVENTS:
        return AGENT_EXECUTION_EVENTS[key]
    return None


def user_enrichment(client: Gitpod, user_id: str | None) -> dict[str, Any] | None:
    if not user_id:
        return None

    response = client.users.get_user(user_id=user_id)
    return to_payload(response.user)


def environment_enrichment(client: Gitpod, environment_id: str | None) -> dict[str, Any] | None:
    if not environment_id:
        return None

    response = client.environments.retrieve(environment_id=environment_id)
    return to_payload(response.environment)


def agent_execution_enrichment(client: Gitpod, agent_execution_id: str | None) -> dict[str, Any] | None:
    if not agent_execution_id:
        return None

    response = client.agents.retrieve_execution(agent_execution_id=agent_execution_id)
    return to_payload(response.agent_execution)


def runner_enrichment(client: Gitpod, runner_id: str | None) -> dict[str, Any] | None:
    if not runner_id:
        return None

    response = client.runners.retrieve(runner_id=runner_id)
    return to_payload(response.runner)


def write_detail(details: list[dict[str, Any]], kind: str, detail: dict[str, Any] | None) -> None:
    if detail is None:
        return
    details.append({"kind": kind, "object": detail})


def environment_ids_from_agent_execution(agent_execution: dict[str, Any] | None) -> list[str]:
    if not agent_execution:
        return []

    environment_ids: list[str] = []
    status = agent_execution.get("status") or {}
    for used_environment in status.get("usedEnvironments") or status.get("used_environments") or []:
        environment_id = used_environment.get("environmentId") or used_environment.get("environment_id")
        if environment_id:
            environment_ids.append(environment_id)

    spec = agent_execution.get("spec") or {}
    code_context = spec.get("codeContext") or spec.get("code_context") or {}
    for key in ("environmentId", "baseEnvironmentId"):
        environment_id = code_context.get(key)
        if environment_id:
            environment_ids.append(environment_id)
    for key in ("environment_id", "base_environment_id"):
        environment_id = code_context.get(key)
        if environment_id:
            environment_ids.append(environment_id)

    return list(dict.fromkeys(environment_ids))


def git_repo_url(environment: dict[str, Any] | None) -> str | None:
    if not environment:
        return None

    status_git = (((environment.get("status") or {}).get("content") or {}).get("git") or {})
    clone_url = status_git.get("cloneUrl") or status_git.get("clone_url")
    if clone_url:
        return clone_url

    initializer = (((environment.get("spec") or {}).get("content") or {}).get("initializer") or {})
    for spec in initializer.get("specs") or []:
        git = spec.get("git") or {}
        remote_uri = git.get("remoteUri") or git.get("remote_uri")
        if remote_uri:
            return remote_uri

    return None


def runner_id_from_environment(environment: dict[str, Any] | None) -> str | None:
    if not environment:
        return None
    metadata = environment.get("metadata") or {}
    return metadata.get("runnerId") or metadata.get("runner_id")


def nested_get(value: dict[str, Any] | None, *keys: str) -> Any:
    current: Any = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def first_s3_url(value: Any) -> str | None:
    if isinstance(value, str):
        if value.startswith("s3://"):
            return value
        return None

    if isinstance(value, dict):
        for item in value.values():
            result = first_s3_url(item)
            if result:
                return result

    if isinstance(value, list):
        for item in value:
            result = first_s3_url(item)
            if result:
                return result

    return None


def conversation_s3_url(agent_execution: dict[str, Any] | None, runner: dict[str, Any] | None = None) -> str | None:
    if not agent_execution:
        return None

    for candidate in (
        nested_get(agent_execution, "status", "conversationUrl"),
        nested_get(agent_execution, "status", "conversation_url"),
        nested_get(agent_execution, "status", "conversationUrls", "history"),
        nested_get(agent_execution, "status", "conversation_urls", "history"),
    ):
        if isinstance(candidate, str) and candidate.startswith("s3://"):
            return candidate

    execution_id = agent_execution.get("id")
    if not execution_id:
        return None

    bucket_url = first_s3_url(runner)
    if not bucket_url:
        return None

    bucket = bucket_url.removeprefix("s3://").split("/", 1)[0]
    if not bucket:
        return None

    return f"s3://{bucket}/conversations/{execution_id}/chunks/"


def creator_user_id(resource: dict[str, Any] | None) -> str | None:
    if not resource:
        return None

    metadata = resource.get("metadata") or {}
    creator = metadata.get("creator") or {}
    if creator.get("principal") != "PRINCIPAL_USER":
        return None
    return creator.get("id")


def set_user_if_missing(client: Gitpod, record: dict[str, Any], user_id: str | None) -> None:
    if record.get("user") is not None or not user_id:
        return

    try:
        user = user_enrichment(client, user_id)
        record["user"] = user
        write_detail(record["details"], "user", user)
    except Exception as exc:
        record["errors"].append(f"failed to fetch creator user {user_id}: {exc}")


def set_runner_if_missing(client: Gitpod, record: dict[str, Any], runner_id: str | None) -> None:
    if record.get("runner") is not None or not runner_id:
        return

    try:
        runner = runner_enrichment(client, runner_id)
        record["runner"] = runner
        write_detail(record["details"], "runner", runner)
    except Exception as exc:
        record["errors"].append(f"failed to fetch runner {runner_id}: {exc}")


def enrich_entry(client: Gitpod, entry: Any, kind: str) -> dict[str, Any]:
    subject_id = attr(entry, "subject_id")
    subject_type = attr(entry, "subject_type")
    actor_id = attr(entry, "actor_id")
    actor_principal = attr(entry, "actor_principal")
    record: dict[str, Any] = {
        "event": kind,
        "auditLog": to_payload(entry),
        "user": None,
        "environment": None,
        "agentExecution": None,
        "runner": None,
        "details": [],
        "errors": [],
    }

    if actor_principal == "PRINCIPAL_USER":
        try:
            user = user_enrichment(client, actor_id)
            record["user"] = user
            write_detail(record["details"], "user", user)
        except Exception as exc:
            record["errors"].append(f"failed to fetch actor user {actor_id}: {exc}")

    if subject_type == "RESOURCE_TYPE_ENVIRONMENT":
        try:
            environment = environment_enrichment(client, subject_id)
            record["environment"] = environment
            write_detail(record["details"], "environment", environment)
            set_user_if_missing(client, record, creator_user_id(environment))
            set_runner_if_missing(client, record, runner_id_from_environment(environment))
        except Exception as exc:
            record["errors"].append(f"failed to fetch environment {subject_id}: {exc}")

    if subject_type == "RESOURCE_TYPE_AGENT_EXECUTION":
        try:
            agent_execution = agent_execution_enrichment(client, subject_id)
            record["agentExecution"] = agent_execution
            write_detail(record["details"], "agentExecution", agent_execution)
            set_user_if_missing(client, record, creator_user_id(agent_execution))
        except Exception as exc:
            agent_execution = None
            record["errors"].append(f"failed to fetch agent execution {subject_id}: {exc}")

        environments = []
        for environment_id in environment_ids_from_agent_execution(agent_execution):
            try:
                environment = environment_enrichment(client, environment_id)
                environments.append(environment)
                write_detail(record["details"], "environment", environment)
                set_runner_if_missing(client, record, runner_id_from_environment(environment))
            except Exception as exc:
                record["errors"].append(f"failed to fetch agent execution environment {environment_id}: {exc}")
        if environments:
            record["environments"] = environments

    if not record["errors"]:
        del record["errors"]

    return record


def enrichment_projection(enriched: dict[str, Any]) -> dict[str, Any]:
    agent_execution = enriched.get("agentExecution")
    return {
        "userEmail": (enriched.get("user") or {}).get("email"),
        "gitRepoUrl": git_repo_url(enriched.get("environment")),
        "agentConversationS3Url": conversation_s3_url(agent_execution, enriched.get("runner")),
    }


def stdout_record(enriched: dict[str, Any]) -> dict[str, Any]:
    return {
        "auditLog": enriched.get("auditLog"),
        "enrichment": enrichment_projection(enriched),
    }


def audit_log_filter(args: argparse.Namespace) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    if args.from_time:
        filters["from"] = args.from_time
    if args.to_time:
        filters["to"] = args.to_time
    if args.actor_id:
        filters["actor_ids"] = args.actor_id
    if args.actor_principal:
        filters["actor_principals"] = args.actor_principal
    if args.subject_id:
        filters["subject_ids"] = args.subject_id
    if args.subject_type:
        filters["subject_types"] = args.subject_type
    return filters


def audit_log_list_kwargs(args: argparse.Namespace) -> dict[str, Any]:
    if args.page_size < 1:
        raise ValueError("--page-size must be greater than zero")

    kwargs: dict[str, Any] = {
        "page_size": args.page_size,
        "sort": {"field": "createdAt", "order": "SORT_ORDER_DESC"},
    }
    filters = audit_log_filter(args)
    if filters:
        kwargs["filter"] = filters
    return kwargs


def poll_audit_logs(args: argparse.Namespace) -> None:
    base_url = args.base_url.rstrip("/") if args.base_url else build_base_url(args.host)
    client = Gitpod(bearer_token=args.api_key, base_url=base_url)
    list_kwargs = audit_log_list_kwargs(args)
    seen_ids: set[str] = set()
    log_file = Path(args.log_file)
    enrichment_detail_file = Path(args.enrichment_detail_file)

    while True:
        page = client.events.list(**list_kwargs)
        entries = list(page.entries)
        new_entries = []

        for entry in entries:
            entry_id = getattr(entry, "id", None)
            if entry_id is None or entry_id not in seen_ids:
                new_entries.append(entry)
            if entry_id is not None:
                seen_ids.add(entry_id)

        with log_file.open("a", encoding="utf-8") as raw_log, enrichment_detail_file.open(
            "a", encoding="utf-8"
        ) as detail_log:
            for entry in reversed(new_entries):
                raw_log.write(f"{compact_json(entry)}\n")

                kind = relevant_event_kind(entry)
                if kind is None:
                    continue

                enriched = enrich_entry(client, entry, kind)
                for detail in enriched.pop("details"):
                    append_formatted_json(detail_log, detail)

                print(formatted_json(stdout_record(enriched)), flush=True)

        if args.once:
            return

        time.sleep(args.interval)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    try:
        poll_audit_logs(args)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        print(f"ona-auditlog: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
