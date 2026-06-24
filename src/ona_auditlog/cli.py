from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gitpod import Gitpod

from ona_auditlog.enrichment import AuditLogEnricher, Enrichment, attr, to_payload

DEFAULT_HOST = "app.gitpod.io"
DEFAULT_LOG_FILE = "auditlog.log"
DEFAULT_ENRICHMENT_DETAIL_FILE = "enrichment-detail.log"
DEFAULT_HISTORY_MINUTES = 60.0
DEFAULT_HISTORY_PAGES = 3

ENVIRONMENT_ACTION_PREFIXES = (
    ("Environment created", "environment.created"),
    ("Environment deleted", "environment.deleted"),
    ("marked for deletion", "environment.deleted"),
    ("force deleted environment", "environment.deleted"),
    ("started environment", "environment.started"),
    ("stopped environment", "environment.stopped"),
)
AGENT_EXECUTION_ACTION_PREFIXES = (("AgentExecution created", "agent_execution.started"),)


# CLI setup


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
        "--history-minutes",
        type=float,
        default=DEFAULT_HISTORY_MINUTES,
        help=(
            "When --from is not set, fetch this many minutes of recent audit log history. "
            f"Defaults to {DEFAULT_HISTORY_MINUTES:g}. Use 0 to disable."
        ),
    )
    parser.add_argument(
        "--history-pages",
        type=int,
        default=DEFAULT_HISTORY_PAGES,
        help=(
            "Number of audit log pages to scan on the first fetch when history is enabled. "
            f"Defaults to {DEFAULT_HISTORY_PAGES}."
        ),
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


# JSON helpers


def compact_json(value: Any) -> str:
    return json.dumps(to_payload(value), sort_keys=True, separators=(",", ":"))


def formatted_json(value: Any) -> str:
    return json.dumps(to_payload(value), indent=2, sort_keys=True)


def append_formatted_json(file, value: Any) -> None:
    file.write(formatted_json(value))
    file.write("\n")


# Audit-log selection


def relevant_event_kind(entry: Any) -> str | None:
    subject_type = attr(entry, "subject_type")
    action = attr(entry, "action") or ""
    if subject_type == "RESOURCE_TYPE_ENVIRONMENT":
        for prefix, kind in ENVIRONMENT_ACTION_PREFIXES:
            if action.startswith(prefix):
                return kind
    if subject_type == "RESOURCE_TYPE_AGENT_EXECUTION":
        for prefix, kind in AGENT_EXECUTION_ACTION_PREFIXES:
            if action.startswith(prefix):
                return kind
    return None


def stdout_record(audit_log: Any, enrichment: Enrichment) -> dict[str, Any]:
    return {
        "auditLog": to_payload(audit_log),
        "enrichment": enrichment.to_payload(),
    }


# Audit-log polling


def recent_from_time(history_minutes: float, now: datetime | None = None) -> str | None:
    if history_minutes < 0:
        raise ValueError("--history-minutes must not be negative")
    if history_minutes == 0:
        return None

    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    recent = now.astimezone(timezone.utc) - timedelta(minutes=history_minutes)
    return recent.isoformat(timespec="seconds").replace("+00:00", "Z")


def audit_log_filter(args: argparse.Namespace, now: datetime | None = None) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    if args.from_time:
        filters["from"] = args.from_time
    else:
        from_time = recent_from_time(getattr(args, "history_minutes", DEFAULT_HISTORY_MINUTES), now=now)
        if from_time:
            filters["from"] = from_time
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
    if args.history_pages < 1:
        raise ValueError("--history-pages must be greater than zero")

    kwargs: dict[str, Any] = {
        "page_size": args.page_size,
        "sort": {"field": "createdAt", "order": "SORT_ORDER_DESC"},
    }
    filters = audit_log_filter(args)
    if filters:
        kwargs["filter"] = filters
    return kwargs


def page_next_token(page: Any) -> str | None:
    pagination = attr(page, "pagination")
    return attr(pagination, "next_token") or attr(pagination, "nextToken")


def list_audit_log_pages(client: Gitpod, list_kwargs: dict[str, Any], page_count: int) -> list[list[Any]]:
    pages: list[list[Any]] = []
    token: str | None = None

    for _ in range(page_count):
        kwargs = dict(list_kwargs)
        if token:
            kwargs["token"] = token

        page = client.events.list(**kwargs)
        pages.append(list(page.entries))
        token = page_next_token(page)
        if not token:
            break

    return pages


def poll_audit_logs(args: argparse.Namespace) -> None:
    base_url = args.base_url.rstrip("/") if args.base_url else build_base_url(args.host)
    client = Gitpod(bearer_token=args.api_key, base_url=base_url)
    enricher = AuditLogEnricher(client)
    list_kwargs = audit_log_list_kwargs(args)
    seen_ids: set[str] = set()
    log_file = Path(args.log_file)
    enrichment_detail_file = Path(args.enrichment_detail_file)
    first_fetch = True

    while True:
        history_enabled = not args.from_time and args.history_minutes > 0
        page_count = args.history_pages if first_fetch and history_enabled else 1
        pages = list_audit_log_pages(client, list_kwargs, page_count)
        new_entries = []

        for entries in pages:
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

                for detail in enricher.prime_from_audit_log(entry):
                    append_formatted_json(detail_log, detail)

                kind = relevant_event_kind(entry)
                if kind is None:
                    continue

                result = enricher.enrich(entry, kind)
                for detail in result.details:
                    append_formatted_json(detail_log, detail)

                record = stdout_record(entry, result.enrichment)
                print(formatted_json(record), flush=True)

        first_fetch = False

        if args.once:
            return

        time.sleep(args.interval)


# Entrypoint


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
