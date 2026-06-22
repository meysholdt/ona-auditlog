from __future__ import annotations

import argparse
import json
import signal
import sys
import time
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from gitpod import Gitpod

DEFAULT_HOST = "app.gitpod.io"


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
        description="Poll Ona audit logs and write each received entry to stdout as JSON.",
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

        for entry in reversed(new_entries):
            print(json.dumps(to_payload(entry), sort_keys=True, separators=(",", ":")), flush=True)

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
