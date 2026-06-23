# ona-auditlog

Demo Python app that polls Ona audit logs, writes the full raw stream to
`auditlog.log`, writes full enrichment fetch responses to
`enrichment-detail.log`, and writes formatted relevant audit log entries with
their enrichment to stdout.

## Setup

Install the app and the Ona SDK dependency:

```bash
python -m pip install -e .
```

Authentication uses `GITPOD_API_KEY` by default:

```bash
export GITPOD_API_KEY="<your-api-key>"
```

You can also pass an API key directly:

```bash
ona-auditlog --api-key "<your-api-key>"
```

## Run

Poll audit logs from the default host, `app.gitpod.io`:

```bash
ona-auditlog
```

By default, the first request includes the last 60 minutes of audit log history
and scans up to 3 pages so stdout and the log files have initial content.
Change or disable that lookback with:

```bash
ona-auditlog --history-minutes 15
ona-auditlog --history-pages 5
ona-auditlog --history-minutes 0
```

Use a different Ona host:

```bash
ona-auditlog --host staging.gitpod.io
```

Use a full API URL for nonstandard deployments:

```bash
ona-auditlog --base-url https://ona.example.com/api
```

Fetch one page and exit:

```bash
ona-auditlog --once
```

Write the full raw audit log stream to a different file:

```bash
ona-auditlog --log-file /tmp/auditlog.log
```

Write full enrichment fetch responses to a different file:

```bash
ona-auditlog --enrichment-detail-file /tmp/enrichment-detail.log
```

Filter audit logs by subject, actor, or creation time:

```bash
ona-auditlog \
  --subject-type RESOURCE_TYPE_ENVIRONMENT \
  --subject-id <environment-id> \
  --actor-principal PRINCIPAL_USER \
  --from 2026-01-01T00:00:00Z
```

When `--from` is set explicitly, it overrides the default history lookback.

## Output

Every received SDK audit log entry is serialized to compact JSON and appended
to `auditlog.log`. Full JSON objects fetched to enrich stdout events are
appended as formatted JSON to `enrichment-detail.log`. Entries already seen in
the current process are suppressed on later polls.

Stdout only receives these events:

- environment created or deleted
- environment started or stopped
- agent execution started

For each matching event, stdout includes all values from the relevant audit log
entry plus a clearly separated `enrichment` object containing:

- creator email
- git repository URL
- S3 streamstore prefix for the agent conversation, only for agent execution events

```json
{
  "auditLog": {
    "action": "started environment",
    "actorId": "user-uuid",
    "actorPrincipal": "PRINCIPAL_USER",
    "createdAt": "2026-01-01T00:00:00Z",
    "id": "audit-log-id",
    "subjectId": "env-uuid",
    "subjectType": "RESOURCE_TYPE_ENVIRONMENT"
  },
  "enrichment": {
    "creatorEmail": "user@example.com",
    "gitRepoUrl": "https://github.com/example/repo.git"
  }
}
```
