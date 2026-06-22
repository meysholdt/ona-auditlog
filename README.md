# ona-auditlog

Demo Python app that polls Ona audit logs and writes every received entry
to stdout as one compact JSON object per line.

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

Filter audit logs by subject, actor, or creation time:

```bash
ona-auditlog \
  --subject-type RESOURCE_TYPE_ENVIRONMENT \
  --subject-id <environment-id> \
  --actor-principal PRINCIPAL_USER \
  --from 2026-01-01T00:00:00Z
```

## Output

Each received SDK audit log entry is serialized to JSON and printed
immediately. Entries already printed in the current process are suppressed on
later polls.

```json
{"action":"environment.start","actorId":"user-uuid","actorPrincipal":"PRINCIPAL_USER","createdAt":"2026-01-01T00:00:00Z","id":"audit-log-id","subjectId":"env-uuid","subjectType":"RESOURCE_TYPE_ENVIRONMENT"}
```
