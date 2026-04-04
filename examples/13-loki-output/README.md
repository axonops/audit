# Example 13: Loki Output

Sends audit events to [Grafana Loki](https://grafana.com/oss/loki/)
with stream labels, gzip compression, and batched delivery.

## What This Demonstrates

- **Stream labels** — events are grouped by `event_type`, `severity`,
  `event_category`, `app_name`, and `host`. Each unique combination
  creates a separate Loki stream, queryable via LogQL.
- **Static labels** — constant labels (`job`, `environment`) appear
  on every stream for filtering and dashboarding.
- **Dynamic label exclusion** — `pid` is excluded from labels to
  avoid high cardinality in development.
- **Gzip compression** — push payloads are compressed by default.
- **YAML-driven config** — the Loki output is configured entirely
  via `outputs.yaml`, loaded by `outputconfig.Load`.

## Prerequisites

Start a local Loki instance:

```bash
docker run -d --name loki -p 3100:3100 grafana/loki:3.0.0
```

## Running

```bash
go run .
```

Output:

```
Audited: user_create by alice
Audited: user_create by bob
Audited: auth_failure by mallory
Audited: permission_denied by mallory
Audited: user_update by alice

Waiting for Loki delivery...
Done. Query your events:
  curl -s 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=10' | jq .
  curl -s 'http://localhost:3100/loki/api/v1/query_range?query={event_type="auth_failure"}&limit=10' | jq .
```

## Querying Events

### All events by job label

```bash
curl -s 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}&limit=20' | jq '.data.result[].values[][1]' -r | jq .
```

### Security events only

```bash
curl -s 'http://localhost:3100/loki/api/v1/query_range?query={event_type="auth_failure"}&limit=10' | jq '.data.result[].values[][1]' -r | jq .
```

### Filter by actor in the log line

```bash
curl -s 'http://localhost:3100/loki/api/v1/query_range?query={job="audit-example"}|="mallory"&limit=10' | jq '.data.result[].values[][1]' -r | jq .
```

## Configuration Reference

See [`outputs.yaml`](outputs.yaml) for the complete configuration.
Key fields:

| Field | Default | Description |
|-------|---------|-------------|
| `url` | (required) | Full Loki push API URL |
| `tenant_id` | (empty) | `X-Scope-OrgID` for multi-tenancy |
| `batch_size` | 100 | Events per push request |
| `max_batch_bytes` | 1 MiB | Max uncompressed payload size |
| `flush_interval` | "5s" | Max time between pushes |
| `gzip` | true | Gzip compress push requests |
| `labels.static` | (empty) | Constant labels on every stream |
| `labels.dynamic` | all true | Per-event label toggles |

## How Stream Labels Work

Every event gets stream labels derived from three sources:

1. **Static labels** from config: `job="audit-example"`,
   `environment="development"`
2. **Framework fields** from the logger: `app_name="audit-example"`,
   `host="dev-machine"`
3. **Per-event metadata**: `event_type="user_create"`,
   `severity="5"`, `event_category="write"`

Events with the same label values are grouped into the same Loki
stream. Different `event_type` or `severity` values create separate
streams, each independently queryable.

## Cleanup

```bash
docker stop loki && docker rm loki
```
