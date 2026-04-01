# CRUD API Example

A complete REST API with Postgres, five audit outputs, Prometheus
metrics, HTTP middleware, lifecycle events, and graceful shutdown.

This is the capstone example: it demonstrates every major go-audit
feature in a realistic application, with all five outputs configured
in `outputs.yaml`.

## What You'll Learn

- Configuring outputs with routing, formatting, and env vars in YAML
- Wiring Prometheus metrics into the audit pipeline
- Using HTTP middleware with authentication and domain hints
- Lifecycle events (startup and shutdown)
- Graceful shutdown ordering

## Prerequisites

- Go 1.26+
- Docker and Docker Compose (for Postgres, syslog-ng, webhook receiver)
- Completed: all previous examples

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Audit event definitions (embedded in binary) |
| `outputs.yaml` | Five outputs with routing, formatting, env vars |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Entry point, signal handling, graceful shutdown |
| `audit_setup.go` | Loads output config, wires metrics factories |
| `server.go` | HTTP mux, middleware wiring, EventBuilder |
| `handlers.go` | CRUD handlers for `/items` |
| `auth.go` | API key middleware, auth failure events |
| `db.go` | Postgres connection and queries |
| `metrics.go` | Prometheus metrics for all four interfaces |
| `docker-compose.yml` | Postgres, syslog-ng, webhook receiver |

## Key Concepts

### Output Configuration

All five outputs are configured in `outputs.yaml`:

```yaml
version: 1
outputs:
  console:
    type: stdout

  audit_log:
    type: file
    file:
      path: "${AUDIT_LOG_PATH:-./audit.log}"
      max_size_mb: 100
      max_backups: 5
      permissions: "0600"
    route:
      exclude_categories:
        - read

  admin_log:
    type: file
    file:
      path: "${ADMIN_LOG_PATH:-./admin-audit.log}"
      max_size_mb: 50
      permissions: "0600"
    route:
      include_categories:
        - admin
    formatter:
      type: cef
      vendor: "AxonOps"
      product: "CRUDExample"
      version: "0.1.0"

  syslog_security:
    type: syslog
    syslog:
      network: tcp
      address: "${SYSLOG_ADDR:-localhost:5514}"
      app_name: crud-api
    route:
      include_categories:
        - security

  webhook_siem:
    type: webhook
    webhook:
      url: "${WEBHOOK_URL:-http://localhost:8081/events}"
      batch_size: 50
      flush_interval: "5s"
      timeout: "10s"
      max_retries: 3
      allow_insecure_http: true   # dev only — use HTTPS in production
      allow_private_ranges: true  # dev only — localhost webhook receiver
    route:
      min_severity: 7
```

| Output | Route | Format | Purpose |
|--------|-------|--------|---------|
| console | all events | JSON | Development visibility |
| audit_log | exclude read | JSON | Persistent audit trail |
| admin_log | admin only | CEF | SIEM-compatible admin log |
| syslog_security | security only | JSON | Central security logging |
| webhook_siem | severity >= 7 | JSON | High-severity alerts to SIEM |

### Environment Variables

Output configs support `${VAR:-default}` syntax:

```yaml
path: "${AUDIT_LOG_PATH:-./audit.log}"
address: "${SYSLOG_ADDR:-localhost:5514}"
```

The defaults work for local development with Docker Compose. In
production, set `SYSLOG_ADDR` and `WEBHOOK_URL` to your real
infrastructure.

### Wiring Prometheus Metrics

go-audit defines four metrics interfaces. The library does not import
Prometheus — your application brings its own implementation. A single
struct can implement all four:

```go
type auditMetrics struct {
    events           *prometheus.CounterVec   // audit.Metrics (7 methods)
    fileRotations    *prometheus.CounterVec   // file.Metrics
    syslogReconnects *prometheus.CounterVec   // syslog.Metrics
    webhookDrops     prometheus.Counter       // webhook.Metrics
    // ...
}
```

To track per-output-type metrics (file rotation, syslog reconnection,
webhook flush timing), register custom factories before loading the
output config:

```go
import (
    "github.com/axonops/go-audit/file"       // named import — calling file.NewFactory
    "github.com/axonops/go-audit/syslog"
    "github.com/axonops/go-audit/webhook"
)

audit.RegisterOutputFactory("file", file.NewFactory(m))
audit.RegisterOutputFactory("syslog", syslog.NewFactory(m))
audit.RegisterOutputFactory("webhook", webhook.NewFactory(m))

result, err := outputconfig.Load(outputsYAML, &tax, m)
```

Note the **named imports** here — not blank imports. In earlier examples,
you used `_ "github.com/axonops/go-audit/file"` (blank import) which
registers a default factory without metrics. Here, the named import lets
you call `file.NewFactory(m)` to register a factory that captures your
metrics implementation.

Your metrics struct needs to implement these interfaces:

| Interface | Methods | What it tracks |
|-----------|---------|----------------|
| `audit.Metrics` | 7 methods | Events emitted, validation errors, buffer drops |
| `file.Metrics` | `RecordFileRotation(path)` | Log file rotation |
| `syslog.Metrics` | `RecordSyslogReconnect(addr, success)` | Syslog reconnections |
| `webhook.Metrics` | `RecordWebhookDrop()`, `RecordWebhookFlush(batchSize, dur)` | Webhook delivery |

The `/metrics` endpoint exposes standard Prometheus counters.

### Authentication and Audit Hints

Auth and audit middleware are composed as layers:

```go
authed := authMiddleware()(mux)
audited := audit.Middleware(logger, buildAuditEvent)(authed)
```

When authentication fails, the auth middleware sets
`Hints.EventType = "auth_failure"` and returns 401 — the audit
middleware automatically emits the failure event. When authentication
succeeds, it sets `Hints.ActorID` so the audit event records who made
the request.

Neither the auth middleware nor the handlers need a direct reference to
the audit logger.

### Lifecycle Events

```go
logger.EmitStartup(audit.Fields{
    FieldAppName: "crud-api",
    FieldVersion: "0.1.0",
})
```

`EmitStartup` records that the application started. When `Close()` is
called, a corresponding shutdown event is emitted automatically. These
prove the audit system was active during the entire application
lifetime.

### Graceful Shutdown

The shutdown sequence matters: stop the HTTP server first (so no new
requests generate events), then close the logger (which flushes all
buffered events and emits the shutdown event).

```go
<-done  // wait for SIGINT/SIGTERM
srv.Shutdown(ctx)    // stop HTTP
logger.Close()       // flush audit, emit shutdown
```

## Run It

```bash
# Start infrastructure:
docker compose up -d

# Wait for Postgres:
docker compose exec postgres pg_isready -U demo -d audit_demo

# Run the API:
go run .

# In another terminal:
# List items:
curl -s -H "X-API-Key: key-alice" http://localhost:8080/items | jq .

# Create an item:
curl -s -X POST -H "X-API-Key: key-alice" \
  -H "Content-Type: application/json" \
  -d '{"name":"widget","description":"A useful widget"}' \
  http://localhost:8080/items | jq .

# Read an item (replace {id} with the ID from create):
curl -s -H "X-API-Key: key-bob" http://localhost:8080/items/{id} | jq .

# Update an item:
curl -s -X PUT -H "X-API-Key: key-alice" \
  -H "Content-Type: application/json" \
  -d '{"name":"updated-widget","description":"An improved widget"}' \
  http://localhost:8080/items/{id} | jq .

# Delete an item:
curl -s -X DELETE -H "X-API-Key: key-alice" \
  http://localhost:8080/items/{id}

# Auth failure:
curl -s -H "X-API-Key: bad-key" http://localhost:8080/items

# Prometheus metrics:
curl -s http://localhost:8080/metrics | grep audit_

# Stop with Ctrl+C, then:
docker compose down -v
```

## Expected Output

On stdout you'll see JSON audit events:

```json
{"timestamp":"...","event_type":"startup","severity":6,"app_name":"crud-api","version":"0.1.0"}
{"timestamp":"...","event_type":"item_list","severity":2,"actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"item_create","severity":4,"actor_id":"alice","outcome":"success","target_id":"..."}
{"timestamp":"...","event_type":"auth_failure","severity":9,"actor_id":"bad-key","outcome":"failure","reason":"invalid API key"}
{"timestamp":"...","event_type":"shutdown","severity":7,"app_name":"crud-api"}
```

Additional outputs:
- `audit.log` — all events except reads (JSON)
- `admin-audit.log` — admin events only (CEF format)
- Syslog on TCP 5514 — security events only
- Webhook receiver — high-severity events (severity >= 7)

## Previous

[Middleware](../08-middleware/) — the HTTP middleware fundamentals.

## Next

[Testing](../10-testing/) — testing audit events with `audittest`.
