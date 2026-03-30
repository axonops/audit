# CRUD API Example

A complete REST API with Postgres, five audit outputs, Prometheus
metrics, HTTP middleware, lifecycle events, and graceful shutdown.

This is the capstone example: it demonstrates every major go-audit
feature in a realistic application.

## What You'll Learn

- YAML taxonomy with `audit-gen` code generation
- Five named outputs with routing and per-output formatting
- HTTP audit middleware with `EventBuilder` and `Hints`
- API key authentication that emits `auth_failure` events
- Prometheus metrics implementing all four metrics interfaces
- Lifecycle events (`EmitStartup`, automatic shutdown)
- Graceful shutdown with signal handling

## Prerequisites

- Go 1.26+
- Docker and Docker Compose (for Postgres, syslog-ng, webhook receiver)
- Completed: all previous examples

## Files

| File | Purpose |
|------|---------|
| `main.go` | Entry point, signal handling, graceful shutdown |
| `server.go` | HTTP mux, middleware wiring, EventBuilder |
| `handlers.go` | CRUD handlers for `/items` |
| `auth.go` | API key middleware, auth_failure events |
| `audit_setup.go` | Five named outputs with routing and formatters |
| `db.go` | Postgres connection and queries |
| `metrics.go` | Prometheus metrics for all four interfaces |
| `taxonomy.yaml` | Audit event definitions |
| `audit_generated.go` | Generated constants (committed) |
| `docker-compose.yml` | Postgres, syslog-ng, webhook receiver |

## Run It

```bash
# Start infrastructure:
docker compose up -d

# Wait for Postgres:
docker compose exec postgres pg_isready -U demo -d audit_demo

# Run the API:
go run .

# In another terminal, make requests:
# List items (empty):
curl -s -H "X-API-Key: key-alice" http://localhost:8080/items | jq .

# Create an item:
curl -s -X POST -H "X-API-Key: key-alice" \
  -H "Content-Type: application/json" \
  -d '{"name":"widget","description":"A useful widget"}' \
  http://localhost:8080/items | jq .

# Read the item (replace ID with the one returned above):
curl -s -H "X-API-Key: key-bob" http://localhost:8080/items/{id} | jq .

# Update the item:
curl -s -X PUT -H "X-API-Key: key-alice" \
  -H "Content-Type: application/json" \
  -d '{"name":"updated-widget","description":"An improved widget"}' \
  http://localhost:8080/items/{id} | jq .

# Delete the item:
curl -s -X DELETE -H "X-API-Key: key-admin" \
  http://localhost:8080/items/{id}

# Auth failure (invalid key):
curl -s -H "X-API-Key: bad-key" http://localhost:8080/items

# Health check (no audit event):
curl -s http://localhost:8080/healthz

# Prometheus metrics:
curl -s http://localhost:8080/metrics | grep audit_

# Stop with Ctrl+C — watch for startup/shutdown events in stdout.

# Tear down:
docker compose down -v
```

## Expected Output

On stdout you will see JSON audit events for every operation:

```json
{"timestamp":"...","event_type":"startup","app_name":"crud-api","version":"0.1.0"}
{"timestamp":"...","event_type":"item_list","actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"item_create","actor_id":"alice","outcome":"success","target_id":"..."}
{"timestamp":"...","event_type":"item_read","actor_id":"bob","outcome":"success","target_id":"..."}
{"timestamp":"...","event_type":"item_update","actor_id":"alice","outcome":"success","target_id":"..."}
{"timestamp":"...","event_type":"item_delete","actor_id":"admin","outcome":"success","target_id":"..."}
{"timestamp":"...","event_type":"auth_failure","actor_id":"bad-key","outcome":"failure","reason":"invalid API key"}
{"timestamp":"...","event_type":"shutdown","app_name":"crud-api"}
```

Additional outputs:
- `audit.log` — all events except reads (JSON)
- `admin-audit.log` — admin events only (CEF format)
- Syslog on TCP 5514 — security events only
- Webhook on HTTP 8081 — all events

## What's Happening

### Five Outputs

| Output | Route | Formatter | Purpose |
|--------|-------|-----------|---------|
| stdout | all events | JSON | Development visibility |
| `audit.log` | exclude read | JSON | Persistent audit trail |
| `admin-audit.log` | admin only | CEF | SIEM-compatible admin log |
| syslog TCP :5514 | security only | JSON | Central security logging |
| webhook HTTP :8081 | all events | JSON | External SIEM forwarding |

### Metrics

`metrics.go` implements all four interfaces with a single struct:
- `audit.Metrics` (7 methods) — core pipeline metrics
- `file.Metrics` — file rotation tracking
- `syslog.Metrics` — syslog reconnection tracking
- `webhook.Metrics` — webhook drop and flush tracking

The `/metrics` endpoint exposes Prometheus-format counters and histograms.

### Authentication

The `auth.go` middleware validates `X-API-Key` headers against a
hardcoded user map. Invalid keys return 401 and emit an `auth_failure`
audit event. Valid keys populate `Hints.ActorID` for the audit
middleware.

### Lifecycle

- `EmitStartup` on boot records the application name and version
- `logger.Close()` automatically emits a shutdown event
- SIGINT/SIGTERM triggers graceful HTTP shutdown, then logger close

## Previous

[Middleware](../middleware/) -- the HTTP middleware fundamentals.
