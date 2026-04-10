[← Back to examples](../README.md)

> **Previous:** [15 — Middleware](../15-middleware/) |
> **Next:** [17 — Testing](../17-testing/)

# Example 16: CRUD API

A complete REST API with Postgres, four audit outputs, HMAC integrity,
CEF formatting, PII stripping, Loki dashboards, Prometheus metrics,
HTTP middleware, and graceful shutdown.

This is the capstone example: it demonstrates every major go-audit
feature in a realistic application, with all four outputs configured
in `outputs.yaml`.

## What You'll Learn

- Configuring a 4-output fan-out with HMAC, CEF, routing, and PII stripping
- Wiring Prometheus metrics into the audit pipeline
- Using HTTP middleware with authentication and domain hints
- Grafana dashboards via Loki stream labels
- Graceful shutdown ordering

## Prerequisites

- Go 1.26+
- Docker and Docker Compose (for Postgres, Loki, Grafana)
- Completed: all previous examples

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | 22 event types, 4 categories, sensitivity labels (embedded) |
| `outputs.yaml` | Four outputs with HMAC, CEF, routing, PII stripping |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Entry point, signal handling, graceful shutdown |
| `audit_setup.go` | Loads output config, wires file + Loki metrics factories |
| `server.go` | HTTP mux, middleware wiring, EventBuilder |
| `handlers.go` | CRUD handlers for `/items` |
| `auth.go` | API key middleware, auth failure events |
| `db.go` | Postgres connection and queries |
| `metrics.go` | Prometheus metrics for audit, file, and Loki interfaces |
| `docker-compose.yml` | Postgres, Loki, Grafana |
| `loki-config.yaml` | Loki server configuration |
| `grafana/` | Pre-provisioned datasource and audit dashboard |

## Key Concepts

### Output Topology

Four outputs demonstrate different go-audit feature combinations:

| Output | Format | Route | HMAC | PII | Purpose |
|--------|--------|-------|------|-----|---------|
| **console** (stdout) | JSON | all events | none | full | Developer debugging via `docker compose logs` |
| **compliance_archive** (file) | CEF | all events | v1 SHA-256 | full | Compliance archive, SIEM-ready |
| **security_feed** (file) | JSON | security + compliance, severity >= 7 | v2 SHA-512 | full | Security team feed |
| **loki_dashboard** (Loki) | JSON | all events | none | stripped | Grafana dashboards, PII removed |

A single `user_create` event with an email field appears differently
in each output: full JSON on stdout, CEF with HMAC on audit.log,
absent from security.log (wrong category), JSON without email on Loki.

### Environment Variables

Output configs support `${VAR:-default}` syntax:

```yaml
path: "${AUDIT_LOG_PATH:-/data/audit.log}"
url: "${LOKI_URL:-http://loki:3100/loki/api/v1/push}"
```

The defaults work for local development with Docker Compose. In
production, set `HMAC_SALT_V1`, `HMAC_SALT_V2`, and `LOKI_URL` to
your real infrastructure.

### Wiring Prometheus Metrics

go-audit defines three metrics interfaces for the outputs used here.
The library does not import Prometheus — your application brings its
own implementation. A single struct can implement all three:

```go
type auditMetrics struct {
    events        *prometheus.CounterVec   // audit.Metrics (7 methods)
    fileRotations *prometheus.CounterVec   // file.Metrics
    lokiDrops     prometheus.Counter       // loki.Metrics
    // ...
}
```

To track per-output-type metrics (file rotation, Loki flush timing,
Loki drops), register custom factories before loading the output
config:

```go
import (
    "github.com/axonops/go-audit/file"
    "github.com/axonops/go-audit/loki"
)

audit.RegisterOutputFactory("file", file.NewFactory(m))
audit.RegisterOutputFactory("loki", loki.NewFactory(m))

result, err := outputconfig.Load(ctx, outputsYAML, &tax, m)
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
| `loki.Metrics` | `RecordLokiDrop()`, `RecordLokiFlush(batchSize, dur)`, `RecordLokiRetry(statusCode, attempt)`, `RecordLokiError(statusCode)` | Loki delivery |

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

### Graceful Shutdown — Critical

> **You MUST call `logger.Close()` before your application exits.**
> If you don't, the drain goroutine is leaked and all buffered audit
> events are lost. This is the single most important thing to get
> right when integrating go-audit.

The shutdown sequence matters — the order is:

1. **Stop the HTTP server** — no new requests, no new audit events
2. **Close the audit logger** — flushes all buffered events to every output
3. **Exit**

```go
// Wait for SIGINT (Ctrl+C) or SIGTERM (Docker/K8s stop).
quit := make(chan os.Signal, 1)
signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
<-quit

log.Println("shutting down...")

// Step 1: Stop accepting new HTTP requests.
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
srv.Shutdown(ctx)

// Step 2: Close the audit logger — THIS FLUSHES ALL PENDING EVENTS.
// Without this call, buffered events are lost and the drain goroutine leaks.
if err := logger.Close(); err != nil {
    log.Printf("audit close: %v", err)
}

log.Println("shutdown complete")
```

`Close()` waits up to `DrainTimeout` (default: 5 seconds) for all
buffered events to be written to outputs, then closes each output.
If events are still in the buffer when the timeout expires, they are
dropped and a warning is logged.

## Run It

```bash
# Start infrastructure:
docker compose up -d

# Wait for services:
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

# View Grafana dashboard:
open http://localhost:3000

# Prometheus metrics:
curl -s http://localhost:8080/metrics | grep audit_

# Stop with Ctrl+C, then:
docker compose down -v
```

## Expected Output

On stdout you'll see JSON audit events for every request:

```json
{"timestamp":"...","event_type":"item_list","severity":3,"actor_id":"alice","outcome":"success","event_category":"read"}
{"timestamp":"...","event_type":"item_create","severity":5,"actor_id":"alice","outcome":"success","target_id":"...","event_category":"write"}
{"timestamp":"...","event_type":"auth_failure","severity":9,"actor_id":"bad-key","outcome":"failure","reason":"invalid API key","event_category":"security"}
```

The same events are routed to different outputs:

- **`audit.log`** — all events in CEF format with HMAC v1 (SHA-256)
- **`security.log`** — security and compliance events (severity >= 7) with HMAC v2 (SHA-512)
- **Loki** — all events with PII fields stripped, queryable in Grafana
- **stdout** — all events in JSON with full PII

## Further Reading

- [Metrics and Monitoring](../../docs/metrics-monitoring.md) — Prometheus integration guide
- [HTTP Middleware](../../docs/http-middleware.md) — middleware placement and EventBuilder
- [Async Delivery](../../docs/async-delivery.md) — graceful shutdown and drain timeout
- [Output Configuration YAML](../../docs/output-configuration.md) — full YAML reference
- [HMAC Integrity](../../docs/hmac-integrity.md) — per-output tamper detection
- [Sensitivity Labels](../../docs/sensitivity-labels.md) — PII stripping per-output
- [Loki Output](../../docs/loki-output.md) — stream labels and Grafana integration
