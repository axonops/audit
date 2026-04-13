[← Back to examples](../README.md)

> **Previous:** [16 — Buffering](../16-buffering/)

# Example 17: Inventory Demo (Capstone)

A complete inventory management application with a web UI, Postgres
database, four simultaneous audit outputs, Grafana dashboards, and
Prometheus metrics. **One command starts everything.**

This is the capstone example — it ties together every audit feature
from the previous 16 examples into a realistic application that you
can explore immediately.

## Quick Start

```bash
docker compose up -d
```

Then open:

- **http://localhost:8080** — Web UI (inventory management)
- **http://localhost:3000** — Grafana (audit dashboard, no login needed)

That's it. Docker Compose builds the app from source, starts Postgres,
Loki, and Grafana, and wires them together. No Go toolchain required.

## Walkthrough

### 1. Log in

Open http://localhost:8080. Default credentials: **alice / password**.

The login generates an `auth_success` audit event. Try wrong
credentials first to generate an `auth_failure` event — you'll see
it in Grafana moments later.

### 2. Create some data

- **Users tab** — create a user with an email address (this is PII —
  watch how it appears differently on each output)
- **Items tab** — create a few inventory items
- **Orders tab** — create an order linking a user to an item

Every action generates audit events: `user_create`, `item_create`,
`order_create`, etc. These flow to all four outputs simultaneously.

### 3. See audit events in Grafana

Open http://localhost:3000 and navigate to **Dashboards →
"audit: Inventory Demo Dashboard"**. You'll see:

- **Events over time** — line chart showing audit activity
- **Events by category** — pie chart (read, write, security, compliance)
- **Events by severity** — bar gauge showing severity distribution
- **Auth failures** — counter for failed authentication attempts
- **Top event types** — which events fire most often
- **Recent events** — live log stream of audit events

The dashboard updates in near-real-time as you interact with the app.

### 4. Trigger security events

- **Wrong credentials** — login with a bad password to generate
  `auth_failure` (severity 9, routed to security.log)
- **Rate limiting** — make 6 rapid failed login attempts to trigger
  `rate_limit_exceeded` (severity 8)
- **Bulk operations** — use the Admin tab's "Bulk Delete" to trigger
  `bulk_delete` (compliance category)

### 5. Inspect the four outputs

Every audit event goes to four outputs simultaneously, each showing
different audit features:

```bash
# stdout — JSON with full PII (visible in container logs)
docker compose logs app | grep event_type

# compliance archive — CEF format with HMAC v1 (SHA-256)
docker compose exec app cat /data/audit.log

# security feed — JSON, severity >= 7 only, HMAC v2 (SHA-512)
docker compose exec app cat /data/security.log

# Loki — JSON with PII stripped (visible in Grafana)
# open http://localhost:3000
```

Notice how the **same event** looks different in each output:
- A `user_create` with an email field appears in **stdout** with the
  full email, in **audit.log** in CEF format with an HMAC signature,
  is **absent** from **security.log** (wrong category — severity 5 < 7),
  and appears in **Loki** with the email field stripped (PII label).

### 6. Prometheus metrics

```bash
curl -s http://localhost:8080/metrics | grep audit_
```

Shows event counts, validation errors, buffer drops, file rotations,
and Loki delivery metrics — all wired automatically from a single
metrics struct.

### 7. Load test (optional)

```bash
./loadtest.sh
```

Generates 300+ diverse events (logins, CRUD operations, auth failures,
admin actions) to populate the Grafana dashboards with realistic data.

### 8. Clean up

```bash
docker compose down -v
```

## Output Topology

```
                          ┌── stdout (JSON, all events, full PII)
                          │     → docker compose logs app
                          │
  audit event → logger ───┼── audit.log (CEF, all events, HMAC v1)
                          │     → compliance archive, SIEM-ready
                          │
                          ├── security.log (JSON, severity >= 7, HMAC v2)
                          │     → security team, different salt
                          │
                          └── Loki (JSON, all events, PII stripped)
                                → Grafana dashboards
```

| Output | Format | Route | HMAC | PII | Purpose |
|--------|--------|-------|------|-----|---------|
| **console** (stdout) | JSON | all events | none | full | Developer debugging via `docker compose logs` |
| **compliance_archive** (file) | CEF | all events | v1 SHA-256 | full | Compliance archive, SIEM-ready |
| **security_feed** (file) | JSON | security + compliance, severity >= 7 | v2 SHA-512 | full | Security team feed |
| **loki_dashboard** (Loki) | JSON | all events | none | stripped | Grafana dashboards, PII removed |

## Files

| File | Purpose |
|------|---------|
| `Dockerfile` | Multi-stage build — compiles Go binary, runs in Alpine |
| `docker-compose.yml` | App + Postgres + Loki + Grafana — one command starts all |
| `taxonomy.yaml` | 21 event types, 4 categories, sensitivity labels |
| `outputs.yaml` | Four outputs with HMAC, CEF, routing, PII stripping |
| `audit_generated.go` | Generated typed builders (committed) |
| `main.go` | Entry point, signal handling, graceful shutdown |
| `audit_setup.go` | Loads output config, wires metrics via auto-detection |
| `server.go` | HTTP mux, audit middleware, EventBuilder |
| `handlers*.go` | CRUD handlers for users, items, orders |
| `auth.go` | Session-based auth, login/logout, auth failure events |
| `admin.go` | Settings, export, bulk operations |
| `db*.go` | Postgres connection and queries |
| `metrics.go` | Prometheus metrics (core + per-output via structural typing) |
| `static/index.html` | Single-page web UI |
| `grafana/` | Pre-provisioned Loki datasource and audit dashboard |
| `loki-config.yaml` | Loki server configuration |
| `loadtest.sh` | Generates 300+ diverse events for dashboard testing |

## Key Concepts

### Metrics Auto-Detection

The `auditMetrics` struct in `metrics.go` implements both the core
`audit.Metrics` interface and the per-output interfaces (`file.Metrics`,
`loki.Metrics`) via structural typing. When passed to `outputconfig.Load`
via `WithCoreMetrics(m)`, the output factories automatically detect
which interfaces it satisfies:

```go
result, err := outputconfig.Load(ctx, outputsYAML, tax,
    outputconfig.WithCoreMetrics(m),
)
```

No `RegisterOutputFactory` calls needed. Adding a new output type to
`outputs.yaml` is a config change, not a code change.

### Authentication and Audit Hints

Auth and audit middleware are composed as HTTP handler layers:

```go
authed := authMiddleware()(mux)
audited := audit.Middleware(logger, buildAuditEvent)(authed)
```

When authentication fails, the auth middleware sets
`Hints.EventType = "auth_failure"` and returns 401 — the audit
middleware automatically emits the failure event. When authentication
succeeds, it sets `Hints.ActorID` so the audit event records who made
the request. Neither the auth middleware nor the handlers need a direct
reference to the audit logger.

### Graceful Shutdown

The shutdown sequence matters:

1. **Stop the HTTP server** — no new requests, no new audit events
2. **Close the audit logger** — flushes all buffered events to outputs
3. **Exit**

Without `logger.Close()`, buffered events are lost and the drain
goroutine leaks. See `main.go` for the signal handling pattern.

## Running Without Docker

If you prefer to run the app directly (for development):

```bash
# Start infrastructure only:
docker compose up -d postgres loki grafana

# Wait for services:
docker compose exec postgres pg_isready -U demo -d audit_demo

# Run the app:
go run .
```

## Further Reading

- [Metrics and Monitoring](../../docs/metrics-monitoring.md)
- [HTTP Middleware](../../docs/http-middleware.md)
- [Async Delivery](../../docs/async-delivery.md) — graceful shutdown
- [Output Configuration](../../docs/output-configuration.md) — YAML reference
- [HMAC Integrity](../../docs/hmac-integrity.md)
- [Sensitivity Labels](../../docs/sensitivity-labels.md)
- [Loki Output](../../docs/loki-output.md)
