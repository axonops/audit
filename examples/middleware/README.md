# Middleware Example

Automatic HTTP audit logging: the middleware captures transport metadata,
handlers populate domain hints, and health checks are silently skipped.

## What You'll Learn

- Using `audit.Middleware` to wrap an HTTP handler
- Writing an `EventBuilder` to map requests to audit events
- Populating `Hints` from handlers via `HintsFromContext`
- Skipping specific paths (health checks) by returning `skip: true`
- How `TransportMetadata` provides method, path, status, duration, client IP

## Prerequisites

- Go 1.26+
- Completed: [Event Routing](../event-routing/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | HTTP server with audit middleware and programmatic test requests |

## Run It

```bash
go run .
```

## Expected Output

```
GET http://127.0.0.1:.../healthz -> 200
GET http://127.0.0.1:.../items -> 200
POST http://127.0.0.1:.../items -> 201
--- Audit events ---
{"timestamp":"...","event_type":"http_request","actor_id":"alice","duration_ms":0,"method":"GET","outcome":"success","path":"/items","source_ip":"127.0.0.1","status_code":200}
{"timestamp":"...","event_type":"http_request","actor_id":"alice","duration_ms":0,"method":"POST","outcome":"success","path":"/items","source_ip":"127.0.0.1","status_code":201,"target_id":"item-42"}

Note: /healthz produced no audit event (skipped by EventBuilder).
```

Three HTTP requests, but only two audit events. The health check was
skipped by the `EventBuilder`.

## What's Happening

1. **Middleware** wraps any `http.Handler`. For each request it:
   - Creates a `Hints` struct and injects it into the request context
   - Records the start time
   - Calls the handler
   - Builds `TransportMetadata` (method, path, status, duration, client IP)
   - Calls `EventBuilder` with hints + transport

2. **EventBuilder** is your mapping function. It decides:
   - **What event type** to emit (here: always `http_request`)
   - **What fields** to include (merging hints + transport)
   - **Whether to skip** (return `true` for health checks)

3. **HintsFromContext** lets handlers communicate domain knowledge
   (actor ID, outcome, target) to the EventBuilder without coupling
   to the audit library directly.

4. **TransportMetadata** is populated automatically: HTTP method, URL
   path, client IP (from X-Forwarded-For/X-Real-IP/RemoteAddr), status
   code, request duration, user agent, and request ID.

## Next

[CRUD API](../crud-api/) -- a complete REST API with Postgres, five
outputs, Prometheus metrics, and Docker Compose.
