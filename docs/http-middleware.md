[&larr; Back to README](../README.md)

# HTTP Middleware

## What Is the Audit Middleware?

The go-audit HTTP middleware automatically captures request metadata
for every HTTP request and makes it available for audit event
construction. It wraps any `http.Handler` and provides a `Hints`
object that your handlers populate with domain-specific audit data.

## Why Use Middleware?

Without middleware, every HTTP handler must manually extract transport
metadata (client IP, TLS state, request duration, status code) and
construct an audit event. This is repetitive, error-prone, and produces
inconsistent field values across handlers.

The middleware captures transport metadata once, consistently, and lets
your handlers focus on the domain-specific audit fields (who did what
to which resource).

## How It Works

```
Request
  └── Middleware wraps the handler
       ├── Captures: client IP, TLS state, method, path, user agent, request ID
       ├── Injects Hints into request context
       ├── Calls your handler
       ├── Captures: status code, duration
       └── Calls your EventBuilder to construct the audit event
```

### Transport Metadata (automatic)

| Field | Source |
|-------|--------|
| `client_ip` | X-Forwarded-For, X-Real-IP, or RemoteAddr |
| `transport_security` | "none", "tls", or "mtls" |
| `method` | HTTP method (GET, POST, etc.) |
| `path` | Request path |
| `user_agent` | User-Agent header (max 512 chars) |
| `request_id` | X-Request-Id header or generated UUID |
| `duration` | Handler execution time |
| `status_code` | HTTP response status |

### Hints (your handlers populate)

```go
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    hints := audit.HintsFromContext(r.Context())
    hints.EventType = "user_create"
    hints.ActorID = r.Header.Get("X-User-ID")
    hints.Outcome = "success"
    hints.TargetType = "user"
    hints.TargetID = "user-42"

    // ... handle the request ...
}
```

Available hint fields: `EventType`, `Outcome`, `ActorID`, `ActorType`,
`AuthMethod`, `Role`, `TargetType`, `TargetID`, `Reason`, `Error`,
and `Extra` (arbitrary key-value pairs).

### EventBuilder Callback

The `EventBuilder` function transforms hints and transport metadata
into an audit event:

```go
builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
    if hints.EventType == "" {
        return "", nil, true // skip — no audit event for this request
    }
    fields := audit.Fields{
        "outcome":   hints.Outcome,
        "actor_id":  hints.ActorID,
        "client_ip": transport.ClientIP,
        "method":    transport.Method,
        "path":      transport.Path,
    }
    return hints.EventType, fields, false
}
```

### Wiring It Up

```go
handler := audit.Middleware(logger, builder)(router)
http.ListenAndServe(":8080", handler)
```

Works with any router: chi, gorilla/mux, stdlib `http.ServeMux`.

## Skipping Requests

Return `skip = true` from the EventBuilder to suppress the audit event
for a request (e.g., health checks, static assets):

```go
if hints.EventType == "" || transport.Path == "/healthz" {
    return "", nil, true // no audit event
}
```

## Further Reading

- [Progressive Example: Middleware](../examples/08-middleware/) — complete HTTP middleware example
- [API Reference: Middleware](https://pkg.go.dev/github.com/axonops/go-audit#Middleware)
- [API Reference: Hints](https://pkg.go.dev/github.com/axonops/go-audit#Hints)
