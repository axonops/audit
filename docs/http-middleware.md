[&larr; Back to README](../README.md)

# HTTP Audit Middleware

- [What Does This Do?](#what-does-this-do)
- [What Gets Captured Automatically](#what-gets-captured-automatically)
- [What Your Handlers Add](#what-your-handlers-add)
- [Skipping Requests](#skipping-requests)
- [Adding Custom Fields](#adding-custom-fields)
- [Wiring It Up](#wiring-it-up)
- [Available Hint Fields](#available-hint-fields)

## 🔍 What Does This Do?

When you build an HTTP API, you want to audit who did what — which
user called which endpoint, from which IP address, how long it took,
and whether it succeeded or failed.

The go-audit middleware is a convenience wrapper that automatically
captures standard HTTP request fields so you don't have to extract
them manually in every handler. It wraps your HTTP router and:

1. **Before your handler runs:** records the start time, extracts the
   client IP, checks TLS state, reads the request ID header
2. **After your handler runs:** records the status code and duration
3. **Calls your callback** to combine the automatic fields with your
   domain-specific audit data (who is the user, what resource did they
   touch, was it allowed)

## 🔍 What Gets Captured Automatically

These fields are extracted from every HTTP request without any code in
your handlers:

| Field | Where It Comes From |
|-------|---------------------|
| Client IP | `X-Forwarded-For` header, `X-Real-IP` header, or `RemoteAddr` |
| TLS state | `"none"`, `"tls"`, or `"mtls"` based on connection |
| HTTP method | `GET`, `POST`, `PUT`, `DELETE`, etc. |
| Request path | The URL path (e.g., `/api/users/42`) |
| User agent | The `User-Agent` header (truncated to 512 characters) |
| Request ID | The `X-Request-Id` header, or a generated UUID if absent |
| Duration | How long your handler took to execute |
| Status code | The HTTP response status (200, 404, 500, etc.) |

The `duration_ms` field is automatically added to the audit event
when the middleware calculates the request duration. This is a
middleware-specific feature — it is not added to events emitted
outside of HTTP request handling.

## 🔍 What Your Handlers Add

Your handlers add domain-specific audit data — the things only
your application code knows:

```go
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    // Get the audit hints from the request context.
    hints := audit.HintsFromContext(r.Context())

    // Tell the middleware what audit event to emit.
    hints.EventType = "user_create"
    hints.ActorID = r.Header.Get("X-User-ID")
    hints.Outcome = "success"
    hints.TargetType = "user"
    hints.TargetID = "user-42"

    // ... handle the request normally ...
    w.WriteHeader(http.StatusCreated)
}
```

## ⏭️ Skipping Requests

> **Not every HTTP request needs an audit event.** If your callback
> returns `skip = true`, no audit event is emitted for that request.
> Use this for health checks, static assets, metrics endpoints, or
> any route that does not need auditing.

The skip decision is made in your `EventBuilder` callback — you
control it completely:

```go
builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
    // Skip health checks and metrics endpoints.
    if transport.Path == "/healthz" || transport.Path == "/metrics" {
        return "", nil, true // skip — no audit event
    }

    // Skip if the handler didn't set an event type.
    if hints.EventType == "" {
        return "", nil, true // skip — handler didn't request auditing
    }

    return hints.EventType, audit.Fields{
        "outcome":  hints.Outcome,
        "actor_id": hints.ActorID,
    }, false
}
```

## ➕ Adding Custom Fields

The predefined hint fields (`ActorID`, `Outcome`, `TargetID`, etc.)
cover common audit data. For anything beyond these, use the `Extra`
field — a `map[string]any` that lets you add **any custom fields**
to the audit event:

```go
func transferHandler(w http.ResponseWriter, r *http.Request) {
    hints := audit.HintsFromContext(r.Context())
    hints.EventType = "funds_transfer"
    hints.ActorID = r.Header.Get("X-User-ID")
    hints.Outcome = "success"

    // Add custom fields — anything your taxonomy defines.
    hints.Extra = map[string]any{
        "amount":        1500.00,
        "currency":      "USD",
        "from_account":  "ACC-123",
        "to_account":    "ACC-456",
        "approval_code": "APR-789",
    }

    // ... process the transfer ...
    w.WriteHeader(http.StatusOK)
}
```

Your `EventBuilder` callback then includes these extra fields in the
audit event:

```go
builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
    if hints.EventType == "" {
        return "", nil, true
    }

    fields := audit.Fields{
        "outcome":   hints.Outcome,
        "actor_id":  hints.ActorID,
        "client_ip": transport.ClientIP,
        "method":    transport.Method,
        "path":      transport.Path,
    }

    // Merge in any custom fields the handler added.
    for k, v := range hints.Extra {
        fields[k] = v
    }

    return hints.EventType, fields, false
}
```

## 🔌 Wiring It Up

The middleware works with any Go HTTP router — stdlib `http.ServeMux`,
chi, gorilla/mux, or anything that uses `http.Handler`.

```go
// 1. Create your EventBuilder callback (see examples above).
builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
    // ... your logic here ...
}

// 2. Wrap your router with the audit middleware.
auditedRouter := audit.Middleware(logger, builder)(router)

// 3. Use the wrapped router as your HTTP handler.
http.ListenAndServe(":8080", auditedRouter)
```

For a complete working example with multiple routes, authentication
middleware, and the full EventBuilder implementation, see
[Progressive Example: Middleware](../examples/06-middleware/).

## 📋 Available Hint Fields

These are the predefined fields you can set on `Hints` in your
handlers. All are optional — set only what applies to your request.

| Field | Type | Purpose |
|-------|------|---------|
| `EventType` | `string` | Which audit event to emit (e.g., `"user_create"`) |
| `Outcome` | `string` | Result: `"success"`, `"failure"`, `"denied"` |
| `ActorID` | `string` | Who performed the action (user ID, service account) |
| `ActorType` | `string` | Category: `"user"`, `"service"`, `"admin"` |
| `AuthMethod` | `string` | How they authenticated: `"bearer"`, `"mtls"`, `"api_key"` |
| `Role` | `string` | Their permission level: `"admin"`, `"viewer"` |
| `TargetType` | `string` | What kind of resource: `"user"`, `"document"`, `"config"` |
| `TargetID` | `string` | Which specific resource: `"user-42"`, `"doc-abc"` |
| `Reason` | `string` | Why (if applicable): `"admin override"`, `"scheduled task"` |
| `Error` | `string` | Error message on failure |
| `Extra` | `map[string]any` | **Any additional custom fields** — use for domain-specific data |

> **`Extra` is your escape hatch.** The predefined fields above cover
> common patterns, but `Extra` lets you add any field your taxonomy
> defines. You are not limited to the predefined set.

## Framework Fields in Middleware Events

Middleware audit events include all configured framework fields
(`app_name`, `host`, `timezone`, `pid`) just like any other event.
These are set once at logger construction and appear automatically
in every serialised event — no middleware configuration needed.

The 31 [reserved standard fields](../examples/13-standard-fields/)
(including `source_ip`, `method`, `path`, `user_agent`, `request_id`)
are populated by the middleware via `AuditHints` and always accepted
without taxonomy declaration.

## 📚 Further Reading

- [Progressive Example: Middleware](../examples/06-middleware/) — complete HTTP middleware example
- [Progressive Example: CRUD API](../examples/17-crud-api/) — middleware in a full REST application
- [API Reference: Middleware](https://pkg.go.dev/github.com/axonops/audit#Middleware)
