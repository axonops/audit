[&larr; Back to README](../README.md)

# HTTP Audit Middleware

## What Does This Do?

When you build an HTTP API, you want to audit who did what — which
user called which endpoint, from which IP address, how long it took,
and whether it succeeded or failed. Extracting this information from
every HTTP handler manually is repetitive and error-prone.

The go-audit middleware is a convenience wrapper that automatically
captures the standard HTTP fields you would otherwise extract by hand
in every handler. It wraps your HTTP router and:

1. **Before your handler runs:** records the start time, extracts the
   client IP, checks TLS state, reads the request ID header
2. **After your handler runs:** records the status code and duration
3. **Calls your callback** to combine the automatic fields with your
   domain-specific audit data (who is the user, what resource did they
   touch, was it allowed)

## What Gets Captured Automatically

These fields are extracted from every HTTP request without any code in
your handlers:

| Field | Where It Comes From |
|-------|---------------------|
| Client IP | `X-Forwarded-For` header, `X-Real-IP` header, or `RemoteAddr` |
| TLS state | Whether the connection uses TLS or mTLS |
| HTTP method | `GET`, `POST`, `PUT`, `DELETE`, etc. |
| Request path | The URL path (e.g., `/api/users/42`) |
| User agent | The `User-Agent` header (truncated to 512 characters) |
| Request ID | The `X-Request-Id` header, or a generated UUID if absent |
| Duration | How long your handler took to execute |
| Status code | The HTTP response status (200, 404, 500, etc.) |

## What Your Handlers Add

Your handlers add the domain-specific audit fields — the things only
your application code knows:

```go
func createUserHandler(w http.ResponseWriter, r *http.Request) {
    // Get the audit hints from the request context
    hints := audit.HintsFromContext(r.Context())

    // Tell the middleware what audit event to emit
    hints.EventType = "user_create"
    hints.ActorID = r.Header.Get("X-User-ID")
    hints.Outcome = "success"
    hints.TargetType = "user"
    hints.TargetID = "user-42"

    // ... handle the request normally ...
    w.WriteHeader(http.StatusCreated)
}
```

If a handler does not set `hints.EventType`, no audit event is emitted
for that request. This lets you skip health checks, static assets, or
any endpoint that doesn't need auditing.

## Wiring It Up

The middleware works with any Go HTTP router — stdlib `http.ServeMux`,
chi, gorilla/mux, or anything that uses `http.Handler`.

```go
// The callback combines auto-captured fields with your handler's hints
builder := func(hints *audit.Hints, transport *audit.TransportMetadata) (string, audit.Fields, bool) {
    if hints.EventType == "" {
        return "", nil, true // skip — no audit for this request
    }
    return hints.EventType, audit.Fields{
        "outcome":   hints.Outcome,
        "actor_id":  hints.ActorID,
        "client_ip": transport.ClientIP,
        "method":    transport.Method,
        "path":      transport.Path,
    }, false
}

// Wrap your router with the middleware
handler := audit.Middleware(logger, builder)(router)
http.ListenAndServe(":8080", handler)
```

## Available Hint Fields

| Field | Purpose |
|-------|---------|
| `EventType` | Which audit event to emit (e.g., `"user_create"`) |
| `Outcome` | Result: `"success"`, `"failure"`, `"denied"` |
| `ActorID` | Who performed the action (user ID, service account) |
| `ActorType` | Category: `"user"`, `"service"`, `"admin"` |
| `AuthMethod` | How they authenticated: `"bearer"`, `"mtls"`, `"api_key"` |
| `Role` | Their permission level: `"admin"`, `"viewer"` |
| `TargetType` | What kind of resource: `"user"`, `"document"`, `"config"` |
| `TargetID` | Which specific resource: `"user-42"`, `"doc-abc"` |
| `Reason` | Why (if applicable): `"admin override"`, `"scheduled task"` |
| `Error` | Error message on failure |
| `Extra` | Arbitrary `map[string]any` for additional fields |

## Further Reading

- [Progressive Example: Middleware](../examples/08-middleware/) — complete HTTP middleware example
- [Progressive Example: CRUD API](../examples/09-crud-api/) — middleware in a full REST application
- [API Reference: Middleware](https://pkg.go.dev/github.com/axonops/go-audit#Middleware)
