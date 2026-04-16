[← Back to examples](../README.md)

> **Next:** [02 — Code Generation](../02-code-generation/)

# Example 01: Basic Audit Logging (Programmatic)

The minimum viable audit event: create an auditor, emit an event, and see
the JSON output. No YAML files, no code generation, no configuration —
just Go code.

This example uses `DevTaxonomy()` and `Stdout()` so you can see how the
library works in a playground. From the next example onwards, you'll
define your events and outputs in YAML files instead — that's how you'd
use audit in a real application.

## What You'll Learn

- Creating an auditor with two lines of setup
- Emitting events with `NewEventKV()` (slog-style) and `NewEvent()` (map-style)
- How the auditor delivers events asynchronously
- Why `Close()` matters

## Prerequisites

- Go 1.26+

## Files

| File | Purpose |
|------|---------|
| `main.go` | Logger setup, event emission |

## Key Concepts

### DevTaxonomy — Quick Setup for Exploration

`DevTaxonomy()` creates a permissive taxonomy that accepts any fields
on the listed event types. It exists so you can experiment without
writing YAML or worrying about field validation:

```go
auditor, err := audit.New(
    audit.WithTaxonomy(audit.DevTaxonomy("user_create", "auth_failure")),
    audit.WithOutputs(audit.Stdout()),
)
```

`New()` takes functional options. `WithTaxonomy()` tells the auditor
what events are valid. `WithOutputs()` tells it where to send them.
`Stdout()` writes JSON to stdout — no file rotation, no network, no
configuration.

In production, you'd define your taxonomy in a YAML file with required
fields and severity levels, then use `audit-gen` to generate type-safe
builders. The [Code Generation](../02-code-generation/) example shows how.

### Emitting Events

Two styles, same result:

**slog-style key-value pairs** (concise):
```go
err := auditor.AuditEvent(audit.NewEventKV("user_create",
    "outcome", "success",
    "actor_id", "alice",
))
```

**Fields map** (explicit):
```go
err := auditor.AuditEvent(audit.NewEvent("auth_failure", audit.Fields{
    "outcome":  "failure",
    "actor_id": "unknown",
}))
```

`AuditEvent()` validates the fields against the taxonomy, serializes the
event to JSON, and **enqueues it to an internal buffer**. The actual
write to stdout happens asynchronously on a background goroutine.

This means `AuditEvent()` is fast — it doesn't block on I/O. The
trade-off: output may appear slightly after the `fmt.Println` that
precedes it in your code.

### Closing the Logger

```go
defer func() { _ = auditor.Close() }()
```

`Close()` waits for buffered events to flush, then shuts down the
background goroutine and closes all outputs. Without `Close()`, buffered
events may be lost.

### Severity

Every audit event has an integer severity from 0 (informational) to 10
(critical). You'll see `"severity":5` in every JSON event in this
example — that's the default when no severity is configured.

Severity becomes useful for routing: you can send high-severity events
to a SIEM webhook while keeping low-severity events in local files.
You'll learn how to set per-category severity levels and route by
threshold in the [Event Routing](../10-event-routing/) example.

### Buffer Full and Delivery Guarantees

audit uses an internal buffer (default 10,000 events) between
`AuditEvent()` and the output writes. If your application emits events
faster than outputs can drain them, the buffer fills up and `AuditEvent()`
returns `audit.ErrQueueFull`.

This is deliberate — audit logging must not silently drop events. Your
application decides how to handle back-pressure:

```go
if err := auditor.AuditEvent(audit.NewEvent("user_create", fields)); err != nil {
    if errors.Is(err, audit.ErrQueueFull) {
        // Buffer is full — outputs can't keep up.
        // Log to stderr, increment a metric, or slow down.
    }
}
```

Delivery to outputs is **at-most-once within a process lifetime**: if
the application crashes before `Close()` flushes the buffer, in-flight
events are lost. For stronger guarantees, use the webhook output with
retries or a durable syslog relay.

## Run It

```bash
go run .
```

## Expected Output

```
--- Valid event ---

--- Auth failure event ---
INFO audit: shutdown started
{"timestamp":"...","event_type":"user_create","severity":5,"timezone":"Local","pid":...,"actor_id":"alice","outcome":"success","event_category":"dev"}
{"timestamp":"...","event_type":"auth_failure","severity":5,"timezone":"Local","pid":...,"actor_id":"unknown","outcome":"failure","event_category":"dev"}
INFO audit: shutdown complete duration=...
```

The JSON events appear between the shutdown messages because
`AuditEvent()` enqueues asynchronously and `Close()` drains the buffer
before finishing. This is normal — `Close()` guarantees all buffered
events are delivered before it returns.

## Further Reading

- [Taxonomy Validation](../../docs/taxonomy-validation.md) — how the library validates events
- [Async Delivery](../../docs/async-delivery.md) — buffering, backpressure, and shutdown
- [API Reference](https://pkg.go.dev/github.com/axonops/audit) — full godoc
