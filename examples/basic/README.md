# Basic Audit Example

The minimum viable audit event: create a logger, emit an event, and see
what happens when validation catches a missing field.

This example uses Go code to set everything up so you can see how the
library works under the hood. From the next example onwards, you'll
define your events and outputs in YAML files instead — that's how you'd
use go-audit in a real application.

## What You'll Learn

- Defining an audit taxonomy (what events your application can produce)
- Creating a logger and emitting events
- How required-field validation works
- Why the logger is asynchronous and what `Close()` does

## Prerequisites

- Go 1.26+

## Files

| File | Purpose |
|------|---------|
| `main.go` | Logger setup, event emission, validation error |

## Key Concepts

### The Taxonomy

Every application that uses go-audit starts by defining a **taxonomy** —
the list of events it can produce, grouped into categories, with
required fields for each:

```go
tax := audit.Taxonomy{
    Version: 1,
    Categories: map[string]*audit.CategoryDef{
        "write":    {Events: []string{"user_create", "user_delete"}},
        "security": {Events: []string{"auth_failure"}},
    },
    Events: map[string]*audit.EventDef{
        "user_create": {
            Required: []string{"outcome", "actor_id"},
        },
        // ...
    },
    DefaultEnabled: []string{"write", "security"},
}
```

Think of the taxonomy as a contract: "these are the audit events we
produce, and each one always includes these fields." If your code tries
to emit an event without a required field, the library rejects it
immediately. This is intentional — audit logging is a compliance
function, and silently dropping fields is worse than failing loudly.

**Categories** let you group related events. You can enable or disable
entire categories at runtime — useful if you need to turn off verbose
`read` events in a high-throughput environment without touching your
code.

In production, you wouldn't define the taxonomy in Go code like this.
You'd write it in a YAML file and use `audit-gen` to generate type-safe
constants. The [Code Generation](../code-generation/) example shows how.

### Creating the Logger

```go
stdout, err := audit.NewStdoutOutput(audit.StdoutConfig{})
if err != nil {
    log.Fatalf("create stdout output: %v", err)
}

logger, err := audit.NewLogger(
    audit.Config{Version: 1, Enabled: true},
    audit.WithTaxonomy(tax),
    audit.WithOutputs(stdout),
)
```

`NewLogger` takes a config struct and a set of options. `WithTaxonomy`
tells the logger what events are valid. `WithOutputs` tells it where to
send them.

`Config.Enabled` is a kill switch — when `false`, `Audit()` does nothing
and returns `nil`. This lets you wire audit logging into your application
unconditionally and toggle it via configuration.

### Emitting Events

```go
err := logger.Audit("user_create", audit.Fields{
    "outcome":  "success",
    "actor_id": "alice",
})
```

`Audit()` validates the fields against the taxonomy, serializes the
event to JSON, and **enqueues it to an internal buffer**. The actual
write to stdout happens asynchronously on a background goroutine.

This means `Audit()` is fast — it doesn't block on I/O. The trade-off:
output may appear slightly after the `fmt.Println` that precedes it in
your code.

### Validation Errors

```go
err = logger.Audit("user_create", audit.Fields{
    "outcome": "success",
    // actor_id intentionally omitted
})
// err: audit: event "user_create" missing required fields: [actor_id]
```

The event is rejected before it enters the buffer. No partial events
reach your outputs.

### Severity

Every audit event has an integer severity from 0 (informational) to 10
(critical). You'll see `"severity":5` in every JSON event in this
example — that's the default when no severity is configured.

Severity becomes useful for routing: you can send high-severity events
to a SIEM webhook while keeping low-severity events in local files.
You'll learn how to set per-category severity levels and route by
threshold in the [Event Routing](../event-routing/) example.

### Closing the Logger

```go
defer func() {
    if err := logger.Close(); err != nil {
        log.Printf("close logger: %v", err)
    }
}()
```

`Close()` waits for buffered events to flush, then shuts down the
background goroutine and closes all outputs. Without `Close()`, buffered
events may be lost.

### Buffer Full and Delivery Guarantees

go-audit uses an internal buffer (default 10,000 events) between
`Audit()` and the output writes. If your application emits events
faster than outputs can drain them, the buffer fills up and `Audit()`
returns `audit.ErrBufferFull`.

This is deliberate — audit logging must not silently drop events. Your
application decides how to handle back-pressure:

```go
if err := logger.Audit("user_create", fields); err != nil {
    if errors.Is(err, audit.ErrBufferFull) {
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

--- Invalid event (missing required field) ---
Validation error: audit: event "user_create" missing required fields: [actor_id]
{"timestamp":"...","event_type":"user_create","severity":5,"actor_id":"alice","outcome":"success"}
```

The JSON event appears after both print statements because `Audit()`
enqueues asynchronously — the background goroutine writes to stdout
after the caller's next statement has already executed.

## Next

[Code Generation](../code-generation/) — define your events in YAML and
generate type-safe Go constants.
