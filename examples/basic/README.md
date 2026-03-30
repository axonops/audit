# Basic Audit Example

The minimum viable audit event: create a logger, emit an event, and see
what happens when validation fails.

## What You'll Learn

- Creating an `audit.Taxonomy` with categories and event definitions
- Configuring `audit.Config` with `Version` and `Enabled`
- Using `audit.NewStdoutOutput` for console output
- Building a logger with `audit.NewLogger`, `WithTaxonomy`, and `WithOutputs`
- Emitting events with `logger.Audit(eventType, fields)`
- How required-field validation works in strict mode

## Prerequisites

- Go 1.26+

## Files

| File | Purpose |
|------|---------|
| `main.go` | Logger setup, event emission, validation error |

## Run It

```bash
go run .
```

## Expected Output

```
--- Valid event ---

--- Invalid event (missing required field) ---
Validation error: audit: event "user_create" missing required fields: [actor_id]
{"timestamp":"2026-03-30T12:00:00.000Z","event_type":"user_create","actor_id":"alice","outcome":"success"}
```

The JSON event line may appear after both print statements because the
logger is **asynchronous** -- `Audit()` enqueues the event and returns
immediately. The drain goroutine writes it to stdout shortly after. The
invalid event returns an error synchronously because validation happens
before enqueueing.

## What's Happening

1. **Taxonomy** defines what events exist, which category they belong to,
   and which fields are required. The logger validates every `Audit()` call
   against the taxonomy.

2. **StdoutOutput** writes JSON-formatted events to standard output. Each
   event is a single line (NDJSON format).

3. **Config** sets `Version: 1` (required) and `Enabled: true`. When
   `Enabled` is false, the logger becomes a no-op.

4. **Validation** is strict by default. Missing a required field returns
   an error immediately. You can change this with `ValidationMode: "warn"`
   or `"permissive"`.

5. **Close** flushes any buffered events and releases resources. Always
   defer it.

## Next

[File Output](../file-output/) -- write events to a log file with rotation.
