# Event Routing Example

Route different event categories to different outputs: security events
to one file, write events to another, and everything to the console.

## What You'll Learn

- Using `WithNamedOutput` for per-output configuration
- Using `audit.WrapOutput` to give outputs human-readable names
- Defining `EventRoute` with `IncludeCategories` for allow-list filtering
- How a nil route means "receive all events"

## Prerequisites

- Go 1.26+
- Completed: [Multi-Output](../multi-output/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | Three named outputs with different routing rules |

## Run It

```bash
go run .
```

## Expected Output

All three events appear on stdout (the console output has no route
filter). Each file contains only the events matching its route:

```
--- security.log ---
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure"}

--- writes.log ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
```

The `user_read` event does not appear in either file because neither
route includes the `read` category.

## What's Happening

1. **WithNamedOutput** replaces `WithOutputs` when you need per-output
   control. Each call takes an output, an optional route, and an optional
   formatter. You cannot mix `WithOutputs` and `WithNamedOutput`.

2. **WrapOutput** overrides an output's default `Name()` with a
   human-readable label. This name appears in metrics, log messages, and
   `EnableOutput`/`DisableOutput` calls.

3. **EventRoute.IncludeCategories** creates an allow-list: only events in
   the listed categories are delivered. You can also use
   `ExcludeCategories` for a deny-list, or `IncludeEventTypes` /
   `ExcludeEventTypes` for event-level granularity.

4. **nil route** means no filtering — the output receives every event.

## Next

[Formatters](../formatters/) -- output events as JSON or CEF side by side.
