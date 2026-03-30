# Event Routing Example

Route different event categories to different outputs: security events
to one file, write events to another, and everything to the console.

## What You'll Learn

- Adding per-output routing rules in `outputs.yaml`
- How `include_categories` and `exclude_categories` work
- What happens to events that don't match any route

## Prerequisites

- Go 1.26+
- Completed: [Multi-Output](../multi-output/)

## Files

| File | Purpose |
|------|---------|
| `taxonomy.yaml` | Three categories: write, read, security |
| `outputs.yaml` | Three outputs with different routing rules |
| `audit_generated.go` | Generated constants (committed) |
| `main.go` | Emits one event per category, shows filtered output |

## Key Concepts

### Routes in YAML

Each output can have a `route:` block that controls which events it
receives:

```yaml
version: 1
outputs:
  console:
    type: stdout
    # No route — receives ALL events.

  security_log:
    type: file
    file:
      path: "./security.log"
    route:
      include_categories:
        - security

  writes_log:
    type: file
    file:
      path: "./writes.log"
    route:
      include_categories:
        - write
```

- **No route** = receives everything (the console output above)
- **`include_categories`** = allow-list — only events in these categories
- **`exclude_categories`** = deny-list — everything except these categories

You can also filter by individual event types with `include_event_types`
and `exclude_event_types`.

### Route Validation

Routes are validated against your taxonomy when the config is loaded. If
you reference a category that doesn't exist in your taxonomy,
`outputconfig.Load` returns an error immediately — no silent
misconfiguration.

### What Happens to Unmatched Events

An event that doesn't match any routed output is simply not delivered to
that output. In this example, the `user_read` event (category `read`)
doesn't match either file's route, so it only appears on stdout.

Events are filtered before serialization — no wasted work formatting
events that won't be delivered.

## Run It

```bash
go run .
```

## Expected Output

All three events appear on stdout. Each file contains only the events
matching its route:

```
--- security.log ---
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure"}

--- writes.log ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
```

The `user_read` event doesn't appear in either file — neither route
includes the `read` category. Notice that `user_read` only requires
`outcome` — `actor_id` is optional for read events. Each event type
defines its own required fields in the taxonomy.

## Next

[Formatters](../formatters/) — output events as JSON or CEF for SIEM
integration.
