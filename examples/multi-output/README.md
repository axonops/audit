# Multi-Output Example

Send every audit event to multiple destinations simultaneously using
fan-out delivery.

## What You'll Learn

- Passing multiple outputs to `WithOutputs`
- How fan-out works: one `Audit()` call delivers to ALL outputs
- Combining stdout (for development) with file (for persistence)

## Prerequisites

- Go 1.26+
- Completed: [Basic](../basic/), [File Output](../file-output/)

## Files

| File | Purpose |
|------|---------|
| `main.go` | Two outputs, fan-out delivery, file readback |

## Run It

```bash
go run .
```

## Expected Output

Three JSON events appear on stdout (from the stdout output), followed by
the same three events read back from `audit.log` (from the file output):

```
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure"}
{"timestamp":"...","event_type":"user_create","actor_id":"bob","outcome":"success"}

--- Contents of audit.log ---
{"timestamp":"...","event_type":"user_create","actor_id":"alice","outcome":"success"}
{"timestamp":"...","event_type":"auth_failure","actor_id":"unknown","outcome":"failure"}
{"timestamp":"...","event_type":"user_create","actor_id":"bob","outcome":"success"}
```

Both outputs received identical events.

## What's Happening

1. **WithOutputs** accepts a variadic list of `audit.Output` values. The
   logger delivers every event to every output. This is the simplest
   fan-out configuration.

2. **Ordering** is preserved: outputs receive events in the order they
   were passed to `WithOutputs`.

3. For per-output filtering (e.g., security events to syslog only), see
   the [Event Routing](../event-routing/) example which uses
   `WithNamedOutput` instead.

## Next

[Code Generation](../code-generation/) -- generate type-safe constants
from a YAML taxonomy.
